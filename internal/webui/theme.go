// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
)

// A theme is a directory with theme.css, theme.yaml, a logo and a favicon.
// Every file is optional. A missing token, text or file comes from the
// built-in eudi-dev theme in theme/.
const (
	themeRoot   = "theme"
	themeCSS    = "theme.css"
	themeTexts  = "theme.yaml"
	textsName   = "texts.json"
	logoName    = "logo"
	faviconName = "favicon"
)

// Image types of a logo or favicon, in search order.
var (
	logoTypes    = []string{".svg", ".png", ".webp", ".jpg", ".jpeg"}
	faviconTypes = []string{".svg", ".png", ".ico"}
)

// Theme is an operator's theme directory. Each request reads the files
// again, so a changed file applies without a restart, for example an updated
// Kubernetes ConfigMap.
type Theme struct {
	files fs.FS
	// parsed is theme.yaml as last parsed. Every page request needs the texts,
	// so a request parses the file again only when its size or modification
	// time changed.
	parsed atomic.Pointer[parsedTexts]
}

type parsedTexts struct {
	size    int64
	modTime time.Time
	texts   Texts
	err     error
}

var active atomic.Pointer[Theme]

// LoadTheme opens a theme directory.
func LoadTheme(dir string) (*Theme, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	t := &Theme{files: root.FS()}
	texts, err := t.currentTexts()
	if err != nil {
		return nil, err
	}
	if t.css() == nil && texts.empty() && t.find(logoName, logoTypes) == "" && t.find(faviconName, faviconTypes) == "" {
		return nil, fmt.Errorf("theme %s has no theme.css, theme.yaml, logo or favicon", dir)
	}
	return t, nil
}

// Texts are the texts of a theme, set in theme.yaml.
type Texts struct {
	// Name is the wallet name in the title and the header of the pages.
	Name string `yaml:"name"`
	// Description is the meta description of the wallet page.
	Description string `yaml:"description"`
	// Edition is a short tag next to the wallet name in the header.
	Edition string `yaml:"edition"`
	// Product is shown in the footer.
	Product Product `yaml:"product"`
	// Nav changes the header menu.
	Nav Nav `yaml:"nav"`
	// Demo changes the demo hints on the wallet page.
	Demo Demo `yaml:"demo"`
}

// Demo changes the demo hints on the wallet page. Issuer and Verifier are
// the link targets of the built-in hints. Each is an http or https URL, or a
// path relative to the wallet page.
type Demo struct {
	Issuer   string   `yaml:"issuer"`
	Verifier string   `yaml:"verifier"`
	Hint     DemoHint `yaml:"hint"`
}

// DemoHint is the hint below the wallet actions.
type DemoHint struct {
	Text string `yaml:"text"`
	// Links replace the links to the demo issuer and the demo verifier.
	Links []Link `yaml:"links"`
}

// Product is a product built on eudi-dev.
type Product struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version,omitempty"`
	// URL is the page of the product. The GitHub entry of the header menu
	// links to it.
	URL string `yaml:"url" json:"url,omitempty"`
}

// Nav changes the header menu.
type Nav struct {
	// Links follow the built-in entries.
	Links []Link `yaml:"links"`
	// Hide lists built-in entries by the names in navEntries.
	Hide []string `yaml:"hide"`
}

// Link is an entry of the header menu or of the demo hint.
type Link struct {
	Label string `yaml:"label"`
	// URL is an http or https URL, or a path relative to the wallet page.
	URL string `yaml:"url"`
}

// navEntries maps the name of a built-in header menu entry to the id of its
// element.
var navEntries = map[string]string{
	"decoder":    "decoder-link",
	"how-to-use": "how-to-use-link",
	"get-cli":    "get-cli-link",
	"settings":   "conformance-link",
	"templates":  "templates-menu",
	"trust":      "trust-link",
	"registrar":  "registrar-menu",
	"github":     "github-link",
}

const (
	maxEditionRunes = 24
	maxLabelRunes   = 40
	maxNavLinks     = 8
	maxHintLinks    = 4
)

func (t Texts) empty() bool {
	return reflect.DeepEqual(t, Texts{})
}

func (t Texts) check() error {
	if utf8.RuneCountInString(t.Edition) > maxEditionRunes {
		return fmt.Errorf("edition is longer than %d characters", maxEditionRunes)
	}
	if t.Product.Name == "" && (t.Product.Version != "" || t.Product.URL != "") {
		return errors.New("product needs a name")
	}
	for name, text := range map[string]string{"product.name": t.Product.Name, "product.version": t.Product.Version} {
		if utf8.RuneCountInString(text) > maxLabelRunes {
			return fmt.Errorf("%s is longer than %d characters", name, maxLabelRunes)
		}
	}
	if t.Product.URL != "" && !isWebURL(t.Product.URL) {
		return errors.New("product.url must be an http or https URL")
	}
	if err := checkLinks("nav.links", t.Nav.Links, maxNavLinks); err != nil {
		return err
	}
	if err := checkLinks("demo.hint.links", t.Demo.Hint.Links, maxHintLinks); err != nil {
		return err
	}
	for name, target := range map[string]string{"demo.issuer": t.Demo.Issuer, "demo.verifier": t.Demo.Verifier} {
		if target != "" && !isWebURL(target) && !isPagePath(target) {
			return fmt.Errorf("%s must be an http or https URL or a path relative to the wallet page", name)
		}
	}
	if utf8.RuneCountInString(t.Demo.Hint.Text) > maxLabelRunes {
		return fmt.Errorf("demo.hint.text is longer than %d characters", maxLabelRunes)
	}
	for _, name := range t.Nav.Hide {
		if _, known := navEntries[name]; !known {
			names := slices.Sorted(maps.Keys(navEntries))
			return fmt.Errorf("nav.hide lists the unknown entry %q. Known entries: %s", name, strings.Join(names, ", "))
		}
	}
	return nil
}

func checkLinks(name string, links []Link, maxLinks int) error {
	if len(links) > maxLinks {
		return fmt.Errorf("%s has more than %d entries", name, maxLinks)
	}
	for i, link := range links {
		if link.Label == "" || utf8.RuneCountInString(link.Label) > maxLabelRunes {
			return fmt.Errorf("%s[%d] needs a label of at most %d characters", name, i, maxLabelRunes)
		}
		if !isWebURL(link.URL) && !isPagePath(link.URL) {
			return fmt.Errorf("%s[%d].url must be an http or https URL or a path relative to the wallet page", name, i)
		}
	}
	return nil
}

func isWebURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// isPagePath reports whether raw is a path relative to the wallet page. A
// leading slash or a ".." segment would leave the path prefix of the wallet
// (ADR-0019). Browsers read a backslash as a slash and "%2e%2e" as "..".
func isPagePath(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || u.Scheme != "" || u.Host != "" || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "\\") {
		return false
	}
	return !slices.Contains(strings.Split(strings.ReplaceAll(u.Path, "\\", "/"), "/"), "..")
}

// texts reads theme.yaml. An unknown field is an error (ADR-0032).
func (t *Theme) texts() (Texts, error) {
	f, err := t.files.Open(themeTexts)
	if errors.Is(err, fs.ErrNotExist) {
		return Texts{}, nil
	}
	if err != nil {
		return Texts{}, err
	}
	defer func() { _ = f.Close() }()
	decoder := yaml.NewDecoder(io.LimitReader(f, maxThemeFile))
	decoder.KnownFields(true)
	var texts Texts
	if err := decoder.Decode(&texts); err != nil && !errors.Is(err, io.EOF) {
		return Texts{}, fmt.Errorf("%s: %w", themeTexts, err)
	}
	// A block scalar keeps its final newline.
	texts.Description = strings.TrimSpace(texts.Description)
	if err := texts.check(); err != nil {
		return Texts{}, fmt.Errorf("%s: %w", themeTexts, err)
	}
	return texts, nil
}

// activeTexts are the texts of the theme.
func activeTexts() Texts {
	if t := active.Load(); t != nil {
		texts, _ := t.currentTexts()
		return texts
	}
	return Texts{}
}

// currentTexts is texts, parsed again only after theme.yaml changed. When a
// changed theme.yaml fails to load while the server runs, it logs a warning
// and keeps the last texts that loaded.
func (t *Theme) currentTexts() (Texts, error) {
	info, err := fs.Stat(t.files, themeTexts)
	if err != nil {
		return t.texts()
	}
	previous := t.parsed.Load()
	if previous != nil && previous.size == info.Size() && previous.modTime.Equal(info.ModTime()) {
		return previous.texts, previous.err
	}
	texts, err := t.texts()
	if err != nil && previous != nil {
		texts = previous.texts
		log.Printf("[Theme] WARNING: %v. The pages keep the texts that loaded before.", err)
	}
	t.parsed.Store(&parsedTexts{size: info.Size(), modTime: info.ModTime(), texts: texts, err: err})
	return texts, err
}

// WalletName is the wallet name of the theme, or the built-in name.
func WalletName() string {
	if name := activeTexts().Name; name != "" {
		return name
	}
	return config.WalletName
}

var (
	walletTitle     = []byte("<title>" + config.WalletName + "</title>")
	metaDescription = regexp.MustCompile(`(<meta name="description" content=")[^"]*(">)`)
	headerTitle     = regexp.MustCompile(`<h1 id="header-title">[^<]*</h1>`)
	githubEntry     = regexp.MustCompile(`<a [^>]*id="github-link"[^>]*>[^<]*</a>`)
	linkTarget      = regexp.MustCompile(`href="[^"]*"`)
	// walletEntry is the link of the decoder page to the wallet page.
	walletEntry = []byte(`id="wallet-link"`)
	headEnd     = []byte("</head>")
)

// Brand puts the texts of the theme into a static page. The wallet page gets
// the wallet name and the description. The decoder page shows the wallet
// name followed by "Decoder". Both get the edition tag and the header menu of
// the theme.
func Brand(page []byte) []byte {
	texts := activeTexts()
	page = brandHeader(page, texts)
	page = brandDemoHints(page, texts.Demo)
	if texts.Description != "" && bytes.Contains(page, walletTitle) {
		// ReplaceAll would expand $ in the description. ReplaceAllFunc inserts it literally.
		page = metaDescription.ReplaceAllFunc(page, func(tag []byte) []byte {
			parts := metaDescription.FindSubmatch(tag)
			return slices.Concat(parts[1], []byte(html.EscapeString(texts.Description)), parts[2])
		})
	}
	if texts.Name == "" || texts.Name == config.WalletName {
		return page
	}
	name := html.EscapeString(texts.Name)
	// One pass, so a name that contains the built-in name is not replaced again.
	return []byte(strings.NewReplacer(config.DecoderName, name+" Decoder", config.WalletName, name).Replace(string(page)))
}

// brandHeader adds the edition tag behind the wallet name and applies the
// header menu of the theme.
func brandHeader(page []byte, texts Texts) []byte {
	if texts.Edition != "" {
		tag := `<span class="edition-tag" id="edition-tag">` + html.EscapeString(texts.Edition) + `</span>`
		page = headerTitle.ReplaceAllFunc(page, func(title []byte) []byte {
			return slices.Concat(title, []byte(tag))
		})
	}
	// The decoder page sits one level below the wallet page.
	base := ""
	if bytes.Contains(page, walletEntry) {
		base = "../"
	}
	var links strings.Builder
	for i, link := range texts.Nav.Links {
		target := base + link.URL
		attributes := ""
		if isWebURL(link.URL) {
			target, attributes = link.URL, ` target="_blank" rel="noopener"`
		}
		fmt.Fprintf(&links, `<a href="%s"%s class="theme-nav-link" id="theme-nav-link-%d">%s</a>`, html.EscapeString(target), attributes, i, html.EscapeString(link.Label))
	}
	if links.Len() > 0 || texts.Product.URL != "" {
		page = githubEntry.ReplaceAllFunc(page, func(entry []byte) []byte {
			if texts.Product.URL != "" {
				entry = linkTarget.ReplaceAllLiteral(entry, []byte(`href="`+html.EscapeString(texts.Product.URL)+`"`))
			}
			return slices.Concat(entry, []byte(links.String()))
		})
	}
	if len(texts.Nav.Hide) > 0 {
		var selectors []string
		for _, name := range texts.Nav.Hide {
			selectors = append(selectors, "#"+navEntries[name])
		}
		// The pages show and hide entries themselves, so a hidden attribute
		// would not last.
		style := `<style id="theme-nav-hide">` + strings.Join(selectors, ",") + `{display:none !important}</style>`
		page = bytes.Replace(page, headEnd, slices.Concat([]byte(style), headEnd), 1)
	}
	return page
}

var (
	demoIssuerHint   = regexp.MustCompile(`(<a href=")[^"]*("[^>]*id="(?:actions-hint|howto-demo)-issuer-link")`)
	demoVerifierHint = regexp.MustCompile(`(<a href=")[^"]*("[^>]*id="(?:actions-hint|howto-demo)-verifier-link")`)
	// The hint text keeps its trailing space inside the span. Chromium places
	// the following link glyphs differently when the span ends before the space.
	demoHintText = regexp.MustCompile(`(<span id="actions-hint-text">)[^<]*( </span>)`)
	// demoHintLinks are the links of the hint below the wallet actions and the
	// separator between them.
	demoHintLinks = regexp.MustCompile(`<a [^>]*id="actions-hint-issuer-link".*id="actions-hint-verifier-link"[^>]*>[^<]*</a>`)
)

// brandDemoHints points the demo hints of the wallet page to the theme's pages.
// The data-theme-link attribute keeps a link visible under --no-builtins.
func brandDemoHints(page []byte, demo Demo) []byte {
	if len(demo.Hint.Links) > 0 {
		var links []string
		for i, link := range demo.Hint.Links {
			links = append(links, fmt.Sprintf(`<a href="%s" id="actions-hint-link-%d" data-theme-link>%s</a>`, html.EscapeString(link.URL), i, html.EscapeString(link.Label)))
		}
		page = demoHintLinks.ReplaceAllLiteral(page, []byte(strings.Join(links, `<span class="hint-separator"> &middot; </span>`)))
	}
	for hint, target := range map[*regexp.Regexp]string{demoIssuerHint: demo.Issuer, demoVerifierHint: demo.Verifier} {
		if target == "" {
			continue
		}
		page = hint.ReplaceAllFunc(page, func(link []byte) []byte {
			parts := hint.FindSubmatch(link)
			return slices.Concat(parts[1], []byte(html.EscapeString(target)), parts[2], []byte(" data-theme-link"))
		})
	}
	if demo.Hint.Text != "" {
		page = demoHintText.ReplaceAllFunc(page, func(element []byte) []byte {
			parts := demoHintText.FindSubmatch(element)
			return slices.Concat(parts[1], []byte(html.EscapeString(demo.Hint.Text)), parts[2])
		})
	}
	return page
}

// themeTextsJSON returns the texts for the footer script.
func themeTextsJSON() []byte {
	data, _ := json.Marshal(struct {
		Product *Product `json:"product,omitempty"`
	}{Product: activeTexts().product()})
	return data
}

func (t Texts) product() *Product {
	if t.Product.Name == "" {
		return nil
	}
	return &t.Product
}

func (t *Theme) css() []byte {
	f, err := t.files.Open(themeCSS)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxThemeFile))
	if err != nil {
		return nil
	}
	return data
}

func (t *Theme) find(name string, types []string) string {
	for _, ext := range types {
		if info, err := fs.Stat(t.files, name+ext); err == nil && info.Mode().IsRegular() {
			return name + ext
		}
	}
	return ""
}

// UseTheme sets the theme of every page. nil restores the built-in theme.
func UseTheme(t *Theme) {
	active.Store(t)
}

// serveTheme serves a file below theme/. theme.css is the built-in theme
// followed by the operator's. theme/logo and theme/favicon are the images of
// the operator's theme, or the built-in ones. A favicon falls back to the
// operator's logo.
func serveTheme(w http.ResponseWriter, r *http.Request, name string) {
	t := active.Load()
	w.Header().Set("Cache-Control", "no-cache")
	switch name {
	case themeCSS:
		css, _ := files.ReadFile(themeRoot + "/" + themeCSS)
		if t != nil {
			if own := t.css(); own != nil {
				css = append(append(bytes.Clone(css), '\n'), own...)
			}
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(css)
	case textsName:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(themeTextsJSON())
	case logoName:
		serveThemeImage(w, r, t, themeRoot+"/logo.svg", t.lookup(logoName, logoTypes))
	case faviconName:
		serveThemeImage(w, r, t, themeRoot+"/favicon.svg", t.lookup(faviconName, faviconTypes), t.lookup(logoName, logoTypes))
	default:
		// Other files are the fonts and images that theme.css links.
		if t == nil {
			http.NotFound(w, r)
			return
		}
		serveThemeFile(w, r, t.files, name)
	}
}

// lookup finds an image of the operator's theme. It returns "" without a
// theme.
func (t *Theme) lookup(name string, types []string) string {
	if t == nil {
		return ""
	}
	return t.find(name, types)
}

// serveThemeImage serves the first existing candidate, or the built-in image.
func serveThemeImage(w http.ResponseWriter, r *http.Request, t *Theme, builtIn string, candidates ...string) {
	for _, name := range candidates {
		if name != "" {
			serveThemeFile(w, r, t.files, name)
			return
		}
	}
	serveThemeFile(w, r, files, builtIn)
}

// maxThemeFile limits a served theme file. Logos and fonts are far smaller.
const maxThemeFile = 4 << 20

// themeAssetTypes are the only files served from a theme directory.
var themeAssetTypes = map[string]string{
	".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".gif": "image/gif", ".avif": "image/avif", ".ico": "image/x-icon",
	".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".otf": "font/otf",
}

// serveThemeFile serves a font or an image. os.Root keeps the name inside the
// theme directory, also through symlinks. Hidden names, such as the ..data
// directory of a ConfigMap volume, and other file types get a 404.
func serveThemeFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	ctype, ok := themeAssetTypes[strings.ToLower(path.Ext(name))]
	if !ok || !fs.ValidPath(name) || slices.ContainsFunc(strings.Split(name, "/"), func(part string) bool { return strings.HasPrefix(part, ".") }) {
		http.NotFound(w, r)
		return
	}
	f, err := fsys.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxThemeFile {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxThemeFile))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	httpsec.ServeImage(w, r, ctype, data)
}
