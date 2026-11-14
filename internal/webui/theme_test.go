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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	FileServer(fstest.MapFS{}).ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func useTheme(t *testing.T, dir string) {
	t.Helper()
	theme, err := LoadTheme(dir)
	if err != nil {
		t.Fatal(err)
	}
	UseTheme(theme)
	t.Cleanup(func() { UseTheme(nil) })
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Without a theme, pages get the built-in theme and nothing is read from
// disk.
func TestPagesUseTheBuiltInThemeByDefault(t *testing.T) {
	builtIn, _ := files.ReadFile("theme/theme.css")
	if rec := get(t, "/theme/theme.css"); !bytes.Equal(rec.Body.Bytes(), builtIn) || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("theme.css = %q (%s), want the built-in theme", rec.Body.String()[:min(40, rec.Body.Len())], rec.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/theme/logo", "/logo.svg"} {
		if rec := get(t, path); !bytes.Equal(rec.Body.Bytes(), LogoSVG()) || rec.Header().Get("Content-Type") != "image/svg+xml" {
			t.Errorf("%s: %d %s, want the eudi-dev logo", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if rec := get(t, "/theme/font.woff2"); rec.Code != http.StatusNotFound {
		t.Errorf("theme file without a theme: %d, want 404", rec.Code)
	}
}

// The example theme sets a few colours and a logo. The rest comes from the
// built-in theme, and the logo is also the favicon.
func TestTheExampleThemeOverridesTheBuiltInTheme(t *testing.T) {
	dir := filepath.FromSlash("../../examples/themes/acme")
	useTheme(t, dir)
	builtIn, _ := files.ReadFile("theme/theme.css")
	own, _ := os.ReadFile(filepath.Join(dir, "theme.css"))
	logo, _ := os.ReadFile(filepath.Join(dir, "logo.svg"))

	css := get(t, "/theme/theme.css").Body.Bytes()
	if !bytes.HasPrefix(css, builtIn) || !bytes.HasSuffix(css, own) {
		t.Error("theme.css is not the built-in theme followed by the example theme")
	}
	for _, path := range []string{"/theme/logo", "/theme/favicon"} {
		if rec := get(t, path); !bytes.Equal(rec.Body.Bytes(), logo) {
			t.Errorf("%s is not the example logo", path)
		}
	}
	if rec := get(t, "/logo.svg"); !bytes.Equal(rec.Body.Bytes(), LogoSVG()) {
		t.Error("/logo.svg is not the eudi-dev logo")
	}
}

// A changed file applies without a restart, as with an updated ConfigMap.
func TestAChangedThemeAppliesWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.css"), ":root { --accent: red; }")
	useTheme(t, dir)
	write(t, filepath.Join(dir, "theme.css"), ":root { --accent: blue; }")
	write(t, filepath.Join(dir, "favicon.png"), "\x89PNG")
	if css := get(t, "/theme/theme.css").Body.String(); !strings.HasSuffix(css, "--accent: blue; }") {
		t.Errorf("theme.css ends with %q, want the changed file", css[len(css)-30:])
	}
	if rec := get(t, "/theme/favicon"); rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("favicon type %s, want the added PNG", rec.Header().Get("Content-Type"))
	}
}

// A Kubernetes ConfigMap volume links each file into a hidden ..data
// directory.
func TestAConfigMapVolumeWorks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "..2026_10_25", "logo.png"), "\x89PNG")
	write(t, filepath.Join(dir, "..2026_10_25", "theme.css"), ":root { --accent: red; }")
	for _, link := range [][2]string{{"..data", "..2026_10_25"}, {"logo.png", "..data/logo.png"}, {"theme.css", "..data/theme.css"}} {
		if err := os.Symlink(link[1], filepath.Join(dir, link[0])); err != nil {
			t.Fatal(err)
		}
	}
	useTheme(t, dir)
	if rec := get(t, "/theme/logo"); rec.Body.String() != "\x89PNG" || rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("logo %q (%s), want the PNG", rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	if rec := get(t, "/theme/..data/logo.png"); rec.Code != http.StatusNotFound {
		t.Errorf("hidden path: %d, want 404", rec.Code)
	}
}

// A theme serves only its fonts and images. Nothing outside the directory is
// reachable, symlinks included, and an image opened on its own can't run
// scripts.
func TestAThemeServesOnlyItsFontsAndImages(t *testing.T) {
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.png"), "secret")
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.css"), "")
	write(t, filepath.Join(dir, "fonts", "brand.woff2"), "font")
	write(t, filepath.Join(dir, ".env"), "TOKEN=secret")
	write(t, filepath.Join(dir, "notes.html"), "<script>")
	write(t, filepath.Join(dir, ".hidden", "logo.png"), "hidden")
	write(t, filepath.Join(dir, "big.png"), strings.Repeat("x", maxThemeFile+1))
	if err := os.Mkdir(filepath.Join(dir, "dir.png"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.png"), filepath.Join(dir, "escape.png")); err != nil {
		t.Fatal(err)
	}
	useTheme(t, dir)

	if rec := get(t, "/theme/fonts/brand.woff2"); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "font/woff2" {
		t.Errorf("font: %d %s, want it served", rec.Code, rec.Header().Get("Content-Type"))
	} else if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("font headers %v, want a sandbox policy and nosniff", rec.Header())
	}
	for _, path := range []string{"/theme/.env", "/theme/notes.html", "/theme/.hidden/logo.png", "/theme/big.png", "/theme/dir.png", "/theme/escape.png", "/theme/../theme.go", "/theme/%2e%2e/theme.go", "/theme/fonts/../../theme.go"} {
		if rec := get(t, path); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("%s: %d %q, want 404", path, rec.Code, rec.Body.String()[:min(20, rec.Body.Len())])
		}
	}
}

func TestAThemeNeedsAThemeFile(t *testing.T) {
	if _, err := LoadTheme(t.TempDir()); err == nil || !strings.Contains(err.Error(), "has no theme.css, theme.yaml, logo or favicon") {
		t.Errorf("empty directory: %v, want an error", err)
	}
	if _, err := LoadTheme(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing directory: want an error")
	}
}

// theme.yaml sets the wallet name. The decoder page shows it too.
func TestAThemeSetsTheWalletName(t *testing.T) {
	wallet := []byte("<title>" + config.WalletName + "</title>")
	decoder := []byte("<title>" + config.DecoderName + "</title>")
	if string(Brand(wallet)) != string(wallet) || WalletName() != config.WalletName {
		t.Errorf("without a theme: %s, %s, want the built-in name", Brand(wallet), WalletName())
	}

	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "name: Example <Wallet>\n")
	useTheme(t, dir)
	if got := string(Brand(wallet)); got != "<title>Example &lt;Wallet&gt;</title>" {
		t.Errorf("wallet page: %s", got)
	}
	if got := string(Brand(decoder)); got != "<title>Example &lt;Wallet&gt; Decoder</title>" {
		t.Errorf("decoder page: %s", got)
	}
	write(t, filepath.Join(dir, "theme.yaml"), "name: "+config.WalletName+" Plus\n")
	if got, want := string(Brand(decoder)), "<title>"+config.WalletName+" Plus Decoder</title>"; got != want {
		t.Errorf("decoder page: %s, want %s", got, want)
	}
	write(t, filepath.Join(dir, "theme.yaml"), "name: Example <Wallet>\n")
	rec := httptest.NewRecorder()
	FileServer(fstest.MapFS{"index.html": {Data: wallet}}).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Body.String() != "<title>Example &lt;Wallet&gt;</title>" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("served page: %s (%s)", rec.Body.String(), rec.Header().Get("Content-Type"))
	}

	write(t, filepath.Join(dir, "theme.yaml"), "name: Example\n")
	if WalletName() != "Example" {
		t.Errorf("after a change: %s, want Example", WalletName())
	}
	write(t, filepath.Join(dir, "theme.yaml"), "name: [")
	if WalletName() != "Example" {
		t.Errorf("with a broken theme.yaml: %s, want the last name that loaded", WalletName())
	}
}

func TestAnUnchangedThemeYAMLIsParsedOnce(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "name: Example\n")
	useTheme(t, dir)
	_ = WalletName()
	first := active.Load().parsed.Load()
	if first == nil || WalletName() != "Example" || active.Load().parsed.Load() != first {
		t.Error("a second page request parsed the unchanged theme.yaml again")
	}
}

// Only the wallet page gets the description.
func TestAThemeDescribesTheWalletPage(t *testing.T) {
	meta := `<meta name="description" content="Built-in text.">`
	wallet := []byte("<title>" + config.WalletName + "</title>" + meta)
	decoder := []byte("<title>" + config.DecoderName + "</title>" + meta)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "description: Wallet of \"Example\" for $1 & more\n")
	useTheme(t, dir)
	want := "<title>" + config.WalletName + `</title><meta name="description" content="Wallet of &#34;Example&#34; for $1 &amp; more">`
	if got := string(Brand(wallet)); got != want {
		t.Errorf("wallet page: %s, want %s", got, want)
	}
	if got := string(Brand(decoder)); got != string(decoder) {
		t.Errorf("decoder page: %s", got)
	}
	rec := httptest.NewRecorder()
	FileServer(fstest.MapFS{"index.html": {Data: wallet}}).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Body.String() != want {
		t.Errorf("served page: %s", rec.Body.String())
	}
}

func TestAThemeRefusesAnUnknownField(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "title: Example\n")
	if _, err := LoadTheme(dir); err == nil || !strings.Contains(err.Error(), "theme.yaml") {
		t.Errorf("unknown field: %v, want an error that mentions theme.yaml", err)
	}
}

const (
	walletHeader  = `<head></head><h1 id="header-title">EUDI Dev Wallet</h1><a href="#" id="get-cli-link">Get the CLI</a><a href="https://github.com/eudi-dev/eudi-dev" target="_blank" rel="noopener" id="github-link">GitHub</a>`
	decoderHeader = `<head></head><h1 id="header-title">EUDI Dev Decoder</h1><a href="../" id="wallet-link" hidden>Wallet</a><a href="https://github.com/eudi-dev/eudi-dev" id="github-link" target="_blank" rel="noopener">GitHub</a>`
)

// The edition is a tag after the wallet name in the header.
func TestAThemeSetsAnEditionTag(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "edition: <Business>\n")
	useTheme(t, dir)
	page := "<title>" + config.WalletName + "</title>" + walletHeader
	got := string(Brand([]byte(page)))
	if want := `<h1 id="header-title">EUDI Dev Wallet</h1><span class="edition-tag" id="edition-tag">&lt;Business&gt;</span>`; !strings.Contains(got, want) {
		t.Errorf("wallet page: %s, want %s", got, want)
	}
	if !strings.HasPrefix(got, "<title>"+config.WalletName+"</title>") {
		t.Errorf("wallet page: %s, want the title unchanged", got)
	}
	if got := string(Brand([]byte(decoderHeader))); !strings.Contains(got, `Decoder</h1><span class="edition-tag" id="edition-tag">`) {
		t.Errorf("decoder page: %s, want the tag", got)
	}
}

// Theme links come after the built-in entries. A relative URL resolves against
// the wallet page, also on the decoder page one level below.
func TestAThemeChangesTheHeaderMenu(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), `
product:
  name: Example Kit
  url: https://example.com/kit?a=1&b=2
nav:
  links:
    - label: Scenarios & <more>
      url: https://example.com/scenarios
    - label: Issuer
      url: issuer/
  hide: [get-cli, registrar]
`)
	useTheme(t, dir)
	external := `<a href="https://example.com/scenarios" target="_blank" rel="noopener" class="theme-nav-link" id="theme-nav-link-0">Scenarios &amp; &lt;more&gt;</a>`
	github := `<a href="https://example.com/kit?a=1&amp;b=2" target="_blank" rel="noopener" id="github-link">GitHub</a>`
	hide := `<head><style id="theme-nav-hide">#get-cli-link,#registrar-menu{display:none !important}</style></head>`

	wallet := string(Brand([]byte(walletHeader)))
	for _, want := range []string{github + external + `<a href="issuer/" class="theme-nav-link" id="theme-nav-link-1">Issuer</a>`, hide} {
		if !strings.Contains(wallet, want) {
			t.Errorf("wallet page: %s, want %s", wallet, want)
		}
	}
	decoder := string(Brand([]byte(decoderHeader)))
	for _, want := range []string{external + `<a href="../issuer/" class="theme-nav-link" id="theme-nav-link-1">Issuer</a>`, `href="https://example.com/kit?a=1&amp;b=2" id="github-link"`, hide} {
		if !strings.Contains(decoder, want) {
			t.Errorf("decoder page: %s, want %s", decoder, want)
		}
	}
}

// The footer script reads the theme's product.
func TestAThemeSetsTheProduct(t *testing.T) {
	if got := get(t, "/theme/texts.json").Body.String(); got != "{}" {
		t.Errorf("without a theme: %s, want {}", got)
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "product:\n  name: Example Kit\n  version: 0.1.0\n  url: https://example.com/kit\n")
	useTheme(t, dir)
	rec := get(t, "/theme/texts.json")
	if want := `{"product":{"name":"Example Kit","version":"0.1.0","url":"https://example.com/kit"}}`; rec.Body.String() != want || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("texts.json: %s (%s), want %s", rec.Body.String(), rec.Header().Get("Content-Type"), want)
	}
}

// The demo hints of the wallet page link to the theme's pages.
func TestAThemeSetsTheDemoHintLinks(t *testing.T) {
	page := `<a href="issuer/" id="actions-hint-issuer-link">Get one</a><a href="verifier/" id="actions-hint-verifier-link">Present</a>` +
		`<a href="issuer/" target="_blank" id="howto-demo-issuer-link">demo issuer</a><a href="verifier/" target="_blank" id="howto-demo-verifier-link">demo verifier</a>` +
		`<a href="verifier/" target="_blank" id="howto-extension-verifier-link">demo verifier</a>`
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "demo:\n  issuer: https://example.com/issuer?a=1&b=2\n")
	useTheme(t, dir)
	want := `<a href="https://example.com/issuer?a=1&amp;b=2" id="actions-hint-issuer-link" data-theme-link>Get one</a><a href="verifier/" id="actions-hint-verifier-link">Present</a>` +
		`<a href="https://example.com/issuer?a=1&amp;b=2" target="_blank" id="howto-demo-issuer-link" data-theme-link>demo issuer</a><a href="verifier/" target="_blank" id="howto-demo-verifier-link">demo verifier</a>` +
		`<a href="verifier/" target="_blank" id="howto-extension-verifier-link">demo verifier</a>`
	if got := string(Brand([]byte(page))); got != want {
		t.Errorf("with demo.issuer: %s, want %s", got, want)
	}
	write(t, filepath.Join(dir, "theme.yaml"), "demo:\n  verifier: scenarios/\n")
	if got := string(Brand([]byte(page))); !strings.Contains(got, `<a href="scenarios/" id="actions-hint-verifier-link" data-theme-link>`) || !strings.Contains(got, `<a href="issuer/" id="actions-hint-issuer-link">`) {
		t.Errorf("with demo.verifier: %s", got)
	}
}

// The theme sets the text of the demo hint and replaces its links.
func TestAThemeSetsTheDemoHintTextAndLinks(t *testing.T) {
	page := `<span id="actions-hint-text">No offer at hand? </span><a href="issuer/" id="actions-hint-issuer-link">Get one from the demo issuer</a>` +
		`<span class="hint-separator"> &middot; </span><a href="verifier/" id="actions-hint-verifier-link">Present to the demo verifier</a>` +
		`<a href="issuer/" target="_blank" id="howto-demo-issuer-link">demo issuer</a>`
	dir := t.TempDir()
	write(t, filepath.Join(dir, "theme.yaml"), "demo:\n  issuer: case-1/\n  hint:\n    text: New here?\n    links:\n      - label: Start the demo with case 1\n        url: https://acme.example/cases/1?a=1&b=2\n      - label: All test scenarios & more\n        url: scenarios/\n")
	useTheme(t, dir)
	want := `<span id="actions-hint-text">New here? </span><a href="https://acme.example/cases/1?a=1&amp;b=2" id="actions-hint-link-0" data-theme-link>Start the demo with case 1</a>` +
		`<span class="hint-separator"> &middot; </span><a href="scenarios/" id="actions-hint-link-1" data-theme-link>All test scenarios &amp; more</a>` +
		`<a href="case-1/" target="_blank" id="howto-demo-issuer-link" data-theme-link>demo issuer</a>`
	if got := string(Brand([]byte(page))); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	write(t, filepath.Join(dir, "theme.yaml"), "name: Acme\n")
	if got := string(Brand([]byte(page))); got != page {
		t.Errorf("without demo keys: %s, want %s", got, page)
	}
}

func TestAThemeRefusesInvalidEntries(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"long edition":            {"edition: " + strings.Repeat("x", maxEditionRunes+1), "edition is longer than 24 characters"},
		"product without a name":  {"product:\n  version: 1.0.0", "product needs a name"},
		"script product URL":      {"product:\n  name: Kit\n  url: javascript:alert(1)", "product.url must be an http or https URL"},
		"script link":             {"nav:\n  links:\n    - label: Run\n      url: javascript:alert(1)", "nav.links[0].url must be an http or https URL or a path relative to the wallet page"},
		"link from the host root": {"nav:\n  links:\n    - label: Root\n      url: /scenarios", "nav.links[0].url"},
		"link to another host":    {"nav:\n  links:\n    - label: Host\n      url: //example.com", "nav.links[0].url"},
		"link to a parent":        {"nav:\n  links:\n    - label: Up\n      url: ../scenarios", "nav.links[0].url"},
		"inner parent link":       {"nav:\n  links:\n    - label: Up\n      url: issuer/../../x", "nav.links[0].url"},
		"encoded parent link":     {"nav:\n  links:\n    - label: Up\n      url: '%2e%2e/x'", "nav.links[0].url"},
		"backslash parent link":   {"nav:\n  links:\n    - label: Up\n      url: 'issuer\\..\\..\\x'", "nav.links[0].url"},
		"parent demo link":        {"demo:\n  verifier: ../verifier/", "demo.verifier must be"},
		"link without a label":    {"nav:\n  links:\n    - url: issuer/", "nav.links[0] needs a label"},
		"script demo link":        {"demo:\n  issuer: javascript:alert(1)", "demo.issuer must be an http or https URL or a path relative to the wallet page"},
		"long demo hint":          {"demo:\n  hint:\n    text: " + strings.Repeat("x", maxLabelRunes+1), "demo.hint.text is longer than 40 characters"},
		"script hint link":        {"demo:\n  hint:\n    links:\n      - label: Run\n        url: javascript:alert(1)", "demo.hint.links[0].url must be an http or https URL or a path relative to the wallet page"},
		"unknown entry":           {"nav:\n  hide: [wallet]", `nav.hide lists the unknown entry "wallet". Known entries: decoder, get-cli, github, how-to-use, registrar, settings, templates, trust`},
	} {
		dir := t.TempDir()
		write(t, filepath.Join(dir, "theme.yaml"), tc.yaml+"\n")
		if _, err := LoadTheme(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
