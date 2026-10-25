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
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
)

// A theme is a directory with theme.css, a logo and a favicon. Every file is
// optional. A missing token or file comes from the built-in eudi-dev theme in
// theme/.
const (
	themeRoot   = "theme"
	themeCSS    = "theme.css"
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
}

var active atomic.Pointer[Theme]

// LoadTheme opens a theme directory.
func LoadTheme(dir string) (*Theme, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	t := &Theme{files: root.FS()}
	if t.css() == nil && t.find(logoName, logoTypes) == "" && t.find(faviconName, faviconTypes) == "" {
		return nil, fmt.Errorf("theme %s has no theme.css, logo or favicon", dir)
	}
	return t, nil
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
