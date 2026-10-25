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

// Package webui holds the files that every eudi-dev page shares: the
// built-in and the operator's theme, the fonts and the scripts for the light
// and dark mode, the footer and the dialogs. Each server serves them next to
// its pages.
package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"slices"
	"strings"
)

//go:embed tokens.css theme.js footer.js dialog-tools.js dialog-tools.css fonts/*.woff2 fonts/LICENSE.txt theme/*
var files embed.FS

// Roots are the first path segments of the shared files. A page links the
// files by relative paths, so they resolve below any path prefix. logo.svg and
// favicon.svg always serve the eudi-dev images, because other sites link
// them. Pages show the theme images.
var Roots = []string{"tokens.css", "theme.js", "footer.js", "dialog-tools.js", "dialog-tools.css", "fonts", themeRoot, "logo.svg", "favicon.svg"}

func init() {
	// Go's built-in type table has no entry for woff2.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}

// LogoSVG is the eudi-dev logo.
func LogoSVG() []byte {
	data, _ := files.ReadFile(themeRoot + "/logo.svg")
	return data
}

// FileServer serves the files of base and the shared files.
func FileServer(base fs.FS) http.Handler {
	server := http.FileServerFS(overlay{base})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/"+themeRoot+"/"); ok {
			serveTheme(w, r, name)
			return
		}
		server.ServeHTTP(w, r)
	})
}

type overlay struct{ base fs.FS }

func (o overlay) Open(name string) (fs.File, error) {
	switch root, _, _ := strings.Cut(name, "/"); {
	case root == "logo.svg" || root == "favicon.svg":
		return files.Open(themeRoot + "/" + name)
	case slices.Contains(Roots, root):
		return files.Open(name)
	}
	return o.base.Open(name)
}

// Mount serves the shared files on mux.
func Mount(mux *http.ServeMux) {
	server := FileServer(emptyFS{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		server.ServeHTTP(w, r)
	})
	mux.Handle("GET /tokens.css", h)
	mux.Handle("GET /theme.js", h)
	mux.Handle("GET /footer.js", h)
	mux.Handle("GET /dialog-tools.js", h)
	mux.Handle("GET /dialog-tools.css", h)
	mux.Handle("GET /fonts/", h)
	mux.Handle("GET /"+themeRoot+"/", h)
}

type emptyFS struct{}

func (emptyFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}
