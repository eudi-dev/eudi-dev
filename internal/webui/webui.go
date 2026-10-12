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

// Package webui holds the fonts that every eudi-dev page shares. Each server
// serves them next to its pages. A page links fonts/plex.css by that relative
// path, so the fonts resolve below any path prefix.
package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"strings"
)

//go:embed fonts/plex.css fonts/*.woff2 fonts/LICENSE.txt
var files embed.FS

// Root is the first path segment of the shared files.
const Root = "fonts"

func init() {
	// Go's built-in type table has no entry for woff2.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}

// Overlay serves the shared files over base.
func Overlay(base fs.FS) fs.FS {
	return overlay{base}
}

type overlay struct{ base fs.FS }

func (o overlay) Open(name string) (fs.File, error) {
	if root, _, _ := strings.Cut(name, "/"); root == Root {
		return files.Open(name)
	}
	return o.base.Open(name)
}

// Mount serves the shared files on mux.
func Mount(mux *http.ServeMux) {
	server := http.FileServerFS(files)
	mux.Handle("GET /"+Root+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		server.ServeHTTP(w, r)
	}))
}
