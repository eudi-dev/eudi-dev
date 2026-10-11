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

// Package webui holds the files that every eudi-dev page shares: the colour
// tokens and the theme script. Each server serves them next to its pages.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"slices"
)

//go:embed tokens.css theme.js
var files embed.FS

// Names are the shared files. A page links them by these relative names.
var Names = []string{"tokens.css", "theme.js"}

// Overlay serves the shared files over base.
func Overlay(base fs.FS) fs.FS {
	return overlay{base}
}

type overlay struct{ base fs.FS }

func (o overlay) Open(name string) (fs.File, error) {
	if slices.Contains(Names, name) {
		return files.Open(name)
	}
	return o.base.Open(name)
}

// Handler serves one shared file.
func Handler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, files, name)
	}
}
