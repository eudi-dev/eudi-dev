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

// Package defaults holds the built-in data of eudi-dev as files. They use the
// same formats as an operator's own files: credential templates under
// templates/, the images and portraits they reference, the credential
// categories and the registrations of the demo issuer and demo verifier.
package defaults

import (
	"embed"
	"encoding/base64"
	"io/fs"
	"path"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

//go:embed templates images portraits categories.json registrations
var files embed.FS

// EmbeddedPrefix starts a reference to a file of this tree, such as
// "embedded:portraits/dutch.jpg".
const EmbeddedPrefix = "embedded:"

// ReadDir lists a directory of the tree.
func ReadDir(dir string) ([]fs.DirEntry, error) {
	return files.ReadDir(dir)
}

// ReadFile reads a file of the tree.
func ReadFile(name string) ([]byte, error) {
	return files.ReadFile(name)
}

// Resolve reads the file of an "embedded:<path>" reference. A bare
// file name is an image, so "embedded:logo.svg" is images/logo.svg.
func Resolve(ref string) (contentType string, data []byte, ok bool) {
	name, found := strings.CutPrefix(strings.TrimSpace(ref), EmbeddedPrefix)
	if !found {
		return "", nil, false
	}
	if !strings.Contains(name, "/") {
		name = "images/" + name
	}
	data, err := files.ReadFile(path.Clean(name))
	if err != nil {
		return "", nil, false
	}
	return ContentType(name), data, true
}

// DataURI returns the referenced file as a base64 data URI.
func DataURI(ref string) (string, bool) {
	contentType, data, ok := Resolve(ref)
	if !ok {
		return "", false
	}
	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data), true
}

// ContentType is the media type of a file name's extension.
func ContentType(name string) string {
	if mediaType, ok := format.ImageMediaType(name); ok {
		return mediaType
	}
	if strings.EqualFold(path.Ext(name), ".json") {
		return "application/json"
	}
	return "application/octet-stream"
}
