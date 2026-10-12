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

// Package news reads the operator's news for visitors of a public demo.
package news

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// maxImageSize keeps an inlined image from bloating every news response.
const maxImageSize = 2 << 20

// The wallet's img-src policy allows only its own origin and data URLs, so
// an image next to the snippet is inlined.
var imageSource = regexp.MustCompile(`src="([A-Za-z0-9._-]+)"`)

// News is an HTML snippet. ID changes with the content, so a visitor sees
// changed news once more.
type News struct {
	ID   string `json:"id"`
	HTML string `json:"html"`
}

// Load reads the operator's news snippet. The snippet is trusted operator
// content, like the imprint.
func Load(path string) (*News, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
	default:
		return nil, fmt.Errorf("news file %s must be an .html snippet", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading news file: %w", err)
	}
	snippet := strings.TrimSpace(string(raw))
	if snippet == "" {
		return nil, fmt.Errorf("news file %s is empty", path)
	}
	snippet, err = inlineImages(snippet, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(snippet))
	return &News{ID: hex.EncodeToString(sum[:8]), HTML: snippet}, nil
}

func inlineImages(snippet, dir string) (string, error) {
	var failure error
	out := imageSource.ReplaceAllStringFunc(snippet, func(attr string) string {
		name := imageSource.FindStringSubmatch(attr)[1]
		mediaType, ok := format.ImageMediaType(name)
		if !ok || failure != nil {
			return attr
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case err != nil:
			failure = fmt.Errorf("reading news image: %w", err)
		case len(data) > maxImageSize:
			failure = fmt.Errorf("news image %s is larger than 2 MiB", name)
		default:
			return `src="data:` + mediaType + ";base64," + base64.StdEncoding.EncodeToString(data) + `"`
		}
		return attr
	})
	return out, failure
}
