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

// Package webuitest checks that a server delivers the shared files to its
// pages.
package webuitest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var (
	baseHref   = regexp.MustCompile(`<base href="([^"]+)">`)
	stylesheet = regexp.MustCompile(`<link rel="stylesheet" href="(tokens\.css)">`)
	fontURL    = regexp.MustCompile(`url\("([^"]+\.woff2)"\)`)
)

// CheckFonts loads the page at path the way a browser does and fetches every
// font in its stylesheet. With a prefix, h sits behind a proxy that strips
// the prefix and sends it as X-Forwarded-Prefix.
func CheckFonts(t *testing.T, h http.Handler, prefix, path string) {
	t.Helper()
	page, _ := url.Parse("https://wallet.example" + prefix + path)
	body, _ := get(t, h, prefix, page)
	base := page
	if m := baseHref.FindStringSubmatch(body); m != nil {
		base = page.ResolveReference(&url.URL{Path: m[1]})
	}
	m := stylesheet.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s links no tokens.css", page.Path)
	}
	css := base.ResolveReference(&url.URL{Path: m[1]})
	styles, _ := get(t, h, prefix, css)
	fonts := fontURL.FindAllStringSubmatch(styles, -1)
	if len(fonts) == 0 {
		t.Fatalf("%s names no font", css.Path)
	}
	for _, font := range fonts {
		u := css.ResolveReference(&url.URL{Path: font[1]})
		if _, contentType := get(t, h, prefix, u); contentType != "font/woff2" {
			t.Errorf("%s for %s has Content-Type %q, want font/woff2", u.Path, page.Path, contentType)
		}
	}
}

func get(t *testing.T, h http.Handler, prefix string, u *url.URL) (body, contentType string) {
	t.Helper()
	path, ok := strings.CutPrefix(u.Path, prefix)
	if !ok {
		t.Fatalf("%s is outside the prefix %s", u.Path, prefix)
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = u.Host
	if prefix != "" {
		req.Header.Set("X-Forwarded-Prefix", prefix)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", u.Path, rec.Code)
	}
	return rec.Body.String(), rec.Header().Get("Content-Type")
}
