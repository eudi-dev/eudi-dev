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
	if _, err := LoadTheme(t.TempDir()); err == nil || !strings.Contains(err.Error(), "has no theme.css, logo or favicon") {
		t.Errorf("empty directory: %v, want an error", err)
	}
	if _, err := LoadTheme(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing directory: want an error")
	}
}
