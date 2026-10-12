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

package imprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWrapsSnippet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imprint.html")
	if err := os.WriteFile(path, []byte("<h1>Imprint</h1><p>Operator: Example Org, Example Street 1</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	page, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	html := string(page)
	if !strings.Contains(html, "Example Org") {
		t.Error("snippet missing from page")
	}
	if !strings.Contains(html, "not</strong> an official service") {
		t.Error("EU non-affiliation disclaimer missing from page")
	}
	if !strings.Contains(html, "<!doctype html>") {
		t.Error("page shell missing")
	}
}

func TestLoadRejectsNonHTMLAndEmpty(t *testing.T) {
	md := filepath.Join(t.TempDir(), "imprint.md")
	if err := os.WriteFile(md, []byte("# Imprint"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(md); err == nil {
		t.Error("Load accepted a markdown file")
	}

	empty := filepath.Join(t.TempDir(), "imprint.html")
	if err := os.WriteFile(empty, []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(empty); err == nil {
		t.Error("Load accepted an empty file")
	}

	if _, err := Load(filepath.Join(t.TempDir(), "missing.html")); err == nil {
		t.Error("Load accepted a missing file")
	}
}

// The server's Content-Security-Policy blocks javascript: links.
func TestLoadPageUsesNoJavascriptLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imprint.html")
	if err := os.WriteFile(path, []byte("<h1>Imprint</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	page, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	html := string(page)
	if strings.Contains(html, "javascript:") {
		t.Error("page uses a javascript: URL, which the Content-Security-Policy blocks")
	}
	if !strings.Contains(html, `<a href="./">`) {
		t.Error("page has no back link to the page that links it")
	}
}
