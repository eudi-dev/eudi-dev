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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

// The pages of every server, with the stylesheets and scripts that define
// page variables.
var pages = map[string][]string{
	"wallet":      {"../wallet/static/index.html", "../wallet/static/style.css", "../wallet/static/app.js"},
	"decoder":     {"../web/static/index.html", "../web/static/style.css", "../web/static/app.js"},
	"proxy":       {"../proxy/static/index.html", "../proxy/static/style.css", "../proxy/static/app.js"},
	"issuer":      {"../demorp/static/issuer.html", "../demorp/static/issuer.js"},
	"verifier":    {"../demorp/static/verifier.html", "../demorp/static/verifier.js"},
	"sign-in":     {"../demorp/issuer_authcode.go"},
	"placeholder": {"../registrar/placeholder.go"},
	"imprint":     {"../imprint/imprint.go"},
}

var (
	// A script defines a variable with style.setProperty('--name', value).
	definition = regexp.MustCompile(`(--[a-z0-9-]+)(?:\s*:|',)`)
	// A name ending in a dash is a prefix. A script completes it at runtime.
	use = regexp.MustCompile(`var\((--[a-z0-9-]*[a-z0-9])\b[^-]`)
)

func tokens(t *testing.T) (dark, light []string) {
	t.Helper()
	data, err := files.ReadFile("theme/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)(:root|\[data-theme="light"\]) \{(.*?)\}`).FindAllSubmatch(data, -1)
	if len(blocks) != 2 {
		t.Fatalf("theme.css has %d blocks, want the dark and the light one", len(blocks))
	}
	for _, m := range definition.FindAllSubmatch(blocks[0][2], -1) {
		dark = append(dark, string(m[1]))
	}
	for _, m := range definition.FindAllSubmatch(blocks[1][2], -1) {
		light = append(light, string(m[1]))
	}
	return dark, light
}

// Both themes set every colour token. The fonts are the same in both.
func TestTheLightThemeSetsEveryColourToken(t *testing.T) {
	dark, light := tokens(t)
	for _, name := range dark {
		if !strings.HasPrefix(name, "--font-") && !slices.Contains(light, name) {
			t.Errorf("the light theme does not set %s", name)
		}
	}
}

// Every page uses only variables defined in the theme or in the page itself,
// because a browser drops a declaration with an undefined variable. No page
// sets a shared token again, so the pages can't drift apart.
func TestThePagesUseTheSharedTokens(t *testing.T) {
	shared, _ := tokens(t)
	for page, sources := range pages {
		var content []byte
		for _, source := range sources {
			data, err := os.ReadFile(filepath.FromSlash(source))
			if err != nil {
				t.Fatal(err)
			}
			content = append(content, data...)
		}
		own := map[string]bool{}
		for _, m := range definition.FindAllSubmatch(content, -1) {
			name := string(m[1])
			if slices.Contains(shared, name) {
				t.Errorf("%s sets the shared token %s", page, name)
			}
			own[name] = true
		}
		for _, m := range use.FindAllSubmatch(content, -1) {
			if name := string(m[1]); !own[name] && !slices.Contains(shared, name) {
				t.Errorf("%s uses %s, which nothing defines", page, name)
			}
		}
		if !regexp.MustCompile(`href="tokens\.css"`).Match(content) || !regexp.MustCompile(`href="theme/theme\.css"`).Match(content) || !regexp.MustCompile(`src="theme\.js"`).Match(content) {
			t.Errorf("%s does not load tokens.css, theme/theme.css and theme.js", page)
		}
	}
}

// The static pages carry the product names of the binary in their title and
// heading.
func TestThePagesShowTheProductNames(t *testing.T) {
	for source, name := range map[string]string{
		"../wallet/static/index.html": config.WalletName,
		"../web/static/index.html":    config.DecoderName,
		"../proxy/static/index.html":  config.ProxyName,
	} {
		data, err := os.ReadFile(filepath.FromSlash(source))
		if err != nil {
			t.Fatal(err)
		}
		page := string(data)
		if !strings.Contains(page, "<title>"+name+"</title>") || !strings.Contains(page, `<h1 id="header-title">`+name+"</h1>") {
			t.Errorf("%s does not show %q in its title and heading", source, name)
		}
	}
}

// An embedded file must sit in its package, so the logo exists in the
// built-in theme, in the defaults and in the docs. The copies stay the same.
func TestTheLogoCopiesMatch(t *testing.T) {
	for _, copies := range [][]string{
		{"../defaults/images/logo.svg", "theme/logo.svg", "../../docs/assets/logo-mark.svg", "../../examples/public-demo/news/logo-mark.svg"},
		{"../../docs/assets/logo.svg", "theme/favicon.svg"},
	} {
		want, err := os.ReadFile(filepath.FromSlash(copies[0]))
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range copies[1:] {
			got, err := os.ReadFile(filepath.FromSlash(other))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from %s", other, copies[0])
			}
		}
	}
}
