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

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each browser opener needs a reason to navigate. Some authorization URLs can be used
// only once, so duplicate navigation breaks the flow. Add new call sites to this list.
var browserOpeners = map[string]string{
	"cmd/wallet_present.go:openBrowser(redirectURI)": "guarded by navigatesHere through followVerifierRedirect: " +
		"the consent tab receives the result and navigates there itself",
	"cmd/wallet_remote_ops.go:openBrowser(target)": "enlists a browser for the remote wallet UI and names it on the call, " +
		"which is what makes that tab the one the wallet hands things to",
	"cmd/wallet_remote_ops.go:openBrowser(authURL)": "guarded by navigatesHere through opensSignInHere: " +
		"a client that named a page leaves the sign-in to that page",
	"cmd/wallet_serve.go:openBrowser(target)": "guarded by AttachedUIs: a tab already watching is told over its event stream",
}

// Unlisted browser openers could navigate to a URL twice. Require an explicit entry
// explaining each call site.
func TestEveryBrowserOpenIsAccountedFor(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package: %v", err)
	}

	found := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, line := range strings.Split(string(source), "\n") {
			call := strings.TrimSpace(line)
			open := strings.Index(call, "openBrowser(")
			if open < 0 || strings.HasPrefix(call, "//") || strings.HasPrefix(call, "func openBrowser(") {
				continue
			}
			end := strings.Index(call[open:], ")")
			if end < 0 {
				continue
			}
			found["cmd/"+name+":"+call[open:open+end+1]] = true
		}
	}

	for site := range found {
		if _, known := browserOpeners[site]; !known {
			t.Errorf("%s opens a browser and browserOpeners does not say why that is the only arrival at the URL.\n"+
				"Add it there with its reason, and guard it with navigatesHere if something else may already be holding the flow.", site)
		}
	}
	for site := range browserOpeners {
		if !found[site] {
			t.Errorf("browserOpeners lists %s, which no longer exists: drop it", site)
		}
	}
}
