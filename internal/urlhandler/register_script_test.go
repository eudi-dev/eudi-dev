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

package urlhandler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerScriptSource(t *testing.T) {
	script := handlerScriptSource("/usr/local/bin/eudi", Options{ListenerPort: 8085})

	// The browser session ID connects the submitted request to the tab opened by the
	// handler.
	if !strings.Contains(script, `open "$LISTENER/?focus=overview&owner=$OWNER"`) {
		t.Error("the URL the handler opens must name the page")
	}
	if strings.Count(script, `-H "$OWNER_HEADER"`) != 2 {
		t.Error("both submissions must carry the page name slot")
	}
	// Local wallet tabs have no browser session ID, so local submissions must leave it
	// empty.
	if !strings.Contains(script, `OWNER_HEADER="X-Eudi-Owner:"`) {
		t.Error("the submission names no page until this script opens one")
	}
	mintIdx := strings.Index(script, "OWNER=$(uuidgen")
	openFnIdx := strings.Index(script, "open_remote_ui() {")
	submitFnIdx := strings.Index(script, "submit_presentation() {")
	if mintIdx < openFnIdx || mintIdx > submitFnIdx {
		t.Error("the name is minted inside the branch that opens the page")
	}

	path := filepath.Join(t.TempDir(), "handler.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("writing the script: %v", err)
	}
	if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Errorf("the generated script does not parse: %v\n%s", err, out)
	}
	if strings.Count(script, `-H "$CLIENT_HEADER"`) < 2 {
		t.Error("the script must name itself on the calls it makes")
	}
	if strings.Contains(script, "{{VERSION}}") {
		t.Error("the release the script reports must be substituted")
	}

	// Submission waits for consent, so the handler must open the UI first.
	openIdx := strings.Index(script, "open_remote_ui")
	submitIdx := strings.Index(script, "submit_presentation()")
	if openIdx < 0 || submitIdx < 0 || openIdx > submitIdx {
		t.Errorf("the UI must be opened before the blocking submit (open at %d, submit at %d)", openIdx, submitIdx)
	}

	if !strings.Contains(script, "INTERACTIVE=true") {
		t.Error("interactive dispatches must be submitted as interactive")
	}
	if !strings.Contains(script, `LISTENER="http://localhost:8085"`) {
		t.Error("the listener port must be rendered into the script")
	}
	if !strings.Contains(script, `BINARY="/usr/local/bin/eudi"`) {
		t.Error("the binary path must be rendered into the script")
	}

	// Every offer scheme goes to the offer branch, whatever its case (RFC 3986
	// §3.1).
	caseIdx := strings.Index(script, `case "$URI" in`)
	if nocase := strings.Index(script, "shopt -s nocasematch"); nocase < 0 || nocase > caseIdx {
		t.Error("the URI case statement must match schemes without case")
	}
	for _, s := range issuanceURLSchemes {
		if !strings.Contains(script[caseIdx:], s+"://*") {
			t.Errorf("the offer branch does not match %s", s)
		}
	}
}

func TestHandlerScriptSourceAutoAccept(t *testing.T) {
	script := handlerScriptSource("/usr/local/bin/eudi", Options{
		ListenerPort: 8085,
		AutoAccept:   true,
	})
	if !strings.Contains(script, "INTERACTIVE=false") {
		t.Error("--auto-accept must submit non-interactively")
	}
	if !strings.Contains(script, `AUTO_ACCEPT="true"`) {
		t.Error("the auto-accept mode must be rendered into the script")
	}
}

// Homebrew upgrades replace the versioned binary. Registration must use the stable
// symlink.
func TestStableBinaryPathKeepsHomebrewSymlink(t *testing.T) {
	root := t.TempDir()
	cellarBin := filepath.Join(root, "Cellar", "eudi-dev", "1.2.3", "bin")
	if err := os.MkdirAll(cellarBin, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cellarBin, "eudi")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(binDir, "eudi")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}

	if got := stableBinaryPath(symlink); got != symlink {
		t.Errorf("Homebrew symlink: got %q, want the symlink %q", got, symlink)
	}
}

func TestStableBinaryPathResolvesNonHomebrewSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "build", "eudi")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "eudi-link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}

	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := stableBinaryPath(symlink); got != want {
		t.Errorf("non-Homebrew symlink: got %q, want the resolved target %q", got, want)
	}
}

func TestStableBinaryPathPlainFile(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "eudi")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(bin)
	if got := stableBinaryPath(bin); got != want {
		t.Errorf("plain file: got %q, want %q", got, want)
	}
}
