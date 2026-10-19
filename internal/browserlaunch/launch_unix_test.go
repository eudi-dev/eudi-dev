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

//go:build !windows

package browserlaunch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBrowser answers the Chrome DevTools Protocol on fds 3 and 4 like
// Chrome. It records its arguments and the commands it receives.
const fakeBrowser = `#!/bin/bash
printf '%s\n' "$@" > "$FAKE_DIR/args"
while IFS= read -r -d '' msg <&3; do
  id=$(printf '%s' "$msg" | sed -E 's/.*"id":([0-9]+).*/\1/')
  method=$(printf '%s' "$msg" | sed -E 's/.*"method":"([^"]+)".*/\1/')
  printf '%s\n' "$msg" >> "$FAKE_DIR/calls"
  case $method in
    Extensions.loadUnpacked) printf '{"id":%s,"result":{"id":"fakeextension"}}\0' "$id" >&4 ;;
    Target.createTarget) printf '{"method":"Target.targetCreated","params":{}}\0{"id":%s,"result":{"targetId":"new"}}\0' "$id" >&4 ;;
    Target.getTargets) printf '{"id":%s,"result":{"targetInfos":[{"targetId":"start","type":"page","url":"about:blank"},{"targetId":"new","type":"page","url":"https://verifier.example/"}]}}\0' "$id" >&4 ;;
    *) printf '{"id":%s,"result":{}}\0' "$id" >&4 ;;
  esac
done
`

func writeFakeBrowser(t *testing.T, script string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "chrome")
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DIR", dir)
	return exe, dir
}

func TestLaunchLoadsTheExtensionAndOpensTheURL(t *testing.T) {
	exe, dir := writeFakeBrowser(t, fakeBrowser)
	b, err := Launch(Options{Executable: exe, ProfileDir: "/profile", ExtensionDir: "/extension", URL: "https://verifier.example/"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = b.cmd.Process.Kill()
		_ = b.Wait()
	}()
	if b.ExtensionID != "fakeextension" {
		t.Errorf("ExtensionID = %q", b.ExtensionID)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	for _, want := range []string{"--user-data-dir=/profile", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging"} {
		if !strings.Contains(string(args), want+"\n") {
			t.Errorf("arguments %q lack %s", args, want)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	for _, want := range []string{
		`"method":"Extensions.loadUnpacked","params":{"path":"/extension"}`,
		`"method":"Target.createTarget","params":{"url":"https://verifier.example/"}`,
		`"method":"Target.closeTarget","params":{"targetId":"start"}`,
	} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("calls %s lack %s", calls, want)
		}
	}
	if strings.Contains(string(calls), `"targetId":"new"}`) {
		t.Errorf("the opened page was closed: %s", calls)
	}
}

// Chrome hands a second launch on the same profile to the running instance
// and exits.
func TestABrowserThatExitsAtOnceIsReported(t *testing.T) {
	exe, _ := writeFakeBrowser(t, "#!/bin/sh\nexit 0\n")
	_, err := Launch(Options{Executable: exe, ProfileDir: "/profile", ExtensionDir: "/extension", URL: "about:blank"})
	if !errors.Is(err, errBrowserClosed) {
		t.Errorf("error %v, want errBrowserClosed", err)
	}
}

func TestAFailedExtensionLoadIsReported(t *testing.T) {
	exe, _ := writeFakeBrowser(t, `#!/bin/bash
while IFS= read -r -d '' msg <&3; do
  id=$(printf '%s' "$msg" | sed -E 's/.*"id":([0-9]+).*/\1/')
  printf '{"id":%s,"error":{"code":-32000,"message":"Method not available."}}\0' "$id" >&4
done
`)
	_, err := Launch(Options{Executable: exe, ProfileDir: "/profile", ExtensionDir: "/extension", URL: "about:blank"})
	if err == nil || !strings.Contains(err.Error(), "loading the extension: Extensions.loadUnpacked: Method not available.") {
		t.Errorf("error %v, want the browser's message", err)
	}
}
