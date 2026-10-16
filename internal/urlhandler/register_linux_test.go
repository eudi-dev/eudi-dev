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

//go:build linux

package urlhandler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// xdg-mime is what snapd asks before a snap browser may open a scheme, and
// what xdg-open uses outside a desktop. It must name the wallet for every
// scheme after Register and nothing after Unregister.
func TestXDGMimeFindsTheRegisteredHandler(t *testing.T) {
	xdgMime, err := exec.LookPath("xdg-mime")
	if err != nil {
		t.Skip("xdg-mime is not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("EUDI_DEV_HOME", filepath.Join(home, ".eudi-dev"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_CURRENT_DESKTOP", "")

	query := func(scheme string) string {
		out, err := exec.Command(xdgMime, "query", "default", schemeHandlerPrefix+scheme).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	reg, err := Register(Options{ListenerPort: 8085})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(reg.DesktopFile); err != nil {
		t.Fatalf("no desktop entry: %v", err)
	}
	for _, scheme := range URLSchemes {
		if got := query(scheme); got != desktopID {
			t.Errorf("xdg-mime names %q for %s, want %s", got, scheme, desktopID)
		}
	}
	if opts, ok, err := LoadOptions(); err != nil || !ok || opts.ListenerPort != 8085 {
		t.Errorf("options %+v (%t, %v), want port 8085", opts, ok, err)
	}

	if _, err := Unregister(); err != nil {
		t.Fatal(err)
	}
	for _, scheme := range URLSchemes {
		if got := query(scheme); got == desktopID {
			t.Errorf("xdg-mime still names the wallet for %s", scheme)
		}
	}
}
