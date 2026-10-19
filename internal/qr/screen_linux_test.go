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

package qr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTools puts shell scripts with the given bodies on an otherwise empty PATH.
func fakeTools(t *testing.T, scripts map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

// Each script writes its own name to the file in its last argument.
const writeOwnName = `for f; do :; done; printf '%s' "${0##*/}" > "$f"`

func TestX11CaptureUsesMaimBeforeScrot(t *testing.T) {
	fakeTools(t, map[string]string{"maim": writeOwnName, "scrot": writeOwnName})
	path, cleanup, err := captureX11Region()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, _ := os.ReadFile(path); string(got) != "maim" {
		t.Errorf("capture written by %q, want maim", got)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup left the capture: %v", err)
	}
}

func TestX11CaptureUsesScrotWithoutMaim(t *testing.T) {
	fakeTools(t, map[string]string{"scrot": writeOwnName})
	path, cleanup, err := captureX11Region()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, _ := os.ReadFile(path); string(got) != "scrot" {
		t.Errorf("capture written by %q, want scrot", got)
	}
}

func TestX11CaptureWithoutAToolExplainsTheInstall(t *testing.T) {
	fakeTools(t, nil)
	_, _, err := captureX11Region()
	if err == nil || !strings.Contains(err.Error(), "sudo apt install maim") {
		t.Errorf("error %v, want the install instructions", err)
	}
}

func TestX11CaptureReportsTheToolError(t *testing.T) {
	fakeTools(t, map[string]string{"maim": "echo 'Selection was cancelled by keystroke or right-click.' >&2; exit 1"})
	_, _, err := captureX11Region()
	if err == nil || err.Error() != "maim: Selection was cancelled by keystroke or right-click." {
		t.Errorf("error %v, want the maim message", err)
	}
}

func TestX11CaptureWithoutAFileIsCancelled(t *testing.T) {
	fakeTools(t, map[string]string{"maim": "exit 0"})
	if _, _, err := captureX11Region(); !errors.Is(err, errCaptureCancelled) {
		t.Errorf("error %v, want errCaptureCancelled", err)
	}
}

func TestX11Session(t *testing.T) {
	for _, tc := range []struct {
		display, wayland string
		want             bool
	}{
		{":0", "", true},
		{":0", "wayland-0", false},
		{"", "", false},
	} {
		t.Setenv("DISPLAY", tc.display)
		t.Setenv("WAYLAND_DISPLAY", tc.wayland)
		if got := x11Session(); got != tc.want {
			t.Errorf("DISPLAY=%q WAYLAND_DISPLAY=%q: x11Session() = %v, want %v", tc.display, tc.wayland, got, tc.want)
		}
	}
}

// Without a session bus, an X11 desktop falls back to the region tool.
func TestCaptureScreenFallsBackOnX11WithoutABus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "no-bus"))
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")
	fakeTools(t, map[string]string{"maim": writeOwnName})
	path, cleanup, err := captureScreen()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, _ := os.ReadFile(path); string(got) != "maim" {
		t.Errorf("capture written by %q, want maim", got)
	}
}

func TestCaptureScreenWithoutX11KeepsThePortalError(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "no-bus"))
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	fakeTools(t, map[string]string{"maim": writeOwnName})
	_, _, err := captureScreen()
	if err == nil || !strings.Contains(err.Error(), "xdg-desktop-portal") {
		t.Errorf("error %v, want the portal error", err)
	}
}
