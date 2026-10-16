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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheDesktopEntryHandsEverySchemeToOpenURL(t *testing.T) {
	entry, err := desktopEntry("/usr/local/bin/eudi")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Exec=/usr/local/bin/eudi wallet open-url %u\n",
		"NoDisplay=true\n",
		"MimeType=x-scheme-handler/openid4vp;x-scheme-handler/eudi-openid4vp;x-scheme-handler/haip-vp;x-scheme-handler/openid-credential-offer;x-scheme-handler/haip-vci;x-scheme-handler/eu-eaa-offer;\n",
	} {
		if !strings.Contains(entry, want) {
			t.Errorf("the desktop entry lacks %q:\n%s", want, entry)
		}
	}
}

// Desktop Entry Specification 1.5, "The Exec key": inside double quotes ", `,
// $ and \ are escaped with a backslash, the string escape doubles the
// backslash again, and % is doubled.
func TestTheExecKeyQuotesThePath(t *testing.T) {
	got, err := desktopExecArg(`/home/a b/50% "x" $y` + "`z`" + `\w/eudi`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"/home/a b/50%% \\"x\\" \\$y\\` + "`z\\\\`" + `\\\\w/eudi"`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, _ := desktopExecArg("/home/me/.local/bin/eudi-dev_3.2.0+x"); got != "/home/me/.local/bin/eudi-dev_3.2.0+x" {
		t.Errorf("a plain path was quoted: %s", got)
	}
	if _, err := desktopExecArg("/tmp/a\nb"); err == nil {
		t.Error("a path with a newline was accepted")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultsAreAddedToANewMimeappsList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mimeapps.list")
	if err := setDefaults(path, []string{"x-scheme-handler/a", "x-scheme-handler/b"}, desktopID, false); err != nil {
		t.Fatal(err)
	}
	want := "[Default Applications]\nx-scheme-handler/a=dev.eudi.wallet.desktop\nx-scheme-handler/b=dev.eudi.wallet.desktop\n"
	if got := readFile(t, path); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// Other groups and other applications' defaults stay. An existing default for
// one of the schemes is replaced.
func TestDefaultsKeepTheRestOfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mimeapps.list")
	writeFile(t, path, "[Added Associations]\ntext/plain=gedit.desktop;\n\n[Default Applications]\ntext/html=firefox.desktop\nx-scheme-handler/a=other.desktop\n\n[Removed Associations]\nimage/png=gimp.desktop;\n")
	if err := setDefaults(path, []string{"x-scheme-handler/a", "x-scheme-handler/b"}, desktopID, false); err != nil {
		t.Fatal(err)
	}
	want := "[Added Associations]\ntext/plain=gedit.desktop;\n\n[Default Applications]\ntext/html=firefox.desktop\nx-scheme-handler/a=dev.eudi.wallet.desktop\nx-scheme-handler/b=dev.eudi.wallet.desktop\n\n[Removed Associations]\nimage/png=gimp.desktop;\n"
	if got := readFile(t, path); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}

	if err := removeDefaults(path, []string{"x-scheme-handler/a", "x-scheme-handler/b"}, desktopID); err != nil {
		t.Fatal(err)
	}
	want = "[Added Associations]\ntext/plain=gedit.desktop;\n\n[Default Applications]\ntext/html=firefox.desktop\n\n[Removed Associations]\nimage/png=gimp.desktop;\n"
	if got := readFile(t, path); got != want {
		t.Errorf("after removal got\n%s\nwant\n%s", got, want)
	}
}

func TestAGroupHeaderOnTheLastLineGetsTheEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mimeapps.list")
	writeFile(t, path, "[Default Applications]\n")
	if err := setDefaults(path, []string{"x-scheme-handler/a"}, desktopID, false); err != nil {
		t.Fatal(err)
	}
	if got, want := readFile(t, path), "[Default Applications]\nx-scheme-handler/a=dev.eudi.wallet.desktop\n"; got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// A desktop-specific file overrides mimeapps.list. Only its entries that name
// another handler are changed, and a file without such entries stays as it is.
func TestADesktopOverrideChangesOnlyItsOwnEntries(t *testing.T) {
	dir := t.TempDir()
	dirs := xdgDirs{dataHome: dir, configHome: dir, desktops: []string{"kde", "gnome"}}
	writeFile(t, filepath.Join(dir, "kde-mimeapps.list"), "[Default Applications]\nx-scheme-handler/openid4vp=other.desktop\ntext/html=firefox.desktop\n")
	writeFile(t, filepath.Join(dir, "gnome-mimeapps.list"), "[Default Applications]\ntext/html=firefox.desktop\n")
	if _, err := dirs.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	if got, want := readFile(t, filepath.Join(dir, "kde-mimeapps.list")), "[Default Applications]\nx-scheme-handler/openid4vp=dev.eudi.wallet.desktop\ntext/html=firefox.desktop\n"; got != want {
		t.Errorf("kde-mimeapps.list:\n%s\nwant\n%s", got, want)
	}
	if got, want := readFile(t, filepath.Join(dir, "gnome-mimeapps.list")), "[Default Applications]\ntext/html=firefox.desktop\n"; got != want {
		t.Errorf("gnome-mimeapps.list changed:\n%s", got)
	}
	if got := readFile(t, filepath.Join(dir, "mimeapps.list")); strings.Count(got, desktopID) != len(URLSchemes) {
		t.Errorf("mimeapps.list names the handler %d times, want once per scheme:\n%s", strings.Count(got, desktopID), got)
	}
}

// home-manager links mimeapps.list into the read-only Nix store. Replacing the
// link would take the file out of its management.
func TestALinkedMimeappsListIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "managed.list")
	writeFile(t, managed, "[Default Applications]\ntext/html=firefox.desktop\n")
	if err := os.Symlink(managed, filepath.Join(dir, "mimeapps.list")); err != nil {
		t.Fatal(err)
	}
	warnings, err := xdgDirs{dataHome: dir, configHome: dir}.applyDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "x-scheme-handler/openid4vp=dev.eudi.wallet.desktop") {
		t.Errorf("warnings %q, want one with the lines to add", warnings)
	}
	if got := readFile(t, managed); strings.Contains(got, desktopID) {
		t.Errorf("the managed file changed:\n%s", got)
	}
}

func TestDesktopWarnings(t *testing.T) {
	found := func(string) (string, error) { return "/usr/bin/x", nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }
	session := func(name string) string {
		if name == "WAYLAND_DISPLAY" {
			return "wayland-0"
		}
		return ""
	}
	if got := desktopWarnings("/usr/bin/eudi", found, session); len(got) != 0 {
		t.Errorf("a desktop with xdg-utils got warnings %q", got)
	}
	got := desktopWarnings("/opt/my apps/eudi", missing, func(string) string { return "" })
	if len(got) != 3 || !strings.Contains(got[0], "needs quotes") || !strings.Contains(got[1], "No graphical session") || !strings.Contains(got[2], "xdg-open and xdg-mime not found") {
		t.Errorf("warnings %q, want the quoted path, the missing session and xdg-utils", got)
	}
}
