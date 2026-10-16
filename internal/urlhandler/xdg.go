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
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Linux desktops find URL scheme handlers through the freedesktop.org
// specifications: a desktop entry announces the schemes as
// x-scheme-handler/<scheme> MIME types (Desktop Entry Specification 1.5), and
// mimeapps.list makes it the default (Association between MIME types and
// applications 1.0.1). Browsers reach it through GIO, xdg-open or the OpenURI
// portal.

const (
	desktopID           = "dev.eudi.wallet.desktop"
	defaultAppsGroup    = "[Default Applications]"
	schemeHandlerPrefix = "x-scheme-handler/"
)

// errManagedElsewhere marks a mimeapps.list that is a symbolic link, for
// example into the Nix store with home-manager. Writing would replace the
// link, so the user adds the defaults to that configuration instead.
var errManagedElsewhere = errors.New("managed elsewhere")

// xdgDirs are the user directories of the freedesktop.org specifications.
type xdgDirs struct {
	dataHome, configHome string
	// desktops are the names in XDG_CURRENT_DESKTOP, in lower case. Each may
	// have a $desktop-mimeapps.list that overrides mimeapps.list.
	desktops []string
}

// mimeappsFiles are the user's mimeapps.list and its desktop-specific
// overrides. The overrides come first in the lookup order.
func (x xdgDirs) mimeappsFiles() (main string, overrides []string) {
	for _, d := range x.desktops {
		overrides = append(overrides, filepath.Join(x.configHome, d+"-mimeapps.list"))
	}
	return filepath.Join(x.configHome, "mimeapps.list"), overrides
}

// plainExecPath reports a path that needs neither quotes nor escapes in Exec.
func plainExecPath(path string) bool {
	return path != "" && strings.Trim(path, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._+-@,:=") == ""
}

func schemeMIMETypes() []string {
	types := make([]string, len(URLSchemes))
	for i, s := range URLSchemes {
		types[i] = schemeHandlerPrefix + s
	}
	return types
}

// desktopEntry is the hidden desktop entry that hands a clicked link to
// 'wallet open-url'.
func desktopEntry(binary string) (string, error) {
	exec, err := desktopExecArg(binary)
	if err != nil {
		return "", err
	}
	return "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=EUDI Dev Wallet\n" +
		"Comment=Opens OpenID4VP requests and OpenID4VCI credential offers in the eudi-dev wallet\n" +
		"Exec=" + exec + " wallet open-url %u\n" +
		"Terminal=false\n" +
		"NoDisplay=true\n" +
		"MimeType=" + strings.Join(schemeMIMETypes(), ";") + ";\n", nil
}

// desktopExecArg writes one Exec argument. A plain path stays bare, because
// xdg-open without a desktop environment runs the first word of Exec as it is
// and doesn't remove quotes. Any other path is quoted as the Desktop Entry
// Specification 1.5 says: ", `, $ and \ are escaped inside double quotes, the
// string escape for \ applies before that, and % is doubled because it starts
// a field code.
func desktopExecArg(arg string) (string, error) {
	if strings.ContainsAny(arg, "\n\r\t") {
		return "", fmt.Errorf("the path %q holds a control character, which a desktop entry can't carry", arg)
	}
	if plainExecPath(arg) {
		return arg, nil
	}
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`).Replace(arg)
	return `"` + strings.NewReplacer(`\`, `\\`, `%`, `%%`).Replace(quoted) + `"`, nil
}

// setDefaults makes id the default application for types in a mimeapps.list.
// With onlyExisting it changes only entries that name another application,
// which is how a desktop-specific override is kept from winning over
// mimeapps.list without adding entries to it.
func setDefaults(path string, types []string, id string, onlyExisting bool) error {
	return editDefaults(path, func(entries map[string]string) []string {
		var missing []string
		for _, t := range types {
			value, present := entries[t]
			switch {
			case present && value != id:
				entries[t] = id
			case !present && !onlyExisting:
				missing = append(missing, t)
			}
		}
		return missing
	})
}

// removeDefaults takes id out of the default entries for types.
func removeDefaults(path string, types []string, id string) error {
	return editDefaults(path, func(entries map[string]string) []string {
		for _, t := range types {
			value, present := entries[t]
			if !present {
				continue
			}
			ids := slices.DeleteFunc(strings.Split(value, ";"), func(v string) bool { return v == id || v == "" })
			entries[t] = strings.Join(ids, ";")
		}
		return nil
	})
}

// editDefaults rewrites the [Default Applications] group of a mimeapps.list
// and keeps everything else. edit changes the entries in place, where an empty
// value removes the entry, and returns the types to add with desktopID. The
// file is only written when it changes.
func editDefaults(path string, edit func(entries map[string]string) (added []string)) error {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var lines []string
	if len(raw) > 0 {
		lines = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	start, end, found := groupBounds(lines, defaultAppsGroup)
	original := map[string]string{}
	for _, line := range lines[start:end] {
		if key, value, ok := strings.Cut(line, "="); ok {
			original[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	entries := maps.Clone(original)
	added := edit(entries)
	if len(added) == 0 && maps.Equal(entries, original) {
		return nil
	}

	var group []string
	for _, line := range lines[start:end] {
		key, _, isEntry := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		switch {
		case !isEntry || entries[key] == original[key]:
			group = append(group, line)
		case entries[key] != "":
			group = append(group, key+"="+entries[key])
		}
	}
	for len(group) > 0 && strings.TrimSpace(group[len(group)-1]) == "" {
		group = group[:len(group)-1]
	}
	for _, t := range added {
		group = append(group, t+"="+desktopID)
	}

	var out []string
	if found {
		out = append(slices.Clone(lines[:start]), group...)
		if end < len(lines) {
			out = append(append(out, ""), lines[end:]...)
		}
	} else {
		out = slices.Clone(lines)
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(append(out, defaultAppsGroup), group...)
	}
	return writeMimeapps(path, strings.Join(out, "\n")+"\n")
}

// groupBounds returns the range of a group's lines after its header. A
// missing group gives an empty range at the end.
func groupBounds(lines []string, header string) (start, end int, found bool) {
	i := slices.IndexFunc(lines, func(l string) bool { return strings.TrimSpace(l) == header })
	if i < 0 {
		return len(lines), len(lines), false
	}
	end = i + 1
	for end < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[end]), "[") {
		end++
	}
	return i + 1, end, true
}

func writeMimeapps(path, content string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errManagedElsewhere
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mimeapps-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// applyDefaults makes the desktop entry the default handler of every scheme.
// A file managed elsewhere gives a warning with the lines to add there.
func (x xdgDirs) applyDefaults() ([]string, error) {
	types := schemeMIMETypes()
	main, overrides := x.mimeappsFiles()
	var warnings []string
	for i, path := range append([]string{main}, overrides...) {
		err := setDefaults(path, types, desktopID, i > 0)
		if errors.Is(err, errManagedElsewhere) {
			warnings = append(warnings, managedWarning(path, types))
			continue
		}
		if err != nil {
			return warnings, fmt.Errorf("updating %s: %w", path, err)
		}
	}
	return warnings, nil
}

func managedWarning(path string, types []string) string {
	lines := make([]string, len(types))
	for i, t := range types {
		lines[i] = "  " + t + "=" + desktopID
	}
	return fmt.Sprintf("%s is a link into a configuration managed elsewhere (such as home-manager), so it was left unchanged. Add these defaults there:\n%s", path, strings.Join(lines, "\n"))
}

// desktopWarnings name what keeps a clicked link from reaching the handler.
// Chrome falls back to xdg-open without the OpenURI portal, and snapd lets a
// snap browser open an unlisted scheme only when xdg-mime names its default
// handler. Both come with xdg-utils.
func desktopWarnings(binary string, lookPath func(string) (string, error), getenv func(string) string) []string {
	var warnings []string
	if !plainExecPath(binary) {
		warnings = append(warnings, fmt.Sprintf("The path %s needs quotes in the desktop entry. Desktop environments handle that, but xdg-open under a bare window manager doesn't. Move eudi to a path without spaces or special characters if links don't open.", binary))
	}
	if getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
		warnings = append(warnings, "No graphical session found. Links open the wallet only in a desktop session with a browser.")
	}
	var missing []string
	for _, tool := range []string{"xdg-open", "xdg-mime"} {
		if _, err := lookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		warnings = append(warnings, fmt.Sprintf("%s not found. Chrome, Chromium and snap browsers need xdg-utils to hand links to the wallet.", strings.Join(missing, " and ")))
	}
	return warnings
}
