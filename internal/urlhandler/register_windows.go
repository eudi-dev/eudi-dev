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

//go:build windows

package urlhandler

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Windows finds URL scheme handlers as "pluggable protocols": a key per scheme
// under HKEY_CURRENT_USER\Software\Classes with a "URL Protocol" value and a
// shell\open\command. The per-user hive needs no administrator rights.
// https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa767914(v=vs.85)
var (
	classesRoot = `Software\Classes`
	// A choice the user made in Settings › Default apps wins over the Classes
	// key. Its hash keeps programs from setting it.
	urlAssociationsRoot = `Software\Microsoft\Windows\Shell\Associations\UrlAssociations`
)

// ownerValue marks a scheme key written by Register, so Unregister leaves the
// registrations of other wallets alone.
const ownerValue = "EUDIDevHandler"

// Register makes this executable the handler of the URL schemes for the
// current user. A clicked link runs 'wallet open-url'.
func Register(opts Options) (Registration, error) {
	executable, err := os.Executable()
	if err != nil {
		return Registration{}, fmt.Errorf("finding executable path: %w", err)
	}
	binary := stableBinaryPath(executable)
	command, err := handlerCommand(binary)
	if err != nil {
		return Registration{}, err
	}
	if err := saveOptions(opts); err != nil {
		return Registration{}, err
	}
	for _, scheme := range URLSchemes {
		if err := writeSchemeKey(scheme, binary, command); err != nil {
			return Registration{}, err
		}
	}
	return Registration{
		Registered:  true,
		RegistryKey: `HKEY_CURRENT_USER\` + classesRoot,
		Handler:     binary + " wallet open-url",
		Binary:      binary,
		AutoAccept:  opts.AutoAccept,
		ServeArgs:   slices.Clone(opts.ServeArgs),
		Schemes:     slices.Clone(URLSchemes),
		Warnings:    userChoiceWarnings(URLSchemes, readUserChoice),
	}, nil
}

func writeSchemeKey(scheme, binary, command string) error {
	path := classesRoot + `\` + scheme
	values := []struct{ key, name, value string }{
		{path, "", "URL:EUDI Dev Wallet (" + scheme + ")"},
		{path, "URL Protocol", ""},
		{path, ownerValue, handlerScriptVersion},
		{path + `\DefaultIcon`, "", `"` + binary + `",0`},
		{path + `\shell\open\command`, "", command},
	}
	for _, v := range values {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, v.key, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("creating HKEY_CURRENT_USER\\%s: %w", v.key, err)
		}
		err = k.SetStringValue(v.name, v.value)
		k.Close()
		if err != nil {
			return fmt.Errorf("writing HKEY_CURRENT_USER\\%s: %w", v.key, err)
		}
	}
	return nil
}

// Unregister removes the scheme keys that Register wrote.
func Unregister() (Unregistration, error) {
	removed := false
	for _, scheme := range URLSchemes {
		path := classesRoot + `\` + scheme
		if !ownedKey(path) {
			continue
		}
		if err := deleteKeyTree(registry.CURRENT_USER, path); err != nil {
			return Unregistration{}, fmt.Errorf("removing HKEY_CURRENT_USER\\%s: %w", path, err)
		}
		removed = true
	}
	_ = os.Remove(optionsPath())
	if !removed {
		return Unregistration{}, nil
	}
	return Unregistration{Unregistered: true, RegistryKey: `HKEY_CURRENT_USER\` + classesRoot}, nil
}

func ownedKey(path string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(ownerValue)
	return err == nil
}

// deleteKeyTree deletes a key with its subkeys. RegDeleteKey only deletes a
// key without subkeys.
func deleteKeyTree(root registry.Key, path string) error {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := deleteKeyTree(root, path+`\`+name); err != nil {
			return err
		}
	}
	return registry.DeleteKey(root, path)
}

// readUserChoice returns the program the user chose in Settings for scheme.
func readUserChoice(scheme string) (progID string, ok bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, urlAssociationsRoot+`\`+scheme+`\UserChoice`, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	progID, _, err = k.GetStringValue("ProgId")
	return progID, err == nil && progID != ""
}

// userChoiceWarnings names the schemes whose links still go to the program
// chosen in Settings. A choice of the scheme's own Classes key is ours.
func userChoiceWarnings(schemes []string, choice func(string) (string, bool)) []string {
	var others []string
	for _, scheme := range schemes {
		if progID, ok := choice(scheme); ok && !strings.EqualFold(progID, scheme) {
			others = append(others, fmt.Sprintf("%s:// (now %s)", scheme, progID))
		}
	}
	if len(others) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("Windows sends these links to the app chosen in Settings: %s. Choose EUDI Dev Wallet in Settings › Apps › Default apps › Choose defaults by link type.", strings.Join(others, ", "))}
}
