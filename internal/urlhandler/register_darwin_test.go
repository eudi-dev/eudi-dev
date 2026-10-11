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

//go:build darwin

package urlhandler

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// The commands build a plist in which every scheme sits once under the URL
// type of its protocol.
func TestPlistCommandsRegisterEverySchemeUnderItsProtocol(t *testing.T) {
	plist := filepath.Join(t.TempDir(), "Info.plist")
	for _, cmd := range plistCommands(plist) {
		if out, err := exec.Command("/usr/libexec/PlistBuddy", cmd...).CombinedOutput(); err != nil {
			t.Fatalf("PlistBuddy %v: %v %s", cmd, err, out)
		}
	}
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-", plist).Output()
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		CFBundleURLTypes []struct {
			CFBundleURLName    string
			CFBundleURLSchemes []string
		}
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"OID4VP": presentationURLSchemes, "OID4VCI": issuanceURLSchemes}
	var all []string
	for _, urlType := range info.CFBundleURLTypes {
		if !slices.Equal(urlType.CFBundleURLSchemes, want[urlType.CFBundleURLName]) {
			t.Errorf("%s has schemes %v, want %v", urlType.CFBundleURLName, urlType.CFBundleURLSchemes, want[urlType.CFBundleURLName])
		}
		all = append(all, urlType.CFBundleURLSchemes...)
	}
	if !slices.Equal(all, URLSchemes) {
		t.Errorf("registered schemes %v, want %v", all, URLSchemes)
	}
}
