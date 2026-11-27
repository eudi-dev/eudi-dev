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
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// useTestRegistry points the scheme keys at a throwaway key below
// HKEY_CURRENT_USER\Software, so the test leaves the real handlers alone.
func useTestRegistry(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	root := `Software\eudi-dev-test-` + hex.EncodeToString(b)
	oldClasses, oldAssoc := classesRoot, urlAssociationsRoot
	classesRoot, urlAssociationsRoot = root+`\Classes`, root+`\UrlAssociations`
	t.Cleanup(func() {
		classesRoot, urlAssociationsRoot = oldClasses, oldAssoc
		if err := deleteKeyTree(registry.CURRENT_USER, root); err != nil {
			t.Errorf("removing the test key: %v", err)
		}
	})
	t.Setenv("EUDI_DEV_HOME", filepath.Join(t.TempDir(), ".eudi-dev"))
	return root
}

func readValue(t *testing.T, path, name string) string {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		t.Fatalf("reading %s\\%s: %v", path, name, err)
	}
	return v
}

func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func TestRegisterWritesPluggableProtocolKeys(t *testing.T) {
	useTestRegistry(t)
	reg, err := Register(Options{ListenerPort: 8085, AutoAccept: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Registered || !strings.HasSuffix(reg.RegistryKey, classesRoot) {
		t.Fatalf("registration %+v", reg)
	}
	for _, scheme := range URLSchemes {
		path := classesRoot + `\` + scheme
		if got := readValue(t, path, "URL Protocol"); got != "" {
			t.Errorf("%s: URL Protocol = %q, want empty", scheme, got)
		}
		if got := readValue(t, path+`\shell\open`, "FriendlyAppName"); got != handlerAppName {
			t.Errorf("%s: FriendlyAppName = %q, want %q", scheme, got, handlerAppName)
		}
		want, _ := handlerCommand(reg.Binary)
		if got := readValue(t, path+`\shell\open\command`, ""); got != want {
			t.Errorf("%s: command %q, want %q", scheme, got, want)
		}
	}
	if opts, ok, err := LoadOptions(); err != nil || !ok || opts.ListenerPort != 8085 || !opts.AutoAccept {
		t.Errorf("options %+v (%t, %v)", opts, ok, err)
	}
}

func TestUnregisterLeavesForeignKeys(t *testing.T) {
	useTestRegistry(t)
	if _, err := Register(Options{ListenerPort: 8085}); err != nil {
		t.Fatal(err)
	}
	// Another wallet took over one scheme after the registration.
	foreign := classesRoot + `\` + URLSchemes[0]
	if err := deleteKeyTree(registry.CURRENT_USER, foreign); err != nil {
		t.Fatal(err)
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, foreign+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.SetStringValue("", `"C:\other\wallet.exe" "%1"`)
	k.Close()

	unreg, err := Unregister()
	if err != nil {
		t.Fatal(err)
	}
	if !unreg.Unregistered {
		t.Errorf("unregistration %+v, want Unregistered", unreg)
	}
	if !keyExists(foreign) {
		t.Errorf("the foreign key %s was removed", foreign)
	}
	for _, scheme := range URLSchemes[1:] {
		if keyExists(classesRoot + `\` + scheme) {
			t.Errorf("%s is still registered", scheme)
		}
	}
	if _, ok, _ := LoadOptions(); ok {
		t.Error("the options are still saved")
	}
	if again, err := Unregister(); err != nil || again.Unregistered {
		t.Errorf("second Unregister: %+v, %v", again, err)
	}
}

func TestUserChoiceWarnings(t *testing.T) {
	choices := map[string]string{"openid4vp": "AppXabc123", "haip-vp": "haip-vp"}
	lookup := func(s string) (string, bool) { v, ok := choices[s]; return v, ok }
	warnings := userChoiceWarnings([]string{"openid4vp", "haip-vp", "eu-eaap"}, lookup)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "openid4vp:// (now AppXabc123)") || strings.Contains(warnings[0], "haip-vp") {
		t.Errorf("warnings %q", warnings)
	}
	if w := userChoiceWarnings([]string{"eu-eaap"}, lookup); w != nil {
		t.Errorf("warnings %q, want none", w)
	}
}
