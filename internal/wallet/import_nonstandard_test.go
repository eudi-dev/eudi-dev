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

package wallet

import (
	"os"
	"strings"
	"testing"
)

func nonStandardCredential(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../pkg/sdjwt/testdata/nested_sd_alg.txt")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// This PID from a real issuer nests _sd_alg, copies its claims into a
// credentialSubject and carries a W3C StatusList2021Entry. Debug mode keeps
// the credential and records the rule breaks. Strict mode refuses it.
func TestImportSDJWT_NonStandardCredential(t *testing.T) {
	raw := nonStandardCredential(t)

	t.Run("debug keeps it", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeDebug
		cred, err := w.parseSDJWTEntry(raw, "", "")
		if err != nil {
			t.Fatalf("debug import refused the credential: %v", err)
		}
		if cred.Claims["family_name"] != "Mustermann" {
			t.Fatalf("family_name not stored: %v", cred.Claims["family_name"])
		}
	})

	t.Run("strict refuses it", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeStrict
		if _, err := w.parseSDJWTEntry(raw, "", ""); err == nil {
			t.Fatal("strict import accepted a credential that breaks RFC 9901")
		}
	})
}
