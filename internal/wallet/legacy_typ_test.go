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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// Replace typ with the legacy value to test import parsing. This invalidates the
// signature, which import does not check.
func legacyTypeCredential(t *testing.T, w *Wallet, typ string) string {
	t.Helper()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: "https://issuer.example", VCT: mock.DefaultPIDVCT,
		Claims: templateClaims("pid-sdjwt"), Key: w.IssuerKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	jwt, rest, _ := strings.Cut(raw, "~")
	seg := strings.Split(jwt, ".")
	hdr, err := base64.RawURLEncoding.DecodeString(seg[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	h["typ"] = typ
	nh, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("encoding header: %v", err)
	}
	seg[0] = base64.RawURLEncoding.EncodeToString(nh)
	return strings.Join(seg, ".") + "~" + rest
}

// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires the typ dc+sd-jwt. Debug mode
// keeps a credential with the earlier vc+sd-jwt typ and records the deviation.
// Strict mode refuses it.
func TestImportSDJWT_LegacyType(t *testing.T) {
	t.Run("debug keeps it", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeDebug
		if _, err := w.parseSDJWTEntry(legacyTypeCredential(t, w, "vc+sd-jwt"), "", ""); err != nil {
			t.Fatalf("debug import refused the credential: %v", err)
		}
	})

	// RFC 7515 §4.1.9: typ values are case insensitive and "application/" is
	// implied when the value has no '/'.
	for _, typ := range []string{"vc+sd-jwt", "VC+SD-JWT", "application/vc+sd-jwt"} {
		t.Run("strict refuses "+typ, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = ValidationModeStrict
			if _, err := w.parseSDJWTEntry(legacyTypeCredential(t, w, typ), "", ""); err == nil {
				t.Fatal("strict import accepted a credential on the earlier typ")
			}
		})
	}
}

// templateClaims returns the claims of a predefined template.
func templateClaims(name string) map[string]any {
	t, ok := credtemplate.Predefined(name)
	if !ok {
		panic("no predefined template " + name)
	}
	return t.Claims
}
