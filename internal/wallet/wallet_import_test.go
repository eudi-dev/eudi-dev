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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func buildPlainJWTForTest(t *testing.T, payload map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
	body, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".signature"
}

// W3C JWT VC uses a type array instead of the SD-JWT VC vct claim.
func TestJWTVCType(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"type array in the vc claim", map[string]any{"vc": map[string]any{"type": []any{"VerifiableCredential", "NFEmployeeCredential"}}}, "NFEmployeeCredential"},
		{"type array at the payload root", map[string]any{"type": []any{"VerifiableCredential", "NFStudentCredential"}}, "NFStudentCredential"},
		{"only the base type", map[string]any{"type": []any{"VerifiableCredential"}}, ""},
		{"no type at all", map[string]any{"iss": "x"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jwtVCType(tc.payload); got != tc.want {
				t.Errorf("jwtVCType = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestImportPlainJWTStoresTheVCType(t *testing.T) {
	w := generateTestWallet(t)
	jwt := buildPlainJWTForTest(t, map[string]any{
		"iss": "https://issuer.example",
		"vc":  map[string]any{"type": []any{"VerifiableCredential", "NFEmployeeCredential"}},
	})

	cred, err := w.parsePlainJWTEntry(jwt, "", "")
	if err != nil {
		t.Fatalf("importPlainJWT: %v", err)
	}
	if cred.Format != "jwt_vc_json" {
		t.Errorf("format = %q, want jwt_vc_json", cred.Format)
	}
	if cred.VCT != "NFEmployeeCredential" {
		t.Errorf("VCT = %q, want NFEmployeeCredential (the type, not the format)", cred.VCT)
	}
}

// A credential stored by eudi-dev 2 keeps its client ID for refresh.
func TestRehydrateMovesTheLegacyClientID(t *testing.T) {
	var cred StoredCredential
	if err := json.Unmarshal([]byte(`{"id":"x","renewal":{"issuer":"https://i.example","client_auth":{"method":"attestation","client_id":"wallet-client"}}}`), &cred); err != nil {
		t.Fatal(err)
	}
	if err := cred.Rehydrate(); err != nil {
		t.Fatal(err)
	}
	if cred.Renewal.ClientID != "wallet-client" || cred.Renewal.ClientAuth.LegacyClientID != "" {
		t.Errorf("renewal = %+v, client auth = %+v", cred.Renewal, cred.Renewal.ClientAuth)
	}
}

// rewrittenSDJWT issues an SD-JWT VC and edits its header and payload. Import
// does not check the issuer signature, so the edited credential still reads.
func rewrittenSDJWT(t *testing.T, w *Wallet, claims map[string]any, edit func(header, payload map[string]any)) string {
	t.Helper()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: "https://issuer.example", VCT: "urn:example:test:1",
		Claims: claims, Key: w.IssuerKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	jwt, rest, _ := strings.Cut(raw, "~")
	parts := strings.Split(jwt, ".")
	for i, apply := range []func(map[string]any){
		func(m map[string]any) { edit(m, nil) },
		func(m map[string]any) { edit(nil, m) },
	} {
		data, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		apply(m)
		if data, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
		parts[i] = base64.RawURLEncoding.EncodeToString(data)
	}
	return strings.Join(parts, ".") + "~" + rest
}

// disclosedClaimSDJWT moves claim from the payload into a Disclosure.
func disclosedClaimSDJWT(t *testing.T, w *Wallet, claim string, value any) string {
	t.Helper()
	encoded, err := json.Marshal([]any{"c2FsdA", claim, value})
	if err != nil {
		t.Fatal(err)
	}
	disclosure := base64.RawURLEncoding.EncodeToString(encoded)
	digest := sha256.Sum256([]byte(disclosure))
	raw := rewrittenSDJWT(t, w, map[string]any{"a": "b"}, func(_, p map[string]any) {
		if p != nil {
			delete(p, claim)
			p["_sd"] = append(p["_sd"].([]any), base64.RawURLEncoding.EncodeToString(digest[:]))
		}
	})
	return raw + disclosure + "~"
}

// An issuer hands over an SD-JWT VC that follows RFC 9901 and
// draft-ietf-oauth-sd-jwt-vc-19. Strict mode refuses one that breaks a MUST.
// Debug mode keeps it and reports the deviation.
func TestImportChecksTheSDJWTVCRules(t *testing.T) {
	keep := func(map[string]any, map[string]any) {}
	w := generateTestWallet(t)
	kb, err := signJSONWebSignature(map[string]any{"iat": 1, "aud": "x", "nonce": "n", "sd_hash": "h"}, w.HolderKey, map[string]any{"alg": "ES256", "typ": "kb+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		// §2.2.1: "The Issuer MUST include the typ header parameter in the
		// SD-JWT. The typ value MUST use dc+sd-jwt."
		"no typ": rewrittenSDJWT(t, w, map[string]any{"a": "b"}, func(h, _ map[string]any) {
			if h != nil {
				delete(h, "typ")
			}
		}),
		"typ JWT": rewrittenSDJWT(t, w, map[string]any{"a": "b"}, func(h, _ map[string]any) {
			if h != nil {
				h["typ"] = "JWT"
			}
		}),
		// §2.2.2.3: "vct: REQUIRED."
		"no vct": rewrittenSDJWT(t, w, map[string]any{"a": "b"}, func(_, p map[string]any) {
			if p != nil {
				delete(p, "vct")
			}
		}),
		// §2.2.2.3: exp, status and cnf "MUST NOT be selectively disclosed".
		"disclosed exp":    disclosedClaimSDJWT(t, w, "exp", 4102444800),
		"disclosed status": disclosedClaimSDJWT(t, w, "status", map[string]any{"status_list": map[string]any{"idx": 1, "uri": "https://issuer.example/sl"}}),
		// RFC 9901 §7.2: "If the Holder receives an SD-JWT+KB, it MUST be
		// rejected."
		"SD-JWT+KB": rewrittenSDJWT(t, w, map[string]any{"a": "b"}, keep) + kb,
	} {
		t.Run(name, func(t *testing.T) {
			strict := generateTestWallet(t)
			strict.ValidationMode = ValidationModeStrict
			if _, err := strict.ImportCredential(raw); err == nil {
				t.Error("strict mode stored the credential")
			}
			debug := generateTestWallet(t)
			if _, err := debug.ImportCredential(raw); err != nil {
				t.Fatalf("debug mode refused the credential: %v", err)
			}
			if findLogEntry(debug.GetLog(), "credential_structure_deviation") == nil {
				t.Error("debug mode did not report the deviation")
			}
		})
	}
}
