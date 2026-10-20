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

package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
)

func TestDecryptRequestObjectJWE(t *testing.T) {
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwt := makeTestJWT(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}, map[string]any{
		"client_id":     "test-verifier",
		"response_type": "vp_token",
		"nonce":         "test-nonce",
	})

	jweStr, _, err := jwe.EncryptECDHES([]byte(jwt), &walletKey.PublicKey, "test-kid", "A128GCM", "JWT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptRequestObjectJWE(jweStr, walletKey)
	if err != nil {
		t.Fatalf("DecryptRequestObjectJWE: %v", err)
	}

	if decrypted != jwt {
		t.Errorf("decrypted JWT doesn't match original")
	}
}

func makeTestJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return format.EncodeBase64URL(h) + "." + format.EncodeBase64URL(p) + ".testsig"
}

func TestRequestObjectContentTypeFinding(t *testing.T) {
	tests := []struct {
		name    string
		header  map[string]any
		finding string
	}{
		{name: "cty JWT", header: map[string]any{"cty": "JWT"}},
		{name: "cty compared case-insensitively", header: map[string]any{"cty": "jwt"}},
		{name: "missing cty", header: map[string]any{}, finding: "The JWE header of the encrypted request object has no cty."},
		{name: "other cty", header: map[string]any{"cty": "json"}, finding: `The JWE header of the encrypted request object sets cty to "json".`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequestObjectContentTypeFinding(jwe.Header{Raw: tt.header})
			if tt.finding == "" && got != "" {
				t.Fatalf("unexpected finding %q", got)
			}
			if !strings.HasPrefix(got, tt.finding) {
				t.Fatalf("finding = %q, want prefix %q", got, tt.finding)
			}
		})
	}
}
