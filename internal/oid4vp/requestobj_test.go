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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
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

	jweStr, _, err := jwe.EncryptECDHES([]byte(jwt), &walletKey.PublicKey, "test-kid", "A128GCM", "", nil, nil)
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
