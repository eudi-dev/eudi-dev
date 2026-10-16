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

package demorp

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// ETSI TS 119 472-3 V1.1.1 CRYPTO-5-01: the provider supports A128GCM and
// A256GCM. Neither encryption is required, so wallets without it keep working.
func TestTheMetadataOffersCredentialEncryption(t *testing.T) {
	d, _, _ := newDemoRP(t)
	_, metadata := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	for _, name := range []string{"credential_request_encryption", "credential_response_encryption"} {
		encryption, ok := metadata[name].(map[string]any)
		if !ok {
			t.Fatalf("the metadata publishes no %s", name)
		}
		if encryption["encryption_required"] != false {
			t.Errorf("%s encryption_required = %v, want false", name, encryption["encryption_required"])
		}
		if got := fmt.Sprint(encryption["enc_values_supported"]); got != "[A128GCM A256GCM]" {
			t.Errorf("%s enc_values_supported = %s, want A128GCM and A256GCM", name, got)
		}
	}
	keys := metadata["credential_request_encryption"].(map[string]any)["jwks"].(map[string]any)["keys"].([]any)
	if key := keys[0].(map[string]any); key["kid"] == "" || key["alg"] != jwe.AlgECDHES {
		t.Errorf("request encryption key = %v, want a kid and alg ECDH-ES (§12.2.4, §10)", key)
	}
}

// encryptedCredentialRequest sends the request members encrypted to the
// issuer's credential_request_encryption key (OpenID4VCI 1.0 §10).
func encryptedCredentialRequest(t *testing.T, d *DemoRP, endpoint, accessToken string, members map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	compact, _, err := jwe.EncryptECDHES(body, &d.requestEncryptionKey.PublicKey, requestEncryptionKID, jwe.EncA256GCM, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(compact))
	req.Header.Set("Content-Type", "application/jwt")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	return rec
}

// withJWEHeader sets a protected header parameter of a compact JWE. The
// header is the AAD, so the result no longer decrypts.
func withJWEHeader(t *testing.T, compact, name, value string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	header[name] = value
	raw, err = json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

func responseEncryptionParams(t *testing.T, key *ecdsa.PrivateKey, enc string) map[string]any {
	t.Helper()
	jwk := holderJWK(t, key)
	jwk["alg"], jwk["kid"] = jwe.AlgECDHES, "wallet-enc"
	return map[string]any{"jwk": jwk, "enc": enc}
}

func decryptCredentialResponse(t *testing.T, rec *httptest.ResponseRecorder, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/jwt" {
		t.Fatalf("Content-Type = %q, want application/jwt (§10): %s", got, rec.Body.String())
	}
	ecdhKey, err := key.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := jwe.Decrypt(rec.Body.String(), ecdhKey)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestAnEncryptedRequestGetsAnEncryptedResponse(t *testing.T) {
	d, _, _ := newDemoRP(t)
	encKey := generateKeys(t, 1)[0]
	for _, enc := range []string{jwe.EncA128GCM, jwe.EncA256GCM} {
		t.Run(enc, func(t *testing.T) {
			token := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
			proofKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			rec := encryptedCredentialRequest(t, d, "/credential", token, map[string]any{
				"credential_configuration_id":    "demo-ticket",
				"proofs":                         map[string]any{"jwt": []string{proofJWTForKey(t, d, proofKey, proofOptions{nonce: issuedNonce(t, d)})}},
				"credential_response_encryption": responseEncryptionParams(t, encKey, enc),
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			if doc := decryptCredentialResponse(t, rec, encKey); len(doc["credentials"].([]any)) != 1 {
				t.Errorf("decrypted response = %v, want one credential", doc)
			}
		})
	}
}

// §9.2: the issuer "MUST use the newly provided" credential_response_encryption
// of the Deferred Credential Request.
func TestAnEncryptedDeferredRequestGetsAnEncryptedResponse(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.deferredDelay = 0
	encKey := generateKeys(t, 1)[0]
	token := redeemPreAuthOffer(t, d, "deferred=true", nil)["access_token"].(string)
	_, accepted := requestCredential(t, d, token, `"credential_configuration_id":"demo-ticket",`)

	rec := encryptedCredentialRequest(t, d, "/deferred_credential", token, map[string]any{
		"transaction_id":                 accepted["transaction_id"],
		"credential_response_encryption": responseEncryptionParams(t, encKey, jwe.EncA128GCM),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if doc := decryptCredentialResponse(t, rec, encKey); doc["credentials"] == nil {
		t.Errorf("decrypted response = %v, want the credentials", doc)
	}
}

func TestUnusableEncryptionParametersAreRefused(t *testing.T) {
	d, _, _ := newDemoRP(t)
	encKey := generateKeys(t, 1)[0]
	other := generateKeys(t, 1)[0]

	t.Run("response encryption in a plaintext request", func(t *testing.T) {
		// §8.2: "Credential Request encryption MUST be used if the
		// credential_response_encryption parameter is included".
		params, err := json.Marshal(responseEncryptionParams(t, encKey, jwe.EncA128GCM))
		if err != nil {
			t.Fatal(err)
		}
		token := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
		code, doc := requestCredential(t, d, token, `"credential_response_encryption":`+string(params)+`,"credential_configuration_id":"demo-ticket",`)
		if code != http.StatusBadRequest || doc["error"] != "invalid_encryption_parameters" {
			t.Errorf("status = %d %v, want 400 invalid_encryption_parameters", code, doc)
		}
	})

	t.Run("an enc outside enc_values_supported", func(t *testing.T) {
		token := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
		rec := encryptedCredentialRequest(t, d, "/credential", token, map[string]any{
			"credential_configuration_id":    "demo-ticket",
			"proofs":                         map[string]any{"jwt": []string{proofJWTWith(t, d, proofOptions{nonce: issuedNonce(t, d)})}},
			"credential_response_encryption": responseEncryptionParams(t, encKey, "A192GCM"),
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_encryption_parameters") {
			t.Errorf("status = %d %s, want 400 invalid_encryption_parameters", rec.Code, rec.Body.String())
		}
	})

	// The enc values come from credential_request_encryption, and §10 has
	// the JWE carry the kid of the issuer's key.
	for _, tc := range []struct {
		name, kid, enc, want string
		key                  *ecdsa.PublicKey
	}{
		{"a request encrypted to another key", requestEncryptionKID, "", "decrypting", &other.PublicKey},
		{"a request enc outside enc_values_supported", requestEncryptionKID, "A192GCM", "enc_values_supported", &d.requestEncryptionKey.PublicKey},
		{"a request without kid", "", "", "kid", &d.requestEncryptionKey.PublicKey},
		{"a request with another kid", "wallet-enc", "", "kid", &d.requestEncryptionKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
			compact, _, err := jwe.EncryptECDHES([]byte(`{}`), tc.key, tc.kid, jwe.EncA128GCM, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.enc != "" {
				compact = withJWEHeader(t, compact, "enc", tc.enc)
			}
			req := httptest.NewRequest(http.MethodPost, "/credential", strings.NewReader(compact))
			req.Header.Set("Content-Type", "application/jwt")
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			d.IssuerHandler().ServeHTTP(rec, req)
			if body := rec.Body.String(); rec.Code != http.StatusBadRequest || !strings.Contains(body, "invalid_encryption_parameters") || !strings.Contains(body, tc.want) {
				t.Errorf("status = %d %s, want 400 invalid_encryption_parameters naming %q", rec.Code, body, tc.want)
			}
		})
	}
}
