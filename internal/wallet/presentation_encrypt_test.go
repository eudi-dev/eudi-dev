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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func verifierEncryptionJWK(t *testing.T, use string) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk["use"], jwk["alg"], jwk["kid"] = use, jwe.AlgECDHES, "verifier-enc"
	return jwk
}

func encryptedResponseRequest(clientMetadata map[string]any) *oid4vp.Request {
	req := queryRequest(map[string]any{"credentials": []any{sdjwtQuery("pid", mock.DefaultPIDVCT)}})
	req.ResponseMode = "direct_post.jwt"
	req.ClientMetadata = clientMetadata
	return req
}

// OID4VP 1.0 §8.3 encrypts the response to a key in client_metadata.jwks with
// an enc from encrypted_response_enc_values_supported. If the wallet cannot
// encrypt the response that way, the request is an invalid_request before any
// consent.
func TestUnencryptableResponseIsRefusedBeforeConsent(t *testing.T) {
	for _, tt := range []struct {
		name     string
		mode     ValidationMode
		metadata map[string]any
		want     string
	}{
		{"no jwks", ValidationModeDebug, map[string]any{}, "no encryption key"},
		{"only a signing key in strict mode", ValidationModeStrict, map[string]any{"jwks": map[string]any{"keys": []any{verifierEncryptionJWK(t, "sig")}}}, "no encryption key"},
		{"no enc this wallet implements", ValidationModeDebug, map[string]any{
			"jwks": map[string]any{"keys": []any{verifierEncryptionJWK(t, "enc")}},
			"encrypted_response_enc_values_supported": []any{"XC20P"},
		}, "implements none of them"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := generateTestWalletWithPID(t)
			w.ValidationMode = tt.mode
			outcome := w.evaluatePresentationRequest(encryptedResponseRequest(tt.metadata), presentationEntry{action: "presentation", subject: "The request"})
			if outcome.invalid == nil || outcome.invalidCode != oid4vp.ErrorInvalidRequest {
				t.Fatalf("outcome = %v (%s), want invalid_request", outcome.invalid, outcome.invalidCode)
			}
			if !strings.Contains(outcome.invalid.Error(), tt.want) {
				t.Errorf("error %q, want %q", outcome.invalid, tt.want)
			}
			if len(outcome.matches) != 0 {
				t.Errorf("the request reached credential matching: %d matches", len(outcome.matches))
			}
		})
	}
}

func TestEncryptableResponseReachesConsent(t *testing.T) {
	w := generateTestWalletWithPID(t)
	metadata := map[string]any{"jwks": map[string]any{"keys": []any{verifierEncryptionJWK(t, "enc")}}}
	outcome := w.evaluatePresentationRequest(encryptedResponseRequest(metadata), presentationEntry{action: "presentation", subject: "The request"})
	if outcome.invalid != nil || len(outcome.matches) != 1 {
		t.Fatalf("outcome = %v with %d matches, want one match", outcome.invalid, len(outcome.matches))
	}
}

// The verifier cannot read an unencrypted error, so /authorize answers only
// its caller and posts nothing to response_uri.
func TestAuthorizeAnswersAnUnencryptableRequestWithInvalidRequest(t *testing.T) {
	var posted atomic.Bool
	verifier := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posted.Store(true) }))
	defer verifier.Close()

	srv := newTestServer(t, false)
	query := url.Values{
		"client_id":       {"redirect_uri:" + verifier.URL},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"response_uri":    {verifier.URL},
		"nonce":           {"n"},
		"client_metadata": {`{}`},
		"dcql_query":      {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["` + mock.DefaultPIDVCT + `"]}}]}`},
	}
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+query.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != oid4vp.ErrorInvalidRequest {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
	if posted.Load() {
		t.Error("the wallet posted to the verifier's response_uri")
	}
}
