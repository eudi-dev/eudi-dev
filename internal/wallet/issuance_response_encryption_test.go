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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// OID4VCI 1.0 §12.2.4: encryption_required says "whether the Credential
// Issuer requires the additional encryption on top of TLS for the Credential
// Requests". Without a usable key the wallet cannot meet that requirement, so
// it stops. An issuer that does not require encryption gets a plain request.
func TestCredentialRequestEncryptionNeedsAUsableKey(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	usable := testEncJWK(t, &key.PublicKey)
	usable["kid"] = "issuer-enc"
	signing := testEncJWK(t, &key.PublicKey)
	signing["kid"], signing["use"] = "issuer-sig", "sig"
	withoutKid := testEncJWK(t, &key.PublicKey)

	metadata := func(required bool, jwk map[string]any) map[string]any {
		return map[string]any{"credential_request_encryption": map[string]any{
			"jwks":                 map[string]any{"keys": []any{jwk}},
			"enc_values_supported": []any{"A128GCM"},
			"encryption_required":  required,
		}}
	}
	for _, tt := range []struct {
		name     string
		metadata map[string]any
		wantErr  string
		wantKid  string
	}{
		{"usable key", metadata(true, usable), "", "issuer-enc"},
		{"required with only a signing key", metadata(true, signing), "no usable ECDH-ES encryption key", ""},
		{"required with a key without kid", metadata(true, withoutKid), "no usable ECDH-ES encryption key", ""},
		{"optional with a key without kid", metadata(false, withoutKid), "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params, err := selectCredentialRequestEncryption(ValidationModeStrict, tt.metadata)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tt.wantKid == "" && params != nil:
				t.Errorf("params %+v, want an unencrypted request", params)
			case tt.wantKid != "" && (params == nil || params.kid != tt.wantKid):
				t.Errorf("params %+v, want the key %q", params, tt.wantKid)
			}
		})
	}
}

// plaintextCredentialIssuer answers every credential request with the given
// plaintext JSON body and status.
func plaintextCredentialIssuer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		_, _ = io.WriteString(rw, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func encryptedResponseAttempt(endpoint string) credentialRequestAttempt {
	return credentialRequestAttempt{
		endpoint: endpoint, credentialConfigurationID: "pid",
		responseEncryption: map[string]any{"enc": "A128GCM"},
	}
}

// OID4VCI 1.0 §8.3: once the request asks for an encrypted response, the
// issuer encrypts it. §10 says a plaintext answer SHOULD be rejected.
func TestPlaintextCredentialResponseAfterEncryptionRequest(t *testing.T) {
	srv := plaintextCredentialIssuer(t, http.StatusOK, `{"credentials":[{"credential":"issued"}]}`)
	proofs := credentialProofs{Type: "jwt", Values: []string{"proof"}}

	strict := generateTestWallet(t)
	strict.ValidationMode = ValidationModeStrict
	if _, err := strict.sendCredentialRequest(encryptedResponseAttempt(srv.URL), proofs); err == nil {
		t.Error("strict mode accepted a plaintext credential response to a request for encryption")
	}

	debug := generateTestWallet(t)
	debug.ValidationMode = ValidationModeDebug
	if _, err := debug.sendCredentialRequest(encryptedResponseAttempt(srv.URL), proofs); err != nil {
		t.Fatalf("debug mode: %v", err)
	}
	if !hasWarningContaining(debug, "answered in plaintext") {
		t.Error("debug mode did not report the plaintext response")
	}
}

// §8.3.1.2: "Credential Error Responses are never encrypted".
func TestPlaintextCredentialErrorResponseIsExpected(t *testing.T) {
	srv := plaintextCredentialIssuer(t, http.StatusBadRequest, `{"error":"invalid_proof"}`)
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	_, err := w.sendCredentialRequest(encryptedResponseAttempt(srv.URL), credentialProofs{Type: "jwt", Values: []string{"proof"}})
	var credErr credentialErrorResponse
	if !errors.As(err, &credErr) || credErr.code != "invalid_proof" {
		t.Errorf("error = %v, want the issuer's invalid_proof", err)
	}
}
