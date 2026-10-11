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
	"testing"
)

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
