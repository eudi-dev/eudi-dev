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
	"crypto/rand"
	"fmt"
	"mime"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
)

// GenerateWalletNonce provides replay protection through wallet_nonce (OID4VP 1.0 §5.10).
func GenerateWalletNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating wallet nonce: %w", err)
	}
	return format.EncodeBase64URL(b), nil
}

// ValidateRequestURIResponse checks the media type of a request_uri response.
// For POST, OID4VP 1.0 §5.10.1 requires "the content type
// application/oauth-authz-req+jwt". For GET, RFC 9101 §4 gives a Request
// Object that type and notes "some existing deployments may alternatively be
// using the type application/jwt".
func ValidateRequestURIResponse(method, contentType string) error {
	cite := "OID4VP 1.0 §5.10.1"
	if method != "post" {
		cite = "RFC 9101 §4"
	}
	if contentType == "" {
		return fmt.Errorf("%s: the request_uri response is missing the Content-Type application/oauth-authz-req+jwt", cite)
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("%s: the request_uri response Content-Type does not parse: %w", cite, err)
	}
	if mediaType == format.MediaTypeRequestObject || (method != "post" && mediaType == "application/jwt") {
		return nil
	}
	return fmt.Errorf("%s: the request_uri response Content-Type must be application/oauth-authz-req+jwt, got %q", cite, contentType)
}

func DecryptCompactJWE(compact string, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("decryption requires a private key")
	}
	ecdhKey, err := key.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting private key to ECDH: %w", err)
	}
	plaintext, err := jwe.Decrypt(compact, ecdhKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(plaintext)), nil
}

func DecryptRequestObjectJWE(jwe string, key *ecdsa.PrivateKey) (string, error) {
	return DecryptCompactJWE(jwe, key)
}
