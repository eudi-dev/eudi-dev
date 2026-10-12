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
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

func (w *Wallet) CreateSelfIssuedIDToken(nonce, clientID string) (string, error) {
	subJWK := mock.PublicKeyJWKMap(&w.HolderKey.PublicKey)
	thumbprint, err := jwkThumbprint(&w.HolderKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("computing JWK thumbprint: %w", err)
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"jwk": subJWK,
	}

	now := time.Now()
	payload := map[string]any{
		"iss":     "https://self-issued.me/v2",
		"sub":     thumbprint,
		"aud":     clientID,
		"nonce":   nonce,
		"iat":     now.Unix(),
		"exp":     now.Add(5 * time.Minute).Unix(),
		"sub_jwk": subJWK,
	}

	return signJWT(header, payload, w.HolderKey)
}

// jwkThumbprint computes the RFC 7638 thumbprint of a P-256 public key.
func jwkThumbprint(key *ecdsa.PublicKey) (string, error) {
	jwk := mock.PublicKeyJWKMap(key)

	// RFC 7638 §3.2: only the required members, in lexicographic order.
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])

	h := sha256.Sum256([]byte(canonical))
	return format.EncodeBase64URL(h[:]), nil
}

func ResponseTypeContains(responseType, target string) bool {
	for _, rt := range strings.Fields(responseType) {
		if rt == target {
			return true
		}
	}
	return false
}

// ResponseTypeRequiresVP reports whether a request requires a vp_token response.
// An empty response_type defaults to vp_token.
func ResponseTypeRequiresVP(responseType string) bool {
	return responseType == "" || ResponseTypeContains(responseType, "vp_token")
}

// presentationAudience returns the aud value for a presentation or a
// self-issued ID token. For the Digital Credentials API, OID4VP 1.0 §5.9.3 says
// "the audience of the Credential Presentation is always the origin value
// prefixed by origin:". Otherwise it is the Client Identifier with its prefix.
func presentationAudience(params *AuthorizationRequestParams) string {
	if params == nil {
		return ""
	}
	if isDCAPIResponseMode(params.ResponseMode) && params.RequestOrigin != "" {
		return "origin:" + params.RequestOrigin
	}
	return params.ClientID
}
