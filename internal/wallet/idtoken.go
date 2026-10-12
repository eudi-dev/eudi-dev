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
	"fmt"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// signedJWTLifetime is the lifetime of short-lived JWTs signed by the wallet:
// ID tokens, client attestations and their proofs of possession.
const signedJWTLifetime = 5 * time.Minute

// crlUpdateInterval is the time to the nextUpdate of a CRL signed by the wallet.
const crlUpdateInterval = 7 * 24 * time.Hour

func (w *Wallet) createSelfIssuedIDToken(nonce, clientID string) (string, error) {
	holderKey := w.HolderKeyPair()
	subJWK := mock.PublicKeyJWKMap(&holderKey.PublicKey)
	thumbprint, err := jwkThumbprint(&holderKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("computing JWK thumbprint: %w", err)
	}

	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": "JWT",
		"jwk": subJWK,
	}

	now := time.Now()
	payload := map[string]any{
		// SIOPv2 §11: iss "MUST be set to the value of the sub claim".
		"iss":     thumbprint,
		"sub":     thumbprint,
		"aud":     clientID,
		"nonce":   nonce,
		"iat":     now.Unix(),
		"exp":     now.Add(signedJWTLifetime).Unix(),
		"sub_jwk": subJWK,
	}

	return signJWT(header, payload, holderKey)
}

// jwkThumbprint computes the RFC 7638 thumbprint of a public key.
func jwkThumbprint(key *ecdsa.PublicKey) (string, error) {
	sum, err := keys.PublicKeyThumbprint(key)
	if err != nil {
		return "", err
	}
	return format.EncodeBase64URL(sum), nil
}

// presentationAudience returns the aud value for a presentation or a
// self-issued ID token. For the Digital Credentials API, OID4VP 1.0 §5.9.3 says
// "the audience of the Credential Presentation is always the origin value
// prefixed by origin:". Otherwise it is the Client Identifier with its prefix.
func presentationAudience(params *oid4vp.Request) string {
	if params == nil {
		return ""
	}
	if oid4vp.IsDCAPIResponseMode(params.ResponseMode) && params.RequestOrigin != "" {
		return "origin:" + params.RequestOrigin
	}
	return params.ClientID
}
