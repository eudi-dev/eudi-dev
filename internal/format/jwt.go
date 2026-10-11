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

package format

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseJWTParts decodes a JWS Compact Serialization without verifying it. An
// undecodable signature gives nil, which no key verifies.
func ParseJWTParts(raw string) (header, payload map[string]any, sig []byte, err error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("expected 3 parts separated by '.', got %d", len(parts))
	}

	headerBytes, err := DecodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding header: %w", err)
	}

	payloadBytes, err := DecodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding payload: %w", err)
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshaling payload: %w", err)
	}

	sig, _ = DecodeBase64URL(parts[2])

	return header, payload, sig, nil
}

// JWT typ values that both a producer and a checker in this tool use.
const (
	// TypeKeyProof is the jwt key proof of OpenID4VCI 1.0.
	TypeKeyProof = "openid4vci-proof+jwt"
	// TypeClientAttestation and TypeClientAttestationPoP are the client
	// attestation and its proof of possession of
	// draft-ietf-oauth-attestation-based-client-auth.
	TypeClientAttestation    = "oauth-client-attestation+jwt"
	TypeClientAttestationPoP = "oauth-client-attestation-pop+jwt"
	// TypeRequestObject is the request object of RFC 9101. A request_uri
	// response carries it as MediaTypeRequestObject.
	TypeRequestObject      = "oauth-authz-req+jwt"
	MediaTypeRequestObject = "application/" + TypeRequestObject
)

// JOSETypeIs reports whether a typ header parameter names the media type
// want. RFC 7515 §4.1.9: "all media type values, subtype values, and parameter
// names are case insensitive" and "A recipient using the media type value MUST
// treat it as if "application/" were prepended to any "typ" value not
// containing a '/'."
func JOSETypeIs(typ, want string) bool {
	return joseMediaType(typ) == joseMediaType(want)
}

func joseMediaType(typ string) string {
	typ = strings.ToLower(typ)
	if !strings.Contains(typ, "/") {
		typ = "application/" + typ
	}
	return typ
}
