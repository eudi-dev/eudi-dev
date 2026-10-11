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

// Package format auto-detects credential formats and handles input reading, encoding, and URL fetching.
package format

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc/scheme"
)

type CredentialFormat string

const (
	FormatSDJWT     CredentialFormat = credtype.FormatSDJWT
	FormatJWT       CredentialFormat = "jwt"
	FormatMDOC      CredentialFormat = credtype.FormatMDOC
	FormatOID4VCI   CredentialFormat = "oid4vci"
	FormatOID4VP    CredentialFormat = "oid4vp"
	FormatTrustList CredentialFormat = "trusted-list"
	FormatUnknown   CredentialFormat = "unknown"
)

// Detect checks JSON first because dots in JSON strings can look like JWT separators.
func Detect(input string) CredentialFormat {
	input = strings.TrimSpace(input)
	if input == "" {
		return FormatUnknown
	}

	if scheme.IsIssuance(input) {
		return FormatOID4VCI
	}
	if scheme.IsPresentation(input) {
		return FormatOID4VP
	}

	lower := strings.ToLower(input)

	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		if f := detectHTTPOID4(input); f != FormatUnknown {
			return f
		}
		// The caller decides whether to fetch any other HTTP URL.
		return FormatUnknown
	}

	if strings.HasPrefix(input, "{") {
		return detectJSONOID4(input)
	}

	detected := DetectEncoding(input)
	if detected == FormatJWT {
		if f := detectJWTPayloadOID4(strings.Split(input, ".")[1]); f != FormatUnknown {
			return f
		}
	}
	return detected
}

// DetectEncoding identifies the token encoding without classifying its claims.
func DetectEncoding(input string) CredentialFormat {
	input = strings.TrimSpace(input)
	if input == "" || strings.HasPrefix(input, "{") || strings.Contains(input, "://") {
		return FormatUnknown
	}

	if strings.Contains(input, "~") {
		return FormatSDJWT
	}

	if isHex(input) {
		b, err := hex.DecodeString(input)
		if err == nil && len(b) > 0 && isCBORStart(b[0]) {
			return FormatMDOC
		}
	}
	b, err := DecodeBase64URL(input)
	if err == nil && len(b) > 0 && isCBORStart(b[0]) {
		return FormatMDOC
	}

	parts := strings.Split(input, ".")
	if len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 {
		return FormatJWT
	}

	return FormatUnknown
}

func detectHTTPOID4(raw string) CredentialFormat {
	u, err := url.Parse(raw)
	if err != nil {
		return FormatUnknown
	}
	q := u.Query()
	if q.Has("credential_offer") || q.Has("credential_offer_uri") {
		return FormatOID4VCI
	}
	if q.Has("client_id") || q.Has("response_type") || q.Has("request_uri") {
		return FormatOID4VP
	}
	return FormatUnknown
}

func detectJWTPayloadOID4(payloadB64 string) CredentialFormat {
	data, err := DecodeBase64URL(payloadB64)
	if err != nil {
		return FormatUnknown
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return FormatUnknown
	}
	if isTrustListPayload(m) {
		return FormatTrustList
	}
	if _, ok := m["credential_issuer"]; ok {
		return FormatOID4VCI
	}
	if _, ok := m["client_id"]; ok {
		return FormatOID4VP
	}
	if _, ok := m["response_type"]; ok {
		return FormatOID4VP
	}
	return FormatUnknown
}

func detectJSONOID4(raw string) CredentialFormat {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return FormatUnknown
	}
	if isTrustListPayload(m) {
		return FormatTrustList
	}
	if _, ok := m["credential_issuer"]; ok {
		return FormatOID4VCI
	}
	if _, ok := m["client_id"]; ok {
		return FormatOID4VP
	}
	return FormatUnknown
}

func isTrustListPayload(m map[string]any) bool {
	lote, ok := m["LoTE"].(map[string]any)
	if !ok {
		return false
	}
	_, hasEntities := lote["TrustedEntitiesList"]
	_, hasSchemeInfo := lote["ListAndSchemeInformation"]
	return hasEntities || hasSchemeInfo
}

func isHex(s string) bool {
	if len(s) < 2 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isCBORStart reports whether a byte can start a CBOR map, tag or array
// (RFC 8949 §3.1 major types 5, 6 and 4).
func isCBORStart(b byte) bool {
	major := b >> 5
	return major == 5 || // map
		major == 6 || // tag (e.g. tag 24)
		major == 4 // array
}
