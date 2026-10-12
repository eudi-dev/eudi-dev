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

// Package statuslist checks credential revocation status using Token Status
// Lists (draft-ietf-oauth-status-list), in both the JWT and the CWT
// representation of a Status List Token.
package statuslist

import (
	"crypto"
	"fmt"
	"net/http"
	"time"
)

// Media types for the two Status List Token representations. Section 8.1:
// "application/statuslist+jwt" for Status List Token in JWT format,
// "application/statuslist+cwt" for Status List Token in CWT format.
const (
	MediaTypeJWT = "application/statuslist+jwt"
	MediaTypeCWT = "application/statuslist+cwt"
)

// TypJWT is the required typ of the JWT header. Section 5.1: "typ: REQUIRED.
// The JWT type MUST be statuslist+jwt."
const TypJWT = "statuslist+jwt"

const (
	FormatJWT = "jwt"
	FormatCWT = "cwt"
)

// CWT claim keys from Section 5.2. The CWT format keys its claims by integer.
const (
	cwtClaimIssuer     = 1
	cwtClaimSubject    = 2
	cwtClaimExpiration = 4
	cwtClaimNotBefore  = 5
	cwtClaimIssuedAt   = 6
	cwtClaimStatusList = 65533
	cwtClaimTTL        = 65534
)

// COSE header labels used by a Status List Token in CWT format: 1 (alg) and
// 16 (type) from RFC 9052 and RFC 9596, 33 (x5chain) from RFC 9360.
const (
	coseHeaderAlg     = 1
	coseHeaderType    = 16
	coseHeaderX5Chain = 33
)

// StatusRef is a reference to a status list entry in a credential. Section 6.2
// makes idx and uri REQUIRED. Invalid is set when either is missing.
type StatusRef struct {
	URI     string `json:"uri"`
	Idx     int    `json:"idx"`
	Invalid string `json:"invalid,omitempty"`
}

type StatusResult struct {
	URI          string `json:"uri"`
	Index        int    `json:"index"`
	Status       int    `json:"status"`
	StatusName   string `json:"statusName"`
	IsValid      bool   `json:"isValid"`
	BitsPerEntry int    `json:"bitsPerEntry"`
	// Format is the representation served by the Status Provider, "jwt" or "cwt".
	Format string `json:"format"`
	// Subject is the sub (or CWT claim 2) of the Status List Token.
	Subject string `json:"subject,omitempty"`
	// SignatureValid is always set on a returned result. A Status List Token
	// whose signature does not verify is reported as an error.
	SignatureValid *bool `json:"signatureValid,omitempty"`
	SignatureInfo  string
	// TrustAnchored reports whether the signing key chains to a caller-supplied
	// trust anchor.
	TrustAnchored bool `json:"trustAnchored"`
	// Warnings collect conformance problems that did not stop the check.
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type CheckOptions struct {
	HTTPClient *http.Client
	// Prefer is FormatJWT or FormatCWT, the format of the credential. The
	// request asks for that representation first and accepts the other one
	// (Section 8.1 uses RFC 9110 content negotiation). An SD-JWT VC prefers
	// JWT, an mdoc CWT.
	Prefer string
	// TrustListCerts are the CA certificates for the token's chain. When empty
	// the key comes from the token and the result is not trust anchored. The
	// signature is still verified: "Relying Parties MUST reject JWTs with an
	// invalid signature" (§5.1).
	TrustListCerts []TrustCert
	// CandidateAnchors anchor the token when its chain verifies to one of
	// them, such as the CA of a local wallet. Otherwise the key comes from the
	// token, as without TrustListCerts.
	CandidateAnchors []TrustCert

	// Keys are public keys resolved out of band. Section 11.3 leaves key
	// resolution to the ecosystem, so a caller can supply the Status Issuer's key
	// for a token without key material.
	Keys []crypto.PublicKey

	// Now overrides the current time used for the exp check. The zero value
	// means time.Now().
	Now time.Time
}

func (o CheckOptions) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

type TrustCert struct {
	Raw []byte
}

// StatusName returns the name of a Status Type value from Section 7.1.
func StatusName(value int) string {
	switch {
	case value == 0:
		return "VALID"
	case value == 1:
		return "INVALID"
	case value == 2:
		return "SUSPENDED"
	case value == 3, value >= 0x0C && value <= 0x0F:
		// Section 7.1: "The Status Type value 0x03 and Status Type values in
		// the range 0x0C until 0x0F are permanently reserved as application
		// specific."
		return fmt.Sprintf("APPLICATION_SPECIFIC(0x%02X)", value)
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", value)
	}
}

// BitsForStatus returns the smallest allowed bits value that can represent
// every status value up to max. Section 4.1: "The Status Issuer MUST define a
// number of bits (bits) of either 1,2,4 or 8".
func BitsForStatus(max int) (int, error) {
	switch {
	case max < 0:
		return 0, fmt.Errorf("status value %d is negative", max)
	case max <= 1:
		return 1, nil
	case max <= 3:
		return 2, nil
	case max <= 15:
		return 4, nil
	case max <= 255:
		return 8, nil
	default:
		// Section 7: "Status Types MUST have a numeric value between 0 and 255".
		return 0, fmt.Errorf("status value %d is above 255", max)
	}
}
