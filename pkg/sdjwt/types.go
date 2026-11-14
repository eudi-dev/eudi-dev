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

// Package sdjwt parses and verifies SD-JWT (RFC 9901) and SD-JWT VC
// (draft-ietf-oauth-sd-jwt-vc-19).
//
// Parse rejects what RFC 9901 §7.1 rejects. Verify checks the signature of the
// Issuer-signed JWT. ValidAt checks its validity period. VerifyKeyBinding checks
// the Key Binding JWT of a presentation. The caller chooses the trusted key.
// ParseLenient reads a credential that breaks the specification and records
// each violation.
//
// The delegate package reads, verifies and creates Delegate SD-JWTs.
package sdjwt

// Token is a parsed SD-JWT or SD-JWT+KB.
type Token struct {
	// Raw is the compact serialization as it arrived, without surrounding
	// whitespace.
	Raw string
	// Header is the JOSE header of the Issuer-signed JWT.
	Header map[string]any
	// Payload is the payload of the Issuer-signed JWT as signed, with its _sd
	// digests.
	Payload map[string]any
	// Signature is the decoded signature of the Issuer-signed JWT.
	Signature []byte
	// Disclosures are the Disclosures in the order of the serialization.
	Disclosures []Disclosure
	// KeyBindingJWT is the Key Binding JWT of an SD-JWT+KB. It is nil for an
	// SD-JWT.
	KeyBindingJWT *JWT
	// ResolvedClaims is the Processed SD-JWT Payload of RFC 9901 §7.1. Every
	// disclosed claim is inserted and every undisclosed array element is removed.
	// The _sd and _sd_alg keys are gone.
	ResolvedClaims map[string]any
	// Warnings are notes that don't stop processing, such as a missing final
	// tilde.
	Warnings []string
	// Deviations lists recoverable violations that ParseLenient accepted. Parse
	// rejects them.
	Deviations []string
}

// JWT is a decoded JWT in compact serialization.
type JWT struct {
	// Raw is the compact serialization.
	Raw string
	// Header is the JOSE header.
	Header map[string]any
	// Payload is the claims set.
	Payload map[string]any
	// Signature is the decoded signature.
	Signature []byte
}

// Disclosure is one Disclosure of an SD-JWT (RFC 9901 §4.2).
type Disclosure struct {
	// Raw is the base64url encoding as it arrived.
	Raw string
	// Decoded is the JSON array behind Raw.
	Decoded string
	// Salt is the first element of the array.
	Salt string
	// Name is the claim name. It is empty for an array element.
	Name string
	// Value is the claim value or the array element.
	Value any
	// Digest is the base64url digest of Raw under the _sd_alg of the payload.
	Digest string
	// IsArrayEntry marks the Disclosure of an array element (RFC 9901 §4.2.2).
	IsArrayEntry bool
}
