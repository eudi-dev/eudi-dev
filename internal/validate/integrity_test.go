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

package validate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func TestCheckMDOCIntegrity_AllMatch(t *testing.T) {
	rawCBOR1 := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	rawCBOR2 := []byte{0xb5, 0x06, 0x07, 0x08, 0x09}

	hash1 := sha256.Sum256(rawCBOR1)
	hash2 := sha256.Sum256(rawCBOR2)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR1},
				{DigestID: 1, ElementIdentifier: "given_name", RawCBOR: rawCBOR2},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hash1[:],
						1: hash2[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_DigestMismatch(t *testing.T) {
	rawCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: []byte("wrong-digest-value-that-wont-match"),
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

// The issuer signature covers only the MSO, so an element in a namespace the
// MSO does not list has no issuer behind it.
func TestCheckMDOCIntegrity_ElementOutsideTheMSO(t *testing.T) {
	rawCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	hash := sha256.Sum256(rawCBOR)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR}},
			"org.example.added": {{DigestID: 0, ElementIdentifier: "vip", RawCBOR: rawCBOR}},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests:    map[string]map[uint64][]byte{"org.iso.18013.5.1": {0: hash[:]}},
			},
		},
	}

	if result := CheckMDOCIntegrity(doc); result.Status != Fail {
		t.Errorf("expected fail for an element outside the MSO, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_NoMSO(t *testing.T) {
	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"ns": {{DigestID: 0, ElementIdentifier: "x"}},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
}

func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestCheckMDOCIntegrity_Tag24EncodedRawCBOR(t *testing.T) {
	// MSO ValueDigests hash the full Tag-24 encoding (#6.24(bstr)).
	innerCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}

	// Tag 24 with 5-byte content: 0xd8 0x18 0x45 <5 bytes>
	tag24Bytes := append([]byte{0xd8, 0x18, 0x45}, innerCBOR...)

	hash := sha256.Sum256(tag24Bytes)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: tag24Bytes},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hash[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "pass" {
		t.Errorf("expected pass for Tag-24 encoded RawCBOR, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_Tag24FailsWithInnerBytesDigest(t *testing.T) {
	// A digest over only the inner bytes must fail.
	innerCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	tag24Bytes := append([]byte{0xd8, 0x18, 0x45}, innerCBOR...)

	hashInner := sha256.Sum256(innerCBOR)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: tag24Bytes},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hashInner[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "fail" {
		t.Errorf("expected fail when digest is over inner bytes but RawCBOR is Tag-24, got %s: %s", result.Status, result.Detail)
	}
}

// disclosed returns a disclosure and its sha-256 digest.
func disclosed(t *testing.T, elements ...any) (string, string) {
	t.Helper()
	encoded, err := json.Marshal(elements)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(encoded)
	return raw, sha256Sum(raw)
}

// inspected parses an unsigned SD-JWT the way validate reads one.
func inspected(t *testing.T, payload map[string]any, disclosures ...string) *sdjwt.Token {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body) + ".c2ln~"
	for _, d := range disclosures {
		raw += d + "~"
	}
	token, err := sdjwt.Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestCheckSDJWTIntegrity(t *testing.T) {
	name, nameDigest := disclosed(t, "salt1", "name", "Alice")
	age, ageDigest := disclosed(t, "salt2", "age", 30)
	locality, localityDigest := disclosed(t, "salt3", "locality", "KOELN")
	address, addressDigest := disclosed(t, "salt4", "address", map[string]any{"_sd": []any{localityDigest}})
	de, deDigest := disclosed(t, "salt5", "DE")
	nationalities, nationalitiesDigest := disclosed(t, "salt6", "nationalities", []any{map[string]any{"...": deDigest}})
	exp, expDigest := disclosed(t, "salt7", "exp", 1893456000)
	status, statusDigest := disclosed(t, "salt8", "status", map[string]any{"status_list": map[string]any{"idx": 0, "uri": "https://example.com/sl"}})
	jwk, jwkDigest := disclosed(t, "salt9", "jwk", map[string]any{"kty": "EC"})

	tests := []struct {
		name        string
		payload     map[string]any
		disclosures []string
		want        string
	}{
		{"all referenced", map[string]any{"_sd": []any{nameDigest, ageDigest}}, []string{name, age}, Pass},
		{"no disclosures", map[string]any{"sub": "user"}, nil, Skipped},
		{"nested _sd", map[string]any{"address": map[string]any{"_sd": []any{nameDigest}}}, []string{name}, Pass},
		{"digest inside a disclosure", map[string]any{"_sd": []any{addressDigest}}, []string{address, locality}, Pass},
		{"array element inside a disclosure", map[string]any{"_sd": []any{nationalitiesDigest}}, []string{nationalities, de}, Pass},
		{"array element", map[string]any{"items": []any{map[string]any{"...": deDigest}}}, []string{de}, Pass},
		// RFC 9901 §7.1 step 5.
		{"unreferenced disclosure", map[string]any{"_sd": []any{"wrong-digest"}}, []string{name}, Fail},
		// RFC 9901 §4.2.4.2 permits only the ... key in a digest placeholder.
		{"placeholder with an extra key", map[string]any{"items": []any{map[string]any{"...": deDigest, "hint": "DE"}}}, []string{de}, Fail},
		// RFC 9901 §4: a Holder MUST NOT send a Disclosure more than once.
		{"disclosure sent twice", map[string]any{"_sd": []any{nameDigest}}, []string{name, name}, Fail},
		// RFC 9901 §7.1 step 4.
		{"digest repeated", map[string]any{"_sd": []any{nameDigest}, "address": map[string]any{"_sd": []any{nameDigest}}}, []string{name}, Fail},
		// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3.
		{"disclosed exp", map[string]any{"_sd": []any{expDigest}}, []string{exp}, Fail},
		{"disclosed status", map[string]any{"_sd": []any{statusDigest}}, []string{status}, Fail},
		{"disclosable cnf sub-claim", map[string]any{"cnf": map[string]any{"_sd": []any{jwkDigest}}}, []string{jwk}, Fail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSDJWTIntegrity(inspected(t, tt.payload, tt.disclosures...))
			if got.Status != tt.want {
				t.Errorf("Status = %q (%s), want %q", got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestCheckMDOCIntegrity_FailsOnParseDeviations(t *testing.T) {
	doc := &mdoc.Document{Deviations: []string{`the document names docType "org.iso.18013.5.1.mDL", but the issuer signed "eu.europa.ec.eudi.pid.1" in the MSO`}}
	if got := CheckMDOCIntegrity(doc); got.Status != Fail {
		t.Errorf("Status = %q (%s), want fail", got.Status, got.Detail)
	}
}
