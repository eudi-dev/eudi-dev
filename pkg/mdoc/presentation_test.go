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

package mdoc

import (
	"crypto/sha256"
	"testing"
)

func docWithDigest(raw []byte, signed []byte) *Document {
	return &Document{
		NameSpaces: map[string][]IssuerSignedItem{
			"ns": {{ElementIdentifier: "given_name", DigestID: 1, RawCBOR: raw}},
		},
		IssuerAuth: &IssuerAuth{
			MSO: &MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests:    map[string]map[uint64][]byte{"ns": {1: signed}},
			},
		},
	}
}

// Every digest mismatch must fail, including a different length.
func TestVerifyValueDigests(t *testing.T) {
	raw := []byte("the encoded item")
	correct := sha256.Sum256(raw)

	differs := sha256.Sum256(raw)
	differs[0] ^= 0xff

	cases := []struct {
		name   string
		signed []byte
		wantOK bool
	}{
		{name: "the digest the issuer signed", signed: correct[:], wantOK: true},
		{name: "a different digest", signed: differs[:], wantOK: false},
		// A prefix of the right digest matches on all of its bytes.
		{name: "a truncated digest", signed: correct[:16], wantOK: false},
		{name: "an empty digest", signed: []byte{}, wantOK: false},
		{name: "a digest with trailing bytes", signed: append(correct[:], 0x00), wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyValueDigests(docWithDigest(raw, tc.signed))
			if tc.wantOK && err != nil {
				t.Errorf("VerifyValueDigests = %v, want nil", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("VerifyValueDigests accepted an element the issuer did not sign")
			}
		})
	}
}

// With several bad elements, the error names the first bad element of the
// first namespace by name. Within a namespace the document order counts.
func TestVerifyValueDigestsNamesTheSameElementOnEveryRun(t *testing.T) {
	bad := func(name string, id uint64) IssuerSignedItem {
		return IssuerSignedItem{ElementIdentifier: name, DigestID: id, RawCBOR: []byte(name)}
	}
	wrong := []byte("wrong")
	doc := &Document{
		NameSpaces: map[string][]IssuerSignedItem{
			"org.iso.18013.5.1":       {bad("family_name", 7)},
			"eu.europa.ec.eudi.pid.1": {bad("given_name", 9), bad("age_over_18", 2)},
		},
		IssuerAuth: &IssuerAuth{MSO: &MSO{
			DigestAlgorithm: "SHA-256",
			ValueDigests: map[string]map[uint64][]byte{
				"org.iso.18013.5.1":       {7: wrong},
				"eu.europa.ec.eudi.pid.1": {9: wrong, 2: wrong},
			},
		}},
	}
	want := `element "given_name" does not match its digest in the MSO`
	for range 50 {
		if err := VerifyValueDigests(doc); err == nil || err.Error() != want {
			t.Fatalf("VerifyValueDigests = %v, want %s", err, want)
		}
	}
}
