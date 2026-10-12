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
