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
	"crypto/sha512"
	"testing"
)

func TestDeviceKeyThumbprint(t *testing.T) {
	key := testKey(t)

	first := DeviceKeyThumbprint(&key.PublicKey)
	if first == "" {
		t.Fatal("thumbprint is empty")
	}
	if second := DeviceKeyThumbprint(&key.PublicKey); first != second {
		t.Error("the same key produced two different thumbprints")
	}
	if other := DeviceKeyThumbprint(&testKey(t).PublicKey); other == first {
		t.Error("two different keys share a thumbprint")
	}
	if got := DeviceKeyThumbprint(nil); got != "" {
		t.Errorf("DeviceKeyThumbprint(nil) = %q, want empty", got)
	}
}

func TestItemDigest(t *testing.T) {
	raw := []byte("the encoded item")
	signed := sha256.Sum256(raw)
	doc := docWithDigest(raw, signed[:])

	got, want, err := ItemDigest(doc, "ns", doc.NameSpaces["ns"][0])
	if err != nil {
		t.Fatalf("ItemDigest: %v", err)
	}
	if string(got) != string(want) {
		t.Error("the recomputed digest does not match the digest in the MSO")
	}
	if string(got) != string(signed[:]) {
		t.Error("the recomputed digest is not the SHA-256 of the encoded item")
	}
}

func TestItemDigestErrors(t *testing.T) {
	raw := []byte("item")
	signed := sha256.Sum256(raw)

	t.Run("no MSO", func(t *testing.T) {
		if _, _, err := ItemDigest(&Document{}, "ns", IssuerSignedItem{}); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("an element that kept no encoded form", func(t *testing.T) {
		doc := docWithDigest(raw, signed[:])
		if _, _, err := ItemDigest(doc, "ns", IssuerSignedItem{DigestID: 1}); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("an unsupported digest algorithm", func(t *testing.T) {
		doc := docWithDigest(raw, signed[:])
		doc.IssuerAuth.MSO.DigestAlgorithm = "MD5"
		if _, _, err := ItemDigest(doc, "ns", doc.NameSpaces["ns"][0]); err == nil {
			t.Error("expected an error")
		}
	})

	// A namespace absent from the MSO has no signed digest. An empty expected digest
	// marks it as unverifiable.
	t.Run("a namespace missing from the MSO", func(t *testing.T) {
		doc := docWithDigest(raw, signed[:])
		_, want, err := ItemDigest(doc, "other", doc.NameSpaces["ns"][0])
		if err != nil {
			t.Fatalf("ItemDigest: %v", err)
		}
		if want != nil {
			t.Errorf("want = %x, expected nothing signed for that namespace", want)
		}
	})
}

func TestDigestHasher(t *testing.T) {
	payload := []byte("payload")
	sum256 := sha256.Sum256(payload)
	sum384 := sha512.Sum384(payload)
	sum512 := sha512.Sum512(payload)

	tests := []struct {
		alg  string
		want []byte
	}{
		// An MSO without an algorithm means SHA-256.
		{"", sum256[:]},
		{"SHA-256", sum256[:]},
		{"SHA-384", sum384[:]},
		{"SHA-512", sum512[:]},
	}
	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			hash, err := digestHasher(tt.alg)
			if err != nil {
				t.Fatalf("digestHasher(%q): %v", tt.alg, err)
			}
			if string(hash(payload)) != string(tt.want) {
				t.Errorf("digest for %q does not match", tt.alg)
			}
		})
	}

	if _, err := digestHasher("SHA-1"); err == nil {
		t.Error("an unsupported digest algorithm was accepted")
	}
}
