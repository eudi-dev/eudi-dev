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

package certchain_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func testChain(t *testing.T) (leaf, ca *x509.Certificate) {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err = mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = mock.GenerateLeafCertWithOptions(caKey, ca, &leafKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return leaf, ca
}

func TestVerifyChainsTheLeafToAnAnchor(t *testing.T) {
	leaf, ca := testChain(t)
	got, err := certchain.Verify([]*x509.Certificate{leaf}, []*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != leaf {
		t.Error("Verify returned another certificate than the leaf")
	}
	otherLeaf, _ := testChain(t)
	if _, err := certchain.Verify([]*x509.Certificate{otherLeaf}, []*x509.Certificate{ca}); err == nil {
		t.Error("a leaf of another CA verified")
	}
	if _, err := certchain.Verify([]*x509.Certificate{leaf}, nil); err == nil {
		t.Error("a chain verified without anchors")
	}
}

// RFC 7515 §4.1.6: x5c is an array of base64 DER certificates. JSON gives
// []any and Go code []string.
func TestFromX5C(t *testing.T) {
	leaf, ca := testChain(t)
	b64 := func(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

	for name, value := range map[string]any{
		"strings":  []string{b64(leaf), b64(ca)},
		"JSON":     []any{b64(leaf), b64(ca)},
		"unpadded": []any{base64.RawStdEncoding.EncodeToString(leaf.Raw), base64.RawStdEncoding.EncodeToString(ca.Raw)},
	} {
		certs, err := certchain.FromX5C(value)
		if err != nil || len(certs) != 2 || certs[0].Subject.String() != leaf.Subject.String() {
			t.Errorf("%s: certs = %d, err = %v, want the leaf and the CA", name, len(certs), err)
		}
	}
	for name, value := range map[string]any{
		"a number entry":    []any{b64(leaf), 42},
		"a scalar":          "just a string",
		"not base64":        []any{"!!!"},
		"not a certificate": []any{base64.StdEncoding.EncodeToString([]byte("nope"))},
	} {
		if _, err := certchain.FromX5C(value); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// RFC 9360 §2 asks for an integrity protected end-entity certificate, so a
// chain in the protected bucket counts first. ISO 18013-5 puts the MSO chain
// in the unprotected bucket.
func TestFromCOSE(t *testing.T) {
	leaf, ca := testChain(t)

	certs, err := certchain.FromCOSE(map[any]any{int64(33): leaf.Raw}, map[any]any{int64(33): ca.Raw})
	if err != nil || len(certs) != 1 || certs[0].Subject.String() != leaf.Subject.String() {
		t.Errorf("protected and unprotected chains: certs = %v, err = %v, want the protected leaf", certs, err)
	}

	for name, value := range map[string]any{
		"an array":       []any{leaf.Raw, ca.Raw},
		"a byte slice":   [][]byte{leaf.Raw, ca.Raw},
		"a single entry": leaf.Raw,
	} {
		certs, err := certchain.FromCOSE(nil, map[any]any{uint64(33): value})
		if err != nil || len(certs) == 0 || certs[0].Subject.String() != leaf.Subject.String() {
			t.Errorf("%s: certs = %v, err = %v, want the leaf first", name, certs, err)
		}
	}

	for name, value := range map[string]any{
		"a text string":    "a string",
		"a text entry":     []any{leaf.Raw, "a string"},
		"not certificates": []byte("nope"),
	} {
		if _, err := certchain.FromCOSE(map[any]any{int64(33): value}, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
