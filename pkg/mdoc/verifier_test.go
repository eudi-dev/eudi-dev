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
	"crypto/rand"
	"errors"
	"testing"

	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/coseutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// HAIP 1.0 §7 allows -9 for the mandatory ECDSA P-256 suite.
func TestVerifyAcceptsESP256(t *testing.T) {
	key := testKey(t)
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: coseutil.ESP256}},
		Payload: []byte("mso"),
	}
	if err := msg.Sign(rand.Reader, nil, esp256Signer{signer}); err != nil {
		t.Fatal(err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	doc := &Document{IssuerAuth: &IssuerAuth{RawCOSE: raw}}
	if err := Verify(doc, &key.PublicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if alg, err := doc.SignatureAlgorithm(); err != nil || alg != "ESP256" {
		t.Fatalf("SignatureAlgorithm = %q, %v, want ESP256", alg, err)
	}
}

// esp256Signer produces an ES256 signature under the ESP256 label. go-cose
// does not know that label.
type esp256Signer struct{ cose.Signer }

func (esp256Signer) Algorithm() cose.Algorithm { return coseutil.ESP256 }

func TestVerify(t *testing.T) {
	raw, issuer, holder := boundMDOC(t, mock.MDOCConfig{})
	other, _ := mock.GenerateKey()
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if err := Verify(doc, &issuer.PublicKey); err != nil {
		t.Errorf("Verify with the issuer key: %v", err)
	}
	if err := Verify(doc, &other.PublicKey); !errors.Is(err, ErrSignature) {
		t.Errorf("Verify with another key = %v, want ErrSignature", err)
	}
	if err := Verify(&Document{}, &issuer.PublicKey); err == nil || errors.Is(err, ErrSignature) {
		t.Errorf("Verify without issuerAuth = %v, want an error about the document", err)
	}
	if err := Verify(nil, &issuer.PublicKey); err == nil {
		t.Error("Verify accepted a nil document")
	}
	if key, err := DeviceKey(doc); err != nil || !key.Equal(&holder.PublicKey) {
		t.Errorf("DeviceKey = %v, %v, want the holder key", key, err)
	}
}
