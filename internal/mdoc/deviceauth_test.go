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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

const testDocType = "eu.europa.ec.eudi.pid.1"

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func deviceKeyCBOR(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	x, y, err := format.ECPublicCoords(pub)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.NewKeyEC2(cose.AlgorithmES256, x, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func emptyDeviceNameSpaces(t *testing.T) []byte {
	t.Helper()
	encoded, err := tag24(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signDeviceAuth(t *testing.T, key *ecdsa.PrivateKey, sessionTranscript []byte, docType string) []byte {
	t.Helper()
	var transcript any
	if err := cbor.Unmarshal(sessionTranscript, &transcript); err != nil {
		t.Fatal(err)
	}
	reencoded, err := cbor.Marshal(transcript)
	if err != nil {
		t.Fatal(err)
	}
	return signDeviceAuthWith(t, key, cose.AlgorithmES256, reencoded, docType, emptyDeviceNameSpaces(t))
}

// signDeviceAuthWith embeds the session transcript and namespaces bytes
// unchanged, as the wallet does.
func signDeviceAuthWith(t *testing.T, key *ecdsa.PrivateKey, alg cose.Algorithm, sessionTranscript []byte, docType string, nameSpaces []byte) []byte {
	t.Helper()
	authentication, err := cbor.Marshal([]any{
		"DeviceAuthentication", cbor.RawMessage(sessionTranscript), docType, cbor.RawMessage(nameSpaces),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := tag24Raw(authentication)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(alg, key)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.UntaggedSign1Message{
		Headers: cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: alg}},
		Payload: payload,
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	// The response carries a detached payload. The verifier rebuilds it.
	msg.Payload = nil
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func transcriptFor(t *testing.T, nonce string) []byte {
	t.Helper()
	encoded, err := cbor.Marshal([]any{nil, nil, []any{"OID4VPHandover", nonce}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The verifier must use the signed transcript bytes unchanged. Re-encoding
// indefinite-length CBOR changes its bytes.
func TestVerifyDeviceAuthEmbedsTheTranscriptVerbatim(t *testing.T) {
	key := testKey(t)
	transcript := []byte{0x9f, 0x00, 0xff} // indefinite-length array holding [0]
	doc := &Document{
		DocType: testDocType,
		IssuerAuth: &IssuerAuth{MSO: &MSO{
			DeviceKeyInfo: map[string]any{"deviceKey": map[string]any{}},
			DeviceKeyCBOR: deviceKeyCBOR(t, &key.PublicKey),
		}},
		DeviceSigned: &DeviceSigned{
			DeviceAuth:         map[string]any{"deviceSignature": []any{}},
			RawDeviceSignature: signDeviceAuthWith(t, key, cose.AlgorithmES256, transcript, testDocType, emptyDeviceNameSpaces(t)),
			RawNameSpaces:      emptyDeviceNameSpaces(t),
		},
	}
	if err := VerifyDeviceAuth(doc, transcript); err != nil {
		t.Errorf("a verbatim-signed transcript that does not canonically round-trip failed to verify: %v", err)
	}
}

func signedDoc(t *testing.T, key *ecdsa.PrivateKey, transcript []byte) *Document {
	t.Helper()
	return &Document{
		DocType: testDocType,
		IssuerAuth: &IssuerAuth{MSO: &MSO{
			DeviceKeyInfo: map[string]any{"deviceKey": map[string]any{}},
			DeviceKeyCBOR: deviceKeyCBOR(t, &key.PublicKey),
		}},
		DeviceSigned: &DeviceSigned{
			DeviceAuth:         map[string]any{"deviceSignature": []any{}},
			RawDeviceSignature: signDeviceAuth(t, key, transcript, testDocType),
			RawNameSpaces:      emptyDeviceNameSpaces(t),
		},
	}
}

func TestVerifyDeviceAuth(t *testing.T) {
	key := testKey(t)
	transcript := transcriptFor(t, "nonce-from-this-request")

	if err := VerifyDeviceAuth(signedDoc(t, key, transcript), transcript); err != nil {
		t.Fatalf("a presentation signed for this request did not verify: %v", err)
	}
}

// A response captured from one request must not verify against another.
func TestVerifyDeviceAuthRejectsAReplayedResponse(t *testing.T) {
	key := testKey(t)
	doc := signedDoc(t, key, transcriptFor(t, "the original request"))

	err := VerifyDeviceAuth(doc, transcriptFor(t, "a different request"))
	if err == nil {
		t.Fatal("a response replayed into another request verified")
	}
	if !strings.Contains(err.Error(), "does not verify against this request") {
		t.Errorf("error = %q, want it to name the request mismatch", err)
	}
}

// The signature must verify with the device key in the MSO.
func TestVerifyDeviceAuthRejectsAnotherHoldersKey(t *testing.T) {
	transcript := transcriptFor(t, "nonce")
	doc := signedDoc(t, testKey(t), transcript)
	// The MSO now holds another holder's device key.
	doc.IssuerAuth.MSO.DeviceKeyCBOR = deviceKeyCBOR(t, &testKey(t).PublicKey)

	if err := VerifyDeviceAuth(doc, transcript); err == nil {
		t.Error("a signature made with a key the issuer never bound was accepted")
	}
}

func TestVerifyDeviceAuthRejectsADifferentDocType(t *testing.T) {
	key := testKey(t)
	transcript := transcriptFor(t, "nonce")
	doc := signedDoc(t, key, transcript)
	doc.DocType = "org.iso.18013.5.1.mDL"

	if err := VerifyDeviceAuth(doc, transcript); err == nil {
		t.Error("a signature over another doctype was accepted")
	}
}

func TestVerifyDeviceAuthErrors(t *testing.T) {
	key := testKey(t)
	transcript := transcriptFor(t, "nonce")

	tests := []struct {
		name string
		doc  func() *Document
		want string
	}{
		{"no document", func() *Document { return nil }, "no device signature"},
		{"no deviceSigned", func() *Document { return &Document{} }, "no device signature"},
		{
			"a deviceMac instead of a signature",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.DeviceSigned.RawDeviceSignature = nil
				return d
			},
			"deviceMac is not supported",
		},
		{
			"no MSO to name a device key",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.IssuerAuth = nil
				return d
			},
			"no MSO",
		},
		{
			"an MSO that binds no key",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.IssuerAuth.MSO.DeviceKeyInfo = nil
				return d
			},
			"not holder-bound",
		},
		{
			"a device signature that is not COSE",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.DeviceSigned.RawDeviceSignature = []byte("not cbor at all")
				return d
			},
			"parsing the device signature",
		},
		{
			"a session transcript that is not CBOR",
			func() *Document { return signedDoc(t, key, transcript) },
			"the session transcript is not valid CBOR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := transcript
			if tt.want == "the session transcript is not valid CBOR" {
				st = []byte{0xff, 0xff, 0xff}
			}
			err := VerifyDeviceAuth(tt.doc(), st)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestDeviceKey(t *testing.T) {
	key := testKey(t)
	doc := signedDoc(t, key, transcriptFor(t, "nonce"))

	got, err := DeviceKey(doc)
	if err != nil {
		t.Fatalf("DeviceKey: %v", err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Error("DeviceKey returned a key other than the one the MSO binds")
	}
}

func TestDeviceKeyErrors(t *testing.T) {
	key := testKey(t)
	transcript := transcriptFor(t, "nonce")

	tests := []struct {
		name string
		doc  func() *Document
		want string
	}{
		{"nil document", func() *Document { return nil }, "no MSO"},
		{
			"deviceKeyInfo without a deviceKey",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.IssuerAuth.MSO.DeviceKeyInfo = map[string]any{"other": 1}
				return d
			},
			"carries no deviceKey",
		},
		{
			"no encoded COSE_Key kept",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.IssuerAuth.MSO.DeviceKeyCBOR = nil
				return d
			},
			"not a COSE_Key map",
		},
		{
			"a COSE_Key that does not decode",
			func() *Document {
				d := signedDoc(t, key, transcript)
				d.IssuerAuth.MSO.DeviceKeyCBOR = []byte{0xff, 0xff}
				return d
			},
			"not a valid COSE_Key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeviceKey(tt.doc())
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The device signature covers the DeviceNameSpacesBytes as received, and its
// protected header names the algorithm.
func TestVerifyDeviceAuthUsesTheReceivedNameSpacesAndAlgorithm(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coseKey, err := cose.NewKeyFromPublic(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyCBOR, err := coseKey.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	nameSpaces, err := tag24(map[string]any{testDocType: map[string]any{"device_claim": "signed by the holder"}})
	if err != nil {
		t.Fatal(err)
	}
	transcript := transcriptFor(t, "nonce")
	doc := &Document{
		DocType: testDocType,
		IssuerAuth: &IssuerAuth{MSO: &MSO{
			DeviceKeyInfo: map[string]any{"deviceKey": map[string]any{}},
			DeviceKeyCBOR: keyCBOR,
		}},
		DeviceSigned: &DeviceSigned{
			DeviceAuth:         map[string]any{"deviceSignature": []any{}},
			RawDeviceSignature: signDeviceAuthWith(t, p384, cose.AlgorithmES384, transcript, testDocType, nameSpaces),
			RawNameSpaces:      nameSpaces,
		},
	}
	if err := VerifyDeviceAuth(doc, transcript); err != nil {
		t.Fatalf("an ES384 signature over non-empty device namespaces did not verify: %v", err)
	}

	doc.DeviceSigned.RawNameSpaces = emptyDeviceNameSpaces(t)
	if err := VerifyDeviceAuth(doc, transcript); err == nil {
		t.Error("a signature over other device namespaces verified")
	}
}
