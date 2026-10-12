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
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func buildIssuerSignedCBOR(t *testing.T, namespace string, items []map[string]any) []byte {
	t.Helper()

	var taggedItems []cbor.Tag
	for _, item := range items {
		itemBytes, err := cbor.Marshal(item)
		if err != nil {
			t.Fatalf("marshaling item: %v", err)
		}
		taggedItems = append(taggedItems, cbor.Tag{Number: 24, Content: itemBytes})
	}

	issuerSigned := map[string]any{
		"nameSpaces": map[string]any{
			namespace: taggedItems,
		},
	}

	data, err := cbor.Marshal(issuerSigned)
	if err != nil {
		t.Fatalf("marshaling issuerSigned: %v", err)
	}
	return data
}

func TestParseIssuerSigned_DeduplicatesClaims(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "resident_country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "resident_country", "elementValue": "DE"},
		{"digestID": uint64(3), "random": []byte("r3"), "elementIdentifier": "family_name", "elementValue": "Mustermann"},
	}

	data := buildIssuerSignedCBOR(t, "eu.europa.ec.eudi.pid.1", items)
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["eu.europa.ec.eudi.pid.1"]
	if len(ns) != 2 {
		t.Fatalf("expected 2 unique claims, got %d", len(ns))
	}

	seen := make(map[string]bool)
	for _, item := range ns {
		if seen[item.ElementIdentifier] {
			t.Errorf("duplicate claim %q found", item.ElementIdentifier)
		}
		seen[item.ElementIdentifier] = true
	}
}

func TestParseIssuerSigned_FirstOccurrenceWins(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "country", "elementValue": "FR"},
	}

	data := buildIssuerSignedCBOR(t, "ns1", items)
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["ns1"]
	if len(ns) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(ns))
	}
	if ns[0].ElementValue != "DE" {
		t.Errorf("expected first value 'DE', got %v", ns[0].ElementValue)
	}
}

// assertTestIssuerAuth checks the parsed fields of the COSE_Sign1 of the
// parseIssuerAuth tests, and that go-cose reads RawCOSE as the same message.
func assertTestIssuerAuth(t *testing.T, ia *IssuerAuth) {
	t.Helper()
	if fmt.Sprint(ia.ProtectedHeader) != "map[1:-7]" {
		t.Errorf("protected header %v, want alg -7", ia.ProtectedHeader)
	}
	if string(ia.Payload) != "payload" || len(ia.Signature) != 64 {
		t.Errorf("payload %q and %d signature bytes, want the payload and 64 bytes", ia.Payload, len(ia.Signature))
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Fatalf("go-cose cannot read RawCOSE: %v", err)
	}
	if alg, err := msg.Headers.Protected.Algorithm(); err != nil || alg != cose.AlgorithmES256 || string(msg.Payload) != "payload" {
		t.Errorf("go-cose read alg %v (%v) and payload %q, want ES256 and the payload", alg, err, msg.Payload)
	}
}

func TestParseIssuerAuth_TaggedInput(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7} (ES256)
		map[any]any{},            // unprotected
		[]byte("payload"),        // payload
		make([]byte, 64),         // signature (64 bytes for ES256)
	}

	tagged := cbor.Tag{Number: 18, Content: coseArr}

	ia, err := parseIssuerAuth(tagged)
	if err != nil {
		t.Fatalf("parseIssuerAuth(tagged) error: %v", err)
	}

	assertTestIssuerAuth(t, ia)
}

func TestParseIssuerAuth_UntaggedArrayInput(t *testing.T) {
	// After a DeviceResponse round trip issuerAuth arrives as []any without its tag.
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7} (ES256)
		map[any]any{},            // unprotected
		[]byte("payload"),        // payload
		make([]byte, 64),         // signature
	}

	ia, err := parseIssuerAuth(coseArr)
	if err != nil {
		t.Fatalf("parseIssuerAuth([]any) error: %v", err)
	}

	assertTestIssuerAuth(t, ia)
}

func TestParseIssuerAuth_BytesInput(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},
		map[any]any{},
		[]byte("payload"),
		make([]byte, 64),
	}
	tagged := cbor.Tag{Number: 18, Content: coseArr}
	data, err := cbor.Marshal(tagged)
	if err != nil {
		t.Fatal(err)
	}

	ia, err := parseIssuerAuth(data)
	if err != nil {
		t.Fatalf("parseIssuerAuth([]byte) error: %v", err)
	}

	assertTestIssuerAuth(t, ia)
}

func TestParseIssuerAuth_UntaggedBytesInput(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},
		map[any]any{},
		[]byte("payload"),
		make([]byte, 64),
	}
	data, err := cbor.Marshal(coseArr)
	if err != nil {
		t.Fatal(err)
	}

	ia, err := parseIssuerAuth(data)
	if err != nil {
		t.Fatalf("parseIssuerAuth(untagged []byte) error: %v", err)
	}

	assertTestIssuerAuth(t, ia)
}

func TestParseIssuerSignedItem_RawCBORContainsTag24(t *testing.T) {
	// MSO ValueDigests hash the complete #6.24(bstr .cbor IssuerSignedItem)
	// encoding, so RawCBOR must keep it.
	item := map[string]any{
		"digestID":          uint64(0),
		"random":            []byte("random-salt"),
		"elementIdentifier": "family_name",
		"elementValue":      "Mustermann",
	}

	innerBytes, err := cbor.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}

	data := buildIssuerSignedCBOR(t, "ns1", []map[string]any{item})
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["ns1"]
	if len(ns) != 1 {
		t.Fatalf("expected 1 item, got %d", len(ns))
	}

	if len(ns[0].RawCBOR) <= len(innerBytes) {
		t.Errorf("RawCBOR length %d should be larger than inner bytes length %d (should include Tag-24 wrapper)",
			len(ns[0].RawCBOR), len(innerBytes))
	}

	// 0xd8 0x18 is the Tag-24 prefix.
	if len(ns[0].RawCBOR) < 2 || ns[0].RawCBOR[0] != 0xd8 || ns[0].RawCBOR[1] != 0x18 {
		t.Errorf("RawCBOR should start with Tag-24 CBOR prefix (0xd8 0x18), got %x", ns[0].RawCBOR[:2])
	}

	var decoded cbor.Tag
	if err := cbor.Unmarshal(ns[0].RawCBOR, &decoded); err != nil {
		t.Fatalf("failed to unmarshal RawCBOR as Tag: %v", err)
	}
	if decoded.Number != 24 {
		t.Errorf("expected tag number 24, got %d", decoded.Number)
	}
}

func TestParseIssuerAuth_ExtractsUnprotectedHeader(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},                         // protected
		map[any]any{int64(33): []byte("cert-der-bytes")}, // unprotected with x5chain
		[]byte("payload"),
		make([]byte, 64),
	}

	ia, err := parseIssuerAuth(cbor.Tag{Number: 18, Content: coseArr})
	if err != nil {
		t.Fatalf("parseIssuerAuth() error: %v", err)
	}

	if ia.UnprotectedHeader == nil {
		t.Fatal("expected UnprotectedHeader to be set")
	}
	if _, ok := ia.UnprotectedHeader[int64(33)]; !ok {
		t.Error("expected x5chain (label 33) in UnprotectedHeader")
	}
}
