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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func issuerSignedMap(t *testing.T) map[any]any {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   testDocType,
		Namespace: testDocType,
		Claims:    templateClaims("pid-mdoc"),
		Key:       key,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := format.DecodeHexOrBase64URL(strings.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	var issuerSigned map[any]any
	if err := cbor.Unmarshal(data, &issuerSigned); err != nil {
		t.Fatal(err)
	}
	return issuerSigned
}

func deviceResponse(t *testing.T, resp map[any]any) string {
	t.Helper()
	encoded, err := cbor.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(encoded)
}

func fullDeviceResponse(t *testing.T) map[any]any {
	t.Helper()
	emptyNamespaces, err := tag24(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return map[any]any{
		"version": "1.0",
		"status":  uint64(0),
		"documents": []any{
			map[any]any{
				"docType":      testDocType,
				"issuerSigned": issuerSignedMap(t),
				"deviceSigned": map[any]any{
					"nameSpaces": cbor.RawMessage(emptyNamespaces),
					"deviceAuth": map[any]any{
						"deviceSignature": []any{[]byte{}, map[any]any{}, nil, []byte("signature")},
					},
				},
			},
		},
	}
}

func TestParseDeviceResponse(t *testing.T) {
	doc, err := Parse(deviceResponse(t, fullDeviceResponse(t)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !doc.IsDeviceResponse {
		t.Error("the document was not marked as coming from a DeviceResponse")
	}
	if doc.DocType != testDocType {
		t.Errorf("DocType = %q, want %q", doc.DocType, testDocType)
	}
	if doc.ResponseVersion != "1.0" {
		t.Errorf("ResponseVersion = %q, want 1.0", doc.ResponseVersion)
	}
	if doc.ResponseStatus == nil || *doc.ResponseStatus != 0 {
		t.Errorf("ResponseStatus = %v, want 0", doc.ResponseStatus)
	}
	if doc.DeviceSigned == nil {
		t.Fatal("deviceSigned was not parsed")
	}
	if len(doc.DeviceSigned.RawDeviceSignature) == 0 {
		t.Error("the device signature was not kept in the form it arrived in")
	}
	if len(doc.NameSpaces[testDocType]) == 0 {
		t.Errorf("no elements parsed from the namespace: %v", doc.NameSpaces)
	}
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		t.Fatal("the issuer authentication was not parsed")
	}
	if doc.IssuerAuth.MSO.ValidityInfo == nil || doc.IssuerAuth.MSO.ValidityInfo.Signed == nil {
		t.Error("validity info was not parsed")
	}
}

// The status decodes as int64 when the decoder reads integers as signed.
func TestParseDeviceResponseReadsAnInt64Status(t *testing.T) {
	resp := fullDeviceResponse(t)
	resp["status"] = int64(10)

	doc, err := Parse(deviceResponse(t, resp))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.ResponseStatus == nil || *doc.ResponseStatus != 10 {
		t.Errorf("ResponseStatus = %v, want 10", doc.ResponseStatus)
	}
}

// ISO 18013-5 §8.3.2.1.2.2 requires the DeviceResponse status, and only
// status 0 is "OK". Another status or none is a deviation.
func TestParseDeviceResponseChecksTheStatus(t *testing.T) {
	for name, status := range map[string]any{"OK": uint64(0), "general error": uint64(10), "missing": nil} {
		resp := fullDeviceResponse(t)
		if status == nil {
			delete(resp, "status")
		} else {
			resp["status"] = status
		}
		doc, err := Parse(deviceResponse(t, resp))
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		deviates := strings.Contains(strings.Join(doc.Deviations, " "), "status")
		if want := name != "OK"; deviates != want {
			t.Errorf("%s: deviations %v, want a status deviation %v", name, doc.Deviations, want)
		}
	}
}

func TestParseDeviceResponseCountsTheDocuments(t *testing.T) {
	resp := fullDeviceResponse(t)
	first := resp["documents"].([]any)[0]
	resp["documents"] = []any{first, first}
	doc, err := Parse(deviceResponse(t, resp))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Documents != 2 {
		t.Errorf("Documents = %d, want 2", doc.Documents)
	}
}

func TestParseDeviceResponseWithoutDeviceSigned(t *testing.T) {
	resp := fullDeviceResponse(t)
	docs := resp["documents"].([]any)
	delete(docs[0].(map[any]any), "deviceSigned")

	doc, err := Parse(deviceResponse(t, resp))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.DeviceSigned != nil {
		t.Error("a device signature was reported where the response carried none")
	}
}

// A deviceAuth with a deviceMac must parse with no device signature.
func TestParseDeviceResponseWithADeviceMac(t *testing.T) {
	resp := fullDeviceResponse(t)
	docs := resp["documents"].([]any)
	ds := docs[0].(map[any]any)["deviceSigned"].(map[any]any)
	ds["deviceAuth"] = map[any]any{"deviceMac": []any{[]byte{}, map[any]any{}, nil, []byte("mac")}}

	doc, err := Parse(deviceResponse(t, resp))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.DeviceSigned == nil {
		t.Fatal("deviceSigned was not parsed")
	}
	if len(doc.DeviceSigned.RawDeviceSignature) != 0 {
		t.Error("a deviceMac was reported as a device signature")
	}
	if err := VerifyDeviceAuth(doc, []byte{}); err == nil {
		t.Error("a MAC-authenticated response was treated as signed")
	}
}

// A map with documents is a DeviceResponse, so a malformed one fails instead of
// reading as an empty IssuerSigned. A map that is neither fails too.
func TestParseDeviceResponseRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		resp map[any]any
	}{
		{"no documents", map[any]any{"version": "1.0", "status": uint64(0)}},
		{"an empty documents array", map[any]any{"documents": []any{}}},
		{"a document that is not a map", map[any]any{"documents": []any{"not a map"}}},
		{"a document without issuerSigned", map[any]any{"documents": []any{map[any]any{"docType": testDocType}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(deviceResponse(t, tt.resp)); err == nil {
				t.Error("a malformed response was accepted")
			}
		})
	}
}

func TestParseRejectsInputThatIsNotCBOR(t *testing.T) {
	if _, err := Parse("not hex and not base64!!"); err == nil {
		t.Error("unparseable input was accepted")
	}
	if _, err := Parse(hex.EncodeToString([]byte("still not cbor"))); err == nil {
		t.Error("bytes that are not CBOR were accepted")
	}
}

// The issuer signs the MSO docType. The unsigned document docType cannot
// relabel the credential.
func TestParseDeviceResponseKeepsTheSignedDocType(t *testing.T) {
	resp := fullDeviceResponse(t)
	resp["documents"].([]any)[0].(map[any]any)["docType"] = "org.iso.18013.5.1.mDL"

	doc, err := Parse(deviceResponse(t, resp))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.DocType != testDocType {
		t.Errorf("DocType = %q, want the signed %q", doc.DocType, testDocType)
	}
	if !strings.Contains(strings.Join(doc.Deviations, "\n"), "org.iso.18013.5.1.mDL") {
		t.Errorf("Deviations = %v, want the docType mismatch", doc.Deviations)
	}
}

func TestParseDeviceResponseKeepsTheDeviceNameSpaces(t *testing.T) {
	doc, err := Parse(deviceResponse(t, fullDeviceResponse(t)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want, err := tag24(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if string(doc.DeviceSigned.RawNameSpaces) != string(want) {
		t.Errorf("RawNameSpaces = %x, want %x", doc.DeviceSigned.RawNameSpaces, want)
	}
}

// templateClaims returns the claims of a predefined template.
func templateClaims(name string) map[string]any {
	t, ok := credtemplate.Predefined(name)
	if !ok {
		panic("no predefined template " + name)
	}
	return t.Claims
}
