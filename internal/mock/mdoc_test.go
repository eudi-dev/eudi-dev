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

package mock

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
)

func TestGenerateMDOC_DefaultClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	if result == "" {
		t.Fatal("empty output")
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	if doc.DocType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("expected docType eu.europa.ec.eudi.pid.1, got %s", doc.DocType)
	}

	ns, ok := doc.NameSpaces["eu.europa.ec.eudi.pid.1"]
	if !ok {
		t.Fatal("missing namespace eu.europa.ec.eudi.pid.1")
	}

	if len(ns) != len(credtemplate.DefaultClaims) {
		t.Errorf("expected %d claims, got %d", len(credtemplate.DefaultClaims), len(ns))
	}

	claimNames := make(map[string]bool)
	for _, item := range ns {
		claimNames[item.ElementIdentifier] = true
	}
	for name := range credtemplate.DefaultClaims {
		if !claimNames[name] {
			t.Errorf("missing claim %q", name)
		}
	}

	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		t.Fatal("missing IssuerAuth/MSO")
	}
	if doc.IssuerAuth.MSO.Version != "1.0" {
		t.Errorf("expected MSO version 1.0, got %s", doc.IssuerAuth.MSO.Version)
	}
	if doc.IssuerAuth.MSO.DigestAlgorithm != "SHA-256" {
		t.Errorf("expected digest alg SHA-256, got %s", doc.IssuerAuth.MSO.DigestAlgorithm)
	}

	verifyResult := mdoc.Verify(doc, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("COSE signature verification failed: %v", verifyResult.Errors)
	}
}

// Claims from JSON keep their CBOR types: a whole number is an integer, as
// the ISO/IEC 5218 sex code needs, and a base64 data URI is a byte string, as
// the ISO 18013-5 portrait needs.
func TestGenerateMDOC_JSONClaimsGetTheirCBORTypes(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	result, err := GenerateMDOC(MDOCConfig{
		DocType:   "org.example.1",
		Namespace: "org.example.1",
		Claims: map[string]any{
			"sex":      float64(1),
			"height":   1.75,
			"portrait": "data:image/jpeg;base64,/9j/4A==",
			"caption":  "data:text/plain,hello",
		},
		Key: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{}
	for _, item := range doc.NameSpaces["org.example.1"] {
		values[item.ElementIdentifier] = item.ElementValue
	}
	if v, ok := values["sex"].(int64); !ok || v != 1 {
		t.Errorf("sex = %#v, want the integer 1", values["sex"])
	}
	if v, ok := values["height"].(float64); !ok || v != 1.75 {
		t.Errorf("height = %#v, want the float 1.75", values["height"])
	}
	if v, ok := values["portrait"].([]byte); !ok || !bytes.Equal(v, []byte{0xff, 0xd8, 0xff, 0xe0}) {
		t.Errorf("portrait = %#v, want the JPEG bytes", values["portrait"])
	}
	if values["caption"] != "data:text/plain,hello" {
		t.Errorf("caption = %#v, want the text", values["caption"])
	}
}

func TestGenerateMDOC_PIDClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    templateClaims("pid-mdoc"),
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	ns := doc.NameSpaces[PIDNamespace]
	if len(ns) != len(templateClaims("pid-mdoc")) {
		t.Errorf("expected %d claims in %s, got %d", len(templateClaims("pid-mdoc")), PIDNamespace, len(ns))
	}
	if len(doc.NameSpaces) != 1 {
		t.Errorf("expected a single namespace, got %d: %v", len(doc.NameSpaces), doc.NameSpaces)
	}
	for _, item := range ns {
		if strings.Contains(item.ElementIdentifier, ":") {
			t.Errorf("element %q kept a namespace prefix", item.ElementIdentifier)
		}
	}
	var birthPlace any
	for _, item := range ns {
		if item.ElementIdentifier == "place_of_birth" {
			birthPlace = item.ElementValue
			break
		}
	}
	bp, ok := birthPlace.(map[string]any)
	if !ok {
		t.Fatalf("expected place_of_birth map, got %T", birthPlace)
	}
	if bp["locality"] != "Amsterdam" {
		t.Errorf("expected place_of_birth.locality Amsterdam, got %v", bp["locality"])
	}

	verifyResult := mdoc.Verify(doc, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("COSE signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateMDOC_CustomClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	claims := map[string]any{"name": "Test", "active": true}

	cfg := MDOCConfig{
		DocType:   "com.example.test",
		Namespace: "com.example.test",
		Claims:    claims,
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	if doc.DocType != "com.example.test" {
		t.Errorf("expected docType com.example.test, got %s", doc.DocType)
	}

	verifyResult := mdoc.Verify(doc, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("COSE signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateMDOC_EmptyClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{},
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	ns := doc.NameSpaces["eu.europa.ec.eudi.pid.1"]
	if len(ns) != 0 {
		t.Errorf("expected 0 claims, got %d", len(ns))
	}

	verifyResult := mdoc.Verify(doc, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("COSE signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateMDOC_ValidityInfo(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		t.Fatal("missing IssuerAuth/MSO")
	}

	vi := doc.IssuerAuth.MSO.ValidityInfo
	if vi == nil {
		t.Fatal("missing ValidityInfo")
	}
	if vi.Signed == nil {
		t.Error("missing Signed time")
	}
	if vi.ValidFrom == nil {
		t.Error("missing ValidFrom time")
	}
	if vi.ValidUntil == nil {
		t.Error("missing ValidUntil time")
	}
	if vi.ValidFrom != nil && vi.ValidUntil != nil {
		diff := vi.ValidUntil.Sub(*vi.ValidFrom)
		if diff.Hours() < 29*24 || diff.Hours() > 31*24 {
			t.Errorf("expected ~30 days validity, got %v", diff)
		}
	}
}

func TestGenerateMDOC_WrongKeyFailsVerify(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key1,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	verifyResult := mdoc.Verify(doc, &key2.PublicKey)
	if verifyResult.SignatureValid {
		t.Error("COSE signature should not verify with a different key")
	}
}

func TestGenerateMDOC_OutputIsBase64URL(t *testing.T) {
	key, _ := GenerateKey()

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	for _, c := range result {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Fatalf("output is not base64url: found character %q", string(c))
		}
	}
}

func TestGenerateMDOC_IssuerAuthPayloadIsTag24MSO(t *testing.T) {
	key, _ := GenerateKey()

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	data, err := base64.RawURLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("decode credential: %v", err)
	}

	var issuerSigned map[any]any
	if err := cbor.Unmarshal(data, &issuerSigned); err != nil {
		t.Fatalf("decode IssuerSigned: %v", err)
	}

	var sign1 []cbor.RawMessage
	issuerAuthBytes, err := cbor.Marshal(issuerSigned["issuerAuth"])
	if err != nil {
		t.Fatalf("re-encode issuerAuth: %v", err)
	}
	if err := cbor.Unmarshal(issuerAuthBytes, &sign1); err != nil {
		t.Fatalf("decode issuerAuth COSE_Sign1: %v", err)
	}
	if len(sign1) != 4 {
		t.Fatalf("expected COSE_Sign1 with 4 elements, got %d", len(sign1))
	}

	var payload []byte
	if err := cbor.Unmarshal(sign1[2], &payload); err != nil {
		t.Fatalf("decode issuerAuth payload bstr: %v", err)
	}

	var tagged cbor.Tag
	if err := cbor.Unmarshal(payload, &tagged); err != nil {
		t.Fatalf("decode issuerAuth payload as Tag 24: %v", err)
	}
	if tagged.Number != 24 {
		t.Fatalf("expected issuerAuth payload tag 24, got %d", tagged.Number)
	}
}

func TestGenerateMDOC_ClaimValuesPreserved(t *testing.T) {
	key, _ := GenerateKey()

	claims := map[string]any{
		"string_val": "hello",
		"bool_val":   true,
		"int_val":    42,
	}

	cfg := MDOCConfig{
		DocType:   "com.test",
		Namespace: "com.test",
		Claims:    claims,
		Key:       key,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}

	ns := doc.NameSpaces["com.test"]
	found := make(map[string]any)
	for _, item := range ns {
		found[item.ElementIdentifier] = item.ElementValue
	}

	if v, ok := found["string_val"]; !ok || v != "hello" {
		t.Errorf("string_val: expected hello, got %v", v)
	}
	if v, ok := found["bool_val"]; !ok || v != true {
		t.Errorf("bool_val: expected true, got %v", v)
	}
}

func TestGenerateMDOC_CustomExpiresIn(t *testing.T) {
	key, _ := GenerateKey()

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key,
		ExpiresIn: 7 * 24 * time.Hour,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatal(err)
	}

	vi := doc.IssuerAuth.MSO.ValidityInfo
	diff := vi.ValidUntil.Sub(*vi.ValidFrom)
	if diff.Hours() < 6*24 || diff.Hours() > 8*24 {
		t.Errorf("expected ~7 days validity, got %v", diff)
	}
}

func TestGenerateMDOC_WithValidFrom(t *testing.T) {
	key, _ := GenerateKey()
	vf := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	cfg := MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    credtemplate.DefaultClaims,
		Key:       key,
		ValidFrom: &vf,
	}

	result, err := GenerateMDOC(cfg)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatal(err)
	}

	vi := doc.IssuerAuth.MSO.ValidityInfo
	if !vi.ValidFrom.Equal(vf) {
		t.Errorf("expected validFrom=%v, got %v", vf, *vi.ValidFrom)
	}
}

// ISO 18013-5 encodes dates as tagged CBOR. A calendar day is a full-date
// (1004) and a timestamp is a tdate (0).
func TestGenerateMDOC_DatesAreTagged(t *testing.T) {
	key, _ := GenerateKey()

	result, err := GenerateMDOC(MDOCConfig{
		DocType:   PIDNamespace,
		Namespace: PIDNamespace,
		Claims: map[string]any{
			"birth_date":         "1964-08-12",
			"expiry_date":        "2031-08-04T00:00:00Z",
			"family_name":        "MUSTERMANN",
			"document_ref":       "2024-INVOICE",
			"raw_eid_birth_date": "1964-08-12",
			"date_as_text":       "2026-07-23",
			"nested":             map[string]any{"issued": "2026-07-23"},
			"age_over_18":        true,
			"nationality":        []any{"DE"},
			"not_a_date_at":      "12-31-2026",
		},
		Key: key,
	})
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	data, err := base64.RawURLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("decoding credential: %v", err)
	}
	var issuerSigned struct {
		NameSpaces map[string][]cbor.RawTag `cbor:"nameSpaces"`
	}
	if err := cbor.Unmarshal(data, &issuerSigned); err != nil {
		t.Fatalf("decoding IssuerSigned: %v", err)
	}

	tags := make(map[string]uint64)
	values := make(map[string]any)
	for _, raw := range issuerSigned.NameSpaces[PIDNamespace] {
		var item struct {
			ElementIdentifier string          `cbor:"elementIdentifier"`
			ElementValue      cbor.RawMessage `cbor:"elementValue"`
		}
		// Tag 24 carries the item as an embedded CBOR byte string.
		var embedded []byte
		if err := cbor.Unmarshal(raw.Content, &embedded); err != nil {
			t.Fatalf("unwrapping Tag 24: %v", err)
		}
		if err := cbor.Unmarshal(embedded, &item); err != nil {
			t.Fatalf("decoding IssuerSignedItem: %v", err)
		}
		var tagged cbor.RawTag
		if err := cbor.Unmarshal(item.ElementValue, &tagged); err == nil {
			tags[item.ElementIdentifier] = tagged.Number
		}
		var plain any
		if err := cbor.Unmarshal(item.ElementValue, &plain); err == nil {
			values[item.ElementIdentifier] = plain
		}
	}

	if got := tags["birth_date"]; got != 1004 {
		t.Errorf("birth_date should be tagged full-date (1004), got tag %d", got)
	}
	if got := tags["expiry_date"]; got != 0 {
		t.Errorf("expiry_date should be tagged tdate (0), got tag %d", got)
	}
	for _, name := range []string{"family_name", "document_ref", "not_a_date_at", "age_over_18", "nationality", "raw_eid_birth_date", "date_as_text"} {
		if tag, ok := tags[name]; ok {
			t.Errorf("%s must not be tagged as a date, got tag %d", name, tag)
		}
	}

	if nested, ok := values["nested"].(map[any]any); !ok || nested["issued"] != "2026-07-23" {
		t.Errorf("nested text was converted to a CBOR date: %v", values["nested"])
	}

	// Parsing unwraps the tags, so the wallet sees plain strings for claim matching.
	doc, err := mdoc.Parse(result)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}
	parsed := make(map[string]any)
	for _, item := range doc.NameSpaces[PIDNamespace] {
		parsed[item.ElementIdentifier] = item.ElementValue
	}
	if parsed["birth_date"] != "1964-08-12" {
		t.Errorf("birth_date should parse back to the plain date, got %v", parsed["birth_date"])
	}
	if parsed["expiry_date"] != "2031-08-04T00:00:00Z" {
		t.Errorf("expiry_date should parse back to the plain timestamp, got %v", parsed["expiry_date"])
	}
	if nested, ok := parsed["nested"].(map[string]any); !ok || nested["issued"] != "2026-07-23" {
		t.Errorf("nested dates should survive the round trip, got %v", parsed["nested"])
	}
}

// x5chain must omit the root because verifiers take trust anchors from a trust list.
func TestGenerateMDOC_X5ChainOmitsTheRoot(t *testing.T) {
	caKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caCert, err := GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}
	issuerKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leaf, err := GenerateLeafCertWithOptions(caKey, caCert, &issuerKey.PublicKey, LeafCertOptions{})
	if err != nil {
		t.Fatalf("GenerateLeafCertWithOptions: %v", err)
	}

	raw, err := GenerateMDOC(MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{"given_name": "ERIKA"},
		Key:       issuerKey,
		CertChain: []*x509.Certificate{leaf, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	doc, err := mdoc.Parse(raw)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}
	certs, err := certchain.FromCOSE(doc.IssuerAuth.ProtectedHeader, doc.IssuerAuth.UnprotectedHeader)
	if err != nil {
		t.Fatalf("reading x5chain: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("x5chain carries %d certificates, want the leaf alone", len(certs))
	}
	if !certs[0].Equal(leaf) {
		t.Error("x5chain does not carry the leaf")
	}
	for _, c := range certs {
		if c.Equal(caCert) {
			t.Error("x5chain carries the self-signed root")
		}
	}
}

func TestGenerateMDOC_DrivingPrivilegeDates(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := GenerateMDOC(MDOCConfig{
		DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1", Key: key,
		Claims: map[string]any{"driving_privileges": []any{map[string]any{
			"vehicle_category_code": "B", "issue_date": "2026-01-01", "expiry_date": "2031-01-01", "restriction_text": "2026-01-01",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		t.Fatal(err)
	}
	var signed struct {
		NameSpaces map[string][]cbor.RawTag `cbor:"nameSpaces"`
	}
	if err := cbor.Unmarshal(data, &signed); err != nil {
		t.Fatal(err)
	}
	var embedded []byte
	if err := cbor.Unmarshal(signed.NameSpaces["org.iso.18013.5.1"][0].Content, &embedded); err != nil {
		t.Fatal(err)
	}
	var item struct {
		Value []struct {
			Issued      cbor.RawTag `cbor:"issue_date"`
			Expiry      cbor.RawTag `cbor:"expiry_date"`
			Restriction string      `cbor:"restriction_text"`
		} `cbor:"elementValue"`
	}
	if err := cbor.Unmarshal(embedded, &item); err != nil {
		t.Fatal(err)
	}
	if len(item.Value) != 1 || item.Value[0].Issued.Number != 1004 || item.Value[0].Expiry.Number != 1004 || item.Value[0].Restriction != "2026-01-01" {
		t.Errorf("driving privilege types = %+v", item.Value)
	}
}
