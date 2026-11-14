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
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

type rawMap = map[string]cbor.RawMessage

func mustEncode(t *testing.T, v any) cbor.RawMessage {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustDecode(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := cbor.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

// boundMDOC returns a credential that follows ISO/IEC 18013-5, with the key
// of its issuer and of its holder.
func boundMDOC(t *testing.T, cfg mock.MDOCConfig) (raw string, issuer, holder *ecdsa.PrivateKey) {
	t.Helper()
	issuer, _ = mock.GenerateKey()
	holder, _ = mock.GenerateKey()
	cfg.Key, cfg.HolderKey = issuer, &holder.PublicKey
	cfg.DocType, cfg.Namespace = "org.iso.18013.5.1.mDL", "org.iso.18013.5.1"
	cfg.Claims = map[string]any{"family_name": "Mustermann"}
	raw, err := mock.GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}
	return raw, issuer, holder
}

// rewritten lets change edit the COSE_Sign1 parts of issuerAuth and the MSO.
// Then it re-encodes raw. An edited MSO or protected header breaks the issuer
// signature.
func rewritten(t *testing.T, raw string, change func(sign1 []cbor.RawMessage, mso rawMap)) string {
	t.Helper()
	data, err := format.DecodeBase64URL(raw)
	if err != nil {
		t.Fatal(err)
	}
	var issuerSigned rawMap
	mustDecode(t, data, &issuerSigned)
	var sign1 []cbor.RawMessage
	mustDecode(t, issuerSigned["issuerAuth"], &sign1)
	var payload []byte
	mustDecode(t, sign1[2], &payload)
	var msoBytes cbor.RawTag
	mustDecode(t, payload, &msoBytes)
	var encodedMSO []byte
	mustDecode(t, msoBytes.Content, &encodedMSO)
	var mso rawMap
	mustDecode(t, encodedMSO, &mso)

	before := maps.Clone(mso)
	change(sign1, mso)
	// An unchanged MSO keeps its bytes, so the issuer signature still verifies.
	if !reflect.DeepEqual(before, mso) {
		sign1[2] = mustEncode(t, []byte(mustEncode(t, cbor.Tag{Number: 24, Content: []byte(mustEncode(t, mso))})))
	}
	issuerSigned["issuerAuth"] = mustEncode(t, sign1)
	return format.EncodeBase64URL(mustEncode(t, issuerSigned))
}

// ParseLenient accepts every credential below. Parse rejects each one, and its
// error contains the required member (ISO/IEC 18013-5 §9.1.2.4).
func TestParseRejectsWhatParseLenientAccepts(t *testing.T) {
	validity := func(change func(info rawMap)) func(*testing.T, []cbor.RawMessage, rawMap) {
		return func(t *testing.T, _ []cbor.RawMessage, mso rawMap) {
			var info rawMap
			mustDecode(t, mso["validityInfo"], &info)
			change(info)
			mso["validityInfo"] = mustEncode(t, info)
		}
	}
	tests := []struct {
		name   string
		change func(t *testing.T, sign1 []cbor.RawMessage, mso rawMap)
		want   string
	}{
		{"no validityInfo", func(_ *testing.T, _ []cbor.RawMessage, mso rawMap) { delete(mso, "validityInfo") }, "the MSO has no validityInfo map"},
		{"no validFrom", validity(func(info rawMap) { delete(info, "validFrom") }), "validityInfo has no validFrom date-time"},
		{"a validUntil that is not a date", validity(func(info rawMap) { info["validUntil"] = cbor.RawMessage{0x63, 'n', 'o', 'w'} }), "validityInfo has no validUntil date-time"},
		{"no digestAlgorithm", func(_ *testing.T, _ []cbor.RawMessage, mso rawMap) { delete(mso, "digestAlgorithm") }, "the MSO has no digestAlgorithm text"},
		{"a docType that is a number", func(t *testing.T, _ []cbor.RawMessage, mso rawMap) { mso["docType"] = mustEncode(t, 7) }, "the MSO has no docType text"},
		{"no deviceKeyInfo", func(_ *testing.T, _ []cbor.RawMessage, mso rawMap) { delete(mso, "deviceKeyInfo") }, "the MSO has no deviceKeyInfo map"},
		{"a deviceKeyInfo without a deviceKey", func(t *testing.T, _ []cbor.RawMessage, mso rawMap) {
			mso["deviceKeyInfo"] = mustEncode(t, map[string]any{})
		}, "deviceKeyInfo has no deviceKey map"},
		{"a digestID that is text", func(t *testing.T, _ []cbor.RawMessage, mso rawMap) {
			mso["valueDigests"] = mustEncode(t, map[string]any{"org.iso.18013.5.1": map[string][]byte{"zero": make([]byte, 32)}})
		}, "has a digestID that is not a number"},
		{"a status that is text", func(t *testing.T, _ []cbor.RawMessage, mso rawMap) { mso["status"] = mustEncode(t, "valid") }, "the status of the MSO is not a map"},
		{"a protected header that is not a map", func(t *testing.T, sign1 []cbor.RawMessage, _ rawMap) {
			sign1[0] = mustEncode(t, []byte{0x01})
		}, "the protected header of issuerAuth is not a CBOR map"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _, _ := boundMDOC(t, mock.MDOCConfig{})
			raw = rewritten(t, raw, func(sign1 []cbor.RawMessage, mso rawMap) { tt.change(t, sign1, mso) })

			if _, err := ParseLenient(raw); err != nil {
				t.Fatalf("ParseLenient: %v", err)
			}
			_, err := Parse(raw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse = %v, want an error with %q", err, tt.want)
			}
		})
	}
}

func TestParseRejectsARecordedDeviation(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "country", "elementValue": "FR"},
	}
	raw := format.EncodeBase64URL(buildIssuerSignedCBOR(t, "ns1", items))

	doc, err := ParseLenient(raw)
	if err != nil || len(doc.Deviations) == 0 {
		t.Fatalf("ParseLenient = %v with deviations %v, want a document with a deviation", err, doc.Deviations)
	}
	_, err = Parse(raw)
	if err == nil || !strings.Contains(err.Error(), doc.Deviations[0]) {
		t.Errorf("Parse = %v, want an error with %q", err, doc.Deviations[0])
	}
}

// ISO/IEC 18013-5 §9.1.2.4 requires validityInfo with validFrom and
// validUntil, so a period without one of them is never valid.
func TestValidAtRejectsAnUnreadableValidityPeriod(t *testing.T) {
	for _, member := range []string{"validityInfo", "validFrom", "validUntil"} {
		raw, _, _ := boundMDOC(t, mock.MDOCConfig{})
		raw = rewritten(t, raw, func(_ []cbor.RawMessage, mso rawMap) {
			if member == "validityInfo" {
				delete(mso, member)
				return
			}
			var info rawMap
			mustDecode(t, mso["validityInfo"], &info)
			info[member] = mustEncode(t, "tomorrow")
			mso["validityInfo"] = mustEncode(t, info)
		})
		doc, err := ParseLenient(raw)
		if err != nil {
			t.Fatalf("ParseLenient: %v", err)
		}
		err = doc.ValidAt(time.Now())
		if err == nil || !strings.Contains(err.Error(), member) {
			t.Errorf("ValidAt without a readable %s = %v, want an error that mentions it", member, err)
		}
		if errors.Is(err, ErrExpired) || errors.Is(err, ErrNotYetValid) {
			t.Errorf("ValidAt without a readable %s = %v, want no validity sentinel", member, err)
		}
	}
}

func TestValidAtAllowsOneMinuteOfClockSkew(t *testing.T) {
	raw, _, _ := boundMDOC(t, mock.MDOCConfig{ExpiresIn: time.Hour})
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	from, until := *doc.IssuerAuth.MSO.ValidityInfo.ValidFrom, *doc.IssuerAuth.MSO.ValidityInfo.ValidUntil

	tests := []struct {
		name string
		at   time.Time
		want error
	}{
		{"1 minute before validFrom", from.Add(-time.Minute), nil},
		{"61 seconds before validFrom", from.Add(-61 * time.Second), ErrNotYetValid},
		{"1 minute after validUntil", until.Add(time.Minute), nil},
		{"61 seconds after validUntil", until.Add(61 * time.Second), ErrExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := doc.ValidAt(tt.at); !errors.Is(err, tt.want) {
				t.Errorf("ValidAt = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestIssuerCertificates(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	ca, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, issuer, _ := boundMDOC(t, mock.MDOCConfig{})
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &issuer.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}

	withChain := rewritten(t, raw, func(sign1 []cbor.RawMessage, _ rawMap) {
		sign1[1] = mustEncode(t, map[int]any{33: [][]byte{leaf.Raw, ca.Raw}})
	})
	doc, err := Parse(withChain)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	certs, err := doc.IssuerCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !certs[0].Equal(leaf) {
		t.Fatalf("IssuerCertificates = %d certificates, want 2 certificates with the leaf first", len(certs))
	}
	if err := Verify(doc, certs[0].PublicKey); err != nil {
		t.Errorf("Verify with the key of the leaf: %v", err)
	}

	withoutChain := rewritten(t, raw, func(sign1 []cbor.RawMessage, _ rawMap) {
		sign1[1] = mustEncode(t, map[int]any{})
	})
	if doc, err = Parse(withoutChain); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if certs, err := doc.IssuerCertificates(); err != nil || len(certs) != 0 {
		t.Errorf("IssuerCertificates without x5chain = %d certificates, %v", len(certs), err)
	}

	broken := rewritten(t, raw, func(sign1 []cbor.RawMessage, _ rawMap) {
		sign1[1] = mustEncode(t, map[int]any{33: []byte("not a certificate")})
	})
	if doc, err = Parse(broken); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := doc.IssuerCertificates(); err == nil {
		t.Error("IssuerCertificates accepted an x5chain entry that is not a certificate")
	}
	if certs, err := (&Document{}).IssuerCertificates(); err != nil || len(certs) != 0 {
		t.Errorf("IssuerCertificates without issuerAuth = %d certificates, %v", len(certs), err)
	}
}
