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
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/cborview"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// Parse decodes an IssuerSigned structure or a DeviceResponse in hex or
// base64url. It does not check signatures or digests. For a DeviceResponse it
// reads only the first document. Document.Documents is the number of documents.
//
// Parse rejects a credential when a member required by ISO/IEC 18013-5 is
// missing or unreadable. It also rejects every deviation that ParseLenient
// records.
func Parse(raw string) (*Document, error) {
	doc, err := ParseLenient(raw)
	if err != nil {
		return nil, err
	}
	if problems := slices.Concat(doc.Deviations, doc.unreadable); len(problems) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(problems, ". "))
	}
	return doc, nil
}

// ParseLenient decodes like Parse and keeps a credential that breaks ISO/IEC
// 18013-5. It lists each accepted violation in Document.Deviations. A
// required member that is missing or unreadable stays empty in the result and
// is not listed there. Use it to display a faulty credential. Its result never
// proves validity. Verifiers use Parse.
func ParseLenient(raw string) (*Document, error) {
	raw = strings.TrimSpace(raw)

	data, err := format.DecodeHexOrBase64URL(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding input: %w", err)
	}

	var top map[any]any
	if err := cborview.DecMode.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("decoding mdoc CBOR: %w", err)
	}
	if _, ok := top["documents"]; ok {
		doc, err := parseDeviceResponse(data)
		if err != nil {
			return nil, fmt.Errorf("reading DeviceResponse: %w", err)
		}
		return doc, nil
	}
	_, hasNameSpaces := top["nameSpaces"]
	_, hasIssuerAuth := top["issuerAuth"]
	if !hasNameSpaces && !hasIssuerAuth {
		return nil, fmt.Errorf("the CBOR map is neither a DeviceResponse nor an IssuerSigned structure")
	}
	return parseIssuerSigned(data)
}

func parseDeviceResponse(data []byte) (*Document, error) {
	var resp map[any]any
	if err := cborview.DecMode.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	docs, ok := resp["documents"]
	if !ok {
		return nil, fmt.Errorf("no documents field")
	}

	docArr, ok := docs.([]any)
	if !ok || len(docArr) == 0 {
		return nil, fmt.Errorf("empty documents array")
	}

	docMap, ok := docArr[0].(map[any]any)
	if !ok {
		return nil, fmt.Errorf("invalid document entry")
	}

	issuerSigned, ok := docMap["issuerSigned"].(map[any]any)
	if !ok {
		return nil, fmt.Errorf("no issuerSigned in document")
	}

	issuerBytes, err := cbor.Marshal(issuerSigned)
	if err != nil {
		return nil, err
	}

	doc, err := parseIssuerSigned(issuerBytes)
	if err != nil {
		return nil, err
	}

	// The issuer signs only the MSO docType, so the document's own docType
	// cannot relabel the credential.
	if dt, ok := docMap["docType"].(string); ok {
		switch {
		case doc.DocType == "":
			doc.DocType = dt
		case dt != doc.DocType:
			doc.Deviations = append(doc.Deviations, fmt.Sprintf("the document has docType %q, but the MSO signed by the issuer has %q", dt, doc.DocType))
		}
	}

	if ds, ok := docMap["deviceSigned"].(map[any]any); ok {
		doc.DeviceSigned = parseDeviceSigned(ds)
	}

	if v, ok := resp["version"].(string); ok {
		doc.ResponseVersion = v
	}
	switch st := resp["status"].(type) {
	case uint64:
		doc.ResponseStatus = &st
	case int64:
		converted := uint64(st)
		doc.ResponseStatus = &converted
	}
	// ISO/IEC 18013-5 §8.3.2.1.2.2 defines status as a required member of the
	// DeviceResponse. Status 0 is "OK". The other codes report an error.
	switch {
	case doc.ResponseStatus == nil:
		doc.Deviations = append(doc.Deviations, "the DeviceResponse has no status, which ISO 18013-5 §8.3.2.1.2.2 requires")
	case *doc.ResponseStatus != 0:
		doc.Deviations = append(doc.Deviations, fmt.Sprintf("the DeviceResponse status is %d. Only 0 (OK) means success (ISO 18013-5 §8.3.2.1.2.2)", *doc.ResponseStatus))
	}

	doc.IsDeviceResponse = true
	doc.Documents = len(docArr)
	doc.Raw = data

	return doc, nil
}

func parseDeviceSigned(ds map[any]any) *DeviceSigned {
	result := &DeviceSigned{}
	if ns, ok := ds["nameSpaces"]; ok {
		if encoded, err := cbor.Marshal(ns); err == nil {
			result.RawNameSpaces = encoded
		}
	}
	da, ok := ds["deviceAuth"].(map[any]any)
	if !ok {
		return result
	}
	if encoded, err := cbor.Marshal(da); err == nil {
		result.RawDeviceAuth = encoded
	}
	// The COSE_Sign1 must be verified as it arrived.
	if sig, ok := da["deviceSignature"]; ok {
		if encoded, err := cbor.Marshal(sig); err == nil {
			result.RawDeviceSignature = encoded
		}
	}
	return result
}

func parseIssuerSigned(data []byte) (*Document, error) {
	var issuerSigned map[any]any
	if err := cborview.DecMode.Unmarshal(data, &issuerSigned); err != nil {
		return nil, fmt.Errorf("decoding IssuerSigned CBOR: %w", err)
	}

	doc := &Document{
		Raw:        data,
		NameSpaces: make(map[string][]IssuerSignedItem),
	}

	// A malformed namespace part becomes a finding, so the rest of the document
	// stays inspectable.
	if ns, ok := issuerSigned["nameSpaces"]; ok {
		nsMap, isMap := ns.(map[any]any)
		if !isMap {
			doc.Deviations = append(doc.Deviations, "the nameSpaces value is not a CBOR map (ISO/IEC 18013-5), so no claims are read")
		}
		for nsKey, nsVal := range nsMap {
			namespace := fmt.Sprintf("%v", nsKey)
			items, ok := nsVal.([]any)
			if !ok {
				doc.Deviations = append(doc.Deviations, fmt.Sprintf("namespace %q is not an array of items, so it is dropped", namespace))
				continue
			}
			seen := make(map[string]bool)
			for _, item := range items {
				isi, unreadable, err := parseIssuerSignedItem(item)
				doc.unreadable = append(doc.unreadable, unreadable...)
				if err != nil {
					doc.Deviations = append(doc.Deviations, fmt.Sprintf("an item in namespace %q could not be read, so it is dropped", namespace))
					continue
				}
				if seen[isi.ElementIdentifier] {
					doc.Deviations = append(doc.Deviations, fmt.Sprintf("namespace %q repeats element %q, so the repeat is dropped", namespace, isi.ElementIdentifier))
					continue
				}
				seen[isi.ElementIdentifier] = true
				doc.NameSpaces[namespace] = append(doc.NameSpaces[namespace], *isi)
			}
		}
	}

	auth, ok := issuerSigned["issuerAuth"]
	if !ok {
		doc.unreadable = append(doc.unreadable, "the document has no issuerAuth")
	} else {
		ia, unreadable, err := parseIssuerAuth(auth)
		doc.unreadable = append(doc.unreadable, unreadable...)
		if err == nil {
			doc.IssuerAuth = ia
			if ia.MSO != nil {
				doc.DocType = ia.MSO.DocType
			}
		} else {
			doc.Deviations = append(doc.Deviations, fmt.Sprintf("the issuerAuth structure could not be read (%s), so the signature and MSO are unavailable", err))
		}
	}

	return doc, nil
}

// parseIssuerSignedItem returns the item and the unreadable required members
// (ISO/IEC 18013-5 §8.3.2.1.2.2).
func parseIssuerSignedItem(raw any) (*IssuerSignedItem, []string, error) {
	// Items are CBOR bstr wrapped in tag 24. MSO ValueDigests hash the complete
	// #6.24(bstr) encoding, so rawTag24 keeps it.
	var itemBytes []byte
	var rawTag24 []byte

	switch v := raw.(type) {
	case []byte:
		itemBytes = v
	case cbor.Tag:
		if v.Number == 24 {
			if b, ok := v.Content.([]byte); ok {
				itemBytes = b
				if encoded, err := cbor.Marshal(v); err == nil {
					rawTag24 = encoded
				}
			} else {
				return nil, nil, fmt.Errorf("tag 24 content is not bstr")
			}
		} else {
			return nil, nil, fmt.Errorf("unexpected tag: %d", v.Number)
		}
	default:
		b, err := cbor.Marshal(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot handle item type %T", raw)
		}
		rawTag24 = b
		inner, err := cborview.UnwrapTag24(b)
		if err != nil {
			return nil, nil, err
		}
		itemBytes = inner
	}

	var itemMap map[any]any
	if err := cborview.DecMode.Unmarshal(itemBytes, &itemMap); err != nil {
		return nil, nil, fmt.Errorf("decoding IssuerSignedItem: %w", err)
	}

	rawForDigest := rawTag24
	if rawForDigest == nil {
		rawForDigest = itemBytes
	}

	isi := &IssuerSignedItem{
		RawCBOR: rawForDigest,
	}

	var unreadable []string
	if ei, ok := itemMap["elementIdentifier"].(string); ok {
		isi.ElementIdentifier = ei
	} else {
		unreadable = append(unreadable, "an IssuerSignedItem has no elementIdentifier text")
	}

	switch v := itemMap["digestID"].(type) {
	case uint64:
		isi.DigestID = v
	case int64:
		isi.DigestID = uint64(v)
	default:
		unreadable = append(unreadable, fmt.Sprintf("element %q has no digestID number", isi.ElementIdentifier))
	}
	if v, ok := itemMap["digestID"].(int64); ok && v < 0 {
		unreadable = append(unreadable, fmt.Sprintf("element %q has a negative digestID", isi.ElementIdentifier))
	}

	if r, ok := itemMap["random"].([]byte); ok {
		isi.Random = r
	} else {
		unreadable = append(unreadable, fmt.Sprintf("element %q has no random byte string", isi.ElementIdentifier))
	}

	if _, ok := itemMap["elementValue"]; !ok {
		unreadable = append(unreadable, fmt.Sprintf("element %q has no elementValue", isi.ElementIdentifier))
	}
	isi.ElementValue = cborview.Value(itemMap["elementValue"])

	return isi, unreadable, nil
}

func parseIssuerAuth(raw any) (*IssuerAuth, []string, error) {
	// COSE_Sign1 = [protected, unprotected, payload, signature]. coseBytes is the
	// untagged array for parsing. rawCOSE is the Tag-18 form go-cose verifies.
	var coseBytes []byte
	var rawCOSE []byte

	switch v := raw.(type) {
	case []byte:
		untagged, err := format.StripCBORTag(v, 18)
		if err != nil {
			return nil, nil, err
		}
		coseBytes = untagged
		rawCOSE, err = cbor.Marshal(cbor.Tag{Number: 18, Content: cbor.RawMessage(untagged)})
		if err != nil {
			return nil, nil, err
		}
	case cbor.Tag:
		tagged, err := cbor.Marshal(v)
		if err != nil {
			return nil, nil, err
		}
		rawCOSE = tagged

		if b, ok := v.Content.([]byte); ok {
			coseBytes = b
		} else {
			b, err := cbor.Marshal(v.Content)
			if err != nil {
				return nil, nil, err
			}
			coseBytes = b
		}
	default:
		// A DeviceResponse round trip strips the tag and leaves []any. go-cose needs Tag 18.
		b, err := cbor.Marshal(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot handle issuerAuth type %T", raw)
		}
		coseBytes = b
		rawCOSE, err = cbor.Marshal(cbor.Tag{Number: 18, Content: raw})
		if err != nil {
			rawCOSE = b
		}
	}

	var coseArr []cbor.RawMessage
	if err := cborview.DecMode.Unmarshal(coseBytes, &coseArr); err != nil {
		return nil, nil, fmt.Errorf("decoding COSE_Sign1 array: %w", err)
	}

	if len(coseArr) != 4 {
		return nil, nil, fmt.Errorf("COSE_Sign1 expected 4 elements, got %d", len(coseArr))
	}

	ia := &IssuerAuth{RawCOSE: rawCOSE}

	// RFC 9052 §4.2 makes the protected header a byte string. It is empty or
	// holds a map.
	var unreadable []string
	var protectedBytes []byte
	if err := cborview.DecMode.Unmarshal(coseArr[0], &protectedBytes); err != nil {
		unreadable = append(unreadable, "the protected header of issuerAuth is not a byte string")
	} else if len(protectedBytes) > 0 {
		var header map[any]any
		if err := cborview.DecMode.Unmarshal(protectedBytes, &header); err != nil {
			unreadable = append(unreadable, "the protected header of issuerAuth is not a CBOR map")
		}
	}
	var header map[any]any
	if err := cborview.DecMode.Unmarshal(coseArr[1], &header); err != nil {
		unreadable = append(unreadable, "the unprotected header of issuerAuth is not a CBOR map")
	}

	// The payload may be nil or wrapped in tag 24.
	var payload []byte
	if err := cborview.DecMode.Unmarshal(coseArr[2], &payload); err == nil {
		ia.Payload = payload
	} else {
		inner, err := cborview.UnwrapTag24(coseArr[2])
		if err == nil {
			ia.Payload = inner
		}
	}

	var sig []byte
	if err := cborview.DecMode.Unmarshal(coseArr[3], &sig); err == nil {
		ia.Signature = sig
	} else {
		unreadable = append(unreadable, "the signature of issuerAuth is not a byte string")
	}

	if ia.Payload == nil {
		return ia, append(unreadable, "issuerAuth has no payload, so there is no MSO"), nil
	}
	msoBytes := ia.Payload
	if inner, err := cborview.UnwrapTag24(msoBytes); err == nil {
		msoBytes = inner
	}
	mso, msoUnreadable, err := parseMSO(msoBytes)
	if err != nil {
		return ia, append(unreadable, "the MSO is not a CBOR map"), nil
	}
	ia.MSO = mso
	return ia, append(unreadable, msoUnreadable...), nil
}

// parseMSO returns the MSO and the unreadable required members (ISO/IEC 18013-5
// §9.1.2.4).
func parseMSO(data []byte) (*MSO, []string, error) {
	var msoMap map[any]any
	if err := cborview.DecMode.Unmarshal(data, &msoMap); err != nil {
		return nil, nil, err
	}

	mso := &MSO{}
	var unreadable []string
	text := func(name string) string {
		value, ok := msoMap[name].(string)
		if !ok {
			unreadable = append(unreadable, fmt.Sprintf("the MSO has no %s text", name))
		}
		return value
	}
	mso.Version = text("version")
	mso.DigestAlgorithm = text("digestAlgorithm")
	mso.DocType = text("docType")

	vd, ok := msoMap["valueDigests"].(map[any]any)
	if !ok {
		unreadable = append(unreadable, "the MSO has no valueDigests map")
	} else {
		mso.ValueDigests = make(map[string]map[uint64][]byte)
	}
	for nsKey, nsVal := range vd {
		ns := fmt.Sprintf("%v", nsKey)
		mso.ValueDigests[ns] = make(map[uint64][]byte)
		digestMap, ok := nsVal.(map[any]any)
		if _, isText := nsKey.(string); !ok || !isText {
			unreadable = append(unreadable, fmt.Sprintf("valueDigests of namespace %q is not a map under a text key", ns))
		}
		for dk, dv := range digestMap {
			var idx uint64
			switch v := dk.(type) {
			case uint64:
				idx = v
			case int64:
				idx = uint64(v)
				if v < 0 {
					unreadable = append(unreadable, fmt.Sprintf("valueDigests of namespace %q has a negative digestID", ns))
				}
			default:
				unreadable = append(unreadable, fmt.Sprintf("valueDigests of namespace %q has a digestID that is not a number", ns))
			}
			if b, ok := dv.([]byte); ok {
				mso.ValueDigests[ns][idx] = b
			} else {
				unreadable = append(unreadable, fmt.Sprintf("digest %d of namespace %q is not a byte string", idx, ns))
			}
		}
	}

	if vi, ok := msoMap["validityInfo"].(map[any]any); ok {
		mso.ValidityInfo = parseValidityInfo(vi)
		for _, date := range []struct {
			name  string
			value *time.Time
		}{{"signed", mso.ValidityInfo.Signed}, {"validFrom", mso.ValidityInfo.ValidFrom}, {"validUntil", mso.ValidityInfo.ValidUntil}} {
			if date.value == nil {
				unreadable = append(unreadable, fmt.Sprintf("validityInfo has no %s date-time", date.name))
			}
		}
	} else {
		unreadable = append(unreadable, "the MSO has no validityInfo map")
	}

	if dk, ok := msoMap["deviceKeyInfo"].(map[any]any); ok {
		mso.hasDeviceKeyInfo = true
		// A COSE library reads the key from its original encoding.
		if key, ok := dk["deviceKey"]; ok {
			if raw, err := cbor.Marshal(key); err == nil {
				mso.deviceKeyCBOR = raw
			}
		}
		if _, isMap := dk["deviceKey"].(map[any]any); !isMap {
			unreadable = append(unreadable, "deviceKeyInfo has no deviceKey map")
		}
	} else {
		unreadable = append(unreadable, "the MSO has no deviceKeyInfo map")
	}

	if st, ok := msoMap["status"].(map[any]any); ok {
		mso.status = cborview.StringKeys(st)
	} else if _, present := msoMap["status"]; present {
		unreadable = append(unreadable, "the status of the MSO is not a map")
	}

	return mso, unreadable, nil
}

func parseValidityInfo(vi map[any]any) *ValidityInfo {
	info := &ValidityInfo{}

	parseTime := func(key string) *time.Time {
		v, ok := vi[key]
		if !ok {
			return nil
		}
		switch val := v.(type) {
		case string:
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return nil
			}
			return &t
		case time.Time:
			return &val
		case cbor.Tag:
			// Tag 0 is a date-time string (RFC 8949 §3.4.1).
			if s, ok := val.Content.(string); ok {
				t, err := time.Parse(time.RFC3339, s)
				if err != nil {
					return nil
				}
				return &t
			}
		}
		return nil
	}

	info.Signed = parseTime("signed")
	info.ValidFrom = parseTime("validFrom")
	info.ValidUntil = parseTime("validUntil")

	return info
}

// StatusClaims returns the status of the MSO in the shape of a JWT status
// claim, {"status": {"status_list": ...}}, or nil without one (ISO/IEC 18013-5
// with the Token Status List draft §6.3).
func (d *Document) StatusClaims() map[string]any {
	if d == nil || d.IssuerAuth == nil || d.IssuerAuth.MSO == nil || d.IssuerAuth.MSO.status == nil {
		return nil
	}
	return map[string]any{"status": d.IssuerAuth.MSO.status}
}
