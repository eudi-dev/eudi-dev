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
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

func Parse(raw string) (*Document, error) {
	raw = strings.TrimSpace(raw)

	data, err := format.DecodeHexOrBase64URL(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding input: %w", err)
	}

	var top map[any]any
	if err := cborDecMode.Unmarshal(data, &top); err != nil {
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
	if err := cborDecMode.Unmarshal(data, &resp); err != nil {
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

	// Only the first document is read.
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
			doc.Deviations = append(doc.Deviations, fmt.Sprintf("the document names docType %q, but the issuer signed %q in the MSO", dt, doc.DocType))
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

	doc.IsDeviceResponse = true
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
	result.DeviceAuth = convertCBORMapToStringKeys(da)
	// The COSE_Sign1 must be verified as it arrived. The display map above turns
	// integer labels into strings and unwraps tags, so it cannot be verified.
	if sig, ok := da["deviceSignature"]; ok {
		if encoded, err := cbor.Marshal(sig); err == nil {
			result.RawDeviceSignature = encoded
		}
	}
	return result
}

func parseIssuerSigned(data []byte) (*Document, error) {
	var issuerSigned map[any]any
	if err := cborDecMode.Unmarshal(data, &issuerSigned); err != nil {
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
				isi, err := parseIssuerSignedItem(item)
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

	if auth, ok := issuerSigned["issuerAuth"]; ok {
		ia, err := parseIssuerAuth(auth)
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

func parseIssuerSignedItem(raw any) (*IssuerSignedItem, error) {
	// Items are Tag-24 wrapped CBOR bstr. MSO ValueDigests hash the complete
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
				return nil, fmt.Errorf("tag 24 content is not bstr")
			}
		} else {
			return nil, fmt.Errorf("unexpected tag: %d", v.Number)
		}
	default:
		b, err := cbor.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("cannot handle item type %T", raw)
		}
		rawTag24 = b
		inner, err := unmarshalTag24(b)
		if err != nil {
			return nil, err
		}
		itemBytes = inner
	}

	var itemMap map[any]any
	if err := cborDecMode.Unmarshal(itemBytes, &itemMap); err != nil {
		return nil, fmt.Errorf("decoding IssuerSignedItem: %w", err)
	}

	rawForDigest := rawTag24
	if rawForDigest == nil {
		rawForDigest = itemBytes
	}

	isi := &IssuerSignedItem{
		RawCBOR: rawForDigest,
	}

	if did, ok := itemMap["digestID"]; ok {
		switch v := did.(type) {
		case uint64:
			isi.DigestID = v
		case int64:
			isi.DigestID = uint64(v)
		}
	}

	if r, ok := itemMap["random"].([]byte); ok {
		isi.Random = r
	}

	if ei, ok := itemMap["elementIdentifier"].(string); ok {
		isi.ElementIdentifier = ei
	}

	isi.ElementValue = convertCBORValue(itemMap["elementValue"])

	return isi, nil
}

func parseIssuerAuth(raw any) (*IssuerAuth, error) {
	// COSE_Sign1 = [protected, unprotected, payload, signature]. coseBytes is the
	// untagged array for parsing. rawCOSE is the Tag-18 form go-cose verifies.
	var coseBytes []byte
	var rawCOSE []byte

	switch v := raw.(type) {
	case []byte:
		untagged, err := format.StripCBORTag(v, 18)
		if err != nil {
			return nil, err
		}
		coseBytes = untagged
		rawCOSE, err = cbor.Marshal(cbor.Tag{Number: 18, Content: cbor.RawMessage(untagged)})
		if err != nil {
			return nil, err
		}
	case cbor.Tag:
		tagged, err := cbor.Marshal(v)
		if err != nil {
			return nil, err
		}
		rawCOSE = tagged

		if b, ok := v.Content.([]byte); ok {
			coseBytes = b
		} else {
			b, err := cbor.Marshal(v.Content)
			if err != nil {
				return nil, err
			}
			coseBytes = b
		}
	default:
		// A DeviceResponse round trip strips the tag and leaves []any. go-cose needs Tag 18.
		b, err := cbor.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("cannot handle issuerAuth type %T", raw)
		}
		coseBytes = b
		rawCOSE, err = cbor.Marshal(cbor.Tag{Number: 18, Content: raw})
		if err != nil {
			rawCOSE = b
		}
	}

	var coseArr []cbor.RawMessage
	if err := cborDecMode.Unmarshal(coseBytes, &coseArr); err != nil {
		return nil, fmt.Errorf("decoding COSE_Sign1 array: %w", err)
	}

	if len(coseArr) != 4 {
		return nil, fmt.Errorf("COSE_Sign1 expected 4 elements, got %d", len(coseArr))
	}

	ia := &IssuerAuth{RawCOSE: rawCOSE}

	var protectedBytes []byte
	if err := cborDecMode.Unmarshal(coseArr[0], &protectedBytes); err == nil && len(protectedBytes) > 0 {
		var ph map[any]any
		if err := cborDecMode.Unmarshal(protectedBytes, &ph); err == nil {
			ia.ProtectedHeader = ph
		}
	}

	var uph map[any]any
	if err := cborDecMode.Unmarshal(coseArr[1], &uph); err == nil {
		ia.UnprotectedHeader = uph
	}

	// The payload may be nil or Tag-24 wrapped.
	var payload []byte
	if err := cborDecMode.Unmarshal(coseArr[2], &payload); err == nil {
		ia.Payload = payload
	} else {
		inner, err := unmarshalTag24(coseArr[2])
		if err == nil {
			ia.Payload = inner
		}
	}

	var sig []byte
	if err := cborDecMode.Unmarshal(coseArr[3], &sig); err == nil {
		ia.Signature = sig
	}

	if ia.Payload != nil {
		msoBytes := ia.Payload
		if inner, err := unmarshalTag24(msoBytes); err == nil {
			msoBytes = inner
		}
		mso, err := parseMSO(msoBytes)
		if err == nil {
			ia.MSO = mso
		}
	}

	return ia, nil
}

func parseMSO(data []byte) (*MSO, error) {
	var msoMap map[any]any
	if err := cborDecMode.Unmarshal(data, &msoMap); err != nil {
		return nil, err
	}

	mso := &MSO{}

	if v, ok := msoMap["version"].(string); ok {
		mso.Version = v
	}
	if v, ok := msoMap["digestAlgorithm"].(string); ok {
		mso.DigestAlgorithm = v
	}
	if v, ok := msoMap["docType"].(string); ok {
		mso.DocType = v
	}

	if vd, ok := msoMap["valueDigests"].(map[any]any); ok {
		mso.ValueDigests = make(map[string]map[uint64][]byte)
		for nsKey, nsVal := range vd {
			ns := fmt.Sprintf("%v", nsKey)
			mso.ValueDigests[ns] = make(map[uint64][]byte)
			if digestMap, ok := nsVal.(map[any]any); ok {
				for dk, dv := range digestMap {
					var idx uint64
					switch v := dk.(type) {
					case uint64:
						idx = v
					case int64:
						idx = uint64(v)
					}
					if b, ok := dv.([]byte); ok {
						mso.ValueDigests[ns][idx] = b
					}
				}
			}
		}
	}

	if vi, ok := msoMap["validityInfo"].(map[any]any); ok {
		mso.ValidityInfo = parseValidityInfo(vi)
	}

	if dk, ok := msoMap["deviceKeyInfo"].(map[any]any); ok {
		mso.DeviceKeyInfo = convertCBORMapToStringKeys(dk)
		// The labels are still integers here. The display map above has string keys.
		if raw, err := cbor.Marshal(dk["deviceKey"]); err == nil {
			mso.DeviceKeyCBOR = raw
		}
	}

	if st, ok := msoMap["status"].(map[any]any); ok {
		mso.Status = convertCBORMapToStringKeys(st)
	}

	return mso, nil
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

func convertCBORValue(v any) any {
	switch val := v.(type) {
	case time.Time:
		// The decoder turns a tdate (tag 0) into a time.Time. A full-date
		// (tag 1004) stays a string. Both display the same way.
		return val.UTC().Format(time.RFC3339)
	case map[any]any:
		return convertCBORMapToStringKeys(val)
	case []any:
		result := make([]any, len(val))
		for i, item := range val {
			result[i] = convertCBORValue(item)
		}
		return result
	case cbor.Tag:
		if val.Number == 0 {
			if s, ok := val.Content.(string); ok {
				return s
			}
		}
		if val.Number == 24 {
			if b, ok := val.Content.([]byte); ok {
				decoded, err := decodeCBOR(b)
				if err == nil {
					return convertCBORValue(decoded)
				}
			}
		}
		return convertCBORValue(val.Content)
	default:
		return v
	}
}

// StatusClaims returns the status of the MSO in the shape of a JWT status
// claim, {"status": {"status_list": ...}}, or nil without one (ISO 18013-5
// with the Token Status List draft §6.3).
func (d *Document) StatusClaims() map[string]any {
	if d == nil || d.IssuerAuth == nil || d.IssuerAuth.MSO == nil || d.IssuerAuth.MSO.Status == nil {
		return nil
	}
	return map[string]any{"status": d.IssuerAuth.MSO.Status}
}
