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

// Package mdoc parses and verifies mdoc credentials (ISO/IEC 18013-5) issued
// over OpenID4VCI and presented over OpenID4VP.
//
// Parse reads an IssuerSigned structure or a DeviceResponse and rejects what
// breaks ISO/IEC 18013-5. Verify checks the issuer signature over the MSO.
// VerifyValueDigests checks the data elements. ValidAt checks the validity
// period. VerifyDeviceAuth checks the device signature over a session
// transcript. The caller chooses the trusted key. ParseLenient reads a
// credential that breaks the specification and records each violation.
package mdoc

import "time"

// Document is a parsed mdoc: an IssuerSigned structure or the first document
// of a DeviceResponse.
type Document struct {
	// Raw is the decoded CBOR input.
	Raw []byte
	// DocType is the docType of the MSO. Without an MSO it is the docType of
	// the document in the DeviceResponse.
	DocType string
	// NameSpaces are the data elements by namespace.
	NameSpaces map[string][]IssuerSignedItem
	// IssuerAuth is the issuer signature with the MSO.
	IssuerAuth *IssuerAuth
	// DeviceSigned is the device part of a DeviceResponse document. It is nil
	// for an IssuerSigned structure.
	DeviceSigned *DeviceSigned
	// ResponseVersion is the version of the DeviceResponse.
	ResponseVersion string
	// ResponseStatus is the status of the DeviceResponse. 0 means OK.
	ResponseStatus *uint64
	// IsDeviceResponse is true when the input was a DeviceResponse.
	IsDeviceResponse bool
	// Documents counts the documents of a DeviceResponse. Only the first is
	// read.
	Documents int
	// Deviations lists the violations that ParseLenient accepted, such as a
	// malformed namespace or a repeated element. A missing or unreadable
	// required member is not listed. Parse rejects both.
	Deviations []string
	// unreadable lists required members that are missing or have the wrong
	// type. Parse rejects them.
	unreadable []string
}

// DeviceSigned is the DeviceSigned structure of a DeviceResponse document.
type DeviceSigned struct {
	// RawDeviceAuth is the CBOR encoding of the DeviceAuth map. It is empty
	// when the document has none.
	RawDeviceAuth []byte
	// RawDeviceSignature is the deviceSignature COSE_Sign1 as it arrived. Only
	// this form can be verified.
	RawDeviceSignature []byte
	// RawNameSpaces is the DeviceNameSpacesBytes as it arrived. The device
	// signature covers this encoding.
	RawNameSpaces []byte
}

// IssuerSignedItem is one data element with its salt.
type IssuerSignedItem struct {
	// DigestID is the key of the digest in the valueDigests of the MSO.
	DigestID uint64
	// Random is the salt.
	Random []byte
	// ElementIdentifier is the name of the data element.
	ElementIdentifier string
	// ElementValue is the value. A CBOR map has string keys, a date-time is an
	// RFC 3339 string and a tagged value is its content.
	ElementValue any
	// RawCBOR holds the original bytes, wrapped in tag 24. Digest verification
	// against MSO ValueDigests hashes them.
	RawCBOR []byte
}

// IssuerAuth is the COSE_Sign1 of the issuer over the MSO.
type IssuerAuth struct {
	// RawCOSE is the COSE_Sign1 with tag 18.
	RawCOSE []byte
	// Payload is the MobileSecurityObjectBytes.
	Payload []byte
	// Signature is the signature bytes.
	Signature []byte
	// MSO is the decoded payload. It is nil when the payload is unreadable.
	MSO *MSO
}

// MSO is the Mobile Security Object (ISO/IEC 18013-5 §9.1.2.4).
type MSO struct {
	// Version is the version of the MSO structure.
	Version string
	// DigestAlgorithm is the hash algorithm of the value digests, for example
	// SHA-256.
	DigestAlgorithm string
	// DocType is the document type signed by the issuer.
	DocType string
	// ValueDigests are the digests of the data elements by namespace and
	// digestID.
	ValueDigests map[string]map[uint64][]byte
	// ValidityInfo is the validity period.
	ValidityInfo *ValidityInfo

	hasDeviceKeyInfo bool
	// deviceKeyCBOR is the deviceKey COSE_Key as it was encoded.
	deviceKeyCBOR []byte
	// status is the status member with string keys.
	status map[string]any
}

// ValidityInfo holds the dates of the MSO. A nil date is missing or
// unreadable.
type ValidityInfo struct {
	// Signed is the time the issuer signed the MSO.
	Signed *time.Time
	// ValidFrom is the start of the validity period.
	ValidFrom *time.Time
	// ValidUntil is the end of the validity period.
	ValidUntil *time.Time
}
