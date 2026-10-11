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

// Package mdoc parses and verifies ISO 18013-5 mdoc (mso_mdoc) credentials encoded as CBOR/COSE.
package mdoc

import "time"

type Document struct {
	Raw          []byte
	DocType      string
	NameSpaces   map[string][]IssuerSignedItem
	IssuerAuth   *IssuerAuth
	DeviceSigned *DeviceSigned
	// ResponseVersion and ResponseStatus are DeviceResponse members outside the
	// document.
	ResponseVersion  string
	ResponseStatus   *uint64
	IsDeviceResponse bool
	// Deviations records unreadable parts the parser dropped, such as a malformed
	// namespace or a repeated element. The rest of the document still displays.
	// Strict mode rejects a document with deviations.
	Deviations []string
}

type DeviceSigned struct {
	DeviceAuth map[string]any
	// RawDeviceSignature is the deviceSignature COSE_Sign1 as it arrived. Only
	// this form can be verified.
	RawDeviceSignature []byte
	// RawNameSpaces is the DeviceNameSpacesBytes as it arrived. The device
	// signature covers this encoding.
	RawNameSpaces []byte
}

type IssuerSignedItem struct {
	DigestID          uint64
	Random            []byte
	ElementIdentifier string
	ElementValue      any
	// RawCBOR holds the original Tag-24 encoded bytes. Digest verification
	// against MSO ValueDigests hashes them.
	RawCBOR []byte
}

type IssuerAuth struct {
	RawCOSE           []byte
	ProtectedHeader   map[any]any
	UnprotectedHeader map[any]any
	Payload           []byte
	Signature         []byte
	MSO               *MSO
}

// MSO is the Mobile Security Object.
type MSO struct {
	Version         string
	DigestAlgorithm string
	DocType         string
	ValueDigests    map[string]map[uint64][]byte
	ValidityInfo    *ValidityInfo
	DeviceKeyInfo   map[string]any
	// DeviceKeyCBOR is the deviceKey COSE_Key as it was encoded. DeviceKeyInfo
	// above has string labels for display, and no COSE library reads those.
	DeviceKeyCBOR []byte
	Status        map[string]any
}

type ValidityInfo struct {
	Signed     *time.Time
	ValidFrom  *time.Time
	ValidUntil *time.Time
}
