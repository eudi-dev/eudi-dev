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
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/coseutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
)

// VerifyValueDigests checks the disclosed items against the digests in the MSO.
// The issuer signature covers only the MSO, so this check protects the element
// values.
func VerifyValueDigests(doc *Document) error {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return fmt.Errorf("document carries no MSO to check digests against")
	}
	mso := doc.IssuerAuth.MSO
	hash, err := digestHasher(mso.DigestAlgorithm)
	if err != nil {
		return err
	}
	if len(doc.NameSpaces) == 0 {
		return fmt.Errorf("document discloses no elements")
	}

	// The namespaces go in name order, and the items keep their order in the
	// document. Then an error reports the same element on every run.
	for _, namespace := range slices.Sorted(maps.Keys(doc.NameSpaces)) {
		items := doc.NameSpaces[namespace]
		digests, ok := mso.ValueDigests[namespace]
		if !ok {
			return fmt.Errorf("the MSO carries no digests for namespace %q", namespace)
		}
		for _, item := range items {
			want, ok := digests[item.DigestID]
			if !ok {
				return fmt.Errorf("element %q has digest id %d, which the MSO does not list",
					item.ElementIdentifier, item.DigestID)
			}
			if len(item.RawCBOR) == 0 {
				return fmt.Errorf("element %q has no encoded form to hash", item.ElementIdentifier)
			}
			got := hash(item.RawCBOR)
			if !bytes.Equal(got, want) {
				return fmt.Errorf("element %q does not match its digest in the MSO", item.ElementIdentifier)
			}
		}
	}
	return nil
}

// VerifyDeviceAuth checks that the holder signed this presentation for this
// exact request. The signature covers the session transcript, so a response
// captured from one request cannot be replayed into another.
func VerifyDeviceAuth(doc *Document, sessionTranscript []byte) error {
	if doc == nil || doc.DeviceSigned == nil || len(doc.DeviceSigned.RawDeviceAuth) == 0 {
		return fmt.Errorf("presentation carries no device signature")
	}
	if len(doc.DeviceSigned.RawDeviceSignature) == 0 {
		return fmt.Errorf("device authentication is not a signature (deviceMac is not supported)")
	}

	deviceKey, err := DeviceKey(doc)
	if err != nil {
		return err
	}

	// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
	// DocType, DeviceNameSpacesBytes]. The payload is its CBOR wrapped in tag 24. The
	// holder signed the session transcript and the namespaces bytes verbatim.
	// Re-encoding breaks an mdoc handover with a map or a tag inside.
	if len(doc.DeviceSigned.RawNameSpaces) == 0 {
		return fmt.Errorf("deviceSigned carries no nameSpaces")
	}
	if err := cbor.Wellformed(sessionTranscript); err != nil {
		return fmt.Errorf("the session transcript is not valid CBOR: %w", err)
	}
	authentication, err := cbor.Marshal([]any{
		"DeviceAuthentication", cbor.RawMessage(sessionTranscript), doc.DocType, cbor.RawMessage(doc.DeviceSigned.RawNameSpaces),
	})
	if err != nil {
		return fmt.Errorf("encoding DeviceAuthentication: %w", err)
	}
	payload, err := tag24Raw(authentication)
	if err != nil {
		return err
	}

	// DeviceAuth carries the COSE_Sign1 untagged.
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(doc.DeviceSigned.RawDeviceSignature); err != nil {
		return fmt.Errorf("parsing the device signature: %w", err)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("the device signature has no algorithm: %w", err)
	}
	verifier, err := coseutil.NewVerifier(alg, deviceKey)
	if err != nil {
		return fmt.Errorf("creating the device signature verifier: %w", err)
	}
	// The payload is detached. The response carries only the signature over the
	// DeviceAuthentication rebuilt above. A mismatch means a different request.
	msg.Payload = payload
	if err := msg.Verify(nil, verifier); err != nil {
		return signatureError("the device signature does not verify against this request: ", err)
	}
	return nil
}

// DeviceKey returns the device key of the MSO (ISO/IEC 18013-5 §9.1.2.4,
// deviceKeyInfo). VerifyDeviceAuth verifies the device signature with it.
func DeviceKey(doc *Document) (*ecdsa.PublicKey, error) {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return nil, fmt.Errorf("%w: document carries no MSO", ErrNoDeviceKey)
	}
	if !doc.IssuerAuth.MSO.hasDeviceKeyInfo {
		return nil, fmt.Errorf("%w: the MSO has no deviceKeyInfo, so the credential is not holder-bound", ErrNoDeviceKey)
	}
	if len(doc.IssuerAuth.MSO.deviceKeyCBOR) == 0 {
		return nil, fmt.Errorf("%w: deviceKeyInfo carries no deviceKey", ErrNoDeviceKey)
	}

	var key cose.Key
	if err := key.UnmarshalCBOR(doc.IssuerAuth.MSO.deviceKeyCBOR); err != nil {
		return nil, fmt.Errorf("device key is not a valid COSE_Key: %w", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the device key is a %T. ES256 needs an EC2 key", pub)
	}
	if _, err := ecPub.ECDH(); err != nil {
		return nil, fmt.Errorf("device key is not a point on %s", ecPub.Curve.Params().Name)
	}
	return ecPub, nil
}

// digestHasher returns the hash function for an MSO digestAlgorithm. A
// missing algorithm means SHA-256.
func digestHasher(alg string) (func([]byte) []byte, error) {
	switch alg {
	case "", "SHA-256":
		return func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }, nil
	case "SHA-384":
		return func(b []byte) []byte { sum := sha512.Sum384(b); return sum[:] }, nil
	case "SHA-512":
		return func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] }, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
}

func tag24(value any) ([]byte, error) {
	encoded, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}
	return tag24Raw(encoded)
}

func tag24Raw(encoded []byte) ([]byte, error) {
	wrapped, err := cbor.Marshal(cbor.Tag{Number: 24, Content: encoded})
	if err != nil {
		return nil, fmt.Errorf("wrapping in Tag 24: %w", err)
	}
	return wrapped, nil
}

// DeviceKeyThumbprint is the RFC 7638 JWK thumbprint of a device key. It
// identifies the key like a kid does elsewhere in the toolkit.
func DeviceKeyThumbprint(key *ecdsa.PublicKey) string {
	if key == nil {
		return ""
	}
	sum, err := keys.PublicKeyThumbprint(key)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(sum)
}

// ItemDigest returns two digests for item. got uses the digest algorithm of the
// MSO. want is the digest stored in the MSO for namespace. want is empty when
// the MSO has no digest for item. VerifyValueDigests compares the two for
// every data element.
func ItemDigest(doc *Document, namespace string, item IssuerSignedItem) (got, want []byte, err error) {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return nil, nil, fmt.Errorf("document carries no MSO")
	}
	hash, err := digestHasher(doc.IssuerAuth.MSO.DigestAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	if len(item.RawCBOR) == 0 {
		return nil, nil, fmt.Errorf("element has no encoded form to hash")
	}
	got = hash(item.RawCBOR)
	want = doc.IssuerAuth.MSO.ValueDigests[namespace][item.DigestID]
	return got, want, nil
}
