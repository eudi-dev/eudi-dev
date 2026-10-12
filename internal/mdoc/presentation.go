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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

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
	hash, err := DigestHasher(mso.DigestAlgorithm)
	if err != nil {
		return err
	}
	if len(doc.NameSpaces) == 0 {
		return fmt.Errorf("document discloses no elements")
	}

	for namespace, items := range doc.NameSpaces {
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
				return fmt.Errorf("element %q kept no encoded form to hash", item.ElementIdentifier)
			}
			got := hash(item.RawCBOR)
			if !bytes.Equal(got, want) {
				return fmt.Errorf("element %q does not match the digest the issuer signed", item.ElementIdentifier)
			}
		}
	}
	return nil
}

// VerifyDeviceAuth checks that the holder signed this presentation for this
// exact request. The signature covers the session transcript, so a response
// captured from one request cannot be replayed into another.
func VerifyDeviceAuth(doc *Document, sessionTranscript []byte) error {
	if doc == nil || doc.DeviceSigned == nil || doc.DeviceSigned.DeviceAuth == nil {
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
	// DocType, DeviceNameSpacesBytes]. The payload is Tag24 of its CBOR. The
	// holder signed the session transcript and the namespaces bytes verbatim,
	// and re-encoding breaks an mdoc handover that carries a map or a tag.
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
		return fmt.Errorf("the device signature names no algorithm: %w", err)
	}
	verifier, err := NewCOSEVerifier(alg, deviceKey)
	if err != nil {
		return fmt.Errorf("creating the device signature verifier: %w", err)
	}
	// The payload is detached. The response carries only the signature over the
	// DeviceAuthentication rebuilt above. A mismatch means a different request.
	msg.Payload = payload
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("the device signature does not verify against this request: %w", err)
	}
	return nil
}

func DeviceKey(doc *Document) (*ecdsa.PublicKey, error) {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return nil, fmt.Errorf("document carries no MSO")
	}
	info := doc.IssuerAuth.MSO.DeviceKeyInfo
	if info == nil {
		return nil, fmt.Errorf("the MSO names no device key, so the credential is not holder-bound")
	}
	if _, ok := info["deviceKey"]; !ok {
		return nil, fmt.Errorf("deviceKeyInfo carries no deviceKey")
	}
	if len(doc.IssuerAuth.MSO.DeviceKeyCBOR) == 0 {
		return nil, fmt.Errorf("deviceKey is not a COSE_Key map")
	}

	var key cose.Key
	if err := key.UnmarshalCBOR(doc.IssuerAuth.MSO.DeviceKeyCBOR); err != nil {
		return nil, fmt.Errorf("device key is not a valid COSE_Key: %w", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("device key is %T, not an EC2 key", pub)
	}
	if _, err := ecPub.ECDH(); err != nil {
		return nil, fmt.Errorf("device key is not a point on %s", ecPub.Curve.Params().Name)
	}
	return ecPub, nil
}

func coseInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

// DigestHasher returns the hash function named by an MSO digestAlgorithm. A
// missing algorithm reads as SHA-256.
func DigestHasher(alg string) (func([]byte) []byte, error) {
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

func ItemDigest(doc *Document, namespace string, item IssuerSignedItem) (got, want []byte, err error) {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return nil, nil, fmt.Errorf("document carries no MSO")
	}
	hash, err := DigestHasher(doc.IssuerAuth.MSO.DigestAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	if len(item.RawCBOR) == 0 {
		return nil, nil, fmt.Errorf("element kept no encoded form to hash")
	}
	got = hash(item.RawCBOR)
	want = doc.IssuerAuth.MSO.ValueDigests[namespace][item.DigestID]
	return got, want, nil
}

var coseHeaderLabels = map[int64]string{
	1: "alg", 2: "crit", 3: "content type", 4: "kid",
	32: "x5bag", 33: "x5chain", 34: "x5t", 35: "x5u",
}

// NameCOSEHeader replaces numeric COSE labels with registered names for display.
func NameCOSEHeader(header map[string]any) map[string]any {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]any, len(header))
	for key, value := range header {
		label := key
		if n, err := strconv.ParseInt(key, 10, 64); err == nil {
			if name, ok := coseHeaderLabels[n]; ok {
				label = name
			}
			if n == 1 {
				if alg, ok := coseAlgorithms[cose.Algorithm(coseInt(value))]; ok {
					value = alg.name
				}
			}
		}
		if label == "x5chain" || label == "x5bag" {
			value = describeCertificates(value)
		}
		out[label] = value
	}
	return out
}

func describeCertificates(value any) any {
	var ders [][]byte
	switch v := value.(type) {
	case []byte:
		ders = [][]byte{v}
	case []any:
		for _, entry := range v {
			if der, ok := entry.([]byte); ok {
				ders = append(ders, der)
			}
		}
	default:
		return value
	}
	out := make([]any, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			out = append(out, fmt.Sprintf("%d bytes (unparseable)", len(der)))
			continue
		}
		out = append(out, map[string]any{
			"subject":   cert.Subject.String(),
			"issuer":    cert.Issuer.String(),
			"notAfter":  cert.NotAfter.Format("2006-01-02"),
			"serial":    cert.SerialNumber.String(),
			"algorithm": cert.SignatureAlgorithm.String(),
		})
	}
	return out
}

// NameCOSEKey replaces numeric COSE_Key labels with registered names for display.
func NameCOSEKey(key map[string]any) map[string]any {
	if len(key) == 0 {
		return nil
	}
	names := map[string]string{"1": "kty", "-1": "crv", "-2": "x", "-3": "y", "3": "alg", "2": "kid"}
	ktyNames := map[int64]string{1: "OKP", 2: "EC2", 3: "RSA", 4: "Symmetric"}
	crvNames := map[int64]string{1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519"}
	out := make(map[string]any, len(key))
	for k, v := range key {
		name := k
		if named, ok := names[k]; ok {
			name = named
		}
		switch name {
		case "kty":
			if s, ok := ktyNames[coseInt(v)]; ok {
				v = s
			}
		case "crv":
			if s, ok := crvNames[coseInt(v)]; ok {
				v = s
			}
		case "x", "y":
			if b, ok := v.([]byte); ok {
				v = base64.RawURLEncoding.EncodeToString(b)
			}
		case "alg":
			if alg, ok := coseAlgorithms[cose.Algorithm(coseInt(v))]; ok {
				v = alg.name
			}
		}
		out[name] = v
	}
	return out
}
