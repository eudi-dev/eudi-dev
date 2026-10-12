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

package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

// COSE tags from RFC 9052 section 2 and the CWT tag from RFC 8392 section 6.
const (
	tagCOSESign1 = 18
	tagCOSEMac0  = 17
	tagCWT       = 61
)

var cwtDecMode cbor.DecMode

func init() {
	// Unsigned integers decode as signed, so a CWT claim key always has one Go type.
	var err error
	cwtDecMode, err = cbor.DecOptions{IntDec: cbor.IntDecConvertSigned}.DecMode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "statuslist: failed to initialize CBOR decode mode: %v\n", err)
		os.Exit(1)
	}
}

// parseCWTStatusListToken parses and verifies a Status List Token in CWT
// format (Section 5.2).
func parseCWTStatusListToken(body []byte, opts CheckOptions) (*statusListToken, error) {
	// Section 5.2: "The Status List Token MUST NOT be tagged with the CWT tag
	// defined in Section 6 of [RFC8392]. The COSE message MUST either be the
	// tagged COSE_Sign1_Tagged (18) or COSE_Mac0_Tagged (17)".
	var raw cbor.RawTag
	if err := cwtDecMode.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("the status list token is not a tagged COSE message, which section 5.2 requires: %w", err)
	}
	switch raw.Number {
	case tagCOSESign1:
	case tagCOSEMac0:
		return nil, fmt.Errorf("the status list token is a COSE_Mac0 message, which cannot be verified without the shared MAC key")
	case tagCWT:
		return nil, fmt.Errorf("the status list token carries the CWT tag 61, which section 5.2 forbids")
	default:
		return nil, fmt.Errorf("the status list token is CBOR tag %d, section 5.2 requires the tagged COSE_Sign1_Tagged (18)", raw.Number)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(body); err != nil {
		return nil, fmt.Errorf("parsing COSE_Sign1: %w", err)
	}

	// Section 5.2: "16 (type): REQUIRED. The type of the CWT MUST be
	// application/statuslist+cwt or the registered CoAP Content-Format ID".
	typeWarning, err := cwtType(msg.Headers.Protected)
	if err != nil {
		return nil, err
	}

	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("the status list token's protected header has no algorithm: %w", err)
	}
	switch alg {
	case cose.AlgorithmES256, cose.AlgorithmES384:
	default:
		return nil, fmt.Errorf("the status list token is signed with %v, which is not one of the accepted algorithms ES256 and ES384", alg)
	}

	certs, err := certsFromX5Chain(msg.Headers)
	if err != nil {
		return nil, err
	}

	// A COSE kid is a byte string. A DID reference puts its text there.
	kid, _ := msg.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	candidates, err := resolveKeys(certs, nil, string(kid), opts)
	if err != nil {
		return nil, err
	}

	verified := false
	for _, key := range candidates.keys {
		verifier, err := cose.NewVerifier(alg, key)
		if err != nil {
			continue
		}
		if err := msg.Verify(nil, verifier); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("the status list token's %v signature does not verify", alg)
	}

	tok := &statusListToken{
		format:        FormatCWT,
		signatureInfo: candidates.info,
		trustAnchored: candidates.anchored,
	}
	if candidates.warning != "" {
		tok.warnings = append(tok.warnings, candidates.warning)
	}
	if typeWarning != "" {
		tok.warnings = append(tok.warnings, typeWarning)
	}

	var claims map[any]any
	if err := cwtDecMode.Unmarshal(msg.Payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing CWT claims set: %w", err)
	}

	tok.subject, _ = cwtClaim(claims, cwtClaimSubject).(string)
	tok.issuedAt = unixClaim(cwtClaim(claims, cwtClaimIssuedAt))
	tok.expiresAt = unixClaim(cwtClaim(claims, cwtClaimExpiration))
	if ttl := cwtClaim(claims, cwtClaimTTL); ttl != nil {
		if n, ok := asInt(ttl); !ok || n <= 0 {
			tok.warnings = append(tok.warnings, "the status list token's time to live claim is not a positive number, which section 5.2 requires")
		}
	}

	sl, ok := cwtClaim(claims, cwtClaimStatusList).(map[any]any)
	if !ok {
		return nil, fmt.Errorf("the status list token has no status list claim (65533), which section 5.2 requires")
	}
	if b, present := sl["bits"]; present {
		n, ok := asInt(b)
		if !ok {
			return nil, fmt.Errorf("the status list bits member is not an unsigned integer (%T)", b)
		}
		tok.bits = n
	}
	// Section 4.3: "lst: REQUIRED. CBOR Byte string (major type 2)". A text
	// string here is the base64url form of the JSON representation.
	if lst, present := sl["lst"]; present {
		b, ok := lst.([]byte)
		if !ok {
			return nil, fmt.Errorf("the status list lst member is not a CBOR byte string (%T), which section 4.3 requires", lst)
		}
		tok.lst = b
	}
	return tok, nil
}

// cwtType checks the COSE type header (16). It returns a warning when the
// value is well-formed and differs from the media type name.
func cwtType(protected cose.ProtectedHeader) (string, error) {
	value, present := headerValue(protected, coseHeaderType)
	if !present {
		return "", fmt.Errorf("the status list token has no type header (16), section 5.2 requires %q", MediaTypeCWT)
	}
	switch v := value.(type) {
	case string:
		if isStatusListTyp(v, "statuslist+cwt") {
			return "", nil
		}
		return "", fmt.Errorf("the status list token has type %q, section 5.2 requires %q", v, MediaTypeCWT)
	case int64, uint64, int:
		// Section 14.8 requests a CoAP Content-Format ID for
		// application/statuslist+cwt. The number is still TBD.
		return fmt.Sprintf("the status list token names its type by CoAP Content-Format ID %v, which section 14.8 has not had assigned yet", v), nil
	default:
		return "", fmt.Errorf("the status list token's type header (16) is a %T, section 5.2 requires the media type name or a CoAP Content-Format ID", value)
	}
}

// certsFromX5Chain reads the RFC 9360 x5chain header (33) from the protected
// or the unprotected bucket.
func certsFromX5Chain(headers cose.Headers) ([]*x509.Certificate, error) {
	value, present := headerValue(map[any]any(headers.Protected), coseHeaderX5Chain)
	if !present {
		value, present = headerValue(map[any]any(headers.Unprotected), coseHeaderX5Chain)
	}
	if !present {
		return nil, nil
	}

	var ders [][]byte
	switch v := value.(type) {
	case []byte:
		ders = [][]byte{v}
	case [][]byte:
		ders = v
	case []any:
		for _, entry := range v {
			der, ok := entry.([]byte)
			if !ok {
				return nil, fmt.Errorf("an x5chain entry in the status list token is not a byte string")
			}
			ders = append(ders, der)
		}
	default:
		return nil, fmt.Errorf("the status list token's x5chain header is a %T", value)
	}

	var certs []*x509.Certificate
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// headerValue looks up an integer-labelled COSE header. A label decodes as
// int64 or uint64 depending on the encoder.
func headerValue(h map[any]any, label int64) (any, bool) {
	for k, v := range h {
		switch key := k.(type) {
		case int64:
			if key == label {
				return v, true
			}
		case uint64:
			if int64(key) == label {
				return v, true
			}
		case int:
			if int64(key) == label {
				return v, true
			}
		}
	}
	return nil, false
}

func cwtClaim(claims map[any]any, key int64) any {
	v, _ := headerValue(claims, key)
	return v
}

// GenerateStatusListCWT creates a signed Status List Token in CWT format
// (Section 5.2) from a bitstring. The result is the raw binary COSE_Sign1
// for the response body of Section 8.2.
func GenerateStatusListCWT(bitstring []byte, signingKey *ecdsa.PrivateKey, cfg StatusListConfig) ([]byte, error) {
	if signingKey == nil {
		return nil, fmt.Errorf("signing requires a private key")
	}
	compressed, err := compressBitstring(bitstring)
	if err != nil {
		return nil, err
	}
	bits, err := normalizeBits(cfg.Bits)
	if err != nil {
		return nil, err
	}

	now := cfg.issuedAt()
	claims := map[int64]any{
		cwtClaimIssuer:     cfg.issuer(),
		cwtClaimSubject:    cfg.URI,
		cwtClaimIssuedAt:   now.Unix(),
		cwtClaimExpiration: now.Add(tokenLifetime).Unix(),
		cwtClaimTTL:        cfg.ttl(),
		cwtClaimStatusList: map[string]any{
			"bits": bits,
			"lst":  compressed,
		},
	}
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encoding CWT claims set: %w", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, signingKey)
	if err != nil {
		return nil, fmt.Errorf("creating COSE signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[int64(coseHeaderType)] = MediaTypeCWT
	msg.Payload = payload

	// RFC 9360 section 2 requires integrity protection for the leaf certificate.
	// EAA-6.2.10.1-08 (EU 2026/1731) places x5chain in the protected header.
	if chain := mock.WithoutSelfSignedTrustAnchor(cfg.CertChain); len(chain) > 0 {
		if len(chain) == 1 {
			msg.Headers.Protected[int64(coseHeaderX5Chain)] = chain[0].Raw
		} else {
			ders := make([][]byte, 0, len(chain))
			for _, cert := range chain {
				ders = append(ders, cert.Raw)
			}
			msg.Headers.Protected[int64(coseHeaderX5Chain)] = ders
		}
	}

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("COSE signing: %w", err)
	}
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encoding COSE_Sign1: %w", err)
	}
	return encoded, nil
}

// compressBitstring applies the Section 4.1 compression step: "The Status
// Issuer compresses the byte array using DEFLATE [RFC1951] with the ZLIB
// [RFC1950] data format. Implementations are RECOMMENDED to use the highest
// compression level available."
func compressBitstring(bitstring []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("creating zlib writer: %w", err)
	}
	if _, err := w.Write(bitstring); err != nil {
		return nil, fmt.Errorf("compressing bitstring: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing zlib writer: %w", err)
	}
	return buf.Bytes(), nil
}
