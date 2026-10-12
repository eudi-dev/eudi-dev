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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func cwtServer(t *testing.T, key *ecdsa.PrivateKey, bits int, bitstring []byte, chain []*x509.Certificate) *httptest.Server {
	t.Helper()
	return statusListServer(t, func(uri string) (string, []byte) {
		token, err := GenerateStatusListCWT(bitstring, key, StatusListConfig{
			URI:       uri,
			Bits:      bits,
			CertChain: chain,
		})
		if err != nil {
			t.Errorf("GenerateStatusListCWT: %v", err)
			return "", nil
		}
		return MediaTypeCWT, token
	})
}

// Section 5.2 defines the CWT representation of a Status List Token. The
// checker must request it, parse the COSE_Sign1 and read the integer-keyed
// claims.
func TestCheck_ResolvesACWTStatusListToken(t *testing.T) {
	key := mustGenerateKey(t)
	bitstring := make([]byte, 16)
	bitstring[0] = 1 << 5
	srv := cwtServer(t, key, 1, bitstring, nil)

	result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 5}, CheckOptions{
		Keys: []crypto.PublicKey{&key.PublicKey},
	})
	if err != nil {
		t.Fatalf("resolving a CWT status list: %v", err)
	}
	if result.Format != FormatCWT {
		t.Errorf("format = %q, want %q", result.Format, FormatCWT)
	}
	if result.Status != 1 || result.StatusName != "INVALID" {
		t.Errorf("status = %d %q, want 1 INVALID", result.Status, result.StatusName)
	}

	valid, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 4}, CheckOptions{
		Keys: []crypto.PublicKey{&key.PublicKey},
	})
	if err != nil {
		t.Fatalf("resolving a CWT status list: %v", err)
	}
	if !valid.IsValid {
		t.Errorf("index 4 = %d, want VALID", valid.Status)
	}
}

// The x5chain header anchors a CWT status list like x5c anchors the JWT form.
func TestCheck_AnchorsACWTStatusListInTheTrustList(t *testing.T) {
	issuerKey, leafCert, caCert := testChain(t)
	srv := cwtServer(t, issuerKey, 1, make([]byte, 16), []*x509.Certificate{leafCert, caCert})

	result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
		TrustListCerts: []TrustCert{{Raw: caCert.Raw}},
	})
	if err != nil {
		t.Fatalf("resolving a CWT status list: %v", err)
	}
	if !result.TrustAnchored {
		t.Error("a chain that validates against the trust list must be reported as anchored")
	}

	otherCA, err := mock.GenerateCACert(mustGenerateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
		TrustListCerts: []TrustCert{{Raw: otherCA.Raw}},
	}); err == nil {
		t.Fatal("a CWT chain that does not reach the trust list must fail the check")
	}
}

// The CWT form follows the JWT claim rules. The subject must equal the
// credential's URI and an expired token must fail.
func TestCheck_CWTClaimRules(t *testing.T) {
	key := mustGenerateKey(t)

	t.Run("subject mismatch", func(t *testing.T) {
		srv := statusListServer(t, func(string) (string, []byte) {
			token, err := GenerateStatusListCWT(make([]byte, 16), key, StatusListConfig{
				URI: "https://elsewhere.example/statuslists/9",
			})
			if err != nil {
				t.Errorf("GenerateStatusListCWT: %v", err)
				return "", nil
			}
			return MediaTypeCWT, token
		})
		_, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{Keys: []crypto.PublicKey{&key.PublicKey}})
		if err == nil || !strings.Contains(err.Error(), "subject") {
			t.Fatalf("error = %v, want a subject mismatch", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		srv := statusListServer(t, func(uri string) (string, []byte) {
			token, err := GenerateStatusListCWT(make([]byte, 16), key, StatusListConfig{
				URI:      uri,
				IssuedAt: time.Now().Add(-72 * time.Hour),
			})
			if err != nil {
				t.Errorf("GenerateStatusListCWT: %v", err)
				return "", nil
			}
			return MediaTypeCWT, token
		})
		_, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{Keys: []crypto.PublicKey{&key.PublicKey}})
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("error = %v, want an expiry failure", err)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		other := mustGenerateKey(t)
		srv := cwtServer(t, key, 1, make([]byte, 16), nil)
		_, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
			Keys: []crypto.PublicKey{&other.PublicKey},
		})
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("error = %v, want a signature failure", err)
		}
	})
}

// Section 5.2: "16 (type): REQUIRED. The type of the CWT MUST be
// application/statuslist+cwt". An MSO is a COSE_Sign1 without it.
func TestCheck_CWTRequiresTheTypeHeader(t *testing.T) {
	key := mustGenerateKey(t)
	for _, tc := range []struct {
		name string
		typ  any
	}{
		{"missing", nil},
		{"an mdoc MSO", "application/mso+cbor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := statusListServer(t, func(uri string) (string, []byte) {
				return MediaTypeCWT, signCWTWithType(t, key, uri, tc.typ)
			})
			_, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{Keys: []crypto.PublicKey{&key.PublicKey}})
			if err == nil || !strings.Contains(err.Error(), "type") {
				t.Fatalf("error = %v, want it to name the type header", err)
			}
		})
	}
}

// Section 5.2: "The Status List Token MUST NOT be tagged with the CWT tag
// defined in Section 6 of [RFC8392]."
func TestCheck_CWTRejectsTheCWTTag(t *testing.T) {
	key := mustGenerateKey(t)
	srv := statusListServer(t, func(uri string) (string, []byte) {
		token, err := GenerateStatusListCWT(make([]byte, 16), key, StatusListConfig{URI: uri})
		if err != nil {
			t.Errorf("GenerateStatusListCWT: %v", err)
			return "", nil
		}
		tagged, err := cbor.Marshal(cbor.RawTag{Number: tagCWT, Content: cbor.RawMessage(token)})
		if err != nil {
			t.Errorf("tagging: %v", err)
			return "", nil
		}
		return MediaTypeCWT, tagged
	})

	_, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{Keys: []crypto.PublicKey{&key.PublicKey}})
	if err == nil || !strings.Contains(err.Error(), "CWT tag") {
		t.Fatalf("error = %v, want it to name the forbidden CWT tag", err)
	}
}

// The generated token must carry the tag, the type header and the claim keys
// of Section 5.2.
func TestGenerateStatusListCWT_Structure(t *testing.T) {
	key := mustGenerateKey(t)
	token, err := GenerateStatusListCWT([]byte{0xb9, 0xa3}, key, StatusListConfig{
		URI:    "https://example.com/statuslists/1",
		Issuer: "https://example.com",
	})
	if err != nil {
		t.Fatalf("GenerateStatusListCWT: %v", err)
	}
	if len(token) == 0 || token[0] != 0xd2 {
		t.Fatalf("the token must be a tagged COSE_Sign1 (tag 18), got %s", hex.EncodeToString(token[:1]))
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		t.Fatalf("parsing COSE_Sign1: %v", err)
	}
	typ, present := headerValue(map[any]any(msg.Headers.Protected), coseHeaderType)
	if !present || typ != MediaTypeCWT {
		t.Errorf("protected header 16 = %v, want %q", typ, MediaTypeCWT)
	}

	var claims map[any]any
	if err := cwtDecMode.Unmarshal(msg.Payload, &claims); err != nil {
		t.Fatalf("parsing CWT claims set: %v", err)
	}
	if got := cwtClaim(claims, cwtClaimSubject); got != "https://example.com/statuslists/1" {
		t.Errorf("claim 2 (subject) = %v", got)
	}
	if got := cwtClaim(claims, cwtClaimIssuer); got != "https://example.com" {
		t.Errorf("claim 1 (issuer) = %v", got)
	}
	if cwtClaim(claims, cwtClaimIssuedAt) == nil {
		t.Error("claim 6 (issued at) is required")
	}
	if cwtClaim(claims, cwtClaimExpiration) == nil {
		t.Error("claim 4 (expiration time) is recommended and must be set")
	}
	if got, _ := asInt(cwtClaim(claims, cwtClaimTTL)); got != defaultTTL {
		t.Errorf("claim 65534 (time to live) = %d, want %d", got, defaultTTL)
	}

	sl, ok := cwtClaim(claims, cwtClaimStatusList).(map[any]any)
	if !ok {
		t.Fatalf("claim 65533 (status list) is not a map: %T", cwtClaim(claims, cwtClaimStatusList))
	}
	if bits, _ := asInt(sl["bits"]); bits != 1 {
		t.Errorf("bits = %v, want 1", sl["bits"])
	}
	// Section 4.3: "lst: REQUIRED. CBOR Byte string (major type 2)."
	lst, ok := sl["lst"].([]byte)
	if !ok {
		t.Fatalf("lst is not a CBOR byte string: %T", sl["lst"])
	}
	decompressed, _, err := zlibDecompress(lst)
	if err != nil {
		t.Fatalf("decompressing lst: %v", err)
	}
	if len(decompressed) != 2 || decompressed[0] != 0xb9 || decompressed[1] != 0xa3 {
		t.Errorf("lst decompressed to %x, want b9a3", decompressed)
	}
}

// Generated CWT tokens must pass the checker at every allowed width.
func TestCWTRoundTrip_EveryWidth(t *testing.T) {
	key := mustGenerateKey(t)
	for _, tc := range []struct {
		bits   int
		idx    int
		status int
	}{
		{bits: 1, idx: 3, status: 1},
		{bits: 2, idx: 5, status: 2},
		{bits: 4, idx: 9, status: 0x0B},
		{bits: 8, idx: 11, status: 0xFE},
	} {
		bitstring := make([]byte, 32)
		bitPos := tc.idx * tc.bits
		bitstring[bitPos/8] |= byte(tc.status << (bitPos % 8))
		srv := cwtServer(t, key, tc.bits, bitstring, nil)

		result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: tc.idx}, CheckOptions{
			Keys: []crypto.PublicKey{&key.PublicKey},
		})
		if err != nil {
			t.Errorf("bits=%d: %v", tc.bits, err)
			continue
		}
		if result.Status != tc.status || result.BitsPerEntry != tc.bits {
			t.Errorf("bits=%d idx=%d: status %d at %d bits, want %d at %d bits",
				tc.bits, tc.idx, result.Status, result.BitsPerEntry, tc.status, tc.bits)
		}
	}
}

func signCWTWithType(t *testing.T, key *ecdsa.PrivateKey, uri string, typ any) []byte {
	t.Helper()
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	return signCWT(t, signer, uri, typ)
}

// esp256Signer produces the ES256 signature under the ESP256 label, which
// go-cose does not know.
type esp256Signer struct{ cose.Signer }

func (esp256Signer) Algorithm() cose.Algorithm { return mdoc.AlgorithmESP256 }

// HAIP 1.0 §7 names -9 next to -7 for ECDSA with P-256 and SHA-256.
func TestCheck_AcceptsAnESP256CWT(t *testing.T) {
	key := mustGenerateKey(t)
	es256, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := statusListServer(t, func(uri string) (string, []byte) {
		return MediaTypeCWT, signCWT(t, esp256Signer{es256}, uri, MediaTypeCWT)
	})
	result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{Keys: []crypto.PublicKey{&key.PublicKey}})
	if err != nil {
		t.Fatalf("CheckWithOptions: %v", err)
	}
	if !result.IsValid {
		t.Errorf("status = %+v, want valid", result)
	}
}

func signCWT(t *testing.T, signer cose.Signer, uri string, typ any) []byte {
	t.Helper()
	compressed, err := compressBitstring(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cbor.Marshal(map[int64]any{
		cwtClaimSubject:    uri,
		cwtClaimIssuedAt:   time.Now().Unix(),
		cwtClaimExpiration: time.Now().Add(time.Hour).Unix(),
		cwtClaimStatusList: map[string]any{"bits": 1, "lst": compressed},
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = signer.Algorithm()
	if typ != nil {
		msg.Headers.Protected[int64(coseHeaderType)] = typ
	}
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// specExampleCWT is the non-normative example of a Status List Token in CWT
// format from Section 5.2, transcribed from the editor's copy. It checks the
// claim keys and the type header against the specification's bytes.
const specExampleCWT = "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b6377" +
	"74a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f73" +
	"74617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2" +
	"646269747301636c73744a78dadbb918000217015d584093fa4d01032b18c35e2fe1" +
	"101b77fd6cc9440022caa4694450c4e4e9feab4e99d1fa6d9772ce2bf3a12e0323de" +
	"d7c982c5e101a5e67f0cbc1e2b6f57ce99c279"

func TestSpecExampleCWT_ClaimKeysAndTypeHeader(t *testing.T) {
	raw, err := hex.DecodeString(specExampleCWT)
	if err != nil {
		t.Fatalf("decoding the example: %v", err)
	}
	if raw[0] != 0xd2 {
		t.Fatalf("the example must be a tagged COSE_Sign1 (tag 18), got 0x%02x", raw[0])
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		t.Fatalf("parsing the example COSE_Sign1: %v", err)
	}
	typ, present := headerValue(map[any]any(msg.Headers.Protected), coseHeaderType)
	if !present || typ != MediaTypeCWT {
		t.Errorf("protected header 16 = %v, want %q", typ, MediaTypeCWT)
	}

	var claims map[any]any
	if err := cwtDecMode.Unmarshal(msg.Payload, &claims); err != nil {
		t.Fatalf("parsing the example CWT claims set: %v", err)
	}
	if got := cwtClaim(claims, cwtClaimSubject); got != "https://example.com/statuslists/1" {
		t.Errorf("claim 2 (subject) = %v", got)
	}
	if got, _ := asInt(cwtClaim(claims, cwtClaimIssuedAt)); got != 1686920170 {
		t.Errorf("claim 6 (issued at) = %d, want 1686920170", got)
	}
	if got, _ := asInt(cwtClaim(claims, cwtClaimExpiration)); got != 2291720170 {
		t.Errorf("claim 4 (expiration time) = %d, want 2291720170", got)
	}
	if got, _ := asInt(cwtClaim(claims, cwtClaimTTL)); got != 43200 {
		t.Errorf("claim 65534 (time to live) = %d, want 43200", got)
	}

	sl, ok := cwtClaim(claims, cwtClaimStatusList).(map[any]any)
	if !ok {
		t.Fatalf("claim 65533 (status list) is not a map: %T", cwtClaim(claims, cwtClaimStatusList))
	}
	if bits, _ := asInt(sl["bits"]); bits != 1 {
		t.Errorf("bits = %v, want 1", sl["bits"])
	}
	lst, ok := sl["lst"].([]byte)
	if !ok {
		t.Fatalf("lst is not a CBOR byte string: %T", sl["lst"])
	}
	decompressed, _, err := zlibDecompress(lst)
	if err != nil {
		t.Fatalf("decompressing lst: %v", err)
	}
	// Section 4.1's worked example: the two bytes 0xb9 0xa3.
	if len(decompressed) != 2 || decompressed[0] != 0xb9 || decompressed[1] != 0xa3 {
		t.Fatalf("lst decompressed to %x, want b9a3", decompressed)
	}
	for idx, want := range []int{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1} {
		got, err := extractStatus(decompressed, idx, 1)
		if err != nil {
			t.Fatalf("index %d: %v", idx, err)
		}
		if got != want {
			t.Errorf("index %d = %d, want %d", idx, got, want)
		}
	}
}
