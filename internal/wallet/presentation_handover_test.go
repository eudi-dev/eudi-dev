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

package wallet

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

// mdocDeviceAuthVerifies presents the first mdoc of the wallet and checks its
// DeviceAuth against a transcript built from the given thumbprint.
func mdocDeviceAuthVerifies(t *testing.T, w *Wallet, params *oid4vp.Request, thumbprint []byte) bool {
	t.Helper()
	matches := mdocMatches(t, w)
	if len(matches) == 0 {
		t.Fatal("the baseline holds no mdoc")
	}
	result, err := w.createVPTokenMap(matches[:1], params)
	if err != nil {
		t.Fatalf("creating the vp_token map: %v", err)
	}
	var transcript []byte
	if oid4vp.IsDCAPIResponseMode(params.ResponseMode) {
		transcript, err = mdoc.OID4VPDCAPISessionTranscript(params.RequestOrigin, params.Nonce, thumbprint)
	} else {
		transcript, err = mdoc.OID4VPSessionTranscript(params.ClientID, params.Nonce, thumbprint, params.ResponseURI)
	}
	if err != nil {
		t.Fatalf("building the transcript: %v", err)
	}
	doc, err := mdoc.Parse(result.TokenMap[matches[0].QueryID][0])
	if err != nil {
		t.Fatalf("parsing the DeviceResponse: %v", err)
	}
	return mdoc.VerifyDeviceAuth(doc, transcript) == nil
}

// OID4VP 1.0 Appendix B.2.6.1 and B.2.6.2: the handover carries the thumbprint
// of the key that encrypts the response, and null when the response is not
// encrypted.
func TestMDocHandoverCarriesTheThumbprintOnlyForEncryptedResponses(t *testing.T) {
	w := pidBaselineWallet(t)
	w.SessionTranscript = oid4vp.SessionTranscriptOID4VP

	wrapping := ecEncJWK(t, "enc")
	wrapping["alg"] = "ECDH-ES+A128KW"
	wrapping["kid"] = "wrap"
	direct := mock.SigningJWKMap(&testKey(t).PublicKey)
	direct["use"], direct["alg"], direct["kid"] = "enc", "ECDH-ES", "direct"
	meta := map[string]any{"jwks": map[string]any{"keys": []any{wrapping, direct}}}

	for _, tc := range []struct {
		mode       string
		thumbprint []byte
	}{
		{"direct_post", nil},
		{"direct_post.jwt", computeJWKThumbprint(direct)},
		{"dc_api", nil},
		{"dc_api.jwt", computeJWKThumbprint(direct)},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "x509_hash:abc", ResponseURI: "https://verifier.example/response", ResponseMode: tc.mode, ClientMetadata: meta}, RequestOrigin: "https://verifier.example"}
			if !mdocDeviceAuthVerifies(t, w, params, tc.thumbprint) {
				t.Errorf("DeviceAuth does not verify against the transcript with thumbprint %x", tc.thumbprint)
			}
		})
	}
}

func decodeJWEHeader(t *testing.T, compact string) map[string]any {
	t.Helper()
	raw, err := format.DecodeBase64URL(strings.Split(compact, ".")[0])
	if err != nil {
		t.Fatalf("decoding the JWE header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("parsing the JWE header: %v", err)
	}
	return header
}

// OID4VP 1.0 §8.3: "The JWE alg algorithm used MUST be equal to the alg value
// of the chosen jwk." The wallet chooses a key whose alg it implements.
func TestEncryptedResponseUsesAKeyWhoseAlgTheWalletImplements(t *testing.T) {
	w := generateTestWallet(t)
	wrapping := ecEncJWK(t, "enc")
	wrapping["alg"], wrapping["kid"] = "ECDH-ES+A128KW", "wrap"
	direct := ecEncJWK(t, "enc")
	direct["kid"] = "direct"

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post.jwt", ClientMetadata: map[string]any{"jwks": map[string]any{"keys": []any{wrapping, direct}}}}}
	compact, _, err := w.encryptResponse(map[string]any{"q": []string{"x"}}, "", "", "", params)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	header := decodeJWEHeader(t, compact)
	if header["alg"] != "ECDH-ES" || header["kid"] != "direct" {
		t.Errorf("JWE header alg=%v kid=%v, want ECDH-ES to the key direct", header["alg"], header["kid"])
	}

	params.ClientMetadata = map[string]any{"jwks": map[string]any{"keys": []any{wrapping}}}
	if _, _, err := w.encryptResponse(map[string]any{"q": []string{"x"}}, "", "", "", params); err == nil {
		t.Error("a verifier offering only ECDH-ES+A128KW got a response, want an error")
	}
}

// OID4VP 1.0 §8.3 takes enc from encrypted_response_enc_values_supported with
// the default A128GCM. HAIP 1.0 §5: "If both are supported, the Wallet SHOULD
// use A256GCM for the JWE enc."
func TestEncryptedResponsePrefersA256GCM(t *testing.T) {
	w := generateTestWallet(t)
	for _, tc := range []struct {
		offered []any
		want    string
	}{
		{nil, "A128GCM"},
		{[]any{"A128GCM", "A256GCM"}, "A256GCM"},
		{[]any{"XC20P", "A128CBC-HS256"}, "A128CBC-HS256"},
	} {
		meta := map[string]any{"jwks": map[string]any{"keys": []any{ecEncJWK(t, "enc")}}}
		if tc.offered != nil {
			meta["encrypted_response_enc_values_supported"] = tc.offered
		}
		compact, _, err := w.encryptResponse(map[string]any{"q": []string{"x"}}, "", "", "", &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post.jwt", ClientMetadata: meta}})
		if err != nil {
			t.Fatalf("offered %v: %v", tc.offered, err)
		}
		if got := decodeJWEHeader(t, compact)["enc"]; got != tc.want {
			t.Errorf("offered %v: enc = %v, want %s", tc.offered, got, tc.want)
		}
	}
}
