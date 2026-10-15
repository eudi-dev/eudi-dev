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
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func mustGenerateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func testChain(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	issuerKey := mustGenerateKey(t)
	caKey := mustGenerateKey(t)
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &issuerKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatalf("GenerateLeafCertWithOptions: %v", err)
	}
	return issuerKey, leafCert, caCert
}

// The server starts before the token exists, so sub can hold its actual URL.
func statusListServer(t *testing.T, gen func(uri string) (string, []byte)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType, body := gen(srv.URL)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func jwtServer(t *testing.T, key *ecdsa.PrivateKey, bits int, bitstring []byte, chain []*x509.Certificate) *httptest.Server {
	t.Helper()
	return statusListServer(t, func(uri string) (string, []byte) {
		token, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{
			URI:       uri,
			Bits:      bits,
			CertChain: chain,
		})
		if err != nil {
			t.Errorf("GenerateStatusListJWT: %v", err)
			return "", nil
		}
		return MediaTypeJWT, []byte(token)
	})
}

func TestExtractStatusRef(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]any
		want        *StatusRef
		wantInvalid bool
	}{
		{
			name: "valid ref",
			claims: map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{
						"uri": "https://example.com/status",
						"idx": float64(42),
					},
				},
			},
			want: &StatusRef{URI: "https://example.com/status", Idx: 42},
		},
		{
			name:   "no status field",
			claims: map[string]any{"iss": "test"},
		},
		{
			name: "no status_list",
			claims: map[string]any{
				"status": map[string]any{"other": "value"},
			},
		},
		{
			name: "empty uri",
			claims: map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{"uri": "", "idx": float64(0)},
				},
			},
			wantInvalid: true,
		},
		{
			name: "int64 idx",
			claims: map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{
						"uri": "https://example.com/status",
						"idx": int64(7),
					},
				},
			},
			want: &StatusRef{URI: "https://example.com/status", Idx: 7},
		},
		{
			name: "uint64 idx, as an mdoc status decodes",
			claims: map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{
						"uri": "https://example.com/status",
						"idx": uint64(9),
					},
				},
			},
			want: &StatusRef{URI: "https://example.com/status", Idx: 9},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractStatusRef(tt.claims)
			if tt.wantInvalid {
				if got == nil || got.Invalid == "" {
					t.Fatalf("expected an invalid reference, got %+v", got)
				}
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.Invalid != "" {
				t.Fatalf("expected a usable reference, got %q", got.Invalid)
			}
			if got.URI != tt.want.URI || got.Idx != tt.want.Idx {
				t.Errorf("got {URI:%q, Idx:%d}, want {URI:%q, Idx:%d}", got.URI, got.Idx, tt.want.URI, tt.want.Idx)
			}
		})
	}
}

// Section 8.3 checks the reference before fetching anything: it needs a uri
// and a non-negative idx.
func TestCheckRefusesAnUnusableReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  *StatusRef
		want string
	}{
		{"no reference", nil, "no status list reference"},
		{"an invalid reference", &StatusRef{URI: "https://example.com/1", Invalid: "the status_list reference has no idx claim"}, "no idx claim"},
		{"no uri", &StatusRef{Idx: 1}, "no uri"},
		{"a negative index", &StatusRef{URI: "https://example.com/1", Idx: -1}, "negative"},
	} {
		if _, err := CheckWithOptions(tc.ref, CheckOptions{}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to contain %q", tc.name, err, tc.want)
		}
	}
}

func TestExtractStatus(t *testing.T) {
	// byte 0 = 0b00000101 (idx 0 = 1, idx 1 = 0, idx 2 = 1)
	bitstring := []byte{0x05, 0x00}

	tests := []struct {
		idx  int
		bits int
		want int
	}{
		{0, 1, 1},
		{1, 1, 0},
		{2, 1, 1},
		{3, 1, 0},
		{8, 1, 0},
	}
	for _, tt := range tests {
		got, err := extractStatus(bitstring, tt.idx, tt.bits)
		if err != nil {
			t.Errorf("extractStatus(idx=%d) error: %v", tt.idx, err)
			continue
		}
		if got != tt.want {
			t.Errorf("extractStatus(idx=%d, bits=%d) = %d, want %d", tt.idx, tt.bits, got, tt.want)
		}
	}
}

func TestExtractStatus_TwoBits(t *testing.T) {
	// 2-bit status: byte 0 = 0b00001001 = idx0=01, idx1=00, idx2=10, idx3=00
	bitstring := []byte{0x09}

	tests := []struct {
		idx  int
		want int
	}{
		{0, 1},
		{1, 2},
		{2, 0},
		{3, 0},
	}
	for _, tt := range tests {
		got, err := extractStatus(bitstring, tt.idx, 2)
		if err != nil {
			t.Errorf("extractStatus(idx=%d) error: %v", tt.idx, err)
			continue
		}
		if got != tt.want {
			t.Errorf("extractStatus(idx=%d, bits=2) = %d, want %d", tt.idx, got, tt.want)
		}
	}
}

func TestExtractStatus_OutOfRange(t *testing.T) {
	bitstring := []byte{0x00}
	_, err := extractStatus(bitstring, 100, 1)
	if err == nil {
		t.Error("expected out of range error")
	}
}

func TestCheck_WithMockServer(t *testing.T) {
	key := mustGenerateKey(t)
	bitstring := make([]byte, 16)
	bitstring[0] = 1 << 5
	srv := jwtServer(t, key, 1, bitstring, nil)

	result, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !result.IsValid {
		t.Errorf("index 0: expected valid, got status=%d", result.Status)
	}
	if result.StatusName != "VALID" {
		t.Errorf("index 0: name = %q, want VALID", result.StatusName)
	}

	result, err = Check(&StatusRef{URI: srv.URL, Idx: 5})
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.IsValid || result.Status != 1 {
		t.Errorf("index 5: status = %d, want 1 and not valid", result.Status)
	}
	if result.StatusName != "INVALID" {
		t.Errorf("index 5: name = %q, want INVALID", result.StatusName)
	}
	if result.Format != FormatJWT {
		t.Errorf("format = %q, want %q", result.Format, FormatJWT)
	}
}

func TestCheck_WithLocalTLSServer(t *testing.T) {
	key := mustGenerateKey(t)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := GenerateStatusListJWT(make([]byte, 16), key, StatusListConfig{URI: srv.URL})
		if err != nil {
			t.Errorf("GenerateStatusListJWT: %v", err)
			return
		}
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	result, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err != nil {
		t.Fatalf("Check() against local TLS server: %v", err)
	}
	if !result.IsValid {
		t.Fatalf("expected valid status, got %d", result.Status)
	}
}

func TestCheck_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	_, err := Check(&StatusRef{URI: server.URL, Idx: 0})
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestCheckWithOptions_SignatureVerification(t *testing.T) {
	issuerKey, leafCert, caCert := testChain(t)
	srv := jwtServer(t, issuerKey, 1, make([]byte, 16), []*x509.Certificate{leafCert, caCert})

	result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
		TrustListCerts: []TrustCert{{Raw: caCert.Raw}},
	})
	if err != nil {
		t.Fatalf("CheckWithOptions error: %v", err)
	}
	if result.SignatureValid == nil || !*result.SignatureValid {
		t.Fatalf("expected a verified signature, got info %q", result.SignatureInfo)
	}
	if !result.TrustAnchored {
		t.Error("a chain that validates against the trust list must be reported as anchored")
	}
	if !result.IsValid {
		t.Errorf("expected status valid, got %d", result.Status)
	}
	if len(result.HAIPFindings) != 0 {
		t.Errorf("HAIP findings = %v, want none for a token with x5c", result.HAIPFindings)
	}
}

func TestCheckWithOptions_UntrustedCert(t *testing.T) {
	issuerKey, leafCert, caCert := testChain(t)
	otherCAKey := mustGenerateKey(t)
	otherCACert, err := mock.GenerateCACert(otherCAKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwtServer(t, issuerKey, 1, make([]byte, 16), []*x509.Certificate{leafCert, caCert})

	_, err = CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
		TrustListCerts: []TrustCert{{Raw: otherCACert.Raw}},
	})
	if err == nil {
		t.Fatal("a chain that does not reach the trust list must fail the check")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("error = %v, want it to name the untrusted chain", err)
	}
}

// A candidate anchor, such as the CA of a local wallet, anchors a token whose
// chain reaches it. A token from elsewhere is still checked with its own
// certificate.
func TestCheckWithOptions_CandidateAnchors(t *testing.T) {
	issuerKey, leafCert, caCert := testChain(t)
	otherCAKey := mustGenerateKey(t)
	otherCACert, err := mock.GenerateCACert(otherCAKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwtServer(t, issuerKey, 1, make([]byte, 16), []*x509.Certificate{leafCert, caCert})

	for _, tc := range []struct {
		name     string
		anchor   *x509.Certificate
		anchored bool
	}{
		{"own CA", caCert, true},
		{"other CA", otherCACert, false},
	} {
		result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
			CandidateAnchors: []TrustCert{{Raw: tc.anchor.Raw}},
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if result.SignatureValid == nil || !*result.SignatureValid || result.TrustAnchored != tc.anchored {
			t.Errorf("%s: signature %v, anchored %t, want a valid signature and anchored %t", tc.name, result.SignatureValid, result.TrustAnchored, tc.anchored)
		}
	}
}

func TestCheckWithOptions_NoX5C(t *testing.T) {
	key := mustGenerateKey(t)
	caKey := mustGenerateKey(t)
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwtServer(t, key, 1, make([]byte, 16), nil)

	_, err = CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{
		TrustListCerts: []TrustCert{{Raw: caCert.Raw}},
	})
	if err == nil {
		t.Fatal("a token with no chain cannot be anchored in a trust list and must fail")
	}
	if !strings.Contains(err.Error(), "no certificate chain") {
		t.Errorf("error = %v, want it to name the missing chain", err)
	}
}

// issuerMetadataStatusServer serves a status list token that names its key
// only by kid, next to the JWT VC Issuer Metadata of its iss. metadataKid is
// the kid the metadata publishes.
func issuerMetadataStatusServer(t *testing.T, key *ecdsa.PrivateKey, bitstring []byte, metadataKid string) (*httptest.Server, string) {
	t.Helper()
	compressed, err := compressBitstring(bitstring)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss := srv.URL + "/registry"
		switch r.URL.Path {
		case "/.well-known/jwt-vc-issuer/registry":
			jwk := mock.SigningJWKMap(&key.PublicKey)
			jwk["kid"] = metadataKid
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks": map[string]any{"keys": []any{jwk}}})
		case "/registry/list":
			token, err := jws.Sign(
				map[string]any{"alg": jws.AlgES256, "typ": TypJWT, "kid": "status-key"},
				map[string]any{
					"sub":         srv.URL + "/registry/list",
					"iss":         iss,
					"iat":         time.Now().Unix(),
					"status_list": map[string]any{"bits": 1, "lst": format.EncodeBase64URL(compressed)},
				}, key)
			if err != nil {
				t.Errorf("Sign: %v", err)
				return
			}
			w.Header().Set("Content-Type", MediaTypeJWT)
			_, _ = w.Write([]byte(token))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/registry/list"
}

// A token that names its key only by kid is verified with the matching key
// of the JWT VC Issuer Metadata of its iss. That key is not anchored, and the
// missing x5c is a HAIP 1.0 §6.1 finding.
func TestCheckWithOptions_KeyFromIssuerMetadata(t *testing.T) {
	key := mustGenerateKey(t)
	bitstring := make([]byte, 16)
	bitstring[0] = 1 << 2
	srv, uri := issuerMetadataStatusServer(t, key, bitstring, "status-key")

	result, err := CheckWithOptions(&StatusRef{URI: uri, Idx: 2}, CheckOptions{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("CheckWithOptions: %v", err)
	}
	if result.Status != 1 || result.TrustAnchored {
		t.Errorf("status %d, anchored %t, want status 1 and not anchored", result.Status, result.TrustAnchored)
	}
	if !strings.Contains(result.SignatureInfo, "issuer metadata") {
		t.Errorf("signature info = %q, want it to name the issuer metadata", result.SignatureInfo)
	}
	if len(result.HAIPFindings) != 1 || !strings.Contains(result.HAIPFindings[0], "HAIP 1.0 §6.1") {
		t.Errorf("HAIP findings = %v, want the missing x5c header", result.HAIPFindings)
	}
}

func TestCheckWithOptions_KeyMissingFromIssuerMetadata(t *testing.T) {
	key := mustGenerateKey(t)
	srv, uri := issuerMetadataStatusServer(t, key, make([]byte, 16), "other-key")

	_, err := CheckWithOptions(&StatusRef{URI: uri, Idx: 0}, CheckOptions{HTTPClient: srv.Client()})
	if err == nil || !strings.Contains(err.Error(), "issuer metadata") {
		t.Fatalf("error = %v, want it to name the issuer metadata", err)
	}
}

func TestZlibDecompress(t *testing.T) {
	data := []byte("hello world")

	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(data)
	w.Close()

	got, rawDeflate, err := zlibDecompress(buf.Bytes())
	if err != nil {
		t.Fatalf("zlibDecompress() error: %v", err)
	}
	if rawDeflate {
		t.Error("a ZLIB stream must not be reported as raw DEFLATE")
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

// idx and bits are untrusted. An invalid value must fail without a panic or a
// made-up status.
func TestExtractStatus_RefusesHostileParameters(t *testing.T) {
	bitstring := []byte{0xFF, 0x00, 0xAA}

	for _, tc := range []struct {
		name string
		idx  int
		bits int
	}{
		{"negative index", -1, 1},
		{"very negative index", -1 << 20, 8},
		{"zero bits", 0, 0},
		{"negative bits", 0, -1},
		{"three bits", 0, 3},
		{"absurd bits", 0, 100},
		{"index past the end", 1 << 20, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of reporting: %v", r)
				}
			}()
			if _, err := extractStatus(bitstring, tc.idx, tc.bits); err == nil {
				t.Error("accepted a parameter it should refuse")
			}
		})
	}
}

func TestExtractStatus_ReadsEveryAllowedWidth(t *testing.T) {
	for _, tc := range []struct {
		bits, idx, want int
		bitstring       []byte
	}{
		{bits: 1, idx: 0, want: 1, bitstring: []byte{0x01}},
		{bits: 1, idx: 3, want: 1, bitstring: []byte{0x08}},
		{bits: 2, idx: 1, want: 3, bitstring: []byte{0x0C}},
		{bits: 4, idx: 1, want: 0x0A, bitstring: []byte{0xA0}},
		{bits: 8, idx: 1, want: 0xBE, bitstring: []byte{0x00, 0xBE}},
	} {
		got, err := extractStatus(tc.bitstring, tc.idx, tc.bits)
		if err != nil {
			t.Errorf("bits=%d idx=%d: %v", tc.bits, tc.idx, err)
			continue
		}
		if got != tc.want {
			t.Errorf("bits=%d idx=%d = %d, want %d", tc.bits, tc.idx, got, tc.want)
		}
	}
}

// A credential can point to an attacker-controlled status list.
func TestZlibDecompress_RefusesABomb(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 64; i++ { // 64 MiB, past the 16 MiB cap
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 1<<20 {
		t.Fatalf("the compressed payload is %d bytes, too large to prove amplification", buf.Len())
	}

	out, _, err := zlibDecompress(buf.Bytes())
	if err == nil {
		t.Fatalf("inflated %d bytes from %d without complaint", len(out), buf.Len())
	}
	if !strings.Contains(err.Error(), "decompresses to more than") {
		t.Errorf("error = %v, want it to name the limit", err)
	}
}

func TestZlibDecompress_ReadsAnHonestList(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, _, err := zlibDecompress(buf.Bytes())
	if err != nil {
		t.Fatalf("zlibDecompress: %v", err)
	}
	if !bytes.Equal(out, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("out = %v, want the three bytes written", out)
	}
}

// A Status Provider that serves both representations answers in the format
// of the credential: JWT for an SD-JWT VC and CWT for an mdoc (Section 8.1).
func TestCheckAsksForTheFormatOfTheCredential(t *testing.T) {
	key, leaf, ca := testChain(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := StatusListConfig{URI: srv.URL, CertChain: []*x509.Certificate{leaf, ca}}
		if NegotiateMediaType(r.Header.Get("Accept")) == MediaTypeCWT {
			token, err := GenerateStatusListCWT(make([]byte, 16), key, cfg)
			if err != nil {
				t.Error(err)
			}
			w.Header().Set("Content-Type", MediaTypeCWT)
			_, _ = w.Write(token)
			return
		}
		token, err := GenerateStatusListJWT(make([]byte, 16), key, cfg)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(srv.Close)
	for credentialFormat, want := range map[string]string{"dc+sd-jwt": FormatJWT, "mso_mdoc": FormatCWT} {
		result, err := CheckWithOptions(&StatusRef{URI: srv.URL, Idx: 0}, CheckOptions{Prefer: FormatForCredential(credentialFormat)})
		if err != nil {
			t.Fatalf("%s: %v", credentialFormat, err)
		}
		if result.Format != want {
			t.Errorf("%s: the status list came as %s, want %s", credentialFormat, result.Format, want)
		}
	}
}
