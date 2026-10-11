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
	"bytes"
	"compress/zlib"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/veraison/go-cose"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

func readPublishedStatus(t *testing.T, token string, idx int) (int, int) {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d segments", len(parts))
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}
	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		t.Fatal("no status_list in the published token")
	}
	bitsFloat, ok := sl["bits"].(float64)
	if !ok {
		t.Fatalf("bits is not a number: %v", sl["bits"])
	}
	bits := int(bitsFloat)

	compressed, err := format.DecodeBase64URL(sl["lst"].(string))
	if err != nil {
		t.Fatalf("decoding lst: %v", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer r.Close()
	bitstring, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decompressing: %v", err)
	}

	bitPos := idx * bits
	if bitPos/8 >= len(bitstring) {
		t.Fatalf("index %d is past the published list of %d bytes", idx, len(bitstring))
	}
	mask := (1 << bits) - 1
	return bits, (int(bitstring[bitPos/8]) >> (bitPos % 8)) & mask
}

// A one-bit status list cannot represent SUSPENDED. Section 7 requires a width large
// enough for every status the issuer uses.
func TestBuildStatusList_WidensForTheStatusValuesInUse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		wantBits int
	}{
		{"valid only", 0, 1},
		{"revoked", 1, 1},
		{"suspended", 2, 2},
		{"application specific", 0x0D, 4},
		{"the widest registered value", 200, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.StatusListCounter = 4
			w.RegisterStatusEntry("cred", 2)
			if _, ok := w.SetCredentialStatus("cred", tc.status); !ok {
				t.Fatalf("SetCredentialStatus(%d) was refused", tc.status)
			}

			bits, bitstring := w.BuildStatusList()
			if bits != tc.wantBits {
				t.Fatalf("bits = %d, want %d for status %d", bits, tc.wantBits, tc.status)
			}
			bitPos := 2 * bits
			mask := (1 << bits) - 1
			got := (int(bitstring[bitPos/8]) >> (bitPos % 8)) & mask
			if got != tc.status {
				t.Errorf("the published entry reads %d, want the stored %d", got, tc.status)
			}
		})
	}
}

func TestHandleStatusList_PublishesTheStoredStatusValue(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	cred := w.GetCredentials()[0]
	entry, ok := w.SetCredentialStatus(cred.ID, 2) // SUSPENDED
	if !ok {
		t.Fatal("SetCredentialStatus(2) was refused")
	}

	resp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	bits, published := readPublishedStatus(t, resp.Body.String(), entry.Index)
	if bits != 2 {
		t.Errorf("published bits = %d, want 2 so SUSPENDED fits", bits)
	}
	if published != 2 {
		t.Errorf("the published status is %d, the wallet stores %d", published, entry.Status)
	}
	if statuslist.StatusName(published) != "SUSPENDED" {
		t.Errorf("published status names %q, want SUSPENDED", statuslist.StatusName(published))
	}
}

// Section 7: "Status Types MUST have a numeric value between 0 and 255 for
// their representation in the Status List."
func TestSetCredentialStatus_RefusesValuesOutsideTheStatusTypeRange(t *testing.T) {
	w := generateTestWallet(t)
	w.StatusListCounter = 1
	w.RegisterStatusEntry("cred", 0)

	for _, status := range []int{-1, 256, 1 << 20} {
		if _, ok := w.SetCredentialStatus("cred", status); ok {
			t.Errorf("status %d was stored", status)
		}
	}
	for _, status := range []int{0, 1, 2, 255} {
		if _, ok := w.SetCredentialStatus("cred", status); !ok {
			t.Errorf("status %d was refused", status)
		}
	}
}

// Section 8.4 recommends HTTP 501 when historical status queries are unsupported.
// Returning the current list would answer for the wrong time.
func TestHandleStatusList_TimeQueryParameterIsNotImplemented(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/api/statuslist?time=1686925000", "")
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.Code)
	}
}

// Section 8.1: "The HTTP endpoint SHOULD support the use of Cross-Origin
// Resource Sharing (CORS) [CORS] ... to enable Browser-based clients to
// access it".
func TestHandleStatusList_AllowsCrossOriginReads(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
}

// Section 8.1 permits content negotiation for the CWT representation.
func TestHandleStatusList_ServesCWTWhenAsked(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	req := httptest.NewRequest("GET", "/api/statuslist", nil)
	req.Header.Set("Accept", statuslist.MediaTypeCWT)
	resp := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != statuslist.MediaTypeCWT {
		t.Fatalf("Content-Type = %q, want %q", got, statuslist.MediaTypeCWT)
	}
	body := resp.Body.Bytes()
	if len(body) == 0 || body[0] != 0xd2 {
		t.Fatalf("the body must be a tagged COSE_Sign1 (tag 18), got % x", body[:min(len(body), 4)])
	}

	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(body); err != nil {
		t.Fatal(err)
	}
	leafDER, ok := message.Headers.Protected[int64(33)].([]byte)
	if !ok {
		t.Fatal("protected x5chain must contain the status signer certificate, without the root")
	}
	if _, exists := message.Headers.Unprotected[int64(33)]; exists {
		t.Error("x5chain must not also occur in the unprotected header")
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("status signer key usage = %v, want digitalSignature only", leaf.KeyUsage)
	}
	if len(leaf.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, w.Signer().TrustAnchor().SubjectKeyId) {
		t.Error("status signer must identify its key and the wallet CA's key")
	}
	for _, extension := range leaf.Extensions {
		if extension.Critical && extension.Id.String() != "2.5.29.15" {
			t.Errorf("status signer has unexpected critical extension %s", extension.Id)
		}
	}
	if len(leaf.ExtKeyUsage) != 0 || len(leaf.UnknownExtKeyUsage) != 0 {
		t.Error("status signer must omit the optional EKU rather than assert document signing")
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != w.IssuerURL+"/api/crl" {
		t.Errorf("status signer CRL distribution points = %v", leaf.CRLDistributionPoints)
	}
	roots := x509.NewCertPool()
	roots.AddCert(w.Signer().TrustAnchor())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("status signer does not chain to the wallet CA: %v", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := message.Verify(nil, verifier); err != nil {
		t.Fatalf("status list signature does not verify: %v", err)
	}
	message.Headers.RawProtected = nil
	message.Headers.Protected[int64(33)] = w.Signer().TrustAnchor().Raw
	if err := message.Verify(nil, verifier); err == nil {
		t.Error("replacing the protected certificate must invalidate the signature")
	}

	jwtResp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if got := jwtResp.Header().Get("Content-Type"); got != statuslist.MediaTypeJWT {
		t.Errorf("Content-Type = %q, want %q", got, statuslist.MediaTypeJWT)
	}
}
