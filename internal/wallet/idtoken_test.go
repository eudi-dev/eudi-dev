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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"

	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func TestCreateSelfIssuedIDToken(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := &Wallet{HolderKey: key}

	token, err := w.createSelfIssuedIDToken("test-nonce", "https://verifier.example")
	if err != nil {
		t.Fatalf("createSelfIssuedIDToken() error: %v", err)
	}

	header, payload, _, err := format.ParseJWTParts(token)
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	if header["alg"] != "ES256" {
		t.Errorf("expected alg=ES256, got %v", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got %v", header["typ"])
	}
	if header["jwk"] == nil {
		t.Error("expected jwk in header")
	}

	// SIOPv2 §11: iss "MUST be set to the value of the sub claim".
	if payload["iss"] == nil || payload["iss"] != payload["sub"] {
		t.Errorf("iss = %v, want the sub %v", payload["iss"], payload["sub"])
	}
	if payload["aud"] != "https://verifier.example" {
		t.Errorf("expected aud=https://verifier.example, got %v", payload["aud"])
	}
	if payload["nonce"] != "test-nonce" {
		t.Errorf("expected nonce=test-nonce, got %v", payload["nonce"])
	}
	if payload["sub"] == nil || payload["sub"] == "" {
		t.Error("expected non-empty sub (JWK thumbprint)")
	}
	if payload["sub_jwk"] == nil {
		t.Error("expected sub_jwk in payload")
	}
	if payload["iat"] == nil {
		t.Error("expected iat in payload")
	}
	if payload["exp"] == nil {
		t.Error("expected exp in payload")
	}

	iat, _ := payload["iat"].(float64)
	exp, _ := payload["exp"].(float64)
	if exp <= iat {
		t.Errorf("expected exp > iat, got exp=%v iat=%v", exp, iat)
	}

	if !verifyES256(t, token, &key.PublicKey) {
		t.Error("signature verification failed")
	}
}

func TestJWKThumbprint(t *testing.T) {
	// The RFC 7638 §3.1 example uses an RSA key. For P-256 this test checks
	// determinism and TestJWKThumbprint_KnownVector checks a fixed vector.
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	tp1, err := jwkThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tp2, err := jwkThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if tp1 != tp2 {
		t.Errorf("thumbprint not deterministic: %s != %s", tp1, tp2)
	}
	if tp1 == "" {
		t.Error("thumbprint should not be empty")
	}

	// A SHA-256 hash is 43 characters in unpadded base64url.
	if len(tp1) != 43 {
		t.Errorf("expected 43 char base64url thumbprint, got %d chars: %s", len(tp1), tp1)
	}
}

func TestJWKThumbprint_KnownVector(t *testing.T) {
	// RFC 7638 §3 hashes the required members in lexicographic order with no
	// whitespace.
	x, _ := hex.DecodeString("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
	y, _ := hex.DecodeString("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")

	key, err := format.ECPublicKeyFromCoords(elliptic.P256(), x, y)
	if err != nil {
		t.Fatal(err)
	}

	tp, err := jwkThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}

	jwk := mock.PublicKeyJWKMap(key)
	canonical := `{"crv":"` + jwk["crv"] + `","kty":"` + jwk["kty"] + `","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`
	h := sha256.Sum256([]byte(canonical))
	expected := format.EncodeBase64URL(h[:])

	if tp != expected {
		t.Errorf("thumbprint mismatch: got %s, expected %s", tp, expected)
	}
}

func verifyES256(t *testing.T, token string, pub *ecdsa.PublicKey) bool {
	t.Helper()
	_, _, sig, err := format.ParseJWTParts(token)
	if err != nil {
		t.Fatalf("parsing JWT for verification: %v", err)
	}

	parts := splitJWT(token)
	sigInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(sigInput))

	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		t.Fatalf("unexpected signature length: %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	return ecdsa.Verify(pub, h[:], r, s)
}

func splitJWT(token string) [3]string {
	var parts [3]string
	i := 0
	for j := 0; j < len(token) && i < 3; j++ {
		if token[j] == '.' && i < 2 {
			parts[i] = token[:j]
			token = token[j+1:]
			j = -1
			i++
		}
	}
	parts[i] = token
	return parts
}

func TestServerIDTokenFlow(t *testing.T) {
	srv := newTestServer(t, true)

	var receivedVPToken, receivedIDToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		receivedVPToken = form.Get("vp_token")
		receivedIDToken = form.Get("id_token")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := pidDCQLQuery()
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	qp := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token id_token"},
		"nonce":         {"nonce123"},
		"state":         {"state456"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+oid4vc.EncodeURIQuery(qp), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Fatalf("expected submitted, got %v", result["status"])
	}

	if receivedVPToken == "" {
		t.Error("expected vp_token in verifier request")
	}
	if receivedIDToken == "" {
		t.Error("expected id_token in verifier request")
	}

	header, payload, _, err := format.ParseJWTParts(receivedIDToken)
	if err != nil {
		t.Fatalf("parsing id_token: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("expected alg=ES256, got %v", header["alg"])
	}
	if payload["iss"] == nil || payload["iss"] != payload["sub"] {
		t.Errorf("iss = %v, want the sub %v", payload["iss"], payload["sub"])
	}
	if payload["aud"] != "https://verifier.example" {
		t.Errorf("expected aud=https://verifier.example, got %v", payload["aud"])
	}
	if payload["nonce"] != "nonce123" {
		t.Errorf("expected nonce=nonce123, got %v", payload["nonce"])
	}
}

func TestServerIDTokenOnlyFlowWithoutCredentialMatch(t *testing.T) {
	srv := newTestServer(t, true)

	var receivedVPToken, receivedIDToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		receivedVPToken = form.Get("vp_token")
		receivedIDToken = form.Get("id_token")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	qp := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"id_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"nonce123"},
		"state":         {"state456"},
		"response_uri":  {verifier.URL},
	}

	req := httptest.NewRequest("GET", "/authorize?"+oid4vc.EncodeURIQuery(qp), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Fatalf("expected submitted, got %v", result["status"])
	}
	if receivedVPToken != "" {
		t.Errorf("expected no vp_token in verifier request, got %q", receivedVPToken)
	}
	if receivedIDToken == "" {
		t.Fatal("expected id_token in verifier request")
	}

	_, payload, _, err := format.ParseJWTParts(receivedIDToken)
	if err != nil {
		t.Fatalf("parsing id_token: %v", err)
	}
	if payload["aud"] != "https://verifier.example" {
		t.Errorf("expected aud=https://verifier.example, got %v", payload["aud"])
	}
	if payload["nonce"] != "nonce123" {
		t.Errorf("expected nonce=nonce123, got %v", payload["nonce"])
	}
}

func TestBrowserIDTokenOnlyFlowWithoutCredentialMatch(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{
		"digital": {
			"requests": [
				{
					"protocol": "openid4vp-v1-unsigned",
					"data": {
						"response_type": "id_token",
						"response_mode": "dc_api",
						"nonce": "browser-nonce",
						"state": "browser-state"
					}
				}
			]
		}
	}`

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://rp.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected browser data object, got %T", result["data"])
	}
	if _, ok := data["vp_token"]; ok {
		t.Fatalf("expected no vp_token in Digital Credentials API result, got %v", data["vp_token"])
	}
	rawIDToken, ok := data["id_token"].(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("expected id_token in Digital Credentials API result, got %v", data["id_token"])
	}

	_, payload, _, err := format.ParseJWTParts(rawIDToken)
	if err != nil {
		t.Fatalf("parsing id_token: %v", err)
	}
	if payload["aud"] != "origin:https://rp.example" {
		t.Errorf("expected aud=origin:https://rp.example, got %v", payload["aud"])
	}
	if payload["nonce"] != "browser-nonce" {
		t.Errorf("expected nonce=browser-nonce, got %v", payload["nonce"])
	}
}
