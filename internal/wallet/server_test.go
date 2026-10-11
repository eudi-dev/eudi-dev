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
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

func newTestServer(t testing.TB, autoAccept bool) *Server {
	t.Helper()
	w := generateTestWallet(t)
	w.AutoAccept = autoAccept
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	return NewServer(w, 0, nil)
}

func newStrictTestServer(t *testing.T, autoAccept bool) *Server {
	t.Helper()
	srv := newTestServer(t, autoAccept)
	srv.wallet.ValidationMode = ValidationModeStrict
	return srv
}

func serverRequest(t testing.TB, srv *Server, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// OpenID4VCI 1.0 §12.2.2 serves signed metadata when the client requests
// application/jwt.
func signedIssuerMetadataRequest(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/.well-known/openid-credential-issuer", nil)
	req.Header.Set("Accept", "application/jwt")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func decodeJSONArray(t *testing.T, w *httptest.ResponseRecorder) []any {
	t.Helper()
	var result []any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON array: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func decodeCompactJWTHeader(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.SplitN(strings.TrimSpace(raw), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", raw)
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding compact JWT header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing compact JWT header: %v", err)
	}
	return header
}

func decodeCompactJWTPayload(t *testing.T, raw string, dest any) {
	t.Helper()
	parts := strings.SplitN(strings.TrimSpace(raw), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", raw)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding compact JWT payload: %v", err)
	}
	if err := json.Unmarshal(payloadBytes, dest); err != nil {
		t.Fatalf("parsing compact JWT payload: %v", err)
	}
}

func verifyCompactJWTSignatureWithX5CLeaf(t *testing.T, raw string, header map[string]any) {
	t.Helper()
	token, err := sdjwt.Parse(strings.TrimSpace(raw))
	if err != nil {
		t.Fatalf("parsing signed JWT: %v", err)
	}
	certs, err := certchain.FromX5C(header["x5c"])
	if err != nil {
		t.Fatalf("parsing x5c header: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected x5c entries in JWT header")
	}
	leafCert := certs[0]
	result := sdjwt.Verify(token, leafCert.PublicKey)
	if result == nil || !result.SignatureValid {
		t.Fatal("expected compact JWT signature to verify with x5c leaf")
	}
}

func TestListCredentials(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/credentials", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	creds := decodeJSONArray(t, w)
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}
}

func TestAuthorize_StrictRejectsTransactionData(t *testing.T) {
	srv := newStrictTestServer(t, true)
	req := httptest.NewRequest("GET", "/authorize?client_id=https://verifier.example&response_type=vp_token&transaction_data=%5B%5D", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "transaction_data") {
		t.Fatalf("expected transaction_data error, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsInvalidMDocAlgValuesSupported(t *testing.T) {
	srv := newTestServer(t, true)
	requestJWT := makeTestJWT(map[string]any{
		"alg": "none",
		"typ": "oauth-authz-req+jwt",
	}, map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_uri":  "https://verifier.example/response",
		"nonce":         "nonce",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid_mdoc",
					"format": "mso_mdoc",
				},
			},
		},
		"client_metadata": map[string]any{
			"vp_formats_supported": map[string]any{
				"mso_mdoc": map[string]any{
					"issuerauth_alg_values": []any{"ES256"},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "/authorize?request="+url.QueryEscape(requestJWT), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "COSE algorithm number") {
		t.Fatalf("expected mdoc alg validation error, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsInvalidOuterClientMetadata(t *testing.T) {
	srv := newTestServer(t, true)
	clientMetadata := `{"vp_formats_supported":{"mso_mdoc":{"deviceauth_alg_values":["ES256"]}}}`
	req := httptest.NewRequest("GET", "/authorize?client_id=https://verifier.example&response_type=vp_token&response_uri=https://verifier.example/response&client_metadata="+url.QueryEscape(clientMetadata), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "COSE algorithm number") {
		t.Fatalf("expected mdoc alg validation error, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsUnsupportedRequestURIMethod(t *testing.T) {
	srv := newTestServer(t, true)
	req := httptest.NewRequest("GET", "/authorize?client_id=https://verifier.example&response_type=vp_token&response_uri=https://verifier.example/response&request_uri=https://verifier.example/request.jwt&request_uri_method=put", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "request_uri_method") {
		t.Fatalf("expected request_uri_method error, got %s", w.Body.String())
	}
}

func TestImportCredentialAPI(t *testing.T) {
	srv := newTestServer(t, false)

	sdjwt := generateSDJWTForTest(t, srv)

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(sdjwt))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["format"] != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %v", result["format"])
	}
	if result["id"] == nil {
		t.Error("expected id in response")
	}
}

func TestServerReloadsSharedStoreBeforeRequest(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	serverWallet, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate server wallet: %v", err)
	}
	srv := NewServer(serverWallet, 0, nil)
	srv.SetStore(store)
	serverWallet.BaseURL = "http://server.example"
	serverWallet.IssuerURL = "https://server.example"

	otherWallet, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate other wallet: %v", err)
	}
	otherWallet.BaseURL = "http://stored.example"
	otherWallet.IssuerURL = "https://stored.example"
	sdjwt := generateSDJWTForTest(t, srv)
	imported, err := otherWallet.ImportCredential(sdjwt)
	if err != nil {
		t.Fatalf("import credential in other wallet: %v", err)
	}
	if err := store.Save(otherWallet); err != nil {
		t.Fatalf("save other wallet: %v", err)
	}

	rec := serverRequest(t, srv, http.MethodGet, "/api/credentials", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	items := decodeJSONArray(t, rec)
	if len(items) != 1 {
		t.Fatalf("expected 1 credential after store reload, got %d", len(items))
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("expected object credential summary, got %T", items[0])
	}
	if item["id"] != imported.ID {
		t.Fatalf("expected credential id %s, got %v", imported.ID, item["id"])
	}
	if serverWallet.BaseURL != "http://server.example" {
		t.Fatalf("expected runtime base URL to be preserved, got %s", serverWallet.BaseURL)
	}
	if serverWallet.IssuerURL != "https://server.example" {
		t.Fatalf("expected runtime issuer URL to be preserved, got %s", serverWallet.IssuerURL)
	}
}

func TestImportCredentialAPI_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "POST", "/api/credentials", "")

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(""))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = w
}

func TestImportCredentialAPI_Invalid(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader("not-a-credential"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid credential, got %d", w.Code)
	}
}

func TestDeleteCredentialAPI(t *testing.T) {
	srv := newTestServer(t, false)

	w := serverRequest(t, srv, "GET", "/api/credentials", "")
	creds := decodeJSONArray(t, w)
	id := creds[0].(map[string]any)["id"].(string)

	req := httptest.NewRequest("DELETE", "/api/credentials/"+id, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	w2 := serverRequest(t, srv, "GET", "/api/credentials", "")
	creds2 := decodeJSONArray(t, w2)
	if len(creds2) != 1 {
		t.Errorf("expected 1 credential after deletion, got %d", len(creds2))
	}
}

func TestDeleteCredentialAPI_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("DELETE", "/api/credentials/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListPendingRequests_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/requests", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	requests := decodeJSONArray(t, w)
	if len(requests) != 0 {
		t.Errorf("expected 0 pending requests, got %d", len(requests))
	}
}

func TestApproveRequest_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/requests/nonexistent/approve", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDenyRequest_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/requests/nonexistent/deny", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestLogAPI_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/log", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestStaticFiles_Index(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "EUDI Dev Wallet") {
		t.Error("expected index.html to contain 'EUDI Dev Wallet'")
	}
	if !strings.Contains(body, "app.js") {
		t.Error("expected index.html to reference app.js")
	}
}

func TestStaticFiles_CSS(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/style.css", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "--bg") {
		t.Error("expected CSS to contain --bg custom property")
	}
}

func TestStaticFiles_JS(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/app.js", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "'api/credentials") {
		t.Error("expected app.js to reference api/credentials")
	}
}

func TestPresentationAPI_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("POST", "/api/presentations", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPresentationAPI_InvalidURI(t *testing.T) {
	srv := newTestServer(t, true)
	w := serverRequest(t, srv, "POST", "/api/presentations", `{"uri":"not-a-valid-uri"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPresentationAPI_InvalidURIWithRequestScopedOptionsShowsErrorOnMainWallet(t *testing.T) {
	srv := newTestServer(t, false)

	uiRequested := false
	srv.SetOnUIRequest(func(string) {
		uiRequested = true
	})

	w := serverRequest(t, srv, "POST", "/api/presentations", `{"uri":"not-a-valid-uri","mode":"strict"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !uiRequested {
		t.Fatal("expected UI request callback")
	}

	rec := serverRequest(t, srv, "GET", "/api/error", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/error, got %d", rec.Code)
	}
	var got consent.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode /api/error: %v", err)
	}
	if got.Message != "Failed to parse authorization request" {
		t.Fatalf("unexpected error message: %#v", got)
	}

	rec = serverRequest(t, srv, "GET", "/api/error", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from second /api/error, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode second /api/error: %v", err)
	}
	if got.Message != "Failed to parse authorization request" {
		t.Fatalf("expected error to remain until dismissed, got %#v", got)
	}

	rec = serverRequest(t, srv, "DELETE", "/api/error", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from DELETE /api/error, got %d", rec.Code)
	}
	rec = serverRequest(t, srv, "GET", "/api/error", "")
	if strings.TrimSpace(rec.Body.String()) != "null" {
		t.Fatalf("expected cleared error, got %s", rec.Body.String())
	}
}

func TestPresentationAPI_AutoAcceptOverrideSkipsConsent(t *testing.T) {
	srv := newTestServer(t, false)

	uiRequested := false
	consentRequested := false
	srv.SetOnUIRequest(func(string) {
		uiRequested = true
	})
	srv.setOnConsentRequest(func(req *consent.Request) {
		consentRequested = true
	})

	var receivedVPToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		receivedVPToken = parsed.Get("vp_token")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := pidDCQLQuery()
	dcqlJSON, _ := json.Marshal(dcqlQuery)
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}.Encode()

	body := fmt.Sprintf(`{"uri":%q,"auto_accept":true}`, uri)
	rec := serverRequest(t, srv, "POST", "/api/presentations", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result := decodeJSON(t, rec)
	if result["status"] != "submitted" {
		t.Fatalf("expected status submitted, got %v", result["status"])
	}
	if receivedVPToken == "" {
		t.Fatal("verifier did not receive VP token")
	}
	if uiRequested {
		t.Fatal("onUIRequest callback should not be called for request-scoped auto-accept")
	}
	if consentRequested {
		t.Fatal("onConsentRequest callback should not be called for request-scoped auto-accept")
	}
}

func TestBrowserPresentationAPI_DCAPIUnsigned(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{
		"digital": {
			"requests": [
				{
					"protocol": "openid4vp-v1-unsigned",
					"data": {
						"response_type": "vp_token",
						"response_mode": "dc_api",
						"nonce": "browser-nonce",
						"state": "browser-state",
						"dcql_query": {
							"credentials": [
								{
									"id": "pid",
									"format": "dc+sd-jwt",
									"meta": {"vct_values": ["` + mock.DefaultPIDVCT + `"]},
									"claims": [{"path": ["given_name"]}]
								}
							]
						}
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
	if result["protocol"] != "openid4vp-v1-unsigned" {
		t.Fatalf("expected unsigned protocol, got %v", result["protocol"])
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected browser data object, got %T", result["data"])
	}
	if data["state"] != "browser-state" {
		t.Fatalf("expected state in browser result, got %v", data["state"])
	}

	vpToken, ok := data["vp_token"].(map[string]any)
	if !ok {
		t.Fatalf("expected vp_token object, got %T", data["vp_token"])
	}
	pidEntries, ok := vpToken["pid"].([]any)
	if !ok || len(pidEntries) != 1 {
		t.Fatalf("expected vp_token.pid with one entry, got %v", vpToken["pid"])
	}
}

// OID4VP 1.0 Appendix A.2: "The value of the response_mode parameter MUST be
// dc_api when the response is not encrypted and dc_api.jwt when the response
// is encrypted". The wallet refuses another mode before it asks for consent.
func TestBrowserPresentationAPI_RefusesANonDCAPIResponseMode(t *testing.T) {
	srv := newTestServer(t, true)
	body := `{"digital": {"requests": [{
		"protocol": "openid4vp-v1-unsigned",
		"data": {
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"response_uri": "https://rp.example/response",
			"nonce": "browser-nonce",
			"dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["` + mock.DefaultPIDVCT + `"]}}]}
		}
	}]}}`

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://rp.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "dc_api") {
		t.Fatalf("got %d: %s, want 400 naming dc_api", rec.Code, rec.Body.String())
	}
}

func TestBrowserPresentationAPI_DCAPIUnsignedWithoutClientID(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{
		"digital": {
			"requests": [
				{
					"protocol": "openid4vp-v1-unsigned",
					"data": {
						"response_type": "vp_token",
						"response_mode": "dc_api",
						"nonce": "browser-nonce",
						"dcql_query": {
							"credentials": [
								{
									"id": "pid",
									"format": "dc+sd-jwt",
									"meta": {"vct_values": ["` + mock.DefaultPIDVCT + `"]},
									"claims": [{"path": ["given_name"]}]
								}
							]
						}
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
}

func TestBrowserPresentationAPI_DCAPISignedJWT(t *testing.T) {
	srv := newTestServer(t, true)
	encKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating encryption key: %v", err)
	}
	jwk := testEncJWK(t, &encKey.PublicKey)

	requestJWT := makeTestJWT(
		map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"},
		map[string]any{
			"client_id":     "https://verifier.example",
			"response_type": "vp_token",
			"response_mode": "dc_api.jwt",
			"nonce":         "browser-nonce",
			"state":         "browser-state",
			"dcql_query": map[string]any{
				"credentials": []any{
					map[string]any{
						"id":     "pid",
						"format": "dc+sd-jwt",
						"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
						"claims": []any{map[string]any{"path": []any{"given_name"}}},
					},
				},
			},
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
				"encrypted_response_enc_values_supported": []any{"A128GCM"},
			},
		},
	)

	payload := map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{
					"protocol": "openid4vp-v1-signed",
					"data": map[string]any{
						"request": requestJWT,
					},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["protocol"] != "openid4vp-v1-signed" {
		t.Fatalf("expected signed protocol, got %v", result["protocol"])
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected browser data object, got %T", result["data"])
	}
	responseJWT, ok := data["response"].(string)
	if !ok || responseJWT == "" {
		t.Fatalf("expected encrypted response JWT, got %v", data["response"])
	}

	plaintext, err := oid4vp.DecryptRequestObjectJWE(responseJWT, encKey)
	if err != nil {
		t.Fatalf("decrypting browser response: %v", err)
	}

	var decrypted map[string]any
	if err := json.Unmarshal([]byte(plaintext), &decrypted); err != nil {
		t.Fatalf("parsing decrypted response: %v", err)
	}
	// OID4VP 1.0 Appendix A.2 leaves state undefined for DC API responses. The
	// verifier correlates the response with its API call.
	if _, present := decrypted["state"]; present {
		t.Errorf("the encrypted Digital Credentials API response carries state: %v", decrypted["state"])
	}
	vpToken, ok := decrypted["vp_token"].(map[string]any)
	if !ok {
		t.Fatalf("expected encrypted vp_token object, got %T", decrypted["vp_token"])
	}
	pidEntries, ok := vpToken["pid"].([]any)
	if !ok || len(pidEntries) != 1 {
		t.Fatalf("expected encrypted vp_token.pid with one entry, got %v", vpToken["pid"])
	}
	entry := findLogEntry(srv.wallet.GetLog(), "presentation_response")
	if entry == nil || entry.Payload == nil || !entry.Payload.Encrypted {
		t.Fatal("encrypted activity payload missing")
	}
	loggedPlain, err := json.Marshal(entry.Payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	actualPlain, err := json.Marshal(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(loggedPlain) != string(actualPlain) {
		t.Fatalf("logged plaintext differs from transmitted JWE: %s != %s", loggedPlain, actualPlain)
	}
	loggedWire, err := json.Marshal(entry.Payload.Wire)
	if err != nil {
		t.Fatal(err)
	}
	var loggedWireValue map[string]any
	if err := json.Unmarshal(loggedWire, &loggedWireValue); err != nil {
		t.Fatal(err)
	}
	loggedWire, err = json.Marshal(loggedWireValue)
	if err != nil {
		t.Fatal(err)
	}
	actualWire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(loggedWire) != string(actualWire) {
		t.Fatal("activity does not contain the exact browser response")
	}
}

// OID4VP 1.0 Appendix A.2 requires ignoring expected_origins in unsigned requests. The
// platform supplies the origin used to authenticate the request.
func TestBrowserPresentationAPI_UnsignedRequestIgnoresExpectedOrigins(t *testing.T) {
	srv := newTestServer(t, true)

	payload := map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{
					"protocol": "openid4vp-v1-unsigned",
					"data": map[string]any{
						"response_type":    "vp_token",
						"response_mode":    "dc_api.jwt",
						"nonce":            "browser-nonce",
						"expected_origins": []any{"https://other.example"},
						"dcql_query":       pidDCQLQuery(),
						"client_metadata":  encryptionClientMetadata(t),
					},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}

	srv.wallet.ValidationMode = ValidationModeStrict
	srv.wallet.RequireHAIP = true

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://wallet.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "expected_origins") {
		t.Fatalf("an unsigned request was refused over expected_origins: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBrowserPresentationAPI_DCAPIMultiSignedPrefersValidSignature(t *testing.T) {
	srv := newTestServer(t, true)

	key, certB64, _ := testCertWithKeyDER([]string{"example.com"})
	header := map[string]any{
		"alg": "ES256",
		"typ": "oauth-authz-req+jwt",
		"x5c": []any{certB64},
	}
	payload := map[string]any{
		"client_id":     "x509_san_dns:example.com",
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"nonce":         "browser-nonce",
		"state":         "browser-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
					"claims": []any{map[string]any{"path": []any{"given_name"}}},
				},
			},
		},
	}

	requestJWT, err := signJWT(header, payload, key)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parts := strings.Split(requestJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", requestJWT)
	}

	payloadBody := map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{
					"protocol": "openid4vp-v1-multisigned",
					"data": map[string]any{
						"request": map[string]any{
							"payload": parts[1],
							"signatures": []any{
								map[string]any{
									"protected": parts[0],
									"signature": "AAAA",
								},
								map[string]any{
									"protected": parts[0],
									"signature": parts[2],
								},
							},
						},
					},
				},
			},
		},
	}
	body, err := json.Marshal(payloadBody)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["protocol"] != "openid4vp-v1-multisigned" {
		t.Fatalf("expected multisigned protocol, got %v", result["protocol"])
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected browser data object, got %T", result["data"])
	}
	if data["state"] != "browser-state" {
		t.Fatalf("expected state in browser result, got %v", data["state"])
	}
}

func TestPresentationFlow_AutoAccept(t *testing.T) {
	srv := newTestServer(t, true)

	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"redirect_uri": "https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"test-nonce-123"},
		"state":         {"test-state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	if receivedBody == "" {
		t.Fatal("verifier did not receive VP token")
	}

	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}

	vpTokenRaw := parsedForm.Get("vp_token")
	if vpTokenRaw == "" {
		t.Fatal("expected vp_token in verifier request")
	}

	var vpToken map[string][]string
	if err := json.Unmarshal([]byte(vpTokenRaw), &vpToken); err != nil {
		t.Fatalf("vp_token should be a JSON object: %v", err)
	}
	pidValues, ok := vpToken["pid"]
	if !ok {
		t.Fatal("expected 'pid' key in vp_token")
	}
	if len(pidValues) != 1 || pidValues[0] == "" {
		t.Error("expected non-empty pid presentation")
	}

	state := parsedForm.Get("state")
	if state != "test-state" {
		t.Errorf("expected state 'test-state', got %s", state)
	}

	response, ok := result["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response object in result")
	}
	if response["redirect_uri"] != "https://verifier.example/done" {
		t.Errorf("expected redirect_uri, got %v", response["redirect_uri"])
	}

	assertWalletLogEvent(t, srv.wallet.GetLog(), "presentation_request")
	assertWalletLogEvent(t, srv.wallet.GetLog(), "presentation_response")
	assertWalletLogEvent(t, srv.wallet.GetLog(), "verifier_response")
	assertWalletLogEventExcludes(t, srv.wallet.GetLog(), "presentation_response", "dcql_query", "request_object", "client_metadata", "nonce")
}

func assertWalletLogEvent(t *testing.T, entries []LogEntry, event string) {
	t.Helper()
	for _, entry := range entries {
		if entry.Details == nil {
			continue
		}
		if entry.Details["event"] == event {
			return
		}
	}
	t.Fatalf("missing wallet log event %q in %#v", event, entries)
}

func assertWalletLogEventExcludes(t *testing.T, entries []LogEntry, event string, excludedKeys ...string) {
	t.Helper()
	for _, entry := range entries {
		if entry.Details == nil || entry.Details["event"] != event {
			continue
		}
		for _, key := range excludedKeys {
			if _, ok := entry.Details[key]; ok {
				t.Fatalf("wallet log event %q should not include %q: %#v", event, key, entry.Details)
			}
		}
		return
	}
	t.Fatalf("missing wallet log event %q in %#v", event, entries)
}

func TestPresentationFlow_AutoAccept_NoMatch(t *testing.T) {
	srv := newTestServer(t, true)

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "mdl",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeJSON(t, w)
	if result["status"] != "no_match" {
		t.Errorf("expected status 'no_match', got %v", result["status"])
	}
}

func TestPresentationFlow_AutoAccept_MultipleCredentials(t *testing.T) {
	srv := newTestServer(t, true)

	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	vpTokenKeys, ok := result["vp_token_keys"].([]any)
	if !ok {
		t.Fatal("expected vp_token_keys in result")
	}
	if len(vpTokenKeys) != 2 {
		t.Errorf("expected 2 vp_token_keys, got %d", len(vpTokenKeys))
	}

	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}

	var vpToken map[string][]string
	if err := json.Unmarshal([]byte(parsedForm.Get("vp_token")), &vpToken); err != nil {
		t.Fatalf("vp_token should be a JSON object with array values: %v", err)
	}

	if _, ok := vpToken["pid_sdjwt"]; !ok {
		t.Error("expected 'pid_sdjwt' key in vp_token")
	}
	if _, ok := vpToken["pid_mdoc"]; !ok {
		t.Error("expected 'pid_mdoc' key in vp_token")
	}

	for _, qid := range []string{"pid_sdjwt", "pid_mdoc"} {
		if len(vpToken[qid]) != 1 || vpToken[qid][0] == "" {
			t.Errorf("expected non-empty presentation for %q", qid)
		}
	}

	if len(vpToken) != 2 {
		t.Errorf("expected exactly 2 keys in vp_token, got %d", len(vpToken))
	}
}

func TestPresentationFlow_AutoAccept_POST(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	form := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}
}

func TestAuthorize_MissingClientID(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("GET", "/authorize?response_type=vp_token", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing client_id, got %d", w.Code)
	}
}

func TestConsentFlow_ApproveAndDeny(t *testing.T) {
	srv := newTestServer(t, false)

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	reqID := waitForPendingRequest(t, srv.wallet).ID

	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve",
		strings.NewReader(`{"selected_claims":{}}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}

	w := <-resultCh
	if w.Code != http.StatusOK {
		t.Fatalf("authorize expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}
}

func TestConsentFlow_Deny(t *testing.T) {
	srv := newTestServer(t, false)
	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	reqID := waitForPendingRequest(t, srv.wallet).ID

	denyReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/deny", nil)
	denyRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(denyRec, denyReq)

	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d", denyRec.Code)
	}
	denyResult := decodeJSON(t, denyRec)
	if denyResult["status"] != "denied" {
		t.Fatalf("expected deny API status 'denied', got %v", denyResult["status"])
	}

	w := <-resultCh
	if w.Code != http.StatusOK {
		t.Fatalf("expected authorize flow to complete with 200, got %d: %s", w.Code, w.Body.String())
	}
	if receivedBody == "" {
		t.Fatal("verifier did not receive denied error response")
	}
	result := decodeJSON(t, w)
	if result["status"] != "denied" {
		t.Errorf("expected status 'denied', got %v", result["status"])
	}
}

func TestPresentationFlow_NextErrorOverride_DirectPostJWT_SubmitsEncryptedErrorWithState(t *testing.T) {
	srv := newTestServer(t, true)

	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	rec := serverRequest(t, srv, "POST", "/api/next-error",
		`{"error":"access_denied","error_description":"testing"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	clientMetadata, _ := json.Marshal(map[string]any{
		"jwks": map[string]any{
			"keys": []any{jwk},
		},
		"encrypted_response_enc_values_supported": []any{"A128GCM"},
	})

	params := url.Values{
		"client_id":       {"https://verifier.example"},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"nonce":           {"nonce"},
		"state":           {"state-123"},
		"response_uri":    {verifier.URL},
		"client_metadata": {string(clientMetadata)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if receivedBody == "" {
		t.Fatal("verifier did not receive error response")
	}

	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}
	if parsedForm.Get("response") == "" {
		t.Fatal("expected response JWT in verifier request")
	}
	if parsedForm.Get("state") != "" {
		t.Fatalf("expected no top-level state form field, got %q", parsedForm.Get("state"))
	}

	plaintext, err := oid4vp.DecryptRequestObjectJWE(parsedForm.Get("response"), key)
	if err != nil {
		t.Fatalf("decrypting error JWT: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["error"] != "access_denied" {
		t.Fatalf("expected error in JWT payload, got %v", payload["error"])
	}
	if payload["error_description"] != "testing" {
		t.Fatalf("expected error_description in JWT payload, got %v", payload["error_description"])
	}
	if payload["state"] != "state-123" {
		t.Fatalf("expected state in JWT payload, got %v", payload["state"])
	}

	result := decodeJSON(t, w)
	if result["status"] != "error" {
		t.Fatalf("expected status 'error', got %v", result["status"])
	}
}

func TestConsentFlow_Deny_DirectPostJWT_SubmitsEncryptedErrorWithState(t *testing.T) {
	srv := newTestServer(t, false)

	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	clientMetadata, _ := json.Marshal(map[string]any{
		"jwks": map[string]any{
			"keys": []any{jwk},
		},
		"encrypted_response_enc_values_supported": []any{"A128GCM"},
	})

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":       {"https://verifier.example"},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"nonce":           {"nonce"},
		"state":           {"state-123"},
		"response_uri":    {verifier.URL},
		"client_metadata": {string(clientMetadata)},
		"dcql_query":      {string(dcqlJSON)},
	}

	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	reqID := waitForPendingRequest(t, srv.wallet).ID

	denyReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/deny", nil)
	denyRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d", denyRec.Code)
	}

	w := <-resultCh
	if receivedBody == "" {
		t.Fatal("verifier did not receive denied error response")
	}

	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}
	if parsedForm.Get("response") == "" {
		t.Fatal("expected response JWT in verifier request")
	}
	if parsedForm.Get("state") != "" {
		t.Fatalf("expected no top-level state form field, got %q", parsedForm.Get("state"))
	}

	plaintext, err := oid4vp.DecryptRequestObjectJWE(parsedForm.Get("response"), key)
	if err != nil {
		t.Fatalf("decrypting error JWT: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["error"] != "access_denied" {
		t.Fatalf("expected error in JWT payload, got %v", payload["error"])
	}
	if payload["error_description"] != "User denied presentation" {
		t.Fatalf("expected error_description in JWT payload, got %v", payload["error_description"])
	}
	if payload["state"] != "state-123" {
		t.Fatalf("expected state in JWT payload, got %v", payload["state"])
	}

	result := decodeJSON(t, w)
	if result["status"] != "denied" {
		t.Fatalf("expected status 'denied', got %v", result["status"])
	}
}

func TestTrustListAPI(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/trustlist", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Errorf("expected Content-Type application/jwt, got %s", ct)
	}

	jwt := w.Body.String()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	loteBody, ok := payload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", payload["LoTE"])
	}
	if _, ok := loteBody["TrustedEntitiesList"]; !ok {
		t.Error("expected TrustedEntitiesList in LoTE payload")
	}
	if _, ok := loteBody["ListAndSchemeInformation"]; !ok {
		t.Error("expected ListAndSchemeInformation in LoTE payload")
	}
}

func TestTrustListAPI_ParseableByTrustlistParser(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/trustlist", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tl, err := lote.Parse(w.Body.String())
	if err != nil {
		t.Fatalf("trusted list parser failed: %v", err)
	}

	if tl.SchemeInfo == nil {
		t.Fatal("expected SchemeInfo to be parsed")
	}
	if tl.SchemeInfo.SchemeOperatorName != "EUDI Dev Wallet" {
		t.Errorf("expected operator name 'EUDI Dev Wallet', got %q", tl.SchemeInfo.SchemeOperatorName)
	}
	if tl.SchemeInfo.LoTEType != lote.PIDProvidersListType {
		t.Errorf("unexpected LoTEType: %s", tl.SchemeInfo.LoTEType)
	}
	if tl.SchemeInfo.ListIssueDatetime == "" {
		t.Fatal("expected ListIssueDateTime to be parsed")
	}

	if len(tl.Entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(tl.Entities))
	}
	if tl.Entities[0].Name != "EUDI Dev Test Provider" {
		t.Errorf("expected test provider organization name, got %q", tl.Entities[0].Name)
	}
	if len(tl.Entities[0].Services) != 2 {
		t.Fatalf("expected 2 services (issuance + revocation), got %d", len(tl.Entities[0].Services))
	}

	issuanceSvc := tl.Entities[0].Services[0]
	if issuanceSvc.ServiceType != "http://uri.etsi.org/19602/SvcType/PID/Issuance" {
		t.Errorf("unexpected issuance service type: %s", issuanceSvc.ServiceType)
	}
	if len(issuanceSvc.Certificates) != 6 {
		t.Fatalf("expected the NL, DE and IT signing certificates and their CAs, got %d", len(issuanceSvc.Certificates))
	}
	certPub, ok := issuanceSvc.Certificates[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ECDSA public key in issuance certificate")
	}
	if !certPub.Equal(&srv.wallet.IssuerKey.PublicKey) {
		t.Error("issuance certificate public key does not match credential signing key")
	}

	revocationSvc := tl.Entities[0].Services[1]
	if revocationSvc.ServiceType != "http://uri.etsi.org/19602/SvcType/PID/Revocation" {
		t.Errorf("unexpected revocation service type: %s", revocationSvc.ServiceType)
	}
	if len(revocationSvc.Certificates) != 1 {
		t.Fatalf("expected 1 certificate in revocation service, got %d", len(revocationSvc.Certificates))
	}
}

// A PID is signed under a CA of its issuing country, so the PID list names
// the CA of every PID template's country.
func TestThePIDListNamesTheCountryOfEveryPIDTemplate(t *testing.T) {
	srv := newTestServer(t, false)
	dir := t.TempDir()
	french := `{"format": "sdjwt", "vct": "urn:eudi:pid:fr:1", "category": "pid", "claims": {"issuing_country": "FR"}}`
	if err := os.WriteFile(filepath.Join(dir, "french-pid-sdjwt.json"), []byte(french), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.wallet.Templates = credtemplate.FileLocation(dir)

	resp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	tl, err := lote.Parse(resp.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	var countries []string
	for _, cert := range tl.Entities[0].Services[0].Certificates {
		if parsed, err := x509.ParseCertificate(cert.Raw); err == nil && parsed.IsCA {
			countries = append(countries, parsed.Subject.Country...)
		}
	}
	for _, want := range []string{"NL", "DE", "IT", "FR"} {
		if !slices.Contains(countries, want) {
			t.Errorf("the PID list names CAs of %v, want one of %s", countries, want)
		}
	}
}

func TestTrustListAPI_RemainsCertificateCentric(t *testing.T) {
	srv := newTestServer(t, false)

	resp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload map[string]any
	decodeCompactJWTPayload(t, resp.Body.String(), &payload)

	loteBody, ok := payload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", payload["LoTE"])
	}
	entities, ok := loteBody["TrustedEntitiesList"].([]any)
	if !ok || len(entities) == 0 {
		t.Fatalf("expected TrustedEntitiesList entries, got %T", loteBody["TrustedEntitiesList"])
	}
	entity, ok := entities[0].(map[string]any)
	if !ok {
		t.Fatalf("expected trusted entity object, got %T", entities[0])
	}
	services, ok := entity["TrustedEntityServices"].([]any)
	if !ok || len(services) == 0 {
		t.Fatalf("expected TrustedEntityServices entries, got %T", entity["TrustedEntityServices"])
	}

	forbiddenKeys := []string{
		"providerId",
		"providerClass",
		"currentStatus",
		"statusHistory",
		"authorizedAttestationTypes",
		"entitlements",
		"providesAttestations",
	}

	for _, serviceEntry := range services {
		service, ok := serviceEntry.(map[string]any)
		if !ok {
			t.Fatalf("expected service object, got %T", serviceEntry)
		}
		info, ok := service["ServiceInformation"].(map[string]any)
		if !ok {
			t.Fatalf("expected ServiceInformation object, got %T", service["ServiceInformation"])
		}
		for _, key := range forbiddenKeys {
			if _, exists := info[key]; exists {
				t.Errorf("trusted list service must not expose %q", key)
			}
		}
	}
}

func TestJWTVCIssuerMetadata_ExposesSigningKeyTrustedByTrustList(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)
	// Use the current signing certificate's expiry. A value captured at startup
	// becomes stale after certificate renewal.
	wantExp := w.SigningCertificateExpiry().Unix()

	metaResp := serverRequest(t, srv, "GET", "/.well-known/jwt-vc-issuer", "")
	if metaResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", metaResp.Code, metaResp.Body.String())
	}
	meta := decodeJSON(t, metaResp)
	if meta["issuer"] != w.IssuerURL {
		t.Fatalf("expected issuer %s, got %v", w.IssuerURL, meta["issuer"])
	}

	jwks, ok := meta["jwks"].(map[string]any)
	if !ok {
		t.Fatal("expected jwks object in metadata")
	}
	keys, ok := jwks["keys"].([]any)
	// One key per category list and one for credentials on no list. The PID
	// key comes first.
	if !ok || len(keys) != 5 {
		t.Fatalf("expected five JWKs, got %v", jwks["keys"])
	}
	jwk, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("expected JWK object, got %T", keys[0])
	}
	wantKid := mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey)
	if jwk["kid"] != wantKid {
		t.Fatalf("expected metadata kid %s, got %v", wantKid, jwk["kid"])
	}
	exp, ok := jwk["exp"].(float64)
	if !ok {
		t.Fatalf("expected numeric exp in JWK, got %T", jwk["exp"])
	}
	if got := int64(exp); got != wantExp {
		t.Fatalf("expected JWK exp %d (the signing certificate's), got %d", wantExp, got)
	}

	x5c, ok := jwk["x5c"].([]any)
	if !ok || len(x5c) != 2 {
		t.Fatalf("expected leaf and intermediate in JWK x5c, got %v", jwk["x5c"])
	}
	leafB64, ok := x5c[0].(string)
	if !ok {
		t.Fatalf("expected string x5c leaf, got %T", x5c[0])
	}
	leafDER, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		t.Fatalf("decoding x5c leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing x5c leaf: %v", err)
	}

	tlResp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if tlResp.Code != http.StatusOK {
		t.Fatalf("expected trusted list 200, got %d: %s", tlResp.Code, tlResp.Body.String())
	}
	tl, err := lote.Parse(strings.TrimSpace(tlResp.Body.String()))
	if err != nil {
		t.Fatalf("parsing trusted list: %v", err)
	}
	tlCerts := lote.ServiceCertificates(tl, lote.IssuanceServices)
	validatedKey, err := validate.ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err != nil {
		t.Fatalf("validating issuer metadata x5c against trusted list: %v", err)
	}
	issuerPub, ok := validatedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", validatedKey)
	}
	if !issuerPub.Equal(&w.IssuerKey.PublicKey) {
		t.Fatal("issuer metadata leaf certificate does not contain the wallet issuer key")
	}

	var rawSDJWT string
	for _, cred := range w.GetCredentials() {
		if cred.Format == "dc+sd-jwt" {
			rawSDJWT = cred.Raw
			break
		}
	}
	if rawSDJWT == "" {
		t.Fatal("expected generated SD-JWT credential")
	}
	token, err := sdjwt.Parse(rawSDJWT)
	if err != nil {
		t.Fatalf("parsing generated SD-JWT: %v", err)
	}
	if token.Payload["iss"] != w.IssuerURL {
		t.Fatalf("expected SD-JWT iss %s, got %v", w.IssuerURL, token.Payload["iss"])
	}
	if token.Header["kid"] != wantKid {
		t.Fatalf("expected SD-JWT kid %s, got %v", wantKid, token.Header["kid"])
	}

	metaResp2 := serverRequest(t, srv, "GET", "/.well-known/jwt-vc-issuer", "")
	if metaResp2.Code != http.StatusOK {
		t.Fatalf("expected second metadata request 200, got %d: %s", metaResp2.Code, metaResp2.Body.String())
	}
	meta2 := decodeJSON(t, metaResp2)
	jwks2, ok := meta2["jwks"].(map[string]any)
	if !ok {
		t.Fatal("expected jwks object in second metadata response")
	}
	keys2, ok := jwks2["keys"].([]any)
	if !ok || len(keys2) != len(keys) {
		t.Fatalf("expected the same JWKs in the second metadata response, got %v", jwks2["keys"])
	}
	jwk2, ok := keys2[0].(map[string]any)
	if !ok {
		t.Fatalf("expected second JWK object, got %T", keys2[0])
	}
	if jwk2["exp"] != jwk["exp"] {
		t.Fatalf("expected JWK exp to stay stable across requests, got %v then %v", jwk["exp"], jwk2["exp"])
	}
}

// OpenID4VCI 1.0 §12.2.2 requires unsigned JSON metadata. Signed metadata is optional.
func TestOpenIDCredentialIssuerMetadata_ServesUnsignedJSONByDefault(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/.well-known/openid-credential-issuer", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if ct := resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %s, want application/json", ct)
	}
	metadata := decodeJSON(t, resp)
	if metadata["credential_issuer"] != w.IssuerURL {
		t.Fatalf("credential_issuer = %v, want %s", metadata["credential_issuer"], w.IssuerURL)
	}
	if _, ok := metadata["credential_configurations_supported"].(map[string]any); !ok {
		t.Fatalf("unsigned metadata has no credential_configurations_supported: %v", metadata)
	}
}

func TestOpenIDCredentialIssuerMetadata_SignedJWTContainsIssuerInfo(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(w, 0, nil)

	resp := signedIssuerMetadataRequest(t, srv)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	// §12.2.2 gives application/jwt as the media type of the signed form.
	// openidvci-issuer-metadata+jwt is the typ header inside it.
	if ct := resp.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Fatalf("expected signed issuer metadata content type, got %s", ct)
	}

	raw := strings.TrimSpace(resp.Body.String())
	header := decodeCompactJWTHeader(t, raw)
	if header["typ"] != "openidvci-issuer-metadata+jwt" {
		t.Fatalf("expected issuer metadata JWT typ, got %v", header["typ"])
	}
	verifyCompactJWTSignatureWithX5CLeaf(t, raw, header)

	var payload map[string]any
	decodeCompactJWTPayload(t, raw, &payload)
	if payload["credential_issuer"] != w.IssuerURL {
		t.Fatalf("expected credential_issuer %s, got %v", w.IssuerURL, payload["credential_issuer"])
	}

	configs, ok := payload["credential_configurations_supported"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential configurations, got %T", payload["credential_configurations_supported"])
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 credential configurations, got %d", len(configs))
	}

	issuerInfo, ok := payload["issuer_info"].([]any)
	if !ok || len(issuerInfo) != 2 {
		t.Fatalf("expected two issuer_info entries, got %v", payload["issuer_info"])
	}
	entry, ok := issuerInfo[0].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info object, got %T", issuerInfo[0])
	}
	if entry["format"] != "registrar_dataset" {
		t.Fatalf("expected registrar_dataset issuer_info, got %v", entry["format"])
	}
	record, ok := entry["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info data object, got %T", entry["data"])
	}
	if want := w.IssuerURL + "/api/registrar/wrp/" + ownProviderIdentifier(t, w); record["registryURI"] != want {
		t.Fatalf("expected registryURI %s, got %v", want, record["registryURI"])
	}
	// The templates make the demo issuer a PID provider and, for the ticket,
	// an EAA provider. Its identity check makes it a service provider (ARF
	// RPRC_05).
	var dataset registrar.RegistrarDataset
	if err := json.Unmarshal([]byte(mustJSON(t, record)), &dataset); err != nil {
		t.Fatal(err)
	}
	var certificate struct {
		Entitlements []string `json:"entitlements"`
	}
	decodeCompactJWTPayload(t, issuerInfo[1].(map[string]any)["data"].(string), &certificate)
	if want := []string{registrar.NonQEAAProviderEntitlement, registrar.PIDProviderEntitlement, registrar.ServiceProviderEntitlement}; !slices.Equal(certificate.Entitlements, want) {
		t.Fatalf("entitlements %v, want %v", certificate.Entitlements, want)
	}
	var vcts, docTypes []string
	for _, att := range dataset.ProvidesAttestations {
		vcts = append(vcts, att.Type)
		if att.Format == "mso_mdoc" {
			docTypes = append(docTypes, att.Type)
		}
	}
	if !slices.Contains(vcts, mock.DefaultPIDVCT) || !slices.Contains(vcts, credtype.DemoTicketVCT) || !slices.Contains(docTypes, mock.PIDNamespace) {
		t.Fatalf("provided attestations %v, want the PID types and the ticket", dataset.ProvidesAttestations)
	}
}

// TS05 v1.5 §3.2.2: providedattestation finds the providers of a credential type.
func TestRegistrarWRPList_FiltersByProvidedAttestation(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	if _, err := w.EnsureDemoRegistrations(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(w, 0, nil)

	list := func(attestation string) []registrar.WalletRelyingParty {
		t.Helper()
		resp := serverRequest(t, srv, "GET", "/api/registrar/wrp?providedattestation="+url.QueryEscape(attestation), "")
		if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/jwt" {
			t.Fatalf("got %d %s: %s", resp.Code, resp.Header().Get("Content-Type"), resp.Body.String())
		}
		var page struct {
			Data []registrar.WalletRelyingParty `json:"data"`
		}
		decodeCompactJWTPayload(t, resp.Body.String(), &page)
		return page.Data
	}
	matched := list(mock.DefaultPIDVCT)
	if len(matched) != 1 || matched[0].Identifier[0].Identifier != ownProviderIdentifier(t, w) {
		t.Fatalf("matched %+v, want the demo issuer", matched)
	}
	if unmatched := list("urn:example:unknown"); len(unmatched) != 0 {
		t.Fatalf("expected no registrar entries for an unknown attestation, got %d", len(unmatched))
	}
}

// An EAA type is registered with the EAA entitlement and is on the EAA list.
// That list has the EAA list type and no PID URIs.
func TestAnEAATypeIsRegisteredAndListedAsAnEAA(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	w.IssuedAttestations = []provider.IssuedAttestationSpec{
		{Format: "dc+sd-jwt", VCT: "urn:test:employee:1", Category: credtemplate.CategoryEAA},
		{Format: "mso_mdoc", DocType: "org.iso.23220.photoid.1", Category: credtemplate.CategoryEAA},
	}
	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(w, 0, nil)

	metaResp := signedIssuerMetadataRequest(t, srv)
	if metaResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", metaResp.Code, metaResp.Body.String())
	}
	var metadata struct {
		IssuerInfo []struct {
			Data json.RawMessage `json:"data"`
		} `json:"issuer_info"`
	}
	decodeCompactJWTPayload(t, metaResp.Body.String(), &metadata)
	var dataset registrar.RegistrarDataset
	var certificate struct {
		Entitlements []string `json:"entitlements"`
	}
	var registration string
	if len(metadata.IssuerInfo) != 2 || json.Unmarshal(metadata.IssuerInfo[0].Data, &dataset) != nil || json.Unmarshal(metadata.IssuerInfo[1].Data, &registration) != nil {
		t.Fatalf("issuer_info %s, want the dataset and the certificate", metaResp.Body.String())
	}
	var types []string
	for _, att := range dataset.ProvidesAttestations {
		types = append(types, att.Type)
	}
	decodeCompactJWTPayload(t, registration, &certificate)
	if !slices.Contains(certificate.Entitlements, registrar.NonQEAAProviderEntitlement) || !slices.Contains(types, "urn:test:employee:1") || !slices.Contains(types, "org.iso.23220.photoid.1") {
		t.Fatalf("dataset %+v, want both types with the EAA entitlement", dataset)
	}

	trustListResp := serverRequest(t, srv, "GET", "/api/trustlist?vct="+url.QueryEscape("urn:test:employee:1"), "")
	if trustListResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", trustListResp.Code, trustListResp.Body.String())
	}
	var list struct {
		LoTE struct {
			ListAndSchemeInformation map[string]any `json:"ListAndSchemeInformation"`
			TrustedEntitiesList      []struct {
				TrustedEntityServices []struct {
					ServiceInformation struct {
						ServiceTypeIdentifier string `json:"ServiceTypeIdentifier"`
					} `json:"ServiceInformation"`
				} `json:"TrustedEntityServices"`
			} `json:"TrustedEntitiesList"`
		} `json:"LoTE"`
	}
	decodeCompactJWTPayload(t, trustListResp.Body.String(), &list)
	scheme := list.LoTE.ListAndSchemeInformation
	if scheme["LoTEType"] != provider.CategoryList(credtemplate.CategoryEAA).LoTEType || scheme["StatusDeterminationApproach"] != provider.CategoryList(credtemplate.CategoryEAA).StatusDeterminationApproach {
		t.Fatalf("scheme %v, want the EAA list type and its status determination approach", scheme)
	}
	if len(list.LoTE.TrustedEntitiesList) != 1 || len(list.LoTE.TrustedEntitiesList[0].TrustedEntityServices) != 2 {
		t.Fatalf("entities %+v, want one entity with two services", list.LoTE.TrustedEntitiesList)
	}
	services := list.LoTE.TrustedEntitiesList[0].TrustedEntityServices
	if services[0].ServiceInformation.ServiceTypeIdentifier != provider.CategoryList(credtemplate.CategoryEAA).IssuanceServiceType || services[1].ServiceInformation.ServiceTypeIdentifier != provider.CategoryList(credtemplate.CategoryEAA).RevocationServiceType {
		t.Fatalf("services %+v, want the EAA issuance and revocation types", services)
	}
}

func TestTrustListsAPI_ListsEveryCategoryWithThePIDListAsDefault(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.RegisterIssuedAttestation(provider.IssuedAttestationSpec{Category: credtemplate.CategoryPID,
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	}); err != nil {
		t.Fatalf("registering PID attestation: %v", err)
	}
	if err := w.RegisterIssuedAttestation(categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryEAA,
		Format:  "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
		Entitlements: []string{
			registrar.NonQEAAProviderEntitlement,
		},
	})); err != nil {
		t.Fatalf("registering local attestation: %v", err)
	}
	srv := NewServer(w, 0, nil)

	indexResp := serverRequest(t, srv, "GET", "/api/trustlists", "")
	if indexResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", indexResp.Code, indexResp.Body.String())
	}
	index := decodeJSON(t, indexResp)
	rawLists, ok := index["trust_lists"].([]any)
	if !ok || len(rawLists) != 7 {
		t.Fatalf("expected the four category lists and the wallet provider, access CA and registrar lists, got %v", index["trust_lists"])
	}
	var sawPIDDefault, sawEAA, sawWalletProvider bool
	for _, raw := range rawLists {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("expected trust-list entry object, got %T", raw)
		}
		path, ok := entry["path"].(string)
		if !ok || !strings.HasPrefix(path, "/api/trustlists/") {
			t.Fatalf("expected relative trust-list path, got %v", entry["path"])
		}
		switch entry["id"] {
		case "pid":
			if entry["default"] != true {
				t.Fatalf("expected pid trusted list to be default, got %v", entry["default"])
			}
			if entry["advertised_url"] != "https://localhost:8443/api/trustlists/pid" {
				t.Fatalf("expected pid advertised_url, got %v", entry["advertised_url"])
			}
			if entry["url"] != entry["advertised_url"] {
				t.Fatalf("expected legacy url alias to match advertised_url, got %v vs %v", entry["url"], entry["advertised_url"])
			}
			sawPIDDefault = true
		case "eaa":
			if entry["advertised_url"] != "https://localhost:8443/api/trustlists/eaa" {
				t.Fatalf("expected eaa advertised_url, got %v", entry["advertised_url"])
			}
			sawEAA = true
		case "wallet-provider":
			if entry["default"] == true {
				t.Fatalf("wallet-provider list must never be the default, got %v", entry)
			}
			if entry["loTEType"] != lote.WalletProvidersListType {
				t.Fatalf("expected wallet-provider LoTE type, got %v", entry["loTEType"])
			}
			if desc, _ := entry["description"].(string); !strings.Contains(strings.ToLower(desc), "attestation") {
				t.Fatalf("expected wallet-provider description to name the wallet attestation, got %v", entry["description"])
			}
			sawWalletProvider = true
		}
	}
	if !sawPIDDefault || !sawEAA || !sawWalletProvider {
		t.Fatalf("expected pid+eaa+wallet-provider trust-list entries, got %v", rawLists)
	}

	legacyResp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if legacyResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", legacyResp.Code, legacyResp.Body.String())
	}
	var legacyPayload map[string]any
	decodeCompactJWTPayload(t, legacyResp.Body.String(), &legacyPayload)
	legacyLoTE, ok := legacyPayload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", legacyPayload["LoTE"])
	}
	legacyScheme := legacyLoTE["ListAndSchemeInformation"].(map[string]any)
	if legacyScheme["LoTEType"] != lote.PIDProvidersListType {
		t.Fatalf("expected legacy /api/trustlist to return pid profile, got %v", legacyScheme["LoTEType"])
	}

	selectedResp := serverRequest(t, srv, "GET", "/api/trustlist?doctype="+url.QueryEscape("org.iso.23220.photoid.1"), "")
	if selectedResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", selectedResp.Code, selectedResp.Body.String())
	}
	var selectedPayload map[string]any
	decodeCompactJWTPayload(t, selectedResp.Body.String(), &selectedPayload)
	selectedLoTE, ok := selectedPayload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", selectedPayload["LoTE"])
	}
	selectedScheme := selectedLoTE["ListAndSchemeInformation"].(map[string]any)
	if selectedScheme["LoTEType"] != provider.CategoryList(credtemplate.CategoryEAA).LoTEType {
		t.Fatalf("doctype-selected list has LoTEType %v, want the EAA list type", selectedScheme["LoTEType"])
	}

	byIDResp := serverRequest(t, srv, "GET", "/api/trustlists/eaa", "")
	if byIDResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", byIDResp.Code, byIDResp.Body.String())
	}
	var byIDPayload map[string]any
	decodeCompactJWTPayload(t, byIDResp.Body.String(), &byIDPayload)
	byIDLoTE, ok := byIDPayload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", byIDPayload["LoTE"])
	}
	byIDScheme := byIDLoTE["ListAndSchemeInformation"].(map[string]any)
	if byIDScheme["LoTEType"] != provider.CategoryList(credtemplate.CategoryEAA).LoTEType {
		t.Fatalf("/api/trustlists/eaa has LoTEType %v, want the EAA list type", byIDScheme["LoTEType"])
	}
	uris, ok := byIDScheme["SchemeInformationURI"].([]any)
	if !ok || len(uris) != 2 {
		t.Fatalf("expected SchemeInformationURI entry, got %v", byIDScheme["SchemeInformationURI"])
	}
	uri, ok := uris[1].(map[string]any)
	if !ok || uri["uriValue"] != "https://localhost:8443/api/trustlists/eaa/history" {
		t.Fatalf("expected per-id history URI, got %v", byIDScheme["SchemeInformationURI"])
	}
}

func TestOfferAPI_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/offers", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestOnConsentRequest_CalledOnInteractiveFlow(t *testing.T) {
	srv := newTestServer(t, false)

	// The callback writes on the request goroutine while this goroutine reads. Protect
	// both accesses with a lock.
	var callbackMu sync.Mutex
	var callbackCalled bool
	var callbackReqID string
	srv.setOnConsentRequest(func(req *consent.Request) {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		callbackCalled = true
		callbackReqID = req.ID
	})

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	reqID := waitForPendingRequest(t, srv.wallet).ID

	callbackMu.Lock()
	called, gotReqID := callbackCalled, callbackReqID
	callbackMu.Unlock()
	if !called {
		t.Error("expected onConsentRequest callback to be called")
	}
	if gotReqID != reqID {
		t.Errorf("callback received request ID %s, expected %s", gotReqID, reqID)
	}

	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve",
		strings.NewReader(`{"selected_claims":{}}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)

	<-resultCh
}

func TestOnConsentRequest_NotCalledOnAutoAccept(t *testing.T) {
	srv := newTestServer(t, true)

	callbackCalled := false
	srv.setOnConsentRequest(func(req *consent.Request) {
		callbackCalled = true
	})

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if callbackCalled {
		t.Error("onConsentRequest callback should not be called in auto-accept mode")
	}
}

func TestOnUIRequest_CalledOnInteractiveOfferImport(t *testing.T) {
	srv := newTestServer(t, false)

	// Protect writes from the request goroutine and reads from the test goroutine.
	var callbackMu sync.Mutex
	callbackCalled := false
	srv.SetOnUIRequest(func(string) {
		callbackMu.Lock()
		callbackCalled = true
		callbackMu.Unlock()
	})

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	body, err := json.Marshal(map[string]any{"uri": offerURI, "interactive": true})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	before := len(srv.wallet.GetCredentials())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- serverRequest(t, srv, http.MethodPost, "/api/offers", string(body))
	}()

	reqID := waitForPendingRequest(t, srv.wallet).ID
	callbackMu.Lock()
	called := callbackCalled
	callbackMu.Unlock()
	if !called {
		t.Fatal("expected onUIRequest callback to be called")
	}
	if got := len(srv.wallet.GetCredentials()); got != before {
		t.Fatalf("interactive issuance should not import before approval, before=%d after=%d", before, got)
	}

	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve", strings.NewReader(`{}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}

	resp := <-done
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	after := len(srv.wallet.GetCredentials())
	if after != before+1 {
		t.Fatalf("expected one imported credential after approval, got before=%d after=%d", before, after)
	}
}

// Interactive issuance fetches the offer before consent and again when processing
// approval. The specification permits repeated fetches.
func TestOnUIRequest_InteractiveOfferImportFetchesOfferForDialogAndAfterApproval(t *testing.T) {
	srv := newTestServer(t, false)
	offerFetched := make(chan struct{}, 2)

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{
		offerViaURI: true,
		onOfferFetch: func() {
			offerFetched <- struct{}{}
		},
	})
	defer issuer.Close()

	body, err := json.Marshal(map[string]any{"uri": offerURI, "interactive": true})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	before := len(srv.wallet.GetCredentials())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- serverRequest(t, srv, http.MethodPost, "/api/offers", string(body))
	}()

	reqID := waitForPendingRequest(t, srv.wallet).ID
	select {
	case <-offerFetched:
	case <-time.After(time.Second):
		t.Fatal("credential_offer_uri should be fetched to describe the pending offer")
	}

	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve", strings.NewReader(`{}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}
	select {
	case <-offerFetched:
	case <-time.After(2 * time.Second):
		t.Fatal("expected credential_offer_uri to be fetched after approval")
	}

	resp := <-done
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	after := len(srv.wallet.GetCredentials())
	if after != before+1 {
		t.Fatalf("expected one imported credential after approval, got before=%d after=%d", before, after)
	}
}

func TestOnUIRequest_NotCalledOnAutoAcceptOfferImport(t *testing.T) {
	srv := newTestServer(t, true)

	// Protect writes from the request goroutine and reads from the test goroutine.
	var callbackMu sync.Mutex
	callbackCalled := false
	srv.SetOnUIRequest(func(string) {
		callbackMu.Lock()
		callbackCalled = true
		callbackMu.Unlock()
	})

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	body, err := json.Marshal(map[string]any{"uri": offerURI, "interactive": true})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	resp := serverRequest(t, srv, http.MethodPost, "/api/offers", string(body))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if callbackCalled {
		t.Fatal("onUIRequest callback should not be called in auto-accept mode")
	}
}

func TestPresentationFlow_RequestURIMethodPost(t *testing.T) {
	w := generateTestWallet(t)
	w.AutoAccept = true
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	var receivedVPToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		receivedVPToken = parsed.Get("vp_token")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	var receivedMethod string
	var receivedWalletMeta string
	var receivedWalletNonce string
	requestURIServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		r.ParseForm()
		receivedWalletMeta = r.Form.Get("wallet_metadata")
		receivedWalletNonce = r.Form.Get("wallet_nonce")

		dcqlQuery := map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
					"claims": []any{map[string]any{"path": []any{"given_name"}}},
				},
			},
		}
		dcqlJSON, _ := json.Marshal(dcqlQuery)

		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "https://verifier.example",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"nonce":         "test-nonce",
			"state":         "test-state",
			"response_uri":  verifier.URL,
			"dcql_query":    json.RawMessage(dcqlJSON),
			"wallet_nonce":  receivedWalletNonce,
		})
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		rw.Write([]byte(jwt))
	}))
	defer requestURIServer.Close()

	params := url.Values{
		"client_id":          {"https://verifier.example"},
		"response_type":      {"vp_token"},
		"request_uri":        {requestURIServer.URL},
		"request_uri_method": {"post"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if receivedMethod != "POST" {
		t.Errorf("expected POST to request_uri, got %s", receivedMethod)
	}
	if receivedWalletMeta == "" {
		t.Error("expected wallet_metadata in POST body")
	}
	if receivedWalletNonce == "" {
		t.Error("expected wallet_nonce in POST body")
	}

	var meta map[string]any
	if err := json.Unmarshal([]byte(receivedWalletMeta), &meta); err != nil {
		t.Fatalf("wallet_metadata not valid JSON: %v", err)
	}
	if meta["vp_formats_supported"] == nil {
		t.Error("expected vp_formats_supported in wallet_metadata")
	}

	if receivedVPToken == "" {
		t.Fatal("verifier did not receive VP token")
	}
}

func TestFetchRequestURIPOST_AcceptsLocalSelfSignedTLS(t *testing.T) {
	w := generateTestWallet(t)

	var receivedMethod string
	requestURIServer := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		walletNonce := r.Form.Get("wallet_nonce")
		if r.Form.Get("wallet_metadata") == "" {
			t.Fatal("expected wallet_metadata")
		}
		if walletNonce == "" {
			t.Fatal("expected wallet_nonce")
		}

		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "https://verifier.example",
			"response_type": "vp_token",
			"nonce":         "test-nonce",
			"wallet_nonce":  walletNonce,
		})
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		rw.Write([]byte(jwt))
	}))
	defer requestURIServer.Close()

	result, err := MakeFetchRequestURI(w, nil)(requestURIServer.URL, "post", "")
	if err != nil {
		t.Fatalf("fetching the request_uri with POST: %v", err)
	}
	if receivedMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", receivedMethod)
	}
	if !format.IsJWT(result) {
		t.Fatalf("expected compact JWT response, got %q", result)
	}
}

func TestPresentationFlow_RequestURIMethodPost_Encrypted(t *testing.T) {
	encKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	w := generateTestWallet(t)
	w.AutoAccept = true
	w.RequireEncryptedRequest = true
	w.RequestEncryptionKey = encKey
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	var receivedVPToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		receivedVPToken = parsed.Get("vp_token")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	requestURIServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		walletMetaStr := r.Form.Get("wallet_metadata")
		walletNonce := r.Form.Get("wallet_nonce")

		var meta map[string]any
		json.Unmarshal([]byte(walletMetaStr), &meta)
		jwks := meta["jwks"].(map[string]any)
		keys := jwks["keys"].([]any)
		jwk := keys[0].(map[string]any)
		pubKey, _, err := ecdsaPublicKeyFromJWK(ValidationModeStrict, jwk["x"].(string), jwk["y"].(string))
		if err != nil {
			t.Fatalf("parsing wallet key: %v", err)
		}

		dcqlQuery := map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
					"claims": []any{map[string]any{"path": []any{"given_name"}}},
				},
			},
		}
		dcqlJSON, _ := json.Marshal(dcqlQuery)

		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "https://verifier.example",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"nonce":         "test-nonce",
			"state":         "test-state",
			"response_uri":  verifier.URL,
			"dcql_query":    json.RawMessage(dcqlJSON),
			"wallet_nonce":  walletNonce,
		})

		jweStr, _, err := jwe.EncryptECDHES([]byte(jwt), pubKey, "kid", "A128GCM", "", nil, nil)
		if err != nil {
			t.Fatalf("encrypting request object: %v", err)
		}
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		rw.Write([]byte(jweStr))
	}))
	defer requestURIServer.Close()

	params := url.Values{
		"client_id":          {"https://verifier.example"},
		"response_type":      {"vp_token"},
		"request_uri":        {requestURIServer.URL},
		"request_uri_method": {"post"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := decodeJSON(t, rec)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	if receivedVPToken == "" {
		t.Fatal("verifier did not receive VP token, wallet failed to decrypt JWE request object")
	}
}

func generateSDJWTForTest(t *testing.T, srv *Server) string {
	t.Helper()
	result, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"test": "value"},
		Key:       srv.wallet.IssuerKey,
	})
	if err != nil {
		t.Fatalf("generating test SD-JWT: %v", err)
	}
	return result
}

func TestSetIssuerListenPortDisablesTLSListener(t *testing.T) {
	w := generateTestWallet(t)
	// An HTTPS issuer URL without a port uses 443 for an external TLS terminator.
	w.IssuerURL = "https://eudi-test.example"
	srv := NewServer(w, 0, nil)
	if srv.issuerPort != 443 {
		t.Fatalf("issuerPort = %d, want 443 before override", srv.issuerPort)
	}
	srv.SetIssuerListenPort(-1)
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("ListenAndServeBackground with disabled issuer listener: %v", err)
	}
	defer srv.Shutdown()
	if addr == "" {
		t.Fatal("expected a listen address")
	}
	if srv.issuerSrv != nil {
		t.Fatal("issuer TLS server started despite SetIssuerListenPort(-1)")
	}
}

func TestStaticAssetsServed(t *testing.T) {
	srv := newTestServer(t, true)
	for _, path := range []string{"/", "/app.js", "/style.css", "/favicon.svg", "/logo.svg", "/robots.txt"} {
		rec := serverRequest(t, srv, "GET", path, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s served an empty body", path)
		}
	}
}

// RFC 9116 requires a contact and an expiry less than a year away.
func TestSecurityTxt(t *testing.T) {
	srv := newTestServer(t, true)
	rec := serverRequest(t, srv, "GET", "/.well-known/security.txt", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET security.txt = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Contact: https://") {
		t.Errorf("security.txt lacks a Contact line:\n%s", body)
	}
	_, rest, _ := strings.Cut(body, "Expires: ")
	expires, err := time.Parse(time.RFC3339, strings.TrimSpace(rest))
	if err != nil {
		t.Fatalf("Expires is not RFC 3339: %v", err)
	}
	if until := time.Until(expires); until <= 0 || until > 365*24*time.Hour {
		t.Errorf("Expires %v is not within the coming year", expires)
	}
}

func TestListCredentialsPaging(t *testing.T) {
	srv := newTestServer(t, true)
	for i := 0; i < 23; i++ {
		body := fmt.Sprintf(`{"format":"sdjwt","vct":"urn:example:%d"}`, i)
		if w := serverRequest(t, srv, "POST", "/api/issue", body); w.Code != http.StatusCreated {
			t.Fatalf("seeding credential %d: %d", i, w.Code)
		}
	}
	total := len(srv.wallet.GetCredentials())
	if total != 25 {
		t.Fatalf("expected 25 credentials, got %d", total)
	}

	listed := func(query string) ([]map[string]any, string) {
		t.Helper()
		rec := serverRequest(t, srv, "GET", "/api/credentials"+query, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", query, rec.Code)
		}
		var docs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &docs); err != nil {
			t.Fatalf("parsing %s: %v", query, err)
		}
		return docs, rec.Header().Get("X-Total-Count")
	}

	all, count := listed("")
	if len(all) != 25 || count != "25" {
		t.Fatalf("without parameters: %d credentials, X-Total-Count %q, want all 25", len(all), count)
	}

	first, count := listed("?limit=10&offset=0")
	if len(first) != 10 || count != "25" {
		t.Fatalf("first page: %d credentials, X-Total-Count %q", len(first), count)
	}
	last, _ := listed("?limit=10&offset=20")
	if len(last) != 5 {
		t.Fatalf("last page: %d credentials, want 5", len(last))
	}
	if first[0]["id"] == last[0]["id"] {
		t.Error("pages returned the same first credential")
	}

	if beyond, _ := listed("?limit=10&offset=999"); len(beyond) != 0 {
		t.Errorf("offset past the end returned %d credentials", len(beyond))
	}

	for _, bad := range []string{"?limit=abc", "?offset=-1"} {
		if rec := serverRequest(t, srv, "GET", "/api/credentials"+bad, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("GET /api/credentials%s = %d, want 400", bad, rec.Code)
		}
	}
}

// Keepalives prevent proxies from closing idle streams and causing repeated browser
// reconnects.
func TestRequestStreamKeepalive(t *testing.T) {
	srv := newTestServer(t, true)

	original := sseKeepaliveInterval
	sseKeepaliveInterval = 50 * time.Millisecond
	t.Cleanup(func() { sseKeepaliveInterval = original })

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/requests/stream", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Two events check that the ticker continues after the first interval.
	reader := bufio.NewReader(resp.Body)
	seen := 0
	for seen < 2 {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading stream after %d keepalives: %v", seen, err)
		}
		if strings.HasPrefix(line, ":") {
			seen++
		}
	}
}

// subscriptionAtFlush records how many event streams were subscribed when the
// handler first flushed its headers.
type subscriptionAtFlush struct {
	*httptest.ResponseRecorder
	srv     *Server
	cancel  context.CancelFunc
	flushed bool
	count   int
}

func (f *subscriptionAtFlush) Flush() {
	if !f.flushed {
		f.flushed = true
		f.count = f.srv.wallet.Consents().AttachedUIs()
		f.cancel()
	}
	f.ResponseRecorder.Flush()
}

// The page reads the pending requests when the stream opens. A request created
// after that read reaches the page only if the stream already listens, so the
// stream subscribes before the browser sees it open.
func TestRequestStreamSubscribesBeforeItOpens(t *testing.T) {
	srv := newTestServer(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &subscriptionAtFlush{ResponseRecorder: httptest.NewRecorder(), srv: srv, cancel: cancel}

	srv.handleRequestStream(rec, httptest.NewRequest("GET", "/api/requests/stream", nil).WithContext(ctx))

	if rec.count != 1 {
		t.Fatalf("%d subscriptions when the stream opened, want 1", rec.count)
	}
}

// A text/plain POST needs no CORS preflight. Without the origin check, another site
// could submit credentials to its own response_uri with auto_accept enabled.
func TestCrossOriginPresentationIsRefused(t *testing.T) {
	srv := newTestServer(t, false)

	stolen := make(chan string, 1)
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case stolen <- string(body):
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	authURI := "openid4vp://authorize?" + url.Values{
		"client_id":     {"redirect_uri:" + attacker.URL + "/steal"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {attacker.URL + "/steal"},
		"nonce":         {"n-cross-origin"},
		"dcql_query":    {`{"credentials":[{"id":"c1","format":"dc+sd-jwt","claims":[{"path":["given_name"]}]}]}`},
	}.Encode()
	body, err := json.Marshal(map[string]any{"uri": authURI, "auto_accept": true})
	if err != nil {
		t.Fatalf("building body: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/presentations", bytes.NewReader(body))
	req.Host = "localhost:8085"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	select {
	case body := <-stolen:
		t.Fatalf("the wallet submitted a presentation to another site: %.120s", body)
	default:
	}
}

func TestSameOriginAndOriginlessAPICallsAreAllowed(t *testing.T) {
	srv := newTestServer(t, false)

	for _, tc := range []struct{ name, origin string }{
		{"the wallet's own UI", "http://localhost:8085"},
		{"the CLI", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/credentials", nil)
			req.Host = "localhost:8085"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

// The DC API is called from the verifier's origin. It therefore allows cross-origin
// requests and relies on the platform origin and wallet consent.
func TestBrowserAPIAcceptsACrossOriginCaller(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(`{}`))
	req.Host = "localhost:8085"
	req.Header.Set("Origin", "https://verifier.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("the guard refused a Digital Credentials API caller: %s", rec.Body.String())
	}
}

func TestTheDCAPIExemptionDoesNotLeakToOtherEndpoints(t *testing.T) {
	srv := newTestServer(t, false)

	for _, path := range []string{"/api/presentations", "/api/credentials", "/api/issue"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
			req.Host = "localhost:8085"
			req.Header.Set("Origin", "https://evil.example")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}

// HAIP §5 requires verifiers to advertise both content encryption algorithms.
func encryptionClientMetadata(t *testing.T) map[string]any {
	t.Helper()
	encKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating encryption key: %v", err)
	}
	return map[string]any{
		"jwks": map[string]any{"keys": []any{testEncJWK(t, &encKey.PublicKey)}},
		"encrypted_response_enc_values_supported": []any{"A128GCM", "A256GCM"},
	}
}

// The catalogue links the list of each category, and the wallet serves it at
// that path.
func TestTheWalletServesTheCategoryListsTheCatalogueLinks(t *testing.T) {
	srv := newTestServer(t, false)
	for _, category := range credtemplate.Categories {
		path := provider.TrustedListPath(category)
		if resp := serverRequest(t, srv, "GET", path, ""); resp.Code != http.StatusOK {
			t.Errorf("GET %s answers %d", path, resp.Code)
		}
	}
}

// The UI forms take their limits and defaults from the server, so they match
// what the server accepts.
func TestTheConfigServesTheFormDefaults(t *testing.T) {
	srv := newTestServer(t, false)
	var config struct {
		FormDefaults map[string]any `json:"form_defaults"`
	}
	if err := json.Unmarshal(serverRequest(t, srv, "GET", "/api/config", "").Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"display_name_max":          float64(maxDisplayNameRunes),
		"display_description_max":   float64(maxDisplayDescriptionRunes),
		"display_alt_text_max":      float64(maxDisplayAltTextRunes),
		"country":                   mock.DefaultCertificateCountry,
		"registration_validity":     "4320h",
		"registration_validity_max": "8760h",
		"access_validity":           "8760h",
		"access_validity_max":       "8760h",
	}
	if !reflect.DeepEqual(config.FormDefaults, want) {
		t.Errorf("form defaults %v, want %v", config.FormDefaults, want)
	}
}

// ADR-0012: the issuance flow writes the activity log, whichever entry point
// runs it. Each step of an offer shows once.
func TestOfferEndpointLogsEachStepOnce(t *testing.T) {
	srv := newTestServer(t, true)
	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	body, _ := json.Marshal(map[string]any{"uri": offerURI, "credential_configuration_id": "test-config"})
	resp := serverRequest(t, srv, http.MethodPost, "/api/offers", string(body))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var result IssuanceResult
	if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	failed := serverRequest(t, srv, http.MethodPost, "/api/offers", `{"uri":"openid-credential-offer://?credential_offer_uri=http://127.0.0.1:1/gone"}`)
	if failed.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unreadable offer, got %d", failed.Code)
	}

	var received, imported, failures int
	for _, entry := range srv.wallet.GetLog() {
		switch {
		case strings.HasPrefix(entry.Detail, "Received credential offer"):
			received++
		case entry.Details["credential_id"] == result.CredentialID:
			imported++
			if entry.Details["credential_requested"] != "test-config" {
				t.Errorf("the import entry names the requested configuration %v, want test-config", entry.Details["credential_requested"])
			}
		case !entry.Success && (entry.Details["event"] == "issuance_failed" || strings.HasPrefix(entry.Detail, "Failed")):
			failures++
		}
	}
	if received != 1 || imported != 1 || failures != 1 {
		t.Errorf("log shows the offer %d times, the import %d times and the failure %d times, want each once", received, imported, failures)
	}
}
