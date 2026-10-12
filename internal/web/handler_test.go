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

package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/webui/webuitest"
)

func apiPost(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiPostTo(t, "/api/validate", body)
}

func apiPostTo(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	NewMux("").ServeHTTP(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func makeJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "."
}

func makeSDJWT(payload map[string]any, disclosures [][]any) string {
	header := map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}
	h, _ := json.Marshal(header)

	if _, has := payload["_sd"]; has && len(disclosures) > 0 {
		var digests []string
		for _, d := range disclosures {
			dJSON, _ := json.Marshal(d)
			dB64 := base64.RawURLEncoding.EncodeToString(dJSON)
			hash := sha256.Sum256([]byte(dB64))
			digests = append(digests, base64.RawURLEncoding.EncodeToString(hash[:]))
		}
		payload["_sd"] = digests
	}

	p, _ := json.Marshal(payload)
	jwt := base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".fakesig"

	result := jwt
	for _, d := range disclosures {
		dJSON, _ := json.Marshal(d)
		result += "~" + base64.RawURLEncoding.EncodeToString(dJSON)
	}
	result += "~"
	return result
}

func TestValidateEndpointDecodes_JWT(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "1234567890", "name": "John Doe"},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	if result["format"] != "jwt" {
		t.Errorf("expected format 'jwt', got %v", result["format"])
	}
	p := result["payload"].(map[string]any)
	if p["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", p["name"])
	}
}

func TestValidateEndpointDecodes_JWTResponseStructure(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "RS256", "kid": "key-1"},
		map[string]any{"iss": "https://auth.example", "sub": "user"},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)

	for _, key := range []string{"format", "header", "payload"} {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in response", key)
		}
	}
	if _, ok := result["validation"]; !ok {
		t.Error("expected validation in decode response")
	}

	header := result["header"].(map[string]any)
	if header["kid"] != "key-1" {
		t.Errorf("header.kid = %v, want key-1", header["kid"])
	}
}

func TestHandleJWTRegardlessOfClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  map[string]any
		payload map[string]any
	}{
		{"empty claims", map[string]any{"alg": "none"}, map[string]any{}},
		{"custom type and claims", map[string]any{"alg": "none", "typ": "custom+jwt"}, map[string]any{"custom": map[string]any{"items": []any{"a", true, nil}}}},
		{"credential offer", map[string]any{"alg": "none"}, map[string]any{"credential_issuer": "https://issuer.example"}},
		{"authorization request", map[string]any{"alg": "none"}, map[string]any{"client_id": "https://verifier.example", "response_type": "vp_token"}},
		{"trusted list", map[string]any{"alg": "none"}, map[string]any{"LoTE": map[string]any{"TrustedEntitiesList": []any{}}}},
	} {
		for _, endpoint := range []string{"/api/validate"} {
			t.Run(tc.name+endpoint, func(t *testing.T) {
				body, err := json.Marshal(map[string]string{"input": " \n" + makeJWT(tc.header, tc.payload) + "\n "})
				if err != nil {
					t.Fatal(err)
				}
				w := apiPostTo(t, endpoint, string(body))
				if w.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
				}
				result := decodeResponse(t, w)
				if result["format"] != "jwt" || !reflect.DeepEqual(result["header"], tc.header) || !reflect.DeepEqual(result["payload"], tc.payload) {
					t.Errorf("JWT header or claims not preserved: %v", result)
				}
			})
		}
	}
}

func TestHandleTrustListJWT(t *testing.T) {
	raw, err := os.ReadFile("testdata/trust-list.jwt")
	if err != nil {
		t.Fatal(err)
	}
	jwt := strings.TrimSpace(string(raw))
	parts := strings.Split(jwt, ".")
	var expectedHeader, expectedPayload map[string]any
	for i, target := range []*map[string]any{&expectedHeader, &expectedPayload} {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(decoded, target); err != nil {
			t.Fatal(err)
		}
	}
	for _, endpoint := range []string{"/api/validate"} {
		t.Run(endpoint, func(t *testing.T) {
			w := apiPostTo(t, endpoint, `{"input":"`+jwt+`"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			result := decodeResponse(t, w)
			if result["format"] != "jwt" {
				t.Errorf("format = %v, want jwt", result["format"])
			}
			if !reflect.DeepEqual(result["header"], expectedHeader) {
				t.Errorf("header = %v, want %v", result["header"], expectedHeader)
			}
			if !reflect.DeepEqual(result["payload"], expectedPayload) {
				t.Error("decoded payload differs from the trust-list JWT payload")
			}
			if result["validation"] == nil {
				t.Error("missing validation results")
			}
		})
	}
}

func TestValidateEndpointDecodes_SDJWT(t *testing.T) {
	sdjwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
			{"salt2", "family_name", "Mustermann"},
		},
	)

	w := apiPost(t, `{"input":"`+sdjwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	if result["format"] != "dc+sd-jwt" {
		t.Errorf("expected format 'dc+sd-jwt', got %v", result["format"])
	}

	discs, ok := result["disclosures"].([]any)
	if !ok {
		t.Fatalf("disclosures should be an array, got %T", result["disclosures"])
	}
	if len(discs) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(discs))
	}

	if _, ok := result["resolvedClaims"]; !ok {
		t.Error("SD-JWT response should have resolvedClaims")
	}
}

func TestValidateEndpointDecodes_SDJWTDisclosureFields(t *testing.T) {
	sdjwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
		},
		[][]any{
			{"salt-abc", "email", "test@example.com"},
		},
	)

	w := apiPost(t, `{"input":"`+sdjwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	discs := result["disclosures"].([]any)
	d := discs[0].(map[string]any)

	if d["name"] != "email" {
		t.Errorf("disclosure.name = %v, want email", d["name"])
	}
	if d["value"] != "test@example.com" {
		t.Errorf("disclosure.value = %v, want test@example.com", d["value"])
	}
	if d["salt"] != "salt-abc" {
		t.Errorf("disclosure.salt = %v, want salt-abc", d["salt"])
	}
	if _, ok := d["digest"]; !ok {
		t.Error("disclosure should have digest field")
	}
	if d["isArrayEntry"] != false {
		t.Errorf("disclosure.isArrayEntry = %v, want false", d["isArrayEntry"])
	}
}

func TestValidateEndpointDecodes_EmptyInput(t *testing.T) {
	w := apiPost(t, `{"input":""}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["error"] != "input is required" {
		t.Errorf("expected error 'input is required', got %v", result["error"])
	}
}

func TestValidateEndpointDecodes_MissingInputField(t *testing.T) {
	w := apiPost(t, `{}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["error"] != "input is required" {
		t.Errorf("expected 'input is required', got %v", result["error"])
	}
}

func TestValidateEndpointDecodes_InvalidCredential(t *testing.T) {
	w := apiPost(t, `{"input":"not-a-credential"}`)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if _, ok := result["error"]; !ok {
		t.Error("expected error field in response")
	}
}

func TestValidateEndpointDecodes_InvalidJSON(t *testing.T) {
	w := apiPost(t, "not json")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestValidateEndpointDecodes_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/validate", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for GET /api/decode")
	}
}

func TestValidateEndpointDecodes_PutMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/validate", strings.NewReader(`{"input":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for PUT /api/validate")
	}
}

func TestValidateEndpointDecodes_ResponseContentType(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{"sub": "test"},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestValidateEndpointDecodes_ErrorResponseContentType(t *testing.T) {
	w := apiPost(t, `{"input":""}`)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestValidateEndpointDecodes_MalformedJWT(t *testing.T) {
	w := apiPost(t, `{"input":"aaa.bbb.ccc"}`)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStaticFiles_Index(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "EUDI Dev") {
		t.Error("expected index.html to contain 'EUDI Dev'")
	}
	if !strings.Contains(body, "app.js") {
		t.Error("expected index.html to reference app.js")
	}
	if !strings.Contains(body, "style.css") {
		t.Error("expected index.html to reference style.css")
	}
}

func TestStaticFiles_CSS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/style.css", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for style.css, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "--bg") {
		t.Error("expected CSS to contain custom property --bg")
	}
}

func TestStaticFiles_JS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for app.js, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "api/validate") {
		t.Error("expected app.js to reference the api/validate endpoint")
	}
}

func TestStaticFiles_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nonexistent.txt", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPrefill_WithCredential(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{"sub": "prefilled"},
	)

	req := httptest.NewRequest(http.MethodGet, "/api/prefill", nil)
	w := httptest.NewRecorder()

	NewMux(jwt).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["credential"] != jwt {
		t.Errorf("expected credential to be the JWT, got %q", result["credential"])
	}
}

func TestPrefill_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/prefill", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["credential"] != "" {
		t.Errorf("expected empty credential, got %q", result["credential"])
	}
}

func TestStaticFiles_IndexContainsNewUIElements(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{
		"raw-view",
		"shortcut-hint",
		"input-editor",
		"header-logo",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
}

func TestValidateEndpointDecodes_JWTWithTimestamps(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{
			"sub": "user",
			"iss": "https://auth.example",
			"iat": 1700000000,
			"exp": 1742592000,
			"nbf": 1700000000,
		},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	p := result["payload"].(map[string]any)

	// Timestamps must stay numeric so the UI can format hover text.
	if _, ok := p["iat"]; !ok {
		t.Error("payload should contain iat")
	}
	if _, ok := p["exp"]; !ok {
		t.Error("payload should contain exp")
	}
	if _, ok := p["nbf"]; !ok {
		t.Error("payload should contain nbf")
	}
}

func TestValidateEndpointDecodes_SDJWTResolvedClaims(t *testing.T) {
	sdjwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
			{"salt2", "family_name", "Mustermann"},
		},
	)

	w := apiPost(t, `{"input":"`+sdjwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)

	resolved, ok := result["resolvedClaims"].(map[string]any)
	if !ok {
		t.Fatalf("resolvedClaims should be a map, got %T", result["resolvedClaims"])
	}
	if resolved["given_name"] != "Erika" {
		t.Errorf("resolvedClaims.given_name = %v, want Erika", resolved["given_name"])
	}
	if resolved["family_name"] != "Mustermann" {
		t.Errorf("resolvedClaims.family_name = %v, want Mustermann", resolved["family_name"])
	}

	// The UI uses digest to decide how to truncate disclosures.
	discs := result["disclosures"].([]any)
	for i, d := range discs {
		disc := d.(map[string]any)
		if _, ok := disc["digest"]; !ok {
			t.Errorf("disclosures[%d] missing digest field", i)
		}
		if _, ok := disc["salt"]; !ok {
			t.Errorf("disclosures[%d] missing salt field", i)
		}
	}
}

func TestValidateEndpointDecodes_JWTIssuerSubjectInPayload(t *testing.T) {
	// The summary reads payload.iss and payload.sub.
	jwt := makeJWT(
		map[string]any{"alg": "RS256"},
		map[string]any{
			"iss": "https://auth.example.com",
			"sub": "user@example.com",
			"vct": "urn:eudi:pid:1",
		},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	p := result["payload"].(map[string]any)

	if p["iss"] != "https://auth.example.com" {
		t.Errorf("payload.iss = %v, want https://auth.example.com", p["iss"])
	}
	if p["sub"] != "user@example.com" {
		t.Errorf("payload.sub = %v, want user@example.com", p["sub"])
	}
	if p["vct"] != "urn:eudi:pid:1" {
		t.Errorf("payload.vct = %v, want urn:eudi:pid:1", p["vct"])
	}
}

func TestPrefill_ContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/prefill", nil)
	w := httptest.NewRecorder()

	NewMux("something").ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleMetaAndImprint(t *testing.T) {
	mux := NewMuxWithOptions(MuxOptions{Version: "v1.2.3"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/meta", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/meta = %d", rec.Code)
	}
	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["version"] != "v1.2.3" || meta["imprint"] != false {
		t.Fatalf("meta = %v", meta)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/imprint", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /imprint without content = %d, want 404", rec.Code)
	}

	page := []byte("<p>Operator: Example Org</p>")
	mounted := http.StripPrefix("/decoder", NewMuxWithOptions(MuxOptions{ImprintHTML: page}))
	rec = httptest.NewRecorder()
	mounted.ServeHTTP(rec, httptest.NewRequest("GET", "/decoder/imprint", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Example Org") {
		t.Fatalf("GET /decoder/imprint = %d body %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mounted.ServeHTTP(rec, httptest.NewRequest("GET", "/decoder/api/meta", nil))
	if !strings.Contains(rec.Body.String(), `"imprint":true`) {
		t.Fatalf("prefixed meta = %s", rec.Body.String())
	}
}

// An ID link serves a large credential without putting it in the URL.
func TestCredentialByID(t *testing.T) {
	mux := NewMuxWithOptions(MuxOptions{
		CredentialByID: func(id string) (string, bool) {
			if id != "cred-1" {
				return "", false
			}
			return "header.payload.signature~", true
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/credentials/cred-1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET known credential = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := decodeResponse(t, w)["credential"]; got != "header.payload.signature~" {
		t.Errorf("credential = %v", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/credentials/nope", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("GET unknown credential = %d, want 404", w.Code)
	}
}

func TestCredentialByIDWithoutAWallet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/credentials/cred-1", nil)
	w := httptest.NewRecorder()
	NewMux("").ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET without a wallet = %d, want 404", w.Code)
	}
	if detail, _ := decodeResponse(t, w)["error"].(string); !strings.Contains(detail, "not attached to a wallet") {
		t.Errorf("error = %q, want it to name the missing wallet", detail)
	}
}

// The decoder page loads the bundled fonts.
func TestDecoderPageLoadsTheFonts(t *testing.T) {
	webuitest.CheckFonts(t, NewMux(""), "", "/")
}
