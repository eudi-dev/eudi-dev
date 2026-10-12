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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func TestNextErrorOverride_ConsumedAfterUse(t *testing.T) {
	srv := newTestServer(t, true)

	rec := serverRequest(t, srv, "POST", "/api/next-error",
		`{"error":"access_denied","error_description":"testing"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := pidDCQLQuery()
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
		t.Fatalf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["status"] != "error" {
		t.Errorf("expected status 'error', got %v", result["status"])
	}
	if result["error"] != "access_denied" {
		t.Errorf("expected error 'access_denied', got %v", result["error"])
	}
	if result["error_description"] != "testing" {
		t.Errorf("expected error_description 'testing', got %v", result["error_description"])
	}

	req2 := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	result2 := decodeJSON(t, w2)
	if result2["status"] != "submitted" {
		t.Errorf("expected status 'submitted' after override consumed, got %v", result2["status"])
	}
}

func TestNextErrorOverride_ClearWithoutConsuming(t *testing.T) {
	srv := newTestServer(t, true)

	rec := serverRequest(t, srv, "POST", "/api/next-error",
		`{"error":"access_denied","error_description":"testing"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	delRec := serverRequest(t, srv, "DELETE", "/api/next-error", "")
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", delRec.Code)
	}

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := pidDCQLQuery()
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

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted' after clear, got %v", result["status"])
	}
}

func TestPreferredFormat_SDJWTPreferred(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.PreferredFormat = "dc+sd-jwt"

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsedForm, _ := url.ParseQuery(string(body))
		vpToken := parsedForm.Get("vp_token")
		// SD-JWT serialization contains ~ separators. mdoc serialization does not.
		if !strings.Contains(vpToken, "~") {
			http.Error(w, "expected SD-JWT token", http.StatusBadRequest)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := bothFormatDCQLQuery()
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
		t.Fatalf("expected status 'submitted', got %v", result["status"])
	}

	vpTokenKeys, ok := result["vp_token_keys"].([]any)
	if !ok {
		t.Fatal("expected vp_token_keys")
	}
	if len(vpTokenKeys) != 1 {
		t.Fatalf("expected 1 vp_token_key, got %d", len(vpTokenKeys))
	}
}

func TestPreferredFormat_MDocPreferred(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.PreferredFormat = "mso_mdoc"

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := bothFormatDCQLQuery()
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
		t.Fatalf("expected status 'submitted', got %v", result["status"])
	}

	vpTokenKeys, ok := result["vp_token_keys"].([]any)
	if !ok {
		t.Fatal("expected vp_token_keys")
	}
	if len(vpTokenKeys) != 1 {
		t.Fatalf("expected 1 vp_token_key, got %d", len(vpTokenKeys))
	}
	if vpTokenKeys[0] != "pid_mdoc" {
		t.Errorf("expected vp_token_key 'pid_mdoc', got %v", vpTokenKeys[0])
	}
}

func TestPreferredFormat_NoPreference(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := bothFormatDCQLQuery()
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
		t.Fatalf("expected status 'submitted', got %v", result["status"])
	}

	// Without a format preference, credential_sets selects the first matching option.
}

func TestPreferredFormat_API(t *testing.T) {
	srv := newTestServer(t, true)

	rec := serverRequest(t, srv, "PUT", "/api/config/preferred-format",
		`{"format":"dc+sd-jwt"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := decodeJSON(t, rec)
	if result["format"] != "dc+sd-jwt" {
		t.Errorf("expected format 'dc+sd-jwt', got %v", result["format"])
	}

	if srv.wallet.PreferredFormat != "dc+sd-jwt" {
		t.Errorf("expected wallet PreferredFormat 'dc+sd-jwt', got %s", srv.wallet.PreferredFormat)
	}

	rec2 := serverRequest(t, srv, "PUT", "/api/config/preferred-format",
		`{"format":""}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}

	if srv.wallet.PreferredFormat != "" {
		t.Errorf("expected empty PreferredFormat, got %s", srv.wallet.PreferredFormat)
	}
}

func pidDCQLQuery() map[string]any {
	return map[string]any{
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
}

func bothFormatDCQLQuery() map[string]any {
	return map[string]any{
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
		"credential_sets": []any{
			map[string]any{
				"options": []any{
					[]any{"pid_sdjwt"},
					[]any{"pid_mdoc"},
				},
				"required": true,
			},
		},
	}
}

func TestAutoAccept_API(t *testing.T) {
	srv := newTestServer(t, false)

	rec := serverRequest(t, srv, "PUT", "/api/config/auto-accept", `{"enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !srv.wallet.AutoAccept {
		t.Error("auto-accept was not enabled")
	}

	rec2 := serverRequest(t, srv, "PUT", "/api/config/auto-accept", `{"enabled":false}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if srv.wallet.AutoAccept {
		t.Error("auto-accept was not disabled")
	}
}
