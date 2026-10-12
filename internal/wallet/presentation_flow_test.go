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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// ADR-0012: /authorize and POST /api/presentations run the same checks.
func TestAuthorizeAndThePresentationAPIRefuseTheSameRequest(t *testing.T) {
	query := "client_id=" + url.QueryEscape("redirect_uri:https://verifier.example/cb") +
		"&response_type=vp_token&response_mode=direct_post&nonce=n&response_uri=" + url.QueryEscape("https://verifier.example/cb")
	for name, extra := range map[string]string{
		"request_uri_method without request_uri": "&request_uri_method=post",
		"client_metadata that is not JSON":       "&client_metadata=" + url.QueryEscape("{"),
	} {
		t.Run(name, func(t *testing.T) {
			srv := newTestServer(t, true)
			authorize := httptest.NewRecorder()
			srv.mux.ServeHTTP(authorize, httptest.NewRequest("GET", "/authorize?"+query+extra, nil))
			body, _ := json.Marshal(map[string]string{"uri": "openid4vp://?" + query + extra})
			api := serverRequest(t, srv, "POST", "/api/presentations", string(body))
			for entry, rec := range map[string]*httptest.ResponseRecorder{"/authorize": authorize, "/api/presentations": api} {
				if rec.Code != http.StatusBadRequest {
					t.Errorf("%s answered %d, want 400: %s", entry, rec.Code, rec.Body)
				}
			}
		})
	}
}

// OID4VP 1.0 §5.5 makes a scope value "an alias for a well-defined DCQL
// query". This wallet defines none, so §8.5 answers with invalid_scope, and
// the verifier receives that error.
func TestUnknownScopeIsAnsweredWithInvalidScope(t *testing.T) {
	var received atomic.Value
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			received.Store(r.PostForm.Get("error"))
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	srv := newTestServer(t, false)
	query := url.Values{
		"client_id":     {"redirect_uri:" + verifier.URL},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {verifier.URL},
		"nonce":         {"n"},
		"scope":         {"com.example.unknown_query"},
	}
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+query.Encode(), nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response %d %s: %v", rec.Code, rec.Body, err)
	}
	if body["error"] != oid4vp.ErrorInvalidScope {
		t.Errorf("wallet answered %v, want invalid_scope", body)
	}
	if got, _ := received.Load().(string); got != oid4vp.ErrorInvalidScope {
		t.Errorf("verifier received error %q, want invalid_scope", got)
	}
}

// Debug mode records a finding in the activity log, so the UI shows it.
func TestTransactionDataInTheQueryIsAnActivityLogFinding(t *testing.T) {
	srv := newTestServer(t, true)
	query := "client_id=" + url.QueryEscape("redirect_uri:https://verifier.example/cb") +
		"&response_type=vp_token&response_mode=direct_post&nonce=n&response_uri=" + url.QueryEscape("https://verifier.example/cb") +
		"&transaction_data=" + url.QueryEscape(`["e30"]`) +
		"&dcql_query=" + url.QueryEscape(`{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:unheld"]}}]}`)
	srv.mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/authorize?"+query, nil))
	if !hasWarning(srv.wallet, "transaction_data") {
		t.Error("the activity log has no transaction_data finding")
	}
}
