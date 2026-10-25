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
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func unsignedPIDRequest(extra map[string]any) map[string]any {
	data := map[string]any{
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"nonce":         "browser-nonce",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		}}},
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// sendDCAPICall sends a call like the eudi-dev extension does.
func sendDCAPICall(t *testing.T, srv *Server, ctx context.Context, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequestWithContext(ctx, "POST", "/api/dc-api", strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "chrome-extension://abc")
	r.Header.Set(CallerOriginHeader, "https://verifier.example")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, r)
	return rec
}

// The log lists every request of a call and explains each unanswered one.
func TestEveryDigitalCredentialsAPICallIsLogged(t *testing.T) {
	srv := newTestServer(t, true)
	call := map[string]any{"digital": map[string]any{"requests": []any{
		map[string]any{"protocol": "org-iso-mdoc", "data": map[string]any{"deviceRequest": "x"}},
		map[string]any{"protocol": "openid4vp", "data": unsignedPIDRequest(nil)},
		map[string]any{"protocol": "openid4vp-v1-unsigned", "data": unsignedPIDRequest(nil)},
		map[string]any{"protocol": "openid4vp-v1-signed", "data": map[string]any{"request": "x.y.z"}},
	}}}
	if rec := sendDCAPICall(t, srv, context.Background(), call, nil); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	entry := findLogEntry(srv.wallet.GetLog(), "dc_api_call")
	if entry == nil {
		t.Fatal("no dc_api_call entry")
	}
	if !strings.Contains(entry.Detail, "https://verifier.example") || entry.Payload == nil {
		t.Errorf("entry %q with payload %v, want the origin and the call", entry.Detail, entry.Payload)
	}
	ignored, _ := entry.Details["ignored_requests"].([]oid4vp.IgnoredBrowserAPIRequest)
	if len(ignored) != 3 {
		t.Fatalf("ignored requests %+v, want 3", entry.Details["ignored_requests"])
	}
	for i, want := range []string{"ISO/IEC 18013-7 Annex C", "Appendix A.1 defines openid4vp-v1-unsigned", "first request with a supported protocol"} {
		if !strings.Contains(ignored[i].Reason, want) {
			t.Errorf("ignored[%d] = %+v, want a reason with %q", i, ignored[i], want)
		}
	}
}

// An unreadable call is logged with its raw body.
func TestAnUnreadableDigitalCredentialsAPICallIsLogged(t *testing.T) {
	srv := newTestServer(t, true)
	r := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(`{"digital": [`))
	r.Header.Set("Origin", "https://verifier.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	entry := findLogEntry(srv.wallet.GetLog(), "dc_api_call")
	if entry == nil || entry.Success || entry.Payload == nil || entry.Payload.Body != `{"digital": [` {
		t.Fatalf("entry %+v, want a failed entry with the body", entry)
	}
}

// OID4VP 1.0 Appendix A.2 lists the parameters of the Digital Credentials
// API. The wallet ignores the others and warns.
func TestParametersTheDigitalCredentialsAPIDoesNotUseAreWarnings(t *testing.T) {
	srv := newTestServer(t, true)
	call := map[string]any{"digital": map[string]any{"requests": []any{map[string]any{
		"protocol": "openid4vp-v1-unsigned",
		"data": unsignedPIDRequest(map[string]any{
			"state": "s", "response_uri": "https://verifier.example/cb", "client_id": "x509_hash:abc", "expected_origins": []any{"https://verifier.example"},
		}),
	}}}}
	if rec := sendDCAPICall(t, srv, context.Background(), call, nil); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	entry := findLogEntry(srv.wallet.GetLog(), "dc_api_parameter")
	if entry == nil || entry.Severity != "warning" {
		t.Fatalf("entry %+v, want a warning", entry)
	}
	findings := strings.Join(entry.Details["findings"].([]string), "\n")
	for _, want := range []string{"response_uri", "state", "client_id MUST be omitted", "expected_origins is not for unsigned requests"} {
		if !strings.Contains(findings, want) {
			t.Errorf("findings %q miss %q", findings, want)
		}
	}
}

// A refusal reported by the extension is logged once per minute, even when
// the page retries in a loop. Web pages can't report refusals.
func TestARefusedCallIsLoggedOncePerMinute(t *testing.T) {
	srv := newTestServer(t, true)
	refuse := func(message string) int {
		body := `{"name":"TypeError","message":"` + message + `","request":{"digital":{"requests":[{"protocol":"openid4vp","data":{}}]}}}`
		r := httptest.NewRequest("POST", "/api/dc-api/refusals", strings.NewReader(body))
		r.Header.Set("Origin", "chrome-extension://abc")
		r.Header.Set(CallerOriginHeader, "https://verifier.example")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, r)
		return rec.Code
	}
	count := func() int {
		n := 0
		for _, e := range srv.wallet.GetLog() {
			if e.Details["event"] == "dc_api_refused" {
				n++
			}
		}
		return n
	}

	for i := 0; i < 3; i++ {
		if code := refuse("No request uses a supported protocol"); code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", code)
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("%d refusal entries, want 1", n)
	}
	entry := findLogEntry(srv.wallet.GetLog(), "dc_api_refused")
	if !strings.Contains(entry.Detail, "https://verifier.example") || entry.Success {
		t.Errorf("entry %q, want a failed entry with the origin", entry.Detail)
	}
	if ignored, _ := entry.Details["ignored_requests"].([]oid4vp.IgnoredBrowserAPIRequest); len(ignored) != 1 || !strings.Contains(ignored[0].Reason, "Appendix A.1") {
		t.Errorf("ignored requests %+v, want the protocol hint", entry.Details["ignored_requests"])
	}
	refuse("The page must be visible and have focus")
	if n := count(); n != 2 {
		t.Errorf("%d refusal entries, want 2 after another reason", n)
	}

	r := httptest.NewRequest("POST", "/api/dc-api/refusals", strings.NewReader(`{"name":"TypeError","message":"from a page"}`))
	r.Header.Set("Origin", "https://verifier.example")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || count() != 2 {
		t.Errorf("report from a web page: status %d with %d entries, want 403 and no entry", rec.Code, count())
	}
}

// The extension cancels its call by ID and gives a reason. Only the calling
// browser can cancel it.
func TestTheExtensionCancelsItsCallWithAReason(t *testing.T) {
	srv := newTestServer(t, false)
	shown := make(chan *consent.Request, 1)
	srv.onConsentRequest = func(req *consent.Request) { shown <- req }
	call := map[string]any{"digital": map[string]any{"requests": []any{map[string]any{"protocol": "openid4vp-v1-unsigned", "data": unsignedPIDRequest(nil)}}}}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- sendDCAPICall(t, srv, context.Background(), call, map[string]string{CallIDHeader: "call-1", OwnerHeader: "owner-a"})
	}()
	select {
	case <-shown:
	case <-time.After(5 * time.Second):
		t.Fatal("the wallet did not ask for consent")
	}

	cancel := func(owner string) int {
		r := httptest.NewRequest("POST", "/api/dc-api/cancel", strings.NewReader(`{"id":"call-1","reason":"The wallet window was closed"}`))
		r.Header.Set(OwnerHeader, owner)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := cancel("owner-b"); code != http.StatusNotFound {
		t.Fatalf("another browser's cancel: status %d, want 404", code)
	}
	if code := cancel("owner-a"); code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", code)
	}
	select {
	case rec := <-done:
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "The wallet window was closed") {
			t.Errorf("answer %d %s, want 409 with the reason", rec.Code, rec.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call kept waiting after the cancel")
	}
	entry := findLogEntry(srv.wallet.GetLog(), "presentation_cancelled")
	if entry == nil || !strings.HasSuffix(entry.Detail, "The wallet window was closed") {
		t.Fatalf("entry %+v, want the reason", entry)
	}
}

// The response entry shows the origin of the presentation and the encryption
// key.
func TestTheResultEntryNamesOriginAndEncryptionKey(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ECDH-ES","enc":"A128GCM","kid":"verifier-key-1"}`))
	result := &oid4vp.BrowserAPIResult{Protocol: "openid4vp-v1-signed", Data: map[string]any{"response": header + "..iv.ct.tag"}}
	details := map[string]any{}
	addDCAPIResultDetails(details, &oid4vp.Request{RequestOrigin: "https://verifier.example"}, result)

	encryption, _ := details["response_encryption"].(map[string]any)
	if details["request_origin"] != "https://verifier.example" || encryption["kid"] != "verifier-key-1" || encryption["enc"] != "A128GCM" {
		t.Errorf("details %v, want the origin and the JWE header", details)
	}
}
