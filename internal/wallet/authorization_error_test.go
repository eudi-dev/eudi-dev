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
	"sync"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

// captureVerifier stands in for a verifier waiting on its response_uri. Every
// refusal of the wallet must arrive here. OpenID4VP 1.0 §5.6 says
// "Both successful and error responses SHOULD be returned using the supplied
// Response Mode, or if none is supplied, using the default Response Mode". A
// verifier that gets no answer waits until it times out.
type captureVerifier struct {
	*httptest.Server
	mu    sync.Mutex
	form  url.Values
	reply string
}

func newCaptureVerifier(t *testing.T) *captureVerifier {
	t.Helper()
	return newCaptureVerifierReplying(t, `{}`)
}

func newCaptureVerifierReplying(t *testing.T, reply string) *captureVerifier {
	t.Helper()
	cv := &captureVerifier{reply: reply}
	cv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		cv.mu.Lock()
		cv.form = parsed
		reply := cv.reply
		cv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(reply))
	}))
	t.Cleanup(cv.Close)
	return cv
}

// newRedirectingVerifier answers every response with a redirect_uri, as OpenID4VP
// 1.0 §8.2 allows for Authorization Responses and Authorization Error Responses.
func newRedirectingVerifier(t *testing.T, redirectURI string) *captureVerifier {
	t.Helper()
	reply, err := json.Marshal(map[string]string{"redirect_uri": redirectURI})
	if err != nil {
		t.Fatalf("marshaling verifier reply: %v", err)
	}
	return newCaptureVerifierReplying(t, string(reply))
}

func (cv *captureVerifier) received(t *testing.T) url.Values {
	t.Helper()
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if cv.form == nil {
		t.Fatal("verifier received no authorization response at its response_uri")
	}
	return cv.form
}

func authorizeRequest(t *testing.T, srv *Server, params url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

func dcqlQueryParam(t *testing.T, query map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(query)
	if err != nil {
		t.Fatalf("marshaling dcql query: %v", err)
	}
	return string(encoded)
}

// unsatisfiableRequest asks for a credential type that no wallet holds.
func unsatisfiableRequest(t *testing.T, verifierURL string) url.Values {
	t.Helper()
	return url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifierURL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "nothing",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:nobody:holds:this"}},
				},
			},
		})},
	}
}

// §8.5 access_denied: "The Wallet did not have the requested Credentials to
// satisfy the Authorization Request."
func TestNoMatchingCredentialsReturnsAccessDeniedToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	rec := authorizeRequest(t, srv, unsatisfiableRequest(t, verifier.URL))

	form := verifier.received(t)
	if got := form.Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if got := form.Get("state"); got != "s" {
		t.Fatalf("verifier received state %q, want s", got)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("local caller got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	local := decodeJSON(t, rec)
	if local["status"] != "no_match" {
		t.Fatalf("local status %v, want no_match", local["status"])
	}
	if local["error_code"] != "access_denied" {
		t.Fatalf("local error_code %v, want access_denied", local["error_code"])
	}
}

// §8.5 vp_formats_not_supported: "The Wallet does not support any of the
// formats requested by the Verifier". A query for a format the wallet cannot
// present fails before any stored credential is checked. The cause is the
// format and has nothing to do with what the wallet holds.
func TestAQueryForAnUnsupportedFormatReturnsVPFormatsNotSupported(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"response_uri":  {verifier.URL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{"id": "ldp", "format": "ldp_vc"},
			},
		})},
	}

	authorizeRequest(t, srv, params)

	if got := verifier.received(t).Get("error"); got != "vp_formats_not_supported" {
		t.Fatalf("verifier received error %q, want vp_formats_not_supported", got)
	}
}

// The wallet cannot trust the response endpoint of a request that fails
// validation. §8.5 says the error response "follows the rules as defined in
// [RFC6749]". RFC 6749 §4.1.2.1 says the server "SHOULD inform the resource
// owner of the error and MUST NOT automatically redirect the user-agent to the
// invalid redirection URI". The wallet tells the caller and sends nothing to
// the verifier.
func TestValidationFailuresAreNotSentToTheVerifier(t *testing.T) {
	tests := []struct {
		name      string
		params    func(responseURI string) url.Values
		wantLocal string
	}{
		{
			name: "a response type the wallet cannot serve",
			params: func(responseURI string) url.Values {
				return url.Values{
					"client_id":     {"https://verifier.example"},
					"response_type": {"not_a_response_type"},
					"response_mode": {"direct_post"},
					"nonce":         {"n"},
					"state":         {"s"},
					"response_uri":  {responseURI},
				}
			},
			wantLocal: "invalid_request",
		},
		{
			name: "a request_uri_method that is neither get nor post",
			params: func(responseURI string) url.Values {
				return url.Values{
					"client_id":          {"https://verifier.example"},
					"response_type":      {"vp_token"},
					"response_mode":      {"direct_post"},
					"nonce":              {"n"},
					"state":              {"s"},
					"response_uri":       {responseURI},
					"request_uri":        {"https://verifier.example/req"},
					"request_uri_method": {"PATCH"},
				}
			},
			// This path answers before the request is built. Its error is the
			// parameter name.
			wantLocal: "request_uri_method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			verifier := newCaptureVerifier(t)

			rec := authorizeRequest(t, srv, tt.params(verifier.URL))

			if got := verifier.form; got != nil {
				t.Errorf("the verifier was contacted with %v, want nothing sent to an unvalidated request's endpoint", got)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("local status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantLocal) {
				t.Errorf("local body = %s, want it to name %s", rec.Body.String(), tt.wantLocal)
			}
		})
	}
}

// A profile violation is found during request validation, so the same rule
// applies. The wallet sends nothing to an unvalidated endpoint.
func TestAHAIPViolationIsNotSentToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.RequireHAIP = true
	srv.wallet.ValidationMode = ValidationModeStrict
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifier.URL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{}},
			},
		})},
	}

	rec := authorizeRequest(t, srv, params)

	if got := verifier.form; got != nil {
		t.Errorf("the verifier was contacted with %v, want nothing sent", got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("local status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestPresentationAPINoMatchReportsAccessDeniedToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	body, err := json.Marshal(map[string]any{"uri": "openid4vp://authorize?" + unsatisfiableRequest(t, verifier.URL).Encode()})
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}

	rec := serverRequest(t, srv, "POST", "/api/presentations", string(body))

	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("local caller got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if local := decodeJSON(t, rec); local["status"] != "no_match" {
		t.Fatalf("local status %v, want no_match", local["status"])
	}
}

func dcAPIRefusal(t *testing.T, srv *Server, request map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{"protocol": oid4vp.BrowserAPIProtocolOpenID4VPUnsigned, "data": request},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshaling browser request: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://rp.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Digital Credentials API caller got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	result := decodeJSON(t, rec)
	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected a data object in the browser result, got %T", result["data"])
	}
	return data
}

// Appendix A.4: "Protocol error responses are returned as an object within the
// data property. This object has a single property with the name error and a
// value containing the error response code as defined in Section 8.5."
func TestDCAPIErrorObjectCarriesOnlyTheErrorCode(t *testing.T) {
	srv := newTestServer(t, true)

	data := dcAPIRefusal(t, srv, map[string]any{
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"nonce":         "browser-nonce",
		"state":         "browser-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "nothing",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:nobody:holds:this"}},
				},
			},
		},
	})

	if data["error"] != "access_denied" {
		t.Fatalf("error object carried %v, want access_denied", data["error"])
	}
	if len(data) != 1 {
		t.Fatalf("error object has %d members, want exactly one: %#v", len(data), data)
	}
}

// A request that fails validation gets no protocol response over the Digital
// Credentials API either. §8.5 says the error response "follows the rules as
// defined in [RFC6749]". RFC 6749 §4.1.2.1 has the server inform the user. The
// calling page learns about the refusal from an HTTP error.
func TestDCAPIMalformedRequestIsRefusedWithoutAProtocolResponse(t *testing.T) {
	srv := newTestServer(t, true)

	payload := map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{
					"protocol": oid4vp.BrowserAPIProtocolOpenID4VPUnsigned,
					"data": map[string]any{
						"response_type": "not_a_response_type",
						"response_mode": "dc_api",
						"nonce":         "n",
						"dcql_query":    pidDCQLQuery(),
					},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://verifier.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("body = %s, want it to name invalid_request", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "vp_token") {
		t.Errorf("a refused request produced a presentation: %s", rec.Body.String())
	}
}

// OID4VP 1.0 Appendix A.4: "Protocol error responses are returned as an object
// within the data property. This object has a single property with the name
// error and a value containing the error response code as defined in Section
// 8.5." That holds for dc_api.jwt too. A Verifier that finds a JWE in place of
// the error object would read it as a response.
func TestDCAPIErrorIsNotEncryptedUnderTheEncryptedResponseMode(t *testing.T) {
	w := generateTestWallet(t)
	params := PresentationParams{
		ResponseMode:   "dc_api.jwt",
		RequestOrigin:  "https://verifier.example",
		ClientMetadata: map[string]any{},
	}

	response, err := w.BuildAuthorizationErrorResponse("invalid_request", "nonce is required", "some-state", params)
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorResponse: %v", err)
	}
	if response.ResponseJWT != "" {
		t.Errorf("the error was encrypted: %s", response.ResponseJWT)
	}
	if got := response.Plain["error"]; got != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", got)
	}

	result, err := oid4vp.BuildBrowserAPIResult(oid4vp.BrowserAPIProtocolOpenID4VPUnsigned, response)
	if err != nil {
		t.Fatalf("oid4vp.BuildBrowserAPIResult: %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %#v, want an object", result.Data)
	}
	if len(data) != 1 {
		t.Errorf("the error object has %d members, want exactly one: %v", len(data), data)
	}
	if data["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", data["error"])
	}
	if _, encrypted := data["response"]; encrypted {
		t.Error("the error object carries an encrypted response")
	}
}

// A credentials file allows IDs shorter than the generated ones.
func TestACredentialWithAShortIDIsPresented(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.ClearCredentials()
	file, err := ParseCredentialsFile([]byte("credentials:\n  - id: pid\n    template: pid-sdjwt\n"))
	if err != nil {
		t.Fatalf("ParseCredentialsFile: %v", err)
	}
	if err := srv.wallet.AddFileCredentials(file, false); err != nil {
		t.Fatalf("AddFileCredentials: %v", err)
	}
	verifier := newCaptureVerifier(t)
	params := unsatisfiableRequest(t, verifier.URL)
	params.Set("dcql_query", dcqlQueryParam(t, map[string]any{
		"credentials": []any{map[string]any{
			"id":     "pid",
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		}},
	}))

	authorizeRequest(t, srv, params)

	if form := verifier.received(t); form.Get("vp_token") == "" {
		t.Fatalf("verifier received %v, want a vp_token", form)
	}
}

// Strict --arf answers a verifier that authenticated with a trusted access
// certificate with access_denied inside the Digital Credentials API result,
// like on /authorize (OpenID4VP 1.0 Appendix A).
func TestStrictARFAnswersOverTheDCAPIWithAccessDenied(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.RequireARF = true
	srv.wallet.ValidationMode = ValidationModeStrict
	key, chain, verifierInfo := registeredVerifier(t, srv.wallet)
	var info []any
	if err := json.Unmarshal([]byte(verifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	requestObject, err := oid4vp.SignRequestObjectJWT(map[string]any{
		"client_id": oid4vp.X509HashClientID(chain[0]), "response_type": "vp_token", "response_mode": "dc_api",
		"nonce": "n", "expected_origins": []any{"https://rp.example"}, "verifier_info": info,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claims": []any{map[string]any{"path": []any{"birthdate"}}},
		}}},
	}, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"digital": map[string]any{"requests": []any{
		map[string]any{"protocol": oid4vp.BrowserAPIProtocolOpenID4VPSigned, "data": map[string]any{"request": requestObject}},
	}}})
	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://rp.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	result := decodeJSON(t, rec)
	data, _ := result["data"].(map[string]any)
	if rec.Code != http.StatusOK || data["error"] != "access_denied" {
		t.Errorf("%d %s, want access_denied in the API result", rec.Code, rec.Body)
	}
}
