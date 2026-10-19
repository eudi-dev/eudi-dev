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

package demorp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// createDCAPIRequest creates a request for the Digital Credentials API and
// returns its transaction_id and the argument of navigator.credentials.get().
func createDCAPIRequest(t *testing.T, ts *httptest.Server, body string) (string, map[string]any) {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/verifier/api/requests", body)
	transactionID, _ := created["transaction_id"].(string)
	argument, _ := created["dc_api"].(map[string]any)
	if transactionID == "" || argument == nil || created["wallet_url"] != nil {
		t.Fatalf("unexpected create response: %v", created)
	}
	return transactionID, argument
}

// dcAPIRequest returns the single request of the argument.
func dcAPIRequest(t *testing.T, argument map[string]any) (string, map[string]any) {
	t.Helper()
	digital, _ := argument["digital"].(map[string]any)
	requests, _ := digital["requests"].([]any)
	if len(requests) != 1 {
		t.Fatalf("argument has %d requests, want 1: %v", len(requests), argument)
	}
	request, _ := requests[0].(map[string]any)
	protocol, _ := request["protocol"].(string)
	data, _ := request["data"].(map[string]any)
	return protocol, data
}

// answerOverDCAPI sends the argument to the wallet the way the eudi-dev
// browser extension does and hands the result to the verifier, as the page
// does. It returns the verifier's result.
func answerOverDCAPI(t *testing.T, ts *httptest.Server, transactionID string, argument map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(argument)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", ts.URL+"/api/dc-api", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "chrome-extension://eudidevextensionid")
	req.Header.Set(wallet.CallerOriginHeader, ts.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wallet answered %d: %s", resp.StatusCode, result)
	}

	resp, err = http.Post(ts.URL+"/verifier/api/requests/"+transactionID+"/dc-api", "application/json", bytes.NewReader(result))
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("verifier answered %d: %s", resp.StatusCode, answer)
	}
	return getJSONFrom(t, ts.URL+"/verifier/api/requests/"+transactionID)
}

func requestObjectClaims(t *testing.T, jar string) map[string]any {
	t.Helper()
	parts := strings.Split(jar, ".")
	if len(parts) != 3 {
		t.Fatalf("request is not a compact JWS: %q", jar)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func wantVerified(t *testing.T, status map[string]any) {
	t.Helper()
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
}

// OpenID4VP 1.0 Appendix A.2: a signed request lists the page origin in
// expected_origins and asks for dc_api.jwt. It has no response_uri and no
// state. §5.9.3 binds the presentation to the origin.
func TestASignedRequestOverTheDCAPIVerifies(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))

	transactionID, argument := createDCAPIRequest(t, ts, `{"type":"pid","format":"sd-jwt","delivery":"dc_api"}`)
	protocol, data := dcAPIRequest(t, argument)
	if protocol != "openid4vp-v1-signed" {
		t.Errorf("protocol = %q, want openid4vp-v1-signed", protocol)
	}
	jar, _ := data["request"].(string)
	claims := requestObjectClaims(t, jar)
	if origins, _ := claims["expected_origins"].([]any); len(origins) != 1 || origins[0] != ts.URL {
		t.Errorf("expected_origins = %v, want [%s]", claims["expected_origins"], ts.URL)
	}
	if claims["response_mode"] != "dc_api.jwt" || claims["response_uri"] != nil || claims["state"] != nil {
		t.Errorf("request object = %v, want dc_api.jwt without response_uri and state", claims)
	}

	wantVerified(t, answerOverDCAPI(t, ts, transactionID, argument))
}

// The mdoc device signature covers the DC API handover (OpenID4VP 1.0
// Appendix B.2.6.2).
func TestAnMDocOverTheDCAPIVerifies(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))

	transactionID, argument := createDCAPIRequest(t, ts, `{"type":"pid","format":"mdoc","delivery":"dc_api"}`)
	wantVerified(t, answerOverDCAPI(t, ts, transactionID, argument))
}

// OpenID4VP 1.0 Appendix A.3.1: an unsigned request carries its parameters as
// JSON and has no client_id.
func TestAnUnsignedRequestOverTheDCAPIVerifies(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))

	transactionID, argument := createDCAPIRequest(t, ts, `{"type":"custom","client_id_scheme":"pre-registered","delivery":"dc_api","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`)
	protocol, data := dcAPIRequest(t, argument)
	if protocol != "openid4vp-v1-unsigned" {
		t.Errorf("protocol = %q, want openid4vp-v1-unsigned", protocol)
	}
	if data["client_id"] != nil || data["response_mode"] != "dc_api.jwt" || data["dcql_query"] == nil {
		t.Errorf("request data = %v, want dc_api.jwt with a dcql_query and no client_id", data)
	}

	wantVerified(t, answerOverDCAPI(t, ts, transactionID, argument))
}

// A request over the DC API takes its response only from the page, and a
// redirect request only at its response_uri.
func TestEachRequestTakesItsResponseOnItsOwnPath(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))

	overAPI := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid","format":"sd-jwt","delivery":"dc_api"}`)
	resp, err := http.PostForm(ts.URL+"/verifier/response/"+overAPI["id"].(string), url.Values{"response": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("response_uri for a DC API request: status %d, want 400", resp.StatusCode)
	}

	redirect := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid","format":"sd-jwt"}`)
	resp, err = http.Post(ts.URL+"/verifier/api/requests/"+redirect["transaction_id"].(string)+"/dc-api", "application/json", strings.NewReader(`{"protocol":"openid4vp-v1-signed","data":{"response":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("DC API response to a redirect request: status %d, want 400", resp.StatusCode)
	}
}

func TestAnUnknownDeliveryIsRefused(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))
	resp, err := http.Post(ts.URL+"/verifier/api/requests", "application/json", strings.NewReader(`{"type":"pid","delivery":"bluetooth"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

// Each link of a redirect request comes with its QR code.
func TestARedirectRequestCarriesAQRCodePerLink(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))
	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid","format":"sd-jwt"}`)
	for _, name := range []string{"wallet_url_qr", "scheme_uri_qr"} {
		if svg, _ := created[name].(string); !strings.HasPrefix(svg, "<svg ") {
			t.Errorf("%s = %.40q, want an SVG", name, created[name])
		}
	}
}

func decodeSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The demo PID request can also go out unsigned.
func TestAnUnsignedPIDRequestOverTheDCAPIVerifies(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))

	transactionID, argument := createDCAPIRequest(t, ts, `{"type":"pid","format":"both","delivery":"dc_api","signing":"unsigned"}`)
	if protocol, data := dcAPIRequest(t, argument); protocol != "openid4vp-v1-unsigned" || data["request"] != nil {
		t.Errorf("protocol %q, data %v, want an unsigned request", protocol, data)
	}
	wantVerified(t, answerOverDCAPI(t, ts, transactionID, argument))
}

// OpenID4VP 1.0 Appendix A.3.2: the payload carries no client_id. Each
// signature names its client identifier in its protected header, and only
// the registered signer sends verifier_info.
func TestAMultisignedRequestOverTheDCAPIVerifies(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))

	transactionID, argument := createDCAPIRequest(t, ts, `{"type":"pid","format":"sd-jwt","delivery":"dc_api","signing":"multisigned"}`)
	protocol, data := dcAPIRequest(t, argument)
	if protocol != "openid4vp-v1-multisigned" {
		t.Fatalf("protocol = %q, want openid4vp-v1-multisigned", protocol)
	}
	request, _ := data["request"].(map[string]any)
	payload := decodeSegment(t, request["payload"].(string))
	if payload["client_id"] != nil || payload["verifier_info"] != nil || payload["iss"] != nil {
		t.Errorf("payload %v holds a signer's client_id, verifier_info or iss", payload)
	}
	if origins, _ := payload["expected_origins"].([]any); len(origins) != 1 || origins[0] != ts.URL {
		t.Errorf("expected_origins = %v, want [%s]", payload["expected_origins"], ts.URL)
	}
	signatures, _ := request["signatures"].([]any)
	if len(signatures) != 2 {
		t.Fatalf("%d signatures, want 2", len(signatures))
	}
	var clientIDs []string
	for i, item := range signatures {
		header := decodeSegment(t, item.(map[string]any)["protected"].(string))
		id, _ := header["client_id"].(string)
		if !strings.HasPrefix(id, "x509_hash:") {
			t.Errorf("signature %d client_id = %q, want x509_hash", i, id)
		}
		clientIDs = append(clientIDs, id)
		if hasInfo := header["verifier_info"] != nil; hasInfo != (i == 0) {
			t.Errorf("signature %d verifier_info present = %v", i, hasInfo)
		}
	}
	if clientIDs[0] == clientIDs[1] {
		t.Errorf("both signatures use client_id %s", clientIDs[0])
	}

	wantVerified(t, answerOverDCAPI(t, ts, transactionID, argument))
}

func TestTheSigningChoiceIsChecked(t *testing.T) {
	_, ts := serveDemoStack(t, customTestWallet(t))
	for name, body := range map[string]string{
		"unknown signing":                `{"type":"pid","delivery":"dc_api","signing":"twice"}`,
		"signing without the DC API":     `{"type":"pid","signing":"unsigned"}`,
		"signed with an unsigned scheme": `{"type":"custom","client_id_scheme":"pre-registered","delivery":"dc_api","signing":"signed","credentials":[{"format":"dc+sd-jwt","vct":"` + PIDVCT + `","claims":[["given_name"]]}]}`,
	} {
		resp, err := http.Post(ts.URL+"/verifier/api/requests", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, resp.StatusCode)
		}
	}
}
