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
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// txCodeOffer creates a pre-authorized offer with a transaction code and
// returns the code, the grant of the offer and a token form without tx_code.
func txCodeOffer(t *testing.T, d *DemoRP) (string, map[string]any, url.Values) {
	t.Helper()
	h := d.IssuerHandler()
	code, offerDoc := doJSON(t, h, "POST", "/api/offers?tx_code=true", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}
	txCode, _ := offerDoc["tx_code"].(string)
	offerURI := offerDoc["offer_uri"].(string)
	code, offer := doJSON(t, h, "GET", "/offer/"+offerURI[strings.LastIndex(offerURI, "/")+1:], "", nil)
	if code != http.StatusOK {
		t.Fatalf("fetching offer: %d %v", code, offer)
	}
	grant := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grant["pre-authorized_code"].(string)}}
	return txCode, grant, form
}

func TestAnOfferWithATransactionCodeDescribesItInTheGrant(t *testing.T) {
	d, _, _ := newDemoRP(t)
	txCode, grant, _ := txCodeOffer(t, d)

	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(txCode) {
		t.Fatalf("tx_code = %q, want six digits", txCode)
	}
	described, _ := json.Marshal(grant["tx_code"])
	var got struct {
		InputMode   string `json:"input_mode"`
		Length      int    `json:"length"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(described, &got); err != nil {
		t.Fatal(err)
	}
	if got.InputMode != "numeric" || got.Length != 6 || got.Description == "" {
		t.Errorf("tx_code of the grant = %s, want numeric with length 6 and a description", described)
	}
}

func TestTheTokenEndpointChecksTheTransactionCode(t *testing.T) {
	tests := []struct {
		name   string
		txCode func(expected string) []string
		status int
		error  string
	}{
		{name: "right code", txCode: func(expected string) []string { return []string{expected} }, status: http.StatusOK},
		{name: "missing code", txCode: func(string) []string { return nil }, status: http.StatusBadRequest, error: "invalid_request"},
		{name: "wrong code", txCode: func(expected string) []string { return []string{expected + "0"} }, status: http.StatusBadRequest, error: "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _, _ := newDemoRP(t)
			expected, _, form := txCodeOffer(t, d)
			if sent := tt.txCode(expected); sent != nil {
				form["tx_code"] = sent
			}
			rec := postFormWithHeaders(t, d.IssuerHandler(), "/token", form, attestedTokenHeaders(t))
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.error) {
				t.Fatalf("token response = %d %s, want %d %s", rec.Code, rec.Body.String(), tt.status, tt.error)
			}
		})
	}
}

// OpenID4VCI 1.0 §6.3 answers a tx_code the offer did not ask for with
// invalid_request.
func TestATransactionCodeForAnOfferWithoutOneIsRefused(t *testing.T) {
	d, _, _ := newDemoRP(t)
	form := preAuthTokenForm(t, d)
	form.Set("tx_code", "123456")

	rec := postFormWithHeaders(t, d.IssuerHandler(), "/token", form, attestedTokenHeaders(t))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("token response = %d %s, want 400 invalid_request", rec.Code, rec.Body.String())
	}
}

func TestATransactionCodeNeedsAPreAuthorizedOffer(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?tx_code=true&grant="+authCodeGrant, "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("creating offer: %d %v, want 400", code, doc)
	}
}
