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
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func TestPresentationSubmissionLogDetailsIncludePresentedCredentialMaterial(t *testing.T) {
	w := &Wallet{PersistedState: PersistedState{Credentials: []StoredCredential{
		{
			ID:     "cred-1",
			Format: "dc+sd-jwt",
			Raw:    "issuer.jwt~disclosure~kb.jwt",
			VCT:    "urn:eudi:pid:1",
			Claims: map[string]any{
				"given_name":  "Erika",
				"family_name": "Mustermann",
			},
		},
	}}}

	details := presentationSubmissionLogDetails(
		&oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "verifier.example", ResponseMode: "direct_post"}, RequestPayload: map[string]any{
			"nonce":         "n-1",
			"response_mode": "direct_post",
		}},
		w,
		[]consent.Match{
			{
				QueryID:      "pid",
				CredentialID: "cred-1",
				Format:       "dc+sd-jwt",
				VCT:          "urn:eudi:pid:1",
				Claims: map[string]any{
					"given_name": "Erika",
				},
				SelectedKeys: []string{"given_name"},
			},
		},
		&VPTokenMapResult{TokenMap: map[string][]string{"pid": {"presented.sdjwt~kb.jwt"}}},
		"",
		&oid4vp.DirectPostResult{StatusCode: 200, Body: "ok"},
	)

	if details["request_object"] == nil {
		t.Fatalf("expected request_object detail: %#v", details)
	}
	presented, ok := details["presented_credentials"].([]map[string]any)
	if !ok || len(presented) != 1 {
		t.Fatalf("expected one presented credential, got %#v", details["presented_credentials"])
	}
	item := presented[0]
	if item["raw_credential"] != "issuer.jwt~disclosure~kb.jwt" {
		t.Fatalf("expected raw credential in verbose details, got %#v", item)
	}
	if item["presentation"] != "presented.sdjwt~kb.jwt" {
		t.Fatalf("expected generated presentation in verbose details, got %#v", item)
	}
	if claims, ok := item["claims"].(map[string]any); !ok || claims["given_name"] != "Erika" {
		t.Fatalf("expected selected claims in verbose details, got %#v", item["claims"])
	}
}

func TestPresentationResponseLogDetailsExcludeRequestMaterial(t *testing.T) {
	w := &Wallet{PersistedState: PersistedState{Credentials: []StoredCredential{
		{
			ID:     "cred-1",
			Format: "dc+sd-jwt",
			Raw:    "issuer.jwt~disclosure~kb.jwt",
			VCT:    "urn:eudi:pid:1",
		},
	}}}

	details := PresentationResponseLogDetails(
		&oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "verifier.example", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response", RedirectURI: "https://verifier.example/redirect", Nonce: "request-nonce", State: "state-1", RequestURIMethod: "post", ClientMetadata: map[string]any{"client_name": "Verifier"}, DCQLQuery: map[string]any{"credentials": []any{}}}, RequestOrigin: "https://rp.example", RequestPayload: map[string]any{"nonce": "request-nonce"}, Source: "api"},
		w,
		[]consent.Match{
			{
				QueryID:      "pid",
				CredentialID: "cred-1",
				Format:       "dc+sd-jwt",
				VCT:          "urn:eudi:pid:1",
				SelectedKeys: []string{"given_name"},
			},
		},
		&VPTokenMapResult{TokenMap: map[string][]string{"pid": {"presented.sdjwt~kb.jwt"}}},
		"id.jwt",
		"https://verifier.example/response",
	)

	for _, key := range []string{
		"client_id",
		"response_type",
		"response_mode",
		"response_uri",
		"redirect_uri",
		"nonce",
		"request_uri_method",
		"request_origin",
		"client_metadata",
		"dcql_query",
		"request_object",
	} {
		if _, ok := details[key]; ok {
			t.Fatalf("presentation response details should not include request field %q: %#v", key, details)
		}
	}
	if details["vp_token"] == nil {
		t.Fatalf("expected vp_token response payload: %#v", details)
	}
	if details["id_token"] != "id.jwt" {
		t.Fatalf("expected id_token response payload: %#v", details)
	}
	if details["state"] != "state-1" {
		t.Fatalf("expected state response payload: %#v", details)
	}
	if details["submission_uri"] != "https://verifier.example/response" {
		t.Fatalf("expected submission_uri routing detail: %#v", details)
	}
	if details["presented_credentials"] == nil {
		t.Fatalf("expected presented credential details: %#v", details)
	}
}

// The log cap bounds storage and reload costs. Public demos need it because visitors
// can generate activity but cannot clear the log.
func TestActivityLog_IsBounded(t *testing.T) {
	w := generateTestWallet(t)
	before := len(w.GetLog())

	for i := 0; i < maxLogEntries*3; i++ {
		w.AddLog("presentation", "entry", true)
	}

	got := len(w.GetLog())
	if got > maxLogEntries+logTrimSlack {
		t.Errorf("log holds %d entries, want it trimmed to around %d", got, maxLogEntries)
	}
	if got < maxLogEntries {
		t.Errorf("log holds %d entries, want it to keep at least %d", got, maxLogEntries)
	}
	_ = before

	w.AddLog("presentation", "the-last-one", true)
	entries := w.GetLog()
	if entries[len(entries)-1].Detail != "the-last-one" {
		t.Error("trimming dropped the newest entry instead of the oldest")
	}
}

// A browser callback that never came leaves no parameters to show.
func TestFormLogPayloadOfAnEmptyFormIsAnEmptyBody(t *testing.T) {
	payload := formLogPayload("Response parameters", nil)
	if payload.Body != "" || payload.Wire != nil {
		t.Errorf("payload = %#v, want an empty body and no wire value", payload)
	}
}
