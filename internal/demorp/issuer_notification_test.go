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
	"net/http"
	"strings"
	"testing"
)

// issuedTicket redeems a pre-authorized offer and requests its ticket. It
// returns the offer id, the access token and the notification_id.
func issuedTicket(t *testing.T, d *DemoRP) (offerID, token, notificationID string) {
	t.Helper()
	h := d.IssuerHandler()
	code, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}
	offerURI := offerDoc["offer_uri"].(string)
	_, offer := doJSON(t, h, "GET", "/offer/"+offerURI[strings.LastIndex(offerURI, "/")+1:], "", nil)
	grant := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := "grant_type=" + preAuthGrant + "&pre-authorized_code=" + grant["pre-authorized_code"].(string)
	_, tokenDoc := doJSON(t, h, "POST", "/token", form, attestedTokenHeaders(t))
	token, _ = tokenDoc["access_token"].(string)

	code, doc := requestCredential(t, d, token, `"credential_configuration_id":"demo-ticket",`)
	if code != http.StatusOK {
		t.Fatalf("credential request: %d %v", code, doc)
	}
	notificationID, _ = doc["notification_id"].(string)
	if notificationID == "" {
		t.Fatalf("credential response carries no notification_id: %v", doc)
	}
	return offerDoc["id"].(string), token, notificationID
}

func sendNotification(t *testing.T, d *DemoRP, token, body string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, d.IssuerHandler(), "POST", "/notification", body, map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	})
}

func TestTheIssuerMetadataNamesTheNotificationEndpoint(t *testing.T) {
	d, _, _ := newDemoRP(t)
	_, metadata := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	endpoint, _ := metadata["notification_endpoint"].(string)
	if endpoint != metadata["credential_issuer"].(string)+"/notification" {
		t.Fatalf("notification_endpoint = %q, want the issuer URL with /notification", endpoint)
	}
}

// OpenID4VCI 1.0 §11.2 answers a valid Notification Request with 204. The
// issuer page lists the event under its offer.
func TestTheIssuerPageShowsTheNotificationOfItsOffer(t *testing.T) {
	d, _, _ := newDemoRP(t)
	offerID, token, notificationID := issuedTicket(t, d)

	code, doc := sendNotification(t, d, token,
		`{"notification_id":"`+notificationID+`","event":"credential_failure","event_description":"Storage is full"}`)
	if code != http.StatusNoContent {
		t.Fatalf("notification: %d %v, want 204", code, doc)
	}

	_, listed := doJSON(t, d.IssuerHandler(), "GET", "/api/offers/"+offerID+"/notifications", "", nil)
	notifications, _ := listed["notifications"].([]any)
	if len(notifications) != 1 {
		t.Fatalf("notifications = %v, want one", listed["notifications"])
	}
	got := notifications[0].(map[string]any)
	if got["event"] != "credential_failure" || got["event_description"] != "Storage is full" || got["credential_configuration_id"] != "demo-ticket" {
		t.Fatalf("notification = %v, want credential_failure with its description for demo-ticket", got)
	}

	_, other := doJSON(t, d.IssuerHandler(), "GET", "/api/offers/unknown/notifications", "", nil)
	if list, _ := other["notifications"].([]any); len(list) != 0 {
		t.Fatalf("another offer lists %v, want none", other["notifications"])
	}
}

// §11.3 answers errors in the request with HTTP 400.
func TestAMalformedNotificationIsRefused(t *testing.T) {
	d, _, _ := newDemoRP(t)
	_, token, notificationID := issuedTicket(t, d)
	_, otherToken, _ := issuedTicket(t, d)

	cases := []struct {
		name, token, body, wantError string
	}{
		{"an unknown event", token, `{"notification_id":"` + notificationID + `","event":"credential_stored"}`, "invalid_notification_request"},
		{"no notification_id", token, `{"event":"credential_accepted"}`, "invalid_notification_request"},
		{"a quote in event_description", token, `{"notification_id":"` + notificationID + `","event":"credential_failure","event_description":"say \"no\""}`, "invalid_notification_request"},
		{"no JSON", token, `event=credential_accepted`, "invalid_notification_request"},
		{"an unknown notification_id", token, `{"notification_id":"unknown","event":"credential_accepted"}`, "invalid_notification_id"},
		{"the id of another access token", otherToken, `{"notification_id":"` + notificationID + `","event":"credential_accepted"}`, "invalid_notification_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, doc := sendNotification(t, d, tc.token, tc.body)
			if code != http.StatusBadRequest || doc["error"] != tc.wantError {
				t.Fatalf("got %d %v, want 400 %s", code, doc, tc.wantError)
			}
		})
	}
}

// §11.3 answers an invalid access token as in RFC 6750 §3.1.
func TestANotificationNeedsAValidAccessToken(t *testing.T) {
	d, _, _ := newDemoRP(t)
	_, _, notificationID := issuedTicket(t, d)

	code, _ := sendNotification(t, d, "unknown", `{"notification_id":"`+notificationID+`","event":"credential_accepted"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

// §9.2 lets the Deferred Credential Response carry a notification_id.
func TestADeferredCredentialResponseCarriesANotificationID(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.deferredDelay = 0
	token := redeemPreAuthOffer(t, d, "deferred=true", nil)["access_token"].(string)
	_, accepted := requestCredential(t, d, token, `"credential_configuration_id":"demo-ticket",`)

	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/deferred_credential", `{"transaction_id":"`+accepted["transaction_id"].(string)+`"}`, map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	})
	if code != http.StatusOK {
		t.Fatalf("collecting the credential: %d %v", code, doc)
	}
	notificationID, _ := doc["notification_id"].(string)
	if code, doc := sendNotification(t, d, token, `{"notification_id":"`+notificationID+`","event":"credential_accepted"}`); code != http.StatusNoContent {
		t.Fatalf("notification: %d %v, want 204", code, doc)
	}
}
