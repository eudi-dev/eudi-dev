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
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// stepIssuer is a credential issuer and authorization server. It serves every
// endpoint called by the issuance steps and records each request.
type stepIssuer struct {
	url string

	mu                 sync.Mutex
	oauth              map[string]any
	tokenResponse      map[string]any
	credentialResponse map[string]any
	deferredResponse   map[string]any
	tokenForms         []url.Values
	tokenAttestations  []string
	credentialRequests []map[string]any
	deferredRequests   int
	notifications      int
	parState           string
	parRedirectURI     string
}

func newStepIssuer(t *testing.T, credRaw string) *stepIssuer {
	t.Helper()
	issued := map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}}
	s := &stepIssuer{
		oauth:              map[string]any{},
		tokenResponse:      map[string]any{"access_token": "step-access-token", "token_type": "Bearer"},
		credentialResponse: issued,
		deferredResponse:   issued,
	}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *stepIssuer) serve(rw http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rw.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(r.Body)
	switch r.URL.Path {
	case "/.well-known/openid-credential-issuer":
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"credential_issuer":            s.url,
			"credential_endpoint":          s.url + "/credential",
			"nonce_endpoint":               s.url + "/nonce",
			"notification_endpoint":        s.url + "/notification",
			"deferred_credential_endpoint": s.url + "/deferred",
			"credential_configurations_supported": map[string]any{
				"first":  map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:first", "scope": "first"},
				"second": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:second", "scope": "second"},
			},
		})
	case "/.well-known/oauth-authorization-server":
		meta := map[string]any{
			"issuer":                                s.url,
			"token_endpoint":                        s.url + "/token",
			"authorization_endpoint":                s.url + "/authorize",
			"pushed_authorization_request_endpoint": s.url + "/par",
		}
		maps.Copy(meta, s.oauth)
		_ = json.NewEncoder(rw).Encode(meta)
	case "/par":
		form, _ := url.ParseQuery(string(body))
		s.parState, s.parRedirectURI = form.Get("state"), form.Get("redirect_uri")
		_ = json.NewEncoder(rw).Encode(map[string]any{"request_uri": "urn:step:par", "expires_in": 60})
	case "/authorize":
		http.Redirect(rw, r, s.parRedirectURI+"?code=step-code&state="+url.QueryEscape(s.parState), http.StatusFound)
	case "/nonce":
		_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "step-nonce"})
	case "/token":
		form, _ := url.ParseQuery(string(body))
		s.tokenForms = append(s.tokenForms, form)
		s.tokenAttestations = append(s.tokenAttestations, r.Header.Get("OAuth-Client-Attestation"))
		_ = json.NewEncoder(rw).Encode(s.tokenResponse)
	case "/credential":
		var request map[string]any
		_ = json.Unmarshal(body, &request)
		s.credentialRequests = append(s.credentialRequests, request)
		_ = json.NewEncoder(rw).Encode(s.credentialResponse)
	case "/deferred":
		s.deferredRequests++
		_ = json.NewEncoder(rw).Encode(s.deferredResponse)
	case "/notification":
		s.notifications++
		rw.WriteHeader(http.StatusNoContent)
	default:
		rw.WriteHeader(http.StatusNotFound)
	}
}

func (s *stepIssuer) preAuthorizedOffer(configs ...string) string {
	return s.offer(configs, map[string]any{
		preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "step-pre-auth-code"},
	})
}

func (s *stepIssuer) authorizationCodeOffer(configs ...string) string {
	return s.offer(configs, map[string]any{"authorization_code": map[string]any{}})
}

func (s *stepIssuer) offer(configs []string, grants map[string]any) string {
	encoded, _ := json.Marshal(map[string]any{
		"credential_issuer":            s.url,
		"credential_configuration_ids": configs,
		"grants":                       grants,
	})
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(encoded))
}

// An offer lists several configurations. The wallet requests the one chosen
// by the user or the API caller. Without a choice it requests the first.
func TestOfferIssuesTheChosenConfiguration(t *testing.T) {
	for _, tc := range []struct {
		chosen, want string
	}{
		{"", "first"},
		{"second", "second"},
	} {
		t.Run("chosen "+tc.chosen, func(t *testing.T) {
			w := generateTestWallet(t)
			issuer := newStepIssuer(t, generateTestCredential(t, w))
			if _, err := w.ProcessCredentialOfferWithOptions(issuer.preAuthorizedOffer("first", "second"), OfferOptions{ConfigurationID: tc.chosen}); err != nil {
				t.Fatalf("ProcessCredentialOfferWithOptions: %v", err)
			}
			if len(issuer.credentialRequests) != 1 {
				t.Fatalf("credential requests = %d, want 1", len(issuer.credentialRequests))
			}
			if got := issuer.credentialRequests[0]["credential_configuration_id"]; got != tc.want {
				t.Errorf("credential_configuration_id = %v, want %s", got, tc.want)
			}
			if got := w.GetCredentials()[0].Renewal; got != nil && got.ConfigurationID != tc.want {
				t.Errorf("renewal configuration = %s, want %s", got.ConfigurationID, tc.want)
			}
		})
	}

	t.Run("a configuration the offer does not list", func(t *testing.T) {
		w := generateTestWallet(t)
		issuer := newStepIssuer(t, generateTestCredential(t, w))
		_, err := w.ProcessCredentialOfferWithOptions(issuer.preAuthorizedOffer("first"), OfferOptions{ConfigurationID: "second"})
		if err == nil || !strings.Contains(err.Error(), `"second"`) {
			t.Fatalf("error = %v, want it to name the configuration", err)
		}
		if len(issuer.tokenForms) != 0 {
			t.Error("the wallet spent the pre-authorized code on a configuration the offer does not list")
		}
	})
}

// The configuration picked in the consent dialog decides what is requested.
// The approve API refuses a configuration missing from the offer.
func TestIssuanceConsentCarriesTheChosenConfiguration(t *testing.T) {
	w := generateTestWallet(t)
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	server := NewServer(w, 0, nil)
	consentReq, _, err := w.prepareIssuanceConsentRequest(issuer.preAuthorizedOffer("first", "second"), "")
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	w.Consents().Create(consentReq)

	if rec := serverRequest(t, server, "POST", "/api/requests/"+consentReq.ID+"/approve", `{"credential_configuration_id":"third"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("approve with an unlisted configuration: %d %s, want 400", rec.Code, rec.Body.String())
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.awaitOfferConsent(noopResponseWriter{}, consentReq, "test issuer", OfferOptions{})
	}()
	if rec := serverRequest(t, server, "POST", "/api/requests/"+consentReq.ID+"/approve", `{"credential_configuration_id":"second"}`); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	<-done
	if len(issuer.credentialRequests) != 1 || issuer.credentialRequests[0]["credential_configuration_id"] != "second" {
		t.Fatalf("credential requests = %v, want one for the chosen configuration", issuer.credentialRequests)
	}
}

// The authorization code flow resolves the format from the offered
// configuration also when the token response returns credential_identifiers.
func TestAuthorizationCodeDeferralKnowsTheFormatWithCredentialIdentifiers(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	issuer.tokenResponse["authorization_details"] = []any{map[string]any{
		"type":                        "openid_credential",
		"credential_configuration_id": "first",
		"credential_identifiers":      []any{"first-id"},
	}}
	issuer.credentialResponse = map[string]any{"transaction_id": "tx-1", "interval": 5}

	result, err := w.ProcessCredentialOffer(issuer.authorizationCodeOffer("first"))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if issuer.credentialRequests[0]["credential_identifier"] != "first-id" {
		t.Fatalf("credential request %v, want the credential_identifier", issuer.credentialRequests[0])
	}
	if !result.Pending || result.Format != "dc+sd-jwt" {
		t.Errorf("result pending=%v format=%q, want a pending dc+sd-jwt issuance", result.Pending, result.Format)
	}
	if pending := w.DeferredIssuanceList(); len(pending) != 1 || pending[0].Format != "dc+sd-jwt" || pending[0].VCT != "urn:test:first" {
		t.Errorf("deferred records %+v, want the format and type of the configuration", pending)
	}
}

// A pre-authorized issuance that attests the client records that client once,
// as the client of the renewal. A refresh then attests the same client.
func TestPreAuthorizedAttestedIssuanceRenewsAsTheSameClient(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "https://wallet.example"
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	issuer.oauth["token_endpoint_auth_methods_supported"] = []any{"attest_jwt_client_auth"}
	issuer.tokenResponse["refresh_token"] = "refresh-1"

	result, err := w.ProcessCredentialOffer(issuer.preAuthorizedOffer("first"))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	stored, _ := w.GetCredential(result.CredentialID)
	if stored.Renewal == nil || stored.Renewal.ClientID != "https://wallet.example" || stored.Renewal.ClientAuth == nil {
		t.Fatalf("renewal = %+v, want the attested client", stored.Renewal)
	}
	if _, err := w.RenewCredential(result.CredentialID); err != nil {
		t.Fatalf("RenewCredential: %v", err)
	}
	if len(issuer.tokenAttestations) != 2 {
		t.Fatalf("token requests = %d, want 2", len(issuer.tokenAttestations))
	}
	for i, attestation := range issuer.tokenAttestations {
		if attestation == "" {
			t.Fatalf("token request %d carried no attestation", i+1)
		}
		if sub := decodeJWTPart(t, attestation, 1)["sub"]; sub != "https://wallet.example" {
			t.Errorf("token request %d attests %v, want the wallet", i+1, sub)
		}
	}
	if got := issuer.tokenForms[1].Get("client_id"); got != "https://wallet.example" {
		t.Errorf("refresh client_id = %q, want the attested client", got)
	}
}

// A renewal stores a credential like any issuance: it logs the import and
// sends the notification of OID4VCI 1.0 §11.
func TestRefreshLogsTheImportAndNotifiesTheIssuer(t *testing.T) {
	w := generateTestWallet(t)
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	issuer.credentialResponse = map[string]any{
		"credentials":     []any{map[string]any{"credential": generateTestCredential(t, w)}},
		"notification_id": "renewal-notification",
	}
	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{
		Issuer: issuer.url, TokenEndpoint: issuer.url + "/token", CredentialEndpoint: issuer.url + "/credential",
		ConfigurationID: "first", RefreshToken: "refresh-1",
	})

	if _, err := w.RenewCredential(imported.ID); err != nil {
		t.Fatalf("RenewCredential: %v", err)
	}
	if issuer.notifications != 1 {
		t.Errorf("notifications = %d, want 1", issuer.notifications)
	}
	entry := findLogEntry(w.GetLog(), "credential_imported")
	if entry == nil || entry.Details["credential_id"] != imported.ID {
		t.Errorf("the renewal logged no import of %s", imported.ID)
	}
}

// RFC 6749 §5.1 requires token_type in every token response, the refresh
// token grant's included. Strict mode refuses a renewal without it.
func TestStrictRefreshRefusesATokenResponseWithoutTokenType(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	issuer.tokenResponse = map[string]any{"access_token": "step-access-token", "refresh_token": "refresh-2"}
	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{
		Issuer: issuer.url, TokenEndpoint: issuer.url + "/token", CredentialEndpoint: issuer.url + "/credential",
		ConfigurationID: "first", RefreshToken: "refresh-1",
	})

	_, err = w.RenewCredential(imported.ID)
	if err == nil || !strings.Contains(err.Error(), "token_type") {
		t.Fatalf("RenewCredential: %v, want a refusal naming token_type", err)
	}
	if len(issuer.credentialRequests) != 0 {
		t.Error("the wallet requested a credential with the refused token")
	}
	if stored, _ := w.GetCredential(imported.ID); stored.Renewal.RefreshToken != "refresh-2" {
		t.Errorf("refresh token = %q, want the rotated one kept", stored.Renewal.RefreshToken)
	}
}

// A deferred credential keeps the renewal context of its issuance, so the
// collected credential can be renewed like one issued at once.
func TestCollectedDeferredCredentialCanBeRenewed(t *testing.T) {
	w := generateTestWallet(t)
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	issuer.tokenResponse["refresh_token"] = "refresh-1"
	issuer.credentialResponse = map[string]any{"transaction_id": "tx-1", "interval": 5}

	result, err := w.ProcessCredentialOffer(issuer.preAuthorizedOffer("first"))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if !result.Pending {
		t.Fatal("expected a deferred issuance")
	}
	pending := w.DeferredIssuanceList()[0]
	attempt, _ := NewServer(w, 0, nil).CollectDeferredNow(pending.ID)
	if !attempt.Collected {
		t.Fatalf("collection: %+v", attempt)
	}
	stored, _ := w.GetCredential(attempt.Credential.ID)
	if !stored.CanRenew() || stored.Renewal.CredentialEndpoint != issuer.url+"/credential" || stored.Renewal.ConfigurationID != "first" {
		t.Fatalf("renewal = %+v, want the issuance's renewal context", stored.Renewal)
	}
}

// Collecting a deferred credential requests a credential, so the issuer
// checks of the offer apply. Strict mode with --arf gives up on an issuer
// without a registration before it asks for the credential.
func TestStrictARFDeferredCollectionChecksTheIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	w.ValidationMode = ValidationModeStrict
	issuer := newStepIssuer(t, generateTestCredential(t, w))
	pending := pendingFor(t, w, issuer.url+"/deferred", 1)
	w.AddDeferredIssuance(pending)

	attempt := NewServer(w, 0, nil).attemptDeferredCollection(*pending)
	if !attempt.Abandoned || !strings.Contains(attempt.Reason, "ARF RPRC_22a") {
		t.Fatalf("attempt = %+v, want it abandoned over the ARF findings", attempt)
	}
	if issuer.deferredRequests != 0 {
		t.Errorf("the wallet sent %d deferred requests to an issuer that failed the checks", issuer.deferredRequests)
	}
}
