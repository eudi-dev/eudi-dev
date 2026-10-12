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
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// httpsWalletCallback is an https redirect URI. auth_via_web requires one
// (OpenID4VCI 1.1 §6.2.1.2).
const httpsWalletCallback = "https://wallet.example/callback"

// useHTTPSCallback gives the wallet an https origin, so it offers auth_via_web.
// The test serves the wallet over http and delivers the callback there.
func useHTTPSCallback(w *wallet.Wallet) {
	w.BaseURL = "https://wallet.example"
	w.VCIRedirectURI = httpsWalletCallback
}

func interactiveTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()

	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	w.VCIVersion = wallet.VCIVersion11
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	return w
}

// Exercise OpenID4VCI 1.1 §6 with a PID presentation. The issuer must verify it before
// returning an authorization code, without browser sign-in.
func TestInteractiveAuthorizationEndToEnd(t *testing.T) {
	w := interactiveTestWallet(t)
	d, ts := serveDemoStack(t, w)

	offer := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationPresentation, `{}`)
	uri, _ := offer["scheme_uri"].(string)
	if uri == "" {
		t.Fatalf("unexpected offer response: %v", offer)
	}

	before := len(w.GetCredentials())
	result, err := w.ProcessCredentialOffer(uri)
	if err != nil {
		t.Fatalf("redeeming the offer through interactive authorization: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if got := len(w.GetCredentials()); got != before+1 {
		t.Errorf("credential count = %d, want %d", got, before+1)
	}

	issued, ok := w.GetCredential(result.CredentialID)
	if !ok {
		t.Fatalf("credential %s is not in the wallet", result.CredentialID)
	}
	if got, _ := issued.Claims["family_name"].(string); got != "'t Hart" {
		t.Errorf("issued credential family_name = %q, want the presented holder", got)
	}

	if got := d.challengeEndpoint(); !strings.HasSuffix(got, "/issuer/authorize-challenge") {
		t.Errorf("challenge endpoint = %q", got)
	}
	for _, entry := range w.GetLog() {
		details := entry.Details
		if details == nil {
			continue
		}
		if details["event"] == "interactive_authorization_presentation" {
			return
		}
	}
	t.Errorf("no log entry recorded the presentation, log: %v", w.GetLog())
}

// A template offer issues its template through presentation during issuance,
// as it does with a pre-authorized code.
func TestInteractiveAuthorizationIssuesTheOfferedTemplate(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)

	for _, tc := range []struct{ id, typ string }{
		{"italian-pid-mdoc", "eu.europa.ec.eudi.pid.1"},
		{"german-pid-sdjwt", "urn:eudi:pid:de:1"},
	} {
		offer := postJSONTo(t, ts.URL+"/issuer/api/offers?credential="+tc.id+"&grant="+authCodeGrant+"&authorization="+authorizationPresentation, `{}`)
		uri, _ := offer["scheme_uri"].(string)
		result, err := w.ProcessCredentialOffer(uri)
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		issued, _ := w.GetCredential(result.CredentialID)
		if issued.VCT != tc.typ && issued.DocType != tc.typ {
			t.Errorf("%s: issued %s %s, want %s", tc.id, issued.VCT, issued.DocType, tc.typ)
		}
	}
}

// The issuer picks the interaction per offer. For an offer that wants browser
// sign-in it asks a wallet that advertises auth_via_web for that interaction
// (OpenID4VCI 1.1 §6.2.1.2). The wallet then publishes the sign-in URL.
func TestOfferCanAskForTheBrowserSignInInstead(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)
	useHTTPSCallback(w)

	offer := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationBrowser, `{}`)
	uri, _ := offer["scheme_uri"].(string)
	if uri == "" {
		t.Fatalf("unexpected offer response: %v", offer)
	}

	authCh, unsubscribe := w.Consents().SubscribeAuthorization(func(consent.AuthorizationPrompt) bool { return true })
	defer unsubscribe()
	done := make(chan error, 1)
	go func() {
		_, err := w.ProcessCredentialOffer(uri)
		done <- err
	}()

	select {
	case prompt := <-authCh:
		if !strings.Contains(prompt.URL, "/issuer/authorize") {
			t.Errorf("sign-in URL = %q, want the issuer's authorization endpoint", prompt.URL)
		}
		if !strings.Contains(prompt.URL, "request_uri=") {
			t.Errorf("sign-in URL = %q, want the pushed request the challenge endpoint handed back", prompt.URL)
		}
	case err := <-done:
		t.Fatalf("the flow ended without asking for a sign-in: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the sign-in URL")
	}

	for _, entry := range w.GetLog() {
		if entry.Details != nil && entry.Details["event"] == "interactive_authorization_auth_via_web" {
			return
		}
	}
	t.Errorf("no log entry recorded the browser interaction, log: %v", w.GetLog())
}

// A wallet that offers only the presentation interaction still reaches the
// browser sign-in. The issuer falls back to redirect_to_web (Section
// 5.2.2.1.1 of the first-party-apps specification). That needs no interaction
// support from the wallet.
func TestBrowserOfferFallsBackToRedirectToWeb(t *testing.T) {
	d, _, _ := newDemoRP(t)
	issuerState := createOfferState(t, d, authorizationBrowser)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		"DPoP":                         dpopProof(t, clientKey, "POST", demoIssuerID+challengePath),
	}, url.Values{
		"issuer_state":                {issuerState},
		"interaction_types_supported": {interactionTypePresentation},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"redirect_to_web"`) {
		t.Errorf("body = %s, want redirect_to_web", rec.Body.String())
	}
}

// A browser offer redeemed by a wallet that advertises auth_via_web gets the
// Interaction Required Response of §6.2.1.2. It holds insufficient_authorization
// with the interaction type and a request_uri for the authorization endpoint.
func TestBrowserOfferAsksForTheAuthViaWebInteraction(t *testing.T) {
	d, _, _ := newDemoRP(t)
	issuerState := createOfferState(t, d, authorizationBrowser)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		"DPoP":                         dpopProof(t, clientKey, "POST", demoIssuerID+challengePath),
	}, url.Values{
		"issuer_state":                {issuerState},
		"interaction_types_supported": {interactionTypePresentation + "," + interactionTypeAuthViaWeb},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("parsing response %q: %v", rec.Body.String(), err)
	}
	if got := response["error"]; got != "insufficient_authorization" {
		t.Errorf("error = %v, want insufficient_authorization", got)
	}
	if got := response["interaction_type_required"]; got != interactionTypeAuthViaWeb {
		t.Errorf("interaction_type_required = %v, want %s", got, interactionTypeAuthViaWeb)
	}
	// §6.2.1.2: "the Authorization Server MUST omit auth_session parameter
	// in the response".
	if session, ok := response["auth_session"]; ok {
		t.Errorf("auth_session = %v, want none", session)
	}
	requestURI, _ := response["request_uri"].(string)
	if !strings.HasPrefix(requestURI, requestURIPrefix) {
		t.Errorf("request_uri = %q, want a pushed authorization request URI", requestURI)
	}
	if _, ok := response["expires_in"].(float64); !ok {
		t.Errorf("expires_in = %v, want a number", response["expires_in"])
	}
}

// RFC 6749 §3.1 sends the request parameters as a form. A body that does not
// parse is an invalid_request.
func TestAnAuthorizationChallengeWithABrokenFormIsRefused(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, challengePath, strings.NewReader("response_type=code&client_id=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof(t, key, "POST", demoIssuerID+challengePath))
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not a form") {
		t.Errorf("status %d %s, want invalid_request for the form", rec.Code, rec.Body.String())
	}
}

// Feature level 1.0 uses the redirect flow for the same offer.
func TestInteractiveAuthorizationIsNotOfferedAtFeatureLevel10(t *testing.T) {
	w := interactiveTestWallet(t)
	w.VCIVersion = wallet.VCIVersion10
	d, _ := serveDemoStack(t, w)

	metadata := d.authorizationServerMetadata()
	if _, published := metadata["authorization_challenge_endpoint"]; published {
		t.Error("the demo issuer published a challenge endpoint to a 1.0 wallet")
	}
	// require_interactive_authorization is never published because this server
	// also accepts the redirect flow.
	if _, published := metadata["require_interactive_authorization"]; published {
		t.Error("the demo issuer claims to require interactive authorization")
	}
}

// §6.2.2: a wallet that redeems a presentation offer without offering the
// presentation interaction is told which interaction type is missing.
func TestAuthorizationChallengeReportsAMissingInteractionType(t *testing.T) {
	d, _, _ := newDemoRP(t)
	issuerState := createOfferState(t, d, authorizationPresentation)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		"DPoP":                         dpopProof(t, clientKey, "POST", demoIssuerID+challengePath),
	}, url.Values{
		"issuer_state":                {issuerState},
		"interaction_types_supported": {interactionTypeAuthViaWeb},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing_interaction_type") {
		t.Errorf("body = %s, want missing_interaction_type", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), interactionTypePresentation) {
		t.Errorf("body = %s, want it to name the missing presentation type", rec.Body.String())
	}
}

func createOfferState(t *testing.T, d *DemoRP, authorization string) string {
	t.Helper()
	status, created := doJSON(t, d.IssuerHandler(), http.MethodPost, "/api/offers?grant="+authCodeGrant+"&authorization="+authorization, "{}", nil)
	if status != http.StatusCreated {
		t.Fatalf("creating the offer: status %d (%v)", status, created)
	}
	offerURI, _ := created["offer_uri"].(string)
	path := strings.TrimPrefix(offerURI, demoIssuerID)
	if path == offerURI || path == "" {
		t.Fatalf("unexpected offer_uri %q", offerURI)
	}
	status, offer := doJSON(t, d.IssuerHandler(), http.MethodGet, path, "", nil)
	if status != http.StatusOK {
		t.Fatalf("fetching the offer: status %d (%v)", status, offer)
	}
	grants, _ := offer["grants"].(map[string]any)
	authCode, _ := grants["authorization_code"].(map[string]any)
	issuerState, _ := authCode["issuer_state"].(string)
	if issuerState == "" {
		t.Fatalf("the offer carries no issuer_state: %v", offer)
	}
	return issuerState
}

// Without an issuer_state, the challenge uses browser sign-in. Reaching
// redirect_to_web proves client authentication succeeded.
func postAuthorizationChallenge(t *testing.T, d *DemoRP, headers map[string]string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	dpopKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating DPoP key: %v", err)
	}
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"http://wallet.example"},
		"redirect_uri":          {"http://wallet.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	for key, values := range extra {
		form[key] = values
	}
	req := httptest.NewRequest(http.MethodPost, challengePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof(t, dpopKey, "POST", demoIssuerID+challengePath))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	return rec
}

// The Authorization Challenge Endpoint authenticates clients like the PAR and
// token endpoints. §6.1 says the Wallet Attestation "has to be included in
// this request" where the server requires one. A wallet without
// OAuth-Client-Attestation headers is refused in required mode and served in
// optional mode.
func TestAuthorizationChallengeRequiresClientAttestation(t *testing.T) {
	t.Run("required by default", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := postAuthorizationChallenge(t, d, nil, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"invalid_client"`) {
			t.Errorf("body = %s, want an invalid_client error", rec.Body.String())
		}
	})

	t.Run("an attested request passes authentication", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		provider := foreignWalletProvider(t)
		clientKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating client key: %v", err)
		}
		rec := postAuthorizationChallenge(t, d, map[string]string{
			"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
			"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		}, nil)
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("an attested request was refused as unauthenticated: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "redirect_to_web") {
			t.Errorf("body = %s, want the redirect_to_web answer that follows authentication", rec.Body.String())
		}
	})

	t.Run("optional", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		d.SetClientAuthMode(ClientAuthOptional)
		rec := postAuthorizationChallenge(t, d, nil, nil)
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("optional mode refused an unauthenticated client: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "redirect_to_web") {
			t.Errorf("body = %s, want the redirect_to_web answer that follows authentication", rec.Body.String())
		}
	})
}

// Exercise auth_via_web under OpenID4VCI 1.1 §6.2.1.2. The ticket must identify the
// account authenticated through the returned browser URL.
func TestAuthViaWebFlowEndToEnd(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)
	useHTTPSCallback(w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationBrowser, `{}`)
	schemeURI, _ := created["scheme_uri"].(string)
	if schemeURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}

	accepted := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if accepted["status"] != "authorization_required" {
		t.Fatalf("redeeming the offer did not ask for a sign-in: %v", accepted)
	}
	authURL, _ := accepted["authorization_url"].(string)
	offerID, _ := accepted["offer_id"].(string)
	if !strings.Contains(authURL, "/issuer/authorize") || !strings.Contains(authURL, "request_uri=") {
		t.Fatalf("unexpected authorization URL %q", authURL)
	}

	sawInteraction := false
	for _, entry := range w.GetLog() {
		if entry.Details == nil {
			continue
		}
		if entry.Details["event"] == "interactive_authorization_auth_via_web" {
			sawInteraction = true
		}
		if entry.Details["event"] == "interactive_authorization_redirect_to_web" {
			t.Error("the flow fell back to redirect_to_web although the wallet offered auth_via_web")
		}
	}
	if !sawInteraction {
		t.Error("no log entry recorded the auth_via_web interaction")
	}

	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	page, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("opening the authorization URL: %v", err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") {
		t.Fatalf("the authorization endpoint did not ask for a login: %d %s", page.StatusCode, truncate(string(body)))
	}

	login, err := client.PostForm(ts.URL+"/issuer/authorize", url.Values{
		"request_uri": {requestURIFromLoginPage(t, string(body))},
		"username":    {"alice"},
		"password":    {"alice"},
	})
	if err != nil {
		t.Fatalf("signing in: %v", err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d, want a redirect back to the wallet", login.StatusCode)
	}
	callback := login.Header.Get("Location")
	if !strings.Contains(callback, "code=") {
		t.Fatalf("login redirect %q carries no authorization code", callback)
	}
	cb, err := client.Get(strings.Replace(callback, httpsWalletCallback, ts.URL+"/callback", 1))
	if err != nil {
		t.Fatalf("following the callback: %v", err)
	}
	cb.Body.Close()

	deadline := time.Now().Add(20 * time.Second)
	for {
		status := getJSONFrom(t, ts.URL+"/api/offers/"+offerID)
		state, _ := status["status"].(string)
		if state == "completed" {
			break
		}
		if state == "failed" {
			t.Fatalf("the auth_via_web flow failed: %v", status["error"])
		}
		if time.Now().After(deadline) {
			t.Fatalf("the issuance never completed after the login, last status %v", status)
		}
		time.Sleep(50 * time.Millisecond)
	}

	var ticket *wallet.StoredCredential
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			credential := c
			ticket = &credential
		}
	}
	if ticket == nil {
		t.Fatal("no demo ticket was stored in the wallet")
	}
	if got := ticket.Claims["given_name"]; got != demoAccountGivenName {
		t.Errorf("ticket given_name = %v, want %q from the logged-in account", got, demoAccountGivenName)
	}
}

func signPID(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey) string {
	t.Helper()
	_, chain, err := d.wallet.Signer().Default()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       PIDVCT,
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA", "family_name": "MUSTERMANN"},
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing PID: %v", err)
	}
	return raw
}

func startInteractiveSession(t *testing.T, d *DemoRP, provider walletProvider, clientKey *ecdsa.PrivateKey, issuerState string) (session, nonce string) {
	t.Helper()
	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		"DPoP":                         dpopProof(t, clientKey, "POST", demoIssuerID+challengePath),
	}, url.Values{
		"issuer_state":                {issuerState},
		"interaction_types_supported": {interactionTypePresentation},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("initial challenge request: status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("parsing challenge response: %v", err)
	}
	session, _ = response["auth_session"].(string)
	request, _ := response["openid4vp_request"].(map[string]any)
	// The presentation request is a signed request object, so the nonce lives
	// in the JWT payload. The unsigned fallback carries it at the top level.
	nonce, _ = request["nonce"].(string)
	if nonce == "" {
		if jar, ok := request["request"].(string); ok {
			nonce, _ = signedRequestClaims(t, jar)["nonce"].(string)
		}
	}
	if session == "" || nonce == "" {
		t.Fatalf("challenge response carries no session or nonce: %v", response)
	}
	return session, nonce
}

// The query's aki must match the issued credential's AuthorityKeyId so the wallet can
// select a credential trusted by this issuer.
func TestInteractiveRequestPinsTheIssuerCA(t *testing.T) {
	d, _, _ := newDemoRP(t)

	aki := d.trustAnchorAKI()
	if aki == "" {
		t.Fatal("the demo issuer has no trust anchor key identifier")
	}

	caCert := d.wallet.CertChain[len(d.wallet.CertChain)-1]
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating a holder key: %v", err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(d.wallet.CAKey, caCert, &holderKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatalf("generating a leaf: %v", err)
	}
	if got := format.EncodeBase64URL(leaf.AuthorityKeyId); got != aki {
		t.Errorf("a credential issued under this CA carries aki %q, but the request pins %q", got, aki)
	}

	request, err := d.interactivePresentationRequest(d.newInteractivePIDRequest())
	if err != nil {
		t.Fatal(err)
	}
	jar, ok := request["request"].(string)
	if !ok {
		t.Fatalf("expected a signed request object, got %v", request)
	}
	dcql, _ := signedRequestClaims(t, jar)["dcql_query"].(map[string]any)
	credentials, _ := dcql["credentials"].([]any)
	if len(credentials) != 2 {
		t.Fatalf("expected 2 credential entries, got %d", len(credentials))
	}
	for _, entry := range credentials {
		cred, _ := entry.(map[string]any)
		authorities, _ := cred["trusted_authorities"].([]any)
		if len(authorities) != 1 {
			t.Fatalf("credential %v carries no trusted_authorities", cred["id"])
		}
		authority, _ := authorities[0].(map[string]any)
		values, _ := authority["values"].([]any)
		if authority["type"] != "aki" || len(values) != 1 || values[0] != aki {
			t.Errorf("credential %v trusted_authorities = %v, want one aki %q", cred["id"], authority, aki)
		}
	}
}

func signedRequestClaims(t *testing.T, jar string) map[string]any {
	t.Helper()
	parts := strings.Split(jar, ".")
	if len(parts) != 3 {
		t.Fatalf("request object is not a JWT: %q", jar)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding request object payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing request object payload: %v", err)
	}
	return claims
}

// Failed presentation checks must return access_denied without a code. Run the valid
// case last to prove the helper can complete the flow.
func TestInteractiveAuthorizationVerifiesThePresentation(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	issuerState := createOfferState(t, d, authorizationPresentation)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	credential := signPID(t, d, holderKey)
	audience := "ia:" + d.challengeEndpoint()

	continueWith := func(t *testing.T, session, presentation string) *httptest.ResponseRecorder {
		t.Helper()
		vpToken, err := json.Marshal(map[string]any{"vp_token": map[string]any{"pid": []string{presentation}}})
		if err != nil {
			t.Fatalf("encoding openid4vp_response: %v", err)
		}
		return postAuthorizationChallenge(t, d, map[string]string{
			"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
			"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			"DPoP":                         dpopProof(t, clientKey, "POST", demoIssuerID+challengePath),
		}, url.Values{
			"auth_session":       {session},
			"openid4vp_response": {string(vpToken)},
		})
	}

	refused := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "access_denied") {
			t.Errorf("body = %s, want access_denied", rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "authorization_code") {
			t.Errorf("a refused presentation was answered with a code: %s", rec.Body.String())
		}
	}

	t.Run("a wrong nonce is refused", func(t *testing.T) {
		session, _ := startInteractiveSession(t, d, provider, clientKey, issuerState)
		refused(t, continueWith(t, session, presentCredential(t, holderKey, credential, audience, "wrong-nonce")))
	})

	t.Run("an audience naming somebody else is refused", func(t *testing.T) {
		session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
		refused(t, continueWith(t, session, presentCredential(t, holderKey, credential, "https://verifier.example", nonce)))
	})

	t.Run("a key binding signed by another key is refused", func(t *testing.T) {
		otherKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
		refused(t, continueWith(t, session, presentCredential(t, otherKey, credential, audience, nonce)))
	})

	t.Run("a presentation passing every check gets the code", func(t *testing.T) {
		session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
		rec := continueWith(t, session, presentCredential(t, holderKey, credential, audience, nonce))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "authorization_code") {
			t.Errorf("body = %s, want an authorization code", rec.Body.String())
		}
		// RFC 6749 §5.1 keeps a response with a code out of caches.
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
	})
}

// Browser sign-in stores its pushed requests in the same state map as the PAR
// endpoint. A full map evicts the request that expires first, so a flood of
// requests doesn't lock out other wallets.
func TestAFullStateMapMakesRoomForTheNextWallet(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	d.mu.Lock()
	for i := 0; i < maxEntries; i++ {
		uri := fmt.Sprintf("%sfill-%d", requestURIPrefix, i)
		d.authRequests[uri] = &authRequestState{requestURI: uri, expires: time.Now().Add(authRequestTTL + time.Duration(i)*time.Second)}
	}
	d.mu.Unlock()

	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	}, nil)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("status = 429, want the next wallet served (%s)", rec.Body.String())
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, kept := d.authRequests[requestURIPrefix+"fill-0"]; kept || len(d.authRequests) != maxEntries {
		t.Errorf("entries = %d, first one kept %t, want %d with the first one evicted", len(d.authRequests), kept, maxEntries)
	}
}

// A presentation session yields one authorization code. first-party-apps
// §5.2.2.1 answers a used auth_session with invalid_session, and §9.5.1 has
// the server "reject subsequent Authorization Challenge Requests [...] unless
// a DPoP proof for the same key presented in the original Authorization
// Challenge Request is provided".
func TestAnInteractiveSessionIsBoundAndSingleUse(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	issuerState := createOfferState(t, d, authorizationPresentation)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	credential := signPID(t, d, holderKey)
	session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
	vpToken, err := json.Marshal(map[string]any{"vp_token": map[string]any{"pid": []string{
		presentCredential(t, holderKey, credential, "ia:"+d.challengeEndpoint(), nonce),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	continueWith := func(dpopKey *ecdsa.PrivateKey) *httptest.ResponseRecorder {
		return postAuthorizationChallenge(t, d, map[string]string{
			"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
			"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			"DPoP":                         dpopProof(t, dpopKey, "POST", demoIssuerID+challengePath),
		}, url.Values{"auth_session": {session}, "openid4vp_response": {string(vpToken)}})
	}

	if rec := continueWith(otherKey); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_dpop_proof") {
		t.Errorf("a continuation with another DPoP key: %d %s, want 400 invalid_dpop_proof", rec.Code, rec.Body.String())
	}
	// Concurrent continuations race for the session, and only one wins.
	results := make(chan *httptest.ResponseRecorder, 4)
	var wg sync.WaitGroup
	for range cap(results) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- continueWith(clientKey)
		}()
	}
	wg.Wait()
	close(results)
	codes := 0
	for rec := range results {
		switch {
		case rec.Code == http.StatusOK:
			codes++
		case rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_session"):
			t.Errorf("a losing continuation: %d %s, want 400 invalid_session", rec.Code, rec.Body.String())
		}
	}
	if codes != 1 {
		t.Errorf("%d continuations got an authorization code, want 1", codes)
	}
}
