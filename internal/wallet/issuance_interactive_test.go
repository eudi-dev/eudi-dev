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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// interactiveIssuer is a test authorization server and credential issuer that
// asks for a presentation before it issues (OpenID4VCI 1.1 §6).
type interactiveIssuer struct {
	t *testing.T

	url        string
	credential string

	interaction      string
	openid4vpRequest map[string]any

	// satisfiedImmediately answers the first request with a code.
	// interactionsToAsk is the number of interactions before the code (one by
	// default). challengeError is returned in place of a challenge.
	satisfiedImmediately bool
	interactionsToAsk    int
	challengeError       map[string]any

	// authorizeRedirect is the query of the redirect back to the wallet for the
	// auth_via_web interaction, for example "code=x". The server appends the
	// initial state and its iss.
	authorizeRedirect string

	initialForm      url.Values
	intermediateForm url.Values
	tokenForm        url.Values
	authorizeQuery   url.Values
	challengeRounds  int
	sessionsSeen     []string
}

const interactiveTestNonce = "ia-nonce-1"

func (s *interactiveIssuer) dcqlQuery() map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
		},
	}
}

func (s *interactiveIssuer) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			writeTestJSON(rw, map[string]any{
				"credential_issuer":     s.url,
				"authorization_servers": []string{s.url},
				"credential_endpoint":   s.url + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "scope": "test-scope"},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			metadata := map[string]any{
				"issuer":                            s.url,
				"token_endpoint":                    s.url + "/token",
				"authorization_challenge_endpoint":  s.url + "/authorize-challenge",
				"require_interactive_authorization": true,
			}
			// Several tests depend on the authorization endpoint being absent
			// unless the browser interaction is scripted.
			if s.authorizeRedirect != "" {
				metadata["authorization_endpoint"] = s.url + "/authorize"
			}
			writeTestJSON(rw, metadata)
		case r.Method == http.MethodPost && r.URL.Path == "/authorize-challenge":
			s.handleChallenge(rw, r)
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			s.authorizeQuery = r.URL.Query()
			redirect := s.initialForm.Get("redirect_uri") + "?" + s.authorizeRedirect +
				"&state=" + url.QueryEscape(s.initialForm.Get("state")) +
				"&iss=" + url.QueryEscape(s.url)
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			s.tokenForm, _ = url.ParseQuery(string(body))
			writeTestJSON(rw, map[string]any{
				"access_token": "interactive-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			writeTestJSON(rw, map[string]any{"credentials": []any{map[string]any{"credential": s.credential}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}
}

func (s *interactiveIssuer) handleChallenge(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	s.challengeRounds++
	s.sessionsSeen = append(s.sessionsSeen, form.Get("auth_session"))
	if s.challengeRounds == 1 {
		s.initialForm = form
	} else {
		s.intermediateForm = form
	}

	if s.challengeError != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(rw).Encode(s.challengeError)
		return
	}

	asked := s.interactionsToAsk
	if asked == 0 && !s.satisfiedImmediately {
		asked = 1
	}
	if s.challengeRounds > asked {
		writeTestJSON(rw, map[string]any{"authorization_code": "interactive-code"})
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusForbidden)
	response := map[string]any{
		"error":                     errorInsufficientAuthorization,
		"interaction_type_required": s.interaction,
	}
	if s.openid4vpRequest != nil {
		response["openid4vp_request"] = s.openid4vpRequest
	}
	switch s.interaction {
	case interactionTypeAuthViaWeb:
		// §6.2.1.2: "the Authorization Server MUST omit auth_session
		// parameter in the response."
		response["request_uri"] = "urn:ietf:params:oauth:request_uri:test-1"
		response["expires_in"] = 60
	default:
		// §6.2.1: "The value returned MUST be distinct for each authorization
		// challenge response."
		response["auth_session"] = fmt.Sprintf("session-%d", s.challengeRounds)
	}
	_ = json.NewEncoder(rw).Encode(response)
}

func writeTestJSON(rw http.ResponseWriter, body map[string]any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(body)
}

func newInteractiveIssuer(t *testing.T, w *Wallet) *interactiveIssuer {
	t.Helper()

	issuer := &interactiveIssuer{t: t, interaction: interactionTypePresentation}
	issuer.credential = generateTestCredential(t, w)
	issuer.openid4vpRequest = map[string]any{
		"response_type": "vp_token",
		"response_mode": "ia_post",
		"nonce":         interactiveTestNonce,
		"dcql_query":    issuer.dcqlQuery(),
	}

	server := httptest.NewServer(issuer.handler())
	t.Cleanup(server.Close)
	issuer.url = server.URL

	return issuer
}

func interactiveOfferURI(issuerURL string) string {
	offer := map[string]any{
		"credential_issuer":            issuerURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{"issuer_state": "issuer-state-1"},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

func newInteractiveWallet(t *testing.T) *Wallet {
	t.Helper()
	w := generateTestWalletWithPID(t)
	w.AutoAccept = true
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "wallet-client"
	return w
}

// The full interactive exchange runs from the presentation challenge through
// the presentation and the authorization code to issuance.
func TestInteractiveAuthorizationIssuesAfterAPresentation(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if issuer.challengeRounds != 2 {
		t.Errorf("challenge rounds = %d, want 2", issuer.challengeRounds)
	}

	// §6.1.1: the initial request lists the interaction types and carries the
	// usual authorization request parameters.
	if got := issuer.initialForm.Get("interaction_types_supported"); got != interactionTypePresentation {
		t.Errorf("interaction_types_supported = %q, want %q", got, interactionTypePresentation)
	}
	if got := issuer.initialForm.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	if got := issuer.initialForm.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if got := issuer.initialForm.Get("scope"); got != "test-scope" {
		t.Errorf("scope = %q, want test-scope", got)
	}
	if got := issuer.initialForm.Get("redirect_uri"); got != "" {
		t.Errorf("redirect_uri = %q, want it absent", got)
	}

	// §6.1.2: the intermediate request carries the session and the response.
	if got := issuer.intermediateForm.Get("auth_session"); got != "session-1" {
		t.Errorf("auth_session = %q, want session-1", got)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	vpToken, ok := response["vp_token"].(map[string]any)
	if !ok {
		t.Fatalf("openid4vp_response has no vp_token object: %v", response)
	}
	presentations, ok := vpToken["pid"].([]any)
	if !ok || len(presentations) == 0 {
		t.Fatalf("vp_token has no presentation for the query: %v", vpToken)
	}

	// Appendix A.3.5: the Key Binding JWT is bound to the challenge endpoint.
	kb := keyBindingClaims(t, presentations[0].(string))
	wantAudience := "ia:" + issuer.url + "/authorize-challenge"
	if got, _ := kb["aud"].(string); got != wantAudience {
		t.Errorf("key binding aud = %q, want %q", got, wantAudience)
	}
	if got, _ := kb["nonce"].(string); got != interactiveTestNonce {
		t.Errorf("key binding nonce = %q, want %q", got, interactiveTestNonce)
	}

	// Section 6 of the first-party-apps specification: the authorization
	// request had no redirect_uri, so the token request has none.
	if got := issuer.tokenForm.Get("code"); got != "interactive-code" {
		t.Errorf("token request code = %q, want interactive-code", got)
	}
	if got := issuer.tokenForm.Get("redirect_uri"); got != "" {
		t.Errorf("token request redirect_uri = %q, want it absent", got)
	}
	if issuer.tokenForm.Get("code_verifier") == "" {
		t.Error("token request carried no code_verifier")
	}
}

// A server that is satisfied at once answers the initial request with a code
// (Section 5.2.1 of the first-party-apps specification). Nothing is presented.
func TestInteractiveAuthorizationTakesACodeWithoutAnInteraction(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.satisfiedImmediately = true

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if issuer.challengeRounds != 1 {
		t.Errorf("challenge rounds = %d, want 1", issuer.challengeRounds)
	}
}

// The exchange runs for as many interactions as the server asks for. §5.3.1 of
// the first-party-apps specification says clients "MUST NOT assume that
// auth_session values are static", so each request carries the value from the
// previous response.
func TestInteractiveAuthorizationFollowsSeveralRoundsAndARotatingSession(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interactionsToAsk = 3

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if issuer.challengeRounds != 4 {
		t.Errorf("challenge rounds = %d, want 4 (three interactions and the code)", issuer.challengeRounds)
	}
	want := []string{"", "session-1", "session-2", "session-3"}
	if len(issuer.sessionsSeen) != len(want) {
		t.Fatalf("auth_session values seen = %v, want %v", issuer.sessionsSeen, want)
	}
	for i, session := range want {
		if issuer.sessionsSeen[i] != session {
			t.Errorf("request %d carried auth_session %q, want %q", i+1, issuer.sessionsSeen[i], session)
		}
	}
}

// The wallet stops at the interaction limit.
func TestInteractiveAuthorizationStopsAfterTooManyRounds(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interactionsToAsk = maxInteractiveAuthorizationRounds + 5

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected the wallet to give up")
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("error = %v, want it to say the exchange did not finish", err)
	}
	if issuer.challengeRounds != maxInteractiveAuthorizationRounds {
		t.Errorf("challenge rounds = %d, want %d", issuer.challengeRounds, maxInteractiveAuthorizationRounds)
	}
}

// §6.2.2 defines missing_interaction_type for a wallet that offered no usable
// type. Any Authorization Challenge Error Response ends the flow with the
// server's description.
func TestInteractiveAuthorizationReportsAChallengeError(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.challengeError = map[string]any{
		"error":             "missing_interaction_type",
		"error_description": "interaction_types_supported is missing 'urn:openid:dcp:ia:auth_via_web'",
	}

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected the challenge error to end the flow")
	}
	if !strings.Contains(err.Error(), "missing_interaction_type") {
		t.Errorf("error = %v, want it to carry the server's error code", err)
	}
	if !strings.Contains(err.Error(), "auth_via_web") {
		t.Errorf("error = %v, want it to carry the server's description", err)
	}
}

// At feature level 1.0 the wallet uses the redirect flow and fails when the
// server has no authorization endpoint.
func TestInteractiveAuthorizationIsNotUsedAtFeatureLevel10(t *testing.T) {
	w := newInteractiveWallet(t)
	w.VCIVersion = VCIVersion10
	w.VCIRedirectURI = "https://wallet.example/callback"
	issuer := newInteractiveIssuer(t, w)

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err == nil {
		t.Fatal("expected the redirect flow to fail against a server that only offers the challenge endpoint")
	}
	if issuer.challengeRounds != 0 {
		t.Errorf("wallet called the challenge endpoint %d times at feature level 1.0", issuer.challengeRounds)
	}
	if !hasInteractiveAuthorizationNote(w, "--vci-version 1.1") {
		t.Errorf("no log entry named the declined offer, log: %v", w.Log)
	}
}

// HAIP 1.0 profiles the channels for a Verifier's Authorization Request. It
// does not cover a presentation inside an OpenID4VCI 1.1 §6 exchange,
// so a HAIP wallet in strict mode applies no HAIP channel rules to it.
func TestInteractiveAuthorizationIsNotHeldToHAIPChannelRules(t *testing.T) {
	w := newInteractiveWallet(t)
	w.RequireHAIP = true
	w.ValidationMode = ValidationModeStrict
	issuer := newInteractiveIssuer(t, w)
	// HAIP 1.0 §6.1.1 asks for the issuer's chain in x5c.
	issuer.credential = generateTestWalletWithPID(t).GetCredentials()[0].Raw

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("a HAIP wallet in strict mode could not use interactive authorization: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "HAIP:") {
			t.Errorf("HAIP finding reported against an interactive authorization presentation: %s", entry.Detail)
		}
	}
}

// §6.2.1: "If a Wallet receives an interaction_type_required value that it
// does not support, it MUST abort the issuance process."
func TestInteractiveAuthorizationAbortsOnAnUnsupportedInteraction(t *testing.T) {
	tests := []struct {
		name        string
		interaction string
		wantIn      string
	}{
		{name: "web", interaction: interactionTypeAuthViaWeb, wantIn: interactionTypeAuthViaWeb},
		{name: "unknown", interaction: "urn:example:ia:smartcard", wantIn: "unsupported interaction type"},
		{name: "missing", interaction: "", wantIn: "without an interaction type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newInteractiveWallet(t)
			issuer := newInteractiveIssuer(t, w)
			issuer.interaction = tc.interaction
			issuer.openid4vpRequest = nil

			_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
			if err == nil {
				t.Fatal("expected the issuance to abort")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
			if issuer.challengeRounds != 1 {
				t.Errorf("challenge rounds = %d, want the wallet to stop after the first", issuer.challengeRounds)
			}
		})
	}
}

// §6.2.1.1 allows ia_post and ia_post.jwt and nothing else, because the
// response goes back to the challenge endpoint.
func TestInteractiveAuthorizationRefusesAnotherResponseMode(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["response_mode"] = "direct_post"
	issuer.openid4vpRequest["response_uri"] = issuer.url + "/response"

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected a request with response_mode direct_post to be refused")
	}
	if !strings.Contains(err.Error(), "response_mode") {
		t.Errorf("error = %v, want it to name the response_mode", err)
	}
}

// The presentation interaction of §6.2.1.1 answers with a presentation. A
// request for an id_token alone is refused.
func TestInteractiveAuthorizationRefusesARequestWithoutAVPToken(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["response_type"] = "id_token"

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil || !strings.Contains(err.Error(), "vp_token") {
		t.Fatalf("error = %v, want the request without a vp_token refused", err)
	}
}

// §6.2.1.1: "If expected_origins is present, it MUST contain only the derived
// Origin of the Authorization Challenge Endpoint." §6.2.1.5 makes this the
// wallet's defence against one authorization server forwarding another's
// request.
func TestInteractiveAuthorizationChecksExpectedOrigins(t *testing.T) {
	for name, origins := range map[string]func(own string) []any{
		"a foreign origin":               func(string) []any { return []any{"https://elsewhere.example"} },
		"another origin besides its own": func(own string) []any { return []any{own, "https://elsewhere.example"} },
		"its own origin with a space":    func(own string) []any { return []any{" " + own} },
		"an empty list":                  func(string) []any { return []any{} },
	} {
		t.Run("strict mode refuses "+name, func(t *testing.T) {
			w := newInteractiveWallet(t)
			w.ValidationMode = ValidationModeStrict
			issuer := newInteractiveIssuer(t, w)
			issuer.openid4vpRequest["expected_origins"] = origins(derivedOrigin(issuer.url))

			_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
			if err == nil {
				t.Fatal("expected the request to be refused")
			}
			if !strings.Contains(err.Error(), "expected_origins") {
				t.Errorf("error = %v, want it to name expected_origins", err)
			}
		})
	}

	t.Run("debug mode warns about a foreign origin and continues", func(t *testing.T) {
		w := newInteractiveWallet(t)
		issuer := newInteractiveIssuer(t, w)
		issuer.openid4vpRequest["expected_origins"] = []any{"https://elsewhere.example"}

		result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
		if err != nil {
			t.Fatalf("ProcessCredentialOffer() error = %v", err)
		}
		if result.CredentialID == "" {
			t.Fatal("expected an imported credential")
		}
		if !hasWarningContaining(w, "expected_origins") {
			t.Error("expected a warning that names expected_origins")
		}
	})

	t.Run("the endpoint's own origin is accepted", func(t *testing.T) {
		w := newInteractiveWallet(t)
		issuer := newInteractiveIssuer(t, w)
		issuer.openid4vpRequest["expected_origins"] = []any{derivedOrigin(issuer.url)}

		if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
			t.Fatalf("ProcessCredentialOffer() error = %v", err)
		}
	})
}

// A wallet that holds nothing matching answers the interaction with an
// OpenID4VP error (§6.2.1.1).
func TestInteractiveAuthorizationReportsThatItHoldsNothingMatching(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["dcql_query"] = map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:example:nothing-here"}},
			},
		},
	}

	// The stub answers the intermediate request with a code in any case, so the
	// test checks what the wallet sent.
	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	if got, _ := response["error"].(string); got != "access_denied" {
		t.Errorf("openid4vp_response error = %q, want access_denied", got)
	}
	if _, ok := response["vp_token"]; ok {
		t.Error("openid4vp_response carried a vp_token as well as an error")
	}
}

// §6.2.1.1: with ia_post.jwt the response is encrypted. The draft's example
// sends it as {"response": ...} inside openid4vp_response.
func TestInteractiveAuthorizationEncryptsWithIAPostJWT(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["response_mode"] = "ia_post.jwt"
	issuer.openid4vpRequest["client_metadata"] = map[string]any{
		"jwks": map[string]any{
			"keys": []any{encryptionJWKForTest(t)},
		},
	}

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	jwe, _ := response["response"].(string)
	if jwe == "" {
		t.Fatalf("openid4vp_response carried no encrypted response: %v", response)
	}
	if len(strings.Split(jwe, ".")) != 5 {
		t.Errorf("response is not a compact JWE: %q", format.Truncate(jwe, 60))
	}
	if _, ok := response["vp_token"]; ok {
		t.Error("openid4vp_response carried the vp_token in the clear as well")
	}
}

func encryptionJWKForTest(t *testing.T) map[string]any {
	t.Helper()

	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating an encryption key: %v", err)
	}
	encX, encY, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatalf("encoding the encryption key: %v", err)
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"use": "enc",
		"alg": "ECDH-ES",
		"kid": "issuer-encryption-key",
		"x":   format.EncodeBase64URL(encX),
		"y":   format.EncodeBase64URL(encY),
	}
}

func keyBindingClaims(t *testing.T, presentation string) map[string]any {
	t.Helper()

	parts := strings.Split(presentation, "~")
	kbJWT := parts[len(parts)-1]
	segments := strings.Split(kbJWT, ".")
	if len(segments) != 3 {
		t.Fatalf("presentation has no key binding JWT: %q", format.Truncate(presentation, 80))
	}
	payload, err := format.DecodeBase64URL(segments[1])
	if err != nil {
		t.Fatalf("decoding key binding payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing key binding payload: %v", err)
	}
	return claims
}

// The browser interaction of §6.2.1.2. The server answers the challenge with
// auth_via_web and a request_uri. The wallet builds an authorization request
// from it (RFC 9126 §4), and the redirect back carries the code. The token
// request repeats the redirect URI because the authorization request carried
// one (RFC 6749 §4.1.3).
func TestInteractiveAuthorizationAuthViaWeb(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interaction = interactionTypeAuthViaWeb
	issuer.openid4vpRequest = nil
	issuer.authorizeRedirect = "code=web-code"
	w.VCIRedirectURI = "https://wallet.example/callback"

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}

	// §6.1.1: a wallet that can complete the browser interaction advertises it.
	offered := issuer.initialForm.Get("interaction_types_supported")
	if !strings.Contains(offered, interactionTypeAuthViaWeb) || !strings.Contains(offered, interactionTypePresentation) {
		t.Errorf("interaction_types_supported = %q, want both interaction types", offered)
	}

	// §6.2.1.2: "The Wallet MUST use the request_uri value to build an
	// Authorization Request as defined in Section 4 of RFC9126."
	if got := issuer.authorizeQuery.Get("request_uri"); got != "urn:ietf:params:oauth:request_uri:test-1" {
		t.Errorf("authorization request request_uri = %q, want the one the challenge handed over", got)
	}
	if got := issuer.authorizeQuery.Get("client_id"); got != "wallet-client" {
		t.Errorf("authorization request client_id = %q, want wallet-client", got)
	}

	if issuer.challengeRounds != 1 {
		t.Errorf("challenge rounds = %d, want 1", issuer.challengeRounds)
	}
	if got := issuer.tokenForm.Get("code"); got != "web-code" {
		t.Errorf("token request code = %q, want the code from the redirect", got)
	}
	if got := issuer.tokenForm.Get("redirect_uri"); got != w.VCIRedirectURI {
		t.Errorf("token request redirect_uri = %q, want %q", got, w.VCIRedirectURI)
	}
}

// §6.2.1.2: the redirect back may carry an auth_session in place of a code when
// further steps remain at the challenge endpoint. The wallet continues with
// that auth_session.
func TestInteractiveAuthorizationAuthViaWebContinuesWithAuthSession(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interaction = interactionTypeAuthViaWeb
	issuer.openid4vpRequest = nil
	issuer.authorizeRedirect = "auth_session=web-session"
	w.VCIRedirectURI = "https://wallet.example/callback"

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}

	if issuer.challengeRounds != 2 {
		t.Fatalf("challenge rounds = %d, want an intermediate request after the redirect", issuer.challengeRounds)
	}
	if got := issuer.intermediateForm.Get("auth_session"); got != "web-session" {
		t.Errorf("intermediate request auth_session = %q, want the one the redirect carried", got)
	}
	// §6.2.1.2: the server enforces the code_verifier in the intermediate
	// request that follows the auth_via_web interaction (RFC 7636 §4.6).
	digest := sha256.Sum256([]byte(issuer.intermediateForm.Get("code_verifier")))
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != issuer.initialForm.Get("code_challenge") {
		t.Errorf("intermediate request code_verifier does not match the code_challenge of the initial request")
	}
	// This code came from the challenge endpoint, so the token request omits
	// the redirect URI (first-party-apps §6).
	if got := issuer.tokenForm.Get("redirect_uri"); got != "" {
		t.Errorf("token request redirect_uri = %q, want none for a challenge endpoint code", got)
	}
}

// A wallet without a redirect URI cannot complete the browser interaction.
// It does not advertise auth_via_web, because §6.2.1 would then require it to
// abort. A server that asks for it anyway is refused.
func TestInteractiveAuthorizationAuthViaWebIsNotOfferedWithoutARedirectURI(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interaction = interactionTypeAuthViaWeb
	issuer.openid4vpRequest = nil
	issuer.authorizeRedirect = "code=web-code"

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected the unadvertised interaction to end the flow")
	}
	if !strings.Contains(err.Error(), "did not advertise") {
		t.Errorf("error = %v, want it to say the interaction was not advertised", err)
	}
	if got := issuer.initialForm.Get("interaction_types_supported"); got != interactionTypePresentation {
		t.Errorf("interaction_types_supported = %q, want the presentation type alone", got)
	}
}

// §6.2.1.2: "the redirect URI MUST be an https URL as per Section 7.2 of
// [RFC8252]". A wallet with an http redirect URI does not offer auth_via_web.
func TestInteractiveAuthorizationAuthViaWebNeedsAnHTTPSRedirectURI(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.authorizeRedirect = "code=web-code"
	w.VCIRedirectURI = "http://localhost:8085/callback"

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if got := issuer.initialForm.Get("interaction_types_supported"); got != interactionTypePresentation {
		t.Errorf("interaction_types_supported = %q, want the presentation type alone", got)
	}
}

// first-party-apps §5.2.2.1.1: redirect_to_web asks the client to finish the
// authorization in a browser. With a request_uri the wallet opens that pushed
// request. Without one it starts its own authorization request. Either way
// the code comes through the redirect, so the token request repeats the
// redirect URI (RFC 6749 §4.1.3).
func TestInteractiveAuthorizationRedirectToWeb(t *testing.T) {
	for _, tc := range []struct {
		name       string
		requestURI string
	}{
		{"with a request_uri", "urn:ietf:params:oauth:request_uri:web-1"},
		{"without a request_uri", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newInteractiveWallet(t)
			issuer := newInteractiveIssuer(t, w)
			issuer.challengeError = map[string]any{"error": errorRedirectToWeb}
			if tc.requestURI != "" {
				issuer.challengeError["request_uri"] = tc.requestURI
			}
			issuer.authorizeRedirect = "code=web-code"
			w.VCIRedirectURI = "https://wallet.example/callback"

			result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
			if err != nil {
				t.Fatalf("ProcessCredentialOffer() error = %v", err)
			}
			if result.CredentialID == "" {
				t.Fatal("expected an imported credential")
			}
			if got := issuer.authorizeQuery.Get("request_uri"); got != tc.requestURI {
				t.Errorf("authorization request request_uri = %q, want %q", got, tc.requestURI)
			}
			if tc.requestURI == "" && issuer.authorizeQuery.Get("redirect_uri") != w.VCIRedirectURI {
				t.Errorf("the wallet's own authorization request carries %v, want its redirect URI", issuer.authorizeQuery)
			}
			if got := issuer.tokenForm.Get("code"); got != "web-code" {
				t.Errorf("token request code = %q, want the code from the redirect", got)
			}
			if got := issuer.tokenForm.Get("redirect_uri"); got != w.VCIRedirectURI {
				t.Errorf("token request redirect_uri = %q, want %q", got, w.VCIRedirectURI)
			}
			assertWalletLogEvent(t, w.GetLog(), "interactive_authorization_redirect_to_web")
		})
	}
}

// The browser sign-in needs a callback, so redirect_to_web without
// --vci-redirect-uri ends the flow.
func TestInteractiveAuthorizationRedirectToWebNeedsARedirectURI(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.challengeError = map[string]any{"error": errorRedirectToWeb, "request_uri": "urn:ietf:params:oauth:request_uri:web-1"}
	issuer.authorizeRedirect = "code=web-code"

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil || !strings.Contains(err.Error(), "--vci-redirect-uri") {
		t.Fatalf("err = %v, want it to ask for --vci-redirect-uri", err)
	}
	if issuer.authorizeQuery != nil {
		t.Errorf("the wallet opened the authorization endpoint with %v", issuer.authorizeQuery)
	}
}

// RFC 6749 §4.1.2.1, applied by OpenID4VP 1.0 §8.5: the error response
// carries the state of the request.
func TestTheInteractiveErrorResponseKeepsTheState(t *testing.T) {
	w := generateTestWallet(t)
	form, err := w.interactionErrorResponse(&oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "ia_post", State: "s-1"}}, oid4vp.ErrorAccessDenied, "declined")
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(form.Get("openid4vp_response")), &response); err != nil {
		t.Fatal(err)
	}
	if response["state"] != "s-1" || response["error"] != oid4vp.ErrorAccessDenied {
		t.Errorf("response = %v, want access_denied with state s-1", response)
	}
}
