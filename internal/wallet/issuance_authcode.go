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
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

type dpopNonceState struct {
	authzServer string
	resource    string
}

func (w *Wallet) processAuthorizationCodeOffer(offer *oid4vc.CredentialOffer, session issuanceSession, oauthMeta map[string]any, opts OfferOptions) (*IssuanceResult, error) {
	if w == nil {
		return nil, fmt.Errorf("wallet is nil")
	}
	clientID := strings.TrimSpace(w.VCIClientID)
	redirectURI := strings.TrimSpace(w.VCIRedirectURI)
	if clientID == "" {
		return nil, fmt.Errorf("OID4VCI authorization_code flow requires a configured wallet client_id")
	}

	// Interactive authorization (OID4VCI 1.1 §6) needs no redirect URI.
	challengeEndpoint := interactiveAuthorizationEndpoint(oauthMeta)
	useInteractive := challengeEndpoint != "" && w.VCIFeatureVersion().UsesInteractiveAuthorization()
	if !useInteractive {
		w.noteDeclinedInteractiveAuthorization(oauthMeta, challengeEndpoint)
		if redirectURI == "" {
			return nil, fmt.Errorf("OID4VCI authorization_code flow requires configured wallet client_id and redirect_uri")
		}
	}

	// RFC 9126 §2 makes publishing the PAR endpoint a SHOULD. Without it the
	// request goes to the authorization endpoint.
	parEndpoint, _ := oauthMeta["pushed_authorization_request_endpoint"].(string)
	authorizationEndpoint, _ := oauthMeta["authorization_endpoint"].(string)
	if authorizationEndpoint == "" && !useInteractive {
		return nil, fmt.Errorf("authorization server metadata did not include authorization_endpoint")
	}

	clientAuthMethod := detectTokenEndpointAuthMethod(oauthMeta)
	switch clientAuthMethod {
	case "", unauthenticatedClientMethod, "private_key_jwt", "attest_jwt_client_auth", "attest_jwt_client_auth_dpop":
	case unregisteredPublicClientMethod:
		// RFC 8414 uses the IANA registry, which has "none" for an
		// unauthenticated client. "public" is not registered.
		if err := w.reportServerDeviation(fmt.Sprintf("authorization server advertises the unregistered token endpoint auth method %q. RFC 8414 takes these values from the OAuth Token Endpoint Authentication Methods registry, where an unauthenticated client is %q", unregisteredPublicClientMethod, unauthenticatedClientMethod)); err != nil {
			return nil, err
		}
	default:
		// Other methods need credentials this wallet does not have, such as a
		// client secret.
		return nil, fmt.Errorf("unsupported token endpoint auth method %q", clientAuthMethod)
	}
	dpopKey := w.dpopKeyForRenewal(session.renewal)

	configID := session.renewal.ConfigurationID
	credentialRequest, err := w.authorizationCredentialRequest(session.metadata, configID)
	if err != nil {
		return nil, err
	}

	state := randomBase64URL(18)
	codeVerifier := randomBase64URL(32)
	codeChallenge := codeChallengeS256(codeVerifier)
	nonces := session.nonces
	parForm := url.Values{}
	parForm.Set("response_type", "code")
	parForm.Set("client_id", clientID)
	parForm.Set("redirect_uri", redirectURI)
	setValues(parForm, credentialRequest)
	parForm.Set("state", state)
	parForm.Set("code_challenge", codeChallenge)
	parForm.Set("code_challenge_method", "S256")
	if offer.Grants.IssuerState != "" {
		parForm.Set("issuer_state", offer.Grants.IssuerState)
	}
	authCtx := clientAuthContext{oauthMeta: oauthMeta, tokenEndpoint: session.renewal.TokenEndpoint}
	clientAuth := w.resolveClientAuthentication(clientAuthMethod, authCtx)
	session.renewal.ClientID = clientID
	session.renewal.ClientAuth = clientAuth

	setup := authorizationCodeSetup{
		clientID:              clientID,
		redirectURI:           redirectURI,
		credentialRequest:     credentialRequest,
		state:                 state,
		codeVerifier:          codeVerifier,
		codeChallenge:         codeChallenge,
		clientAuth:            clientAuth,
		dpopKey:               dpopKey,
		nonces:                nonces,
		authorizationEndpoint: authorizationEndpoint,
		issuer:                oauthIssuer(oauthMeta, ""),
		issRequired:           w.issRequired(oauthMeta),

		presentationConsented: opts.PresentationConsented,
		owner:                 opts.Owner,
		flow:                  opts.Flow,
	}
	issuance := authorizationCodeIssuance{
		session:      session,
		codeVerifier: codeVerifier,
	}

	// Without PAR, requestURI stays empty and the parameters go in the query
	// string.
	var requestURI string

	if useInteractive {
		code, viaWeb, err := w.obtainInteractiveAuthorizationCode(challengeEndpoint, setup, offer)
		switch {
		case err == nil:
			// The challenge flow has no redirect, so the token request omits
			// redirect_uri (first-party-apps §6). An auth_via_web code came
			// through a request that carried redirect_uri, so the token request
			// repeats it (RFC 6749 §4.1.3).
			if viaWeb {
				issuance.redirectURI = redirectURI
			}
			return w.completeAuthorizationCodeIssuance(issuance, code)
		case isRedirectToWeb(err):
			// The server can send a request_uri with the redirect to the web
			// sign-in. The browser then opens that pushed request.
			if err := w.noteRedirectToWeb(challengeEndpoint, redirectURI, authorizationEndpoint); err != nil {
				return nil, err
			}
			requestURI = redirectToWebRequestURI(err)
			issuance.redirectURI = redirectURI
		default:
			return nil, err
		}
	}

	if requestURI == "" && parEndpoint != "" {
		w.addProtocolLog("issuance", "par_request", fmt.Sprintf("Request PAR from %s", parEndpoint), true, formRequestLogDetails(parEndpoint, "par", parForm), &LogPayload{Label: "Request", Body: parForm.Encode()})
		parPayload := &LogPayload{}
		parResp, err := postFormWithDPoP(w.HTTPClient(), parEndpoint, parForm, dpopKey, "", &nonces.authzServer, w.clientAuthenticatorFor(clientAuth, clientID), parPayload)
		w.addProtocolLog("issuance", "par_response", fmt.Sprintf("PAR response from %s", parEndpoint), err == nil, responseMapLogDetails(parEndpoint, "par", parResp, err), parPayload)
		if err != nil {
			return nil, fmt.Errorf("PAR request: %w", err)
		}
		requestURI, _ = parResp["request_uri"].(string)
		if requestURI == "" {
			return nil, fmt.Errorf("PAR response missing request_uri")
		}
	}

	authURL, _ := authorizationRequestURL(authorizationEndpoint, clientID, requestURI, parForm)
	w.addProtocolLog("issuance", "authorization_request", fmt.Sprintf("Start authorization request at %s", authorizationEndpoint), true, map[string]any{
		"direction":    "outbound",
		"method":       "GET",
		"url":          authorizationEndpoint,
		"endpoint":     "authorization",
		"client_id":    clientID,
		"request_uri":  requestURI,
		"redirect_uri": redirectURI,
		"state":        state,
	}, &LogPayload{Label: "Request URL", Body: authURL})
	callbackValues, err := runAuthorizationCodeRequest(w, authorizationEndpoint, clientID, requestURI, parForm, redirectURI, state, oauthIssuer(oauthMeta, ""), consent.AuthorizationPrompt{Owner: opts.Owner, Flow: opts.Flow}, w.issRequired(oauthMeta))
	authorizationResponseDetails := map[string]any{
		"direction": "inbound",
		"endpoint":  "authorization",
		"state":     state,
	}
	if callbackValues != nil {
		authorizationResponseDetails["callback_values"] = callbackValues
	}
	if err != nil {
		authorizationResponseDetails["error"] = err.Error()
	}
	w.addProtocolLog("issuance", "authorization_response", fmt.Sprintf("Authorization response for %s", authorizationEndpoint), err == nil, authorizationResponseDetails, &LogPayload{Label: "Response parameters", Body: callbackValues.Encode()})
	if err != nil {
		return nil, fmt.Errorf("authorization request: %w", err)
	}
	code := callbackValues.Get("code")
	if code == "" {
		return nil, fmt.Errorf("authorization callback missing code in values %q", callbackValues.Encode())
	}

	issuance.redirectURI = redirectURI
	return w.completeAuthorizationCodeIssuance(issuance, code)
}

type authorizationCodeSetup struct {
	clientID    string
	redirectURI string
	// credentialRequest names the credential: scope or authorization_details.
	credentialRequest url.Values
	state             string
	codeVerifier      string
	codeChallenge     string
	clientAuth        *ClientAuthentication
	dpopKey           *ecdsa.PrivateKey
	nonces            *dpopNonceState
	// The auth_via_web interaction (OpenID4VCI 1.1 §6.2.1.2) takes the
	// request_uri to authorizationEndpoint and checks the redirect back against
	// issuer.
	authorizationEndpoint string
	issuer                string
	issRequired           bool
	// presentationConsented is set when the caller already consented to a
	// presentation the issuer asks for.
	presentationConsented bool
	// owner identifies the browser the issuance belongs to.
	owner string
	flow  string
}

// authorizationCodeIssuance holds what the token request needs, whichever
// flow produced the code.
type authorizationCodeIssuance struct {
	session issuanceSession
	// redirectURI is empty when the flow that produced the code had none. The
	// token request then omits it (RFC 6749 §4.1.3).
	redirectURI  string
	codeVerifier string
}

func (w *Wallet) completeAuthorizationCodeIssuance(ctx authorizationCodeIssuance, code string) (*IssuanceResult, error) {
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("client_id", ctx.session.renewal.ClientID)
	if ctx.redirectURI != "" {
		tokenForm.Set("redirect_uri", ctx.redirectURI)
	}
	tokenForm.Set("code_verifier", ctx.codeVerifier)
	return w.issueWithToken(ctx.session, tokenForm)
}

// unauthenticatedClientMethod is the IANA registered token endpoint auth method
// of a client that does not authenticate (RFC 8414).
const unauthenticatedClientMethod = "none"

// unregisteredPublicClientMethod is advertised by some servers for
// unauthenticated clients. The wallet reports it as an unregistered alias and
// treats it as none.
const unregisteredPublicClientMethod = "public"

// noteDeclinedInteractiveAuthorization logs an offered interactive
// authorization and the flag that enables it.
func (w *Wallet) noteDeclinedInteractiveAuthorization(oauthMeta map[string]any, endpoint string) {
	if endpoint == "" {
		return
	}
	details := map[string]any{"authorization_challenge_endpoint": endpoint}
	required, _ := oauthMeta["require_interactive_authorization"].(bool)
	if required {
		details["require_interactive_authorization"] = true
	}
	detail := fmt.Sprintf("authorization server offers interactive authorization (OID4VCI 1.1 §6) at %s, and this wallet is set to OID4VCI 1.0, so the redirect flow is used (--vci-version 1.1 selects the challenge endpoint)", endpoint)
	if required {
		detail = fmt.Sprintf("authorization server requires interactive authorization (OID4VCI 1.1 §6, require_interactive_authorization) at %s, and this wallet is set to OID4VCI 1.0, so the redirect flow is attempted and is likely to be refused (--vci-version 1.1 selects the challenge endpoint)", endpoint)
	}
	w.addProtocolLog("issuance", "interactive_authorization_offered", detail, true, details)
	log.Printf("[VCI] %s", detail)
}

// reportServerDeviation warns in debug mode and returns an error in strict
// mode.
func (w *Wallet) reportServerDeviation(detail string) error {
	return w.reportDeviation(deviation{action: "issuance", event: "server_deviation", detail: detail, details: map[string]any{"deviation": detail}})
}

// detectTokenEndpointAuthMethod prefers attestation. It falls back to
// unauthenticated access only when no supported method is offered.
func detectTokenEndpointAuthMethod(oauthMeta map[string]any) string {
	methods, ok := oauthMeta["token_endpoint_auth_methods_supported"].([]any)
	if !ok || len(methods) == 0 {
		return ""
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "attest_jwt_client_auth" {
			return method
		}
	}
	// The draft-10 §5.2 combined method makes the DPoP proof the possession
	// proof. The dedicated PoP method comes first because it works without
	// DPoP.
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "attest_jwt_client_auth_dpop" {
			return method
		}
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "private_key_jwt" {
			return method
		}
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == unauthenticatedClientMethod || method == unregisteredPublicClientMethod {
			return method
		}
	}
	if method, _ := methods[0].(string); method != "" {
		return method
	}
	return ""
}

func supportsDPoP(oauthMeta map[string]any) bool {
	values, ok := oauthMeta["dpop_signing_alg_values_supported"].([]any)
	return ok && len(values) > 0
}

// authorizationCredentialRequest returns the authorization request parameter
// that names the credential. OID4VCI 1.0 §12.2.4: "If scope is absent, the
// only way to request the Credential is using authorization_details" (§5.1.1).
func (w *Wallet) authorizationCredentialRequest(metadata map[string]any, configID string) (url.Values, error) {
	if scope := resolveCredentialScope(metadata, configID); scope != "" {
		return url.Values{"scope": {scope}}, nil
	}
	detail := map[string]any{"type": "openid_credential", "credential_configuration_id": configID}
	// §5.1.1: "If the Credential Issuer metadata contains an
	// authorization_servers parameter, the authorization detail's locations
	// common data field MUST be set to the Credential Issuer Identifier value."
	if _, ok := metadata["authorization_servers"]; ok {
		if issuer, _ := metadata["credential_issuer"].(string); issuer != "" {
			detail["locations"] = []string{issuer}
		}
	}
	details, err := json.Marshal([]map[string]any{detail})
	if err != nil {
		return nil, err
	}
	return url.Values{"authorization_details": {string(details)}}, nil
}

func setValues(form, values url.Values) {
	for key, entries := range values {
		form[key] = entries
	}
}

func resolveCredentialScope(metadata map[string]any, configID string) string {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return ""
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return ""
	}
	scope, _ := cfg["scope"].(string)
	return scope
}

func oauthIssuer(oauthMeta map[string]any, fallback string) string {
	if issuer, _ := oauthMeta["issuer"].(string); issuer != "" {
		return issuer
	}
	return fallback
}

// issRequired reports whether the authorization response must carry iss. RFC
// 9207 requires it when the authorization server advertises
// authorization_response_iss_parameter_supported. HAIP 1.0 §4 applies FAPI
// 2.0, whose authorization server "shall return an iss parameter in the
// authorization response according to [RFC9207]" (§5.3.2.2).
func (w *Wallet) issRequired(oauthMeta map[string]any) bool {
	supported, _ := oauthMeta["authorization_response_iss_parameter_supported"].(bool)
	return supported || w.HAIPChecks()
}

// attestsClient reports whether to authenticate with the wallet attestation.
// The wallet attests when the server advertises it
// (draft-ietf-oauth-attestation-based-client-auth §8) or when
// ForceClientAttestation is set.
//
// HAIP 1.0 §4.4.1 says "Wallets MUST use, and Issuers MUST require, an OAuth2
// Client authentication mechanism". Under HAIP the wallet also attests when no
// method is advertised, since every draft makes advertising only a SHOULD
// (see abcaMetadataSection). When only
// unauthenticated access is advertised, strict mode attests and debug mode does
// not.
func (w *Wallet) attestsClient(oauthMeta map[string]any) bool {
	if w == nil {
		return false
	}
	method := detectTokenEndpointAuthMethod(oauthMeta)
	if w.ForceClientAttestation || method == "attest_jwt_client_auth" || method == "attest_jwt_client_auth_dpop" {
		return true
	}
	if !w.HAIPChecks() {
		return false
	}
	if w.Mode() == ValidationModeStrict {
		return true
	}
	return method == ""
}

// clientAuthContext holds the inputs for choosing client authentication.
// tokenEndpoint is the audience when the metadata has no issuer.
type clientAuthContext struct {
	oauthMeta     map[string]any
	tokenEndpoint string
}

// resolveClientAuthentication returns the client authentication to store with
// the credential for refresh requests. It returns nil for unauthenticated
// access.
func (w *Wallet) resolveClientAuthentication(method string, ctx clientAuthContext) *ClientAuthentication {
	if method == ClientAuthPrivateKeyJWT {
		return &ClientAuthentication{
			Method:   ClientAuthPrivateKeyJWT,
			Audience: oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		}
	}
	if w.attestsClient(ctx.oauthMeta) {
		auth := w.attestationClientAuth(ctx)
		if w != nil && w.HAIPChecks() && w.Mode() != ValidationModeStrict &&
			!w.ForceClientAttestation &&
			detectTokenEndpointAuthMethod(ctx.oauthMeta) == "" {
			w.addProtocolWarning("issuance", "client_authentication_not_advertised",
				fmt.Sprintf("The issuer's authorization server advertises no token endpoint client authentication method (draft-ietf-oauth-attestation-based-client-auth-%02d %s recommends it). Attesting anyway, since HAIP requires client authentication.", auth.ABCADraft, abcaMetadataSection(auth.ABCADraft)),
				map[string]any{"token_endpoint": ctx.tokenEndpoint})
		}
		return auth
	}
	if w != nil && w.HAIPChecks() && !w.ForceClientAttestation {
		w.addProtocolWarning("issuance", "haip_client_authentication_unavailable",
			"HAIP 1.0 §4.4.1 requires client authentication at the token endpoint, but this issuer's authorization server offers only unauthenticated access. Proceeding without it.",
			map[string]any{"token_endpoint": ctx.tokenEndpoint})
	}
	return nil
}

// abcaMetadataSection returns the section of an ABCA draft that recommends
// advertising attest_jwt_client_auth in token_endpoint_auth_methods_supported
// (a SHOULD in each draft).
func abcaMetadataSection(draft int) string {
	switch draft {
	case 7:
		return "§10.1"
	case 8:
		return "§9"
	default:
		return "§8"
	}
}

func (w *Wallet) attestationClientAuth(ctx clientAuthContext) *ClientAuthentication {
	challengeEndpoint, _ := ctx.oauthMeta["challenge_endpoint"].(string)
	auth := &ClientAuthentication{
		Method:            ClientAuthAttestation,
		Audience:          oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		ChallengeEndpoint: challengeEndpoint,
		ABCADraft:         w.VCIFeatureVersion().ABCADraft(),
	}
	if usesCombinedPoP(ctx.oauthMeta) {
		auth.CombinedPoP = true
		if auth.ABCADraft < ABCALatestDraft {
			w.addProtocolWarning("issuance", "abca_draft_feature",
				fmt.Sprintf("This authorization server takes the DPoP proof as the attestation's possession proof (dpop_combined), a draft-10 mechanism, while the configured OpenID4VCI version pins attestation-based client authentication draft-0%d. Using it, since the server offers nothing earlier.", auth.ABCADraft),
				map[string]any{"token_endpoint": ctx.tokenEndpoint})
		}
	}
	return auth
}

// usesCombinedPoP reports whether the DPoP proof is the attestation's
// possession proof (draft-10 §5.2). That holds when the server offers
// attest_jwt_client_auth_dpop without attest_jwt_client_auth, or when
// client_attestation_pop_methods_supported lists dpop_combined without
// attestation_pop_jwt. Servers on earlier drafts omit that parameter.
func usesCombinedPoP(oauthMeta map[string]any) bool {
	if detectTokenEndpointAuthMethod(oauthMeta) == "attest_jwt_client_auth_dpop" {
		return true
	}
	values, ok := oauthMeta["client_attestation_pop_methods_supported"].([]any)
	if !ok {
		return false
	}
	combined, dedicated := false, false
	for _, raw := range values {
		switch raw {
		case "dpop_combined":
			combined = true
		case "attestation_pop_jwt":
			dedicated = true
		}
	}
	return combined && !dedicated
}

// usesDPoP reports whether requests to this authorization server carry a DPoP
// proof. They do when it advertises DPoP (RFC 9449 §5.1) or demands the
// combined possession proof (draft-10 §5.2). RFC 9449 makes the metadata
// optional, so the wallet treats a server without it as issuing bearer tokens.
func usesDPoP(oauthMeta map[string]any) bool {
	return supportsDPoP(oauthMeta) || usesCombinedPoP(oauthMeta)
}

func (w *Wallet) clientAuthenticatorFor(auth *ClientAuthentication, clientID string) *clientAuthenticator {
	if auth == nil || (auth.Method != ClientAuthAttestation && auth.Method != ClientAuthPrivateKeyJWT) {
		return nil
	}
	return &clientAuthenticator{wallet: w, auth: auth, clientID: clientID}
}

// clientAuthenticator authenticates each request to the authorization server.
// Every attempt, including a retry, gets fresh proofs, since a server may
// accept a jti only once.
//
// For attestation it tracks the server's challenges. Every supported ABCA
// draft lets a server return a fresh challenge in the
// OAuth-Client-Attestation-Challenge header of any response. The client MUST
// send it in the next PoP.
type clientAuthenticator struct {
	wallet *Wallet
	auth   *ClientAuthentication
	// clientID is the subject of the attestation.
	clientID string
	// challenge comes from the server and goes into the next PoP.
	challenge string
}

// headers creates the attestation headers for one request. In combined mode the
// challenge goes in the DPoP proof instead (see dpopChallenge).
func (a *clientAuthenticator) headers() (map[string]string, error) {
	if a.auth.Method != ClientAuthAttestation {
		return nil, nil
	}
	challenge := ""
	if !a.auth.CombinedPoP {
		var err error
		challenge, err = a.requestChallenge()
		if err != nil {
			return nil, err
		}
	}
	headers, err := createClientAttestationHeaders(a.wallet, a.auth, a.clientID, challenge)
	if err != nil {
		return nil, fmt.Errorf("creating client attestation headers: %w", err)
	}
	return headers, nil
}

// requestChallenge returns the challenge for one request. A challenge from a
// response header is single use, so it is consumed here. Without one the wallet
// fetches a fresh challenge from the challenge endpoint.
func (a *clientAuthenticator) requestChallenge() (string, error) {
	challenge := a.challenge
	a.challenge = ""
	if challenge != "" {
		return challenge, nil
	}
	challenge, err := fetchAttestationChallenge(a.auth.ChallengeEndpoint, a.wallet.HTTPClient())
	if err != nil {
		return "", fmt.Errorf("fetching client attestation challenge: %w", err)
	}
	return challenge, nil
}

// dpopChallenge returns the challenge for the DPoP proof in combined mode,
// where that proof is the possession proof (draft-10 §5.2). It is empty with a
// dedicated PoP, which carries the challenge itself.
//
// Draft-10 §7.3 step 5: the challenge "MUST match the nonce payload claim of
// the DPoP proof". Drafts -07 and -08 have no combined mode, so this is the
// only rule. RFC 9449 §8 puts a pending DPoP-Nonce in the same claim. A proof
// has one nonce, so the attestation challenge takes it: §6.1 makes the client
// use the endpoint challenge, and a server in combined mode checks its
// challenge as the DPoP nonce.
func (a *clientAuthenticator) dpopChallenge() (string, error) {
	if a.auth.Method != ClientAuthAttestation || !a.auth.CombinedPoP {
		return "", nil
	}
	return a.requestChallenge()
}

func (a *clientAuthenticator) observe(headers http.Header) {
	if value := strings.TrimSpace(headers.Get("OAuth-Client-Attestation-Challenge")); value != "" {
		a.challenge = value
	}
}

// retryAfterRefusal reports whether a refusal asks for a retry with fresh
// attestation material. use_attestation_challenge comes with the challenge for
// the retry (§6.2 requires the header alongside it). use_fresh_attestation
// needs no extra step because the wallet creates a new attestation per request.
func (a *clientAuthenticator) retryAfterRefusal(body []byte) bool {
	if a.auth.Method != ClientAuthAttestation {
		return false
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	switch parsed.Error {
	case "use_attestation_challenge":
		return a.challenge != ""
	case "use_fresh_attestation":
		return true
	}
	return false
}

// formBody adds a fresh private_key_jwt client assertion to a form body (RFC
// 7523 §2.2). Attestation authentication uses headers instead.
func (a *clientAuthenticator) formBody(contentType string, body []byte) ([]byte, error) {
	if a.auth.Method != ClientAuthPrivateKeyJWT || contentType != "application/x-www-form-urlencoded" {
		return body, nil
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("reading form body: %w", err)
	}
	assertion, err := createClientAssertionJWT(a.wallet.HolderKeyPair(), a.clientID, a.auth.Audience)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return []byte(form.Encode()), nil
}

// createClientAttestationHeaders creates the attestation and, outside combined
// mode, the PoP for the attested key. Both carry the claims of every supported
// draft (the draft-07 shape). Every draft allows extra claims in these JWTs
// (§5.1 and §5.2 rule 1), so one shape verifies under all of them.
func createClientAttestationHeaders(w *Wallet, auth *ClientAuthentication, clientID, challenge string) (map[string]string, error) {

	signingKey, chain, err := w.Signer().WalletProvider()
	if err != nil {
		return nil, err
	}

	x5c := certchain.X5C(chain)
	holderKey := w.HolderKeyPair()
	holderJWK := mock.SigningJWKMap(&holderKey.PublicKey)
	clientAttestationHeader := map[string]any{
		"alg": jws.AlgES256,
		"typ": format.TypeClientAttestation,
		"x5c": x5c,
	}
	if kid := mock.KeyIDForPublicKey(&signingKey.PublicKey); kid != "" {
		clientAttestationHeader["kid"] = kid
	}
	clientAttestationPayload := map[string]any{
		"sub": clientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(signedJWTLifetime).Unix(),
		"cnf": map[string]any{"jwk": holderJWK},
		// Draft-07 §5.1 requires iss and defines nbf. Later drafts allow extra
		// claims (§5.1 rule 1).
		"iss": w.IssuerURL,
		"nbf": time.Now().Unix(),
	}
	clientAttestationJWT, err := signJWT(clientAttestationHeader, clientAttestationPayload, signingKey)
	if err != nil {
		return nil, err
	}
	if auth.CombinedPoP {
		// The DPoP proof is the possession proof here (draft-10 §5.2), so the
		// attestation goes alone.
		return map[string]string{"OAuth-Client-Attestation": clientAttestationJWT}, nil
	}

	popHeader := map[string]any{
		"alg": jws.AlgES256,
		"typ": format.TypeClientAttestationPoP,
		"jwk": holderJWK,
	}
	popPayload := map[string]any{
		"aud": auth.Audience,
		"iat": time.Now().Unix(),
		"jti": randomBase64URL(18),
		// Draft-07 §5.2 requires iss and defines nbf. Later drafts allow extra
		// claims (§5.2 rule 1).
		"iss": clientID,
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(signedJWTLifetime).Unix(),
	}
	if challenge != "" {
		popPayload["challenge"] = challenge
	}
	clientAttestationPoP, err := signJWT(popHeader, popPayload, holderKey)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"OAuth-Client-Attestation":     clientAttestationJWT,
		"OAuth-Client-Attestation-PoP": clientAttestationPoP,
	}, nil
}

func fetchAttestationChallenge(endpoint string, client *http.Client) (string, error) {
	if endpoint == "" {
		return "", nil
	}
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating challenge request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("challenge request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
		return "", fmt.Errorf("challenge endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if _, err := format.DecodeRemoteJSON(resp.Body, "challenge response", &payload); err != nil {
		return "", fmt.Errorf("parsing challenge response: %w", err)
	}
	challenge, _ := payload["attestation_challenge"].(string)
	if challenge == "" {
		challenge, _ = payload["challenge"].(string)
	}
	return challenge, nil
}

func createKeyAttestation(w *Wallet, metadata map[string]any, configID, cNonce string, proofKeys []*ecdsa.PrivateKey) (string, error) {
	requirement, required := credentialKeyAttestationRequirement(metadata, configID)
	if !required {
		return "", nil
	}
	signingKey, chain, err := w.Signer().WalletProvider()
	if err != nil {
		return "", err
	}

	if len(proofKeys) == 0 {
		proofKeys = []*ecdsa.PrivateKey{w.HolderKeyPair()}
	}
	attestedKeys := make([]any, 0, len(proofKeys))
	for _, key := range proofKeys {
		attestedKeys = append(attestedKeys, mock.SigningJWKMap(&key.PublicKey))
	}
	// Appendix D.1 takes the key header parameters from Appendix F.1, where
	// kid "MUST NOT be present if jwk or x5c is present".
	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": "key-attestation+jwt",
		"x5c": certchain.X5C(chain),
	}
	payload := map[string]any{
		"iat":           time.Now().Unix(),
		"nbf":           time.Now().Unix(),
		"exp":           time.Now().Add(signedJWTLifetime).Unix(),
		"attested_keys": attestedKeys,
	}
	claims := w.keyAttestationClaims(requirement)
	for claim, values := range claims {
		payload[claim] = values
	}
	w.noteKeyAttestationClaims(claims, requirement)
	if cNonce != "" {
		payload["nonce"] = cNonce
	}
	keyAttestationJWT, err := signJWT(header, payload, signingKey)
	if err != nil {
		return "", fmt.Errorf("creating key attestation JWT: %w", err)
	}
	return keyAttestationJWT, nil
}

// keyAttestationClaimNames are the attack potential resistance claims of a
// key attestation (OpenID4VCI 1.0 Appendix D.2).
var keyAttestationClaimNames = []string{"key_storage", "user_authentication"}

// keyAttestationLevelValues are the values of those claims in Appendix D.2,
// the ISO/IEC 18045 attack potentials that a catalogue entry also names.
var keyAttestationLevelValues = registrar.OptionValues(registrar.AttestationLevels)

// ParseKeyAttestationLevel validates the --key-attestation-level setting. Valid
// values are "" (use what the issuer requires), "none" and the Appendix D.2
// values.
func ParseKeyAttestationLevel(value string) (string, error) {
	if value == "" || value == "none" || slices.Contains(keyAttestationLevelValues, value) {
		return value, nil
	}
	return "", fmt.Errorf("%q is not a key attestation level: use 'none' or one of %s", value, strings.Join(keyAttestationLevelValues, ", "))
}

// keyAttestationClaims returns the key_storage and user_authentication claims
// for a key attestation. The default is what the issuer requires. "none"
// returns no claims, and any other level is set on both claims.
func (w *Wallet) keyAttestationClaims(requirement map[string]any) map[string]any {
	switch level := w.KeyAttestationLevelSetting(); level {
	case "none":
		return nil
	case "":
		return requiredKeyAttestationClaims(requirement)
	default:
		claims := map[string]any{}
		for _, claim := range keyAttestationClaimNames {
			claims[claim] = []any{level}
		}
		return claims
	}
}

func requiredKeyAttestationClaims(requirement map[string]any) map[string]any {
	required := map[string]any{}
	for _, claim := range keyAttestationClaimNames {
		if values, ok := requirement[claim].([]any); ok && len(values) > 0 {
			required[claim] = values
		}
	}
	return required
}

func (w *Wallet) noteKeyAttestationClaims(claims, requirement map[string]any) {
	if len(claims) > 0 {
		w.AddWarning("issuance", "The key attestation claims key storage levels that the wallet's software keys can't back (a test setting, see --key-attestation-level)", claims)
	} else if required := requiredKeyAttestationClaims(requirement); len(required) > 0 {
		w.AddWarning("issuance", "The key attestation omits levels the issuer requires (--key-attestation-level none)", required)
	}
}

func credentialProofTypes(metadata map[string]any, configID string) map[string]any {
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	cfg, _ := configs[configID].(map[string]any)
	proofTypes, _ := cfg["proof_types_supported"].(map[string]any)
	return proofTypes
}

// credentialProofType picks the proof type for the credential request. It picks
// attestation (Appendix F.3) when that is the only type offered or when a jwt
// proof would need a key attestation anyway. Otherwise it picks jwt (Appendix
// F.1).
func credentialProofType(metadata map[string]any, configID string) string {
	proofTypes := credentialProofTypes(metadata, configID)
	if _, offered := proofTypes["attestation"].(map[string]any); !offered {
		return "jwt"
	}
	jwtProof, offered := proofTypes["jwt"].(map[string]any)
	if !offered {
		return "attestation"
	}
	if _, required := jwtProof["key_attestations_required"]; required {
		return "attestation"
	}
	return "jwt"
}

// proofSigningAlgFinding reports a proof type without ES256 in
// proof_signing_alg_values_supported. The wallet signs proofs only with ES256,
// and Appendix F.1 and F.3 require the proof alg to be in that list. HAIP 1.0
// §7 also requires issuers to support ES256 for key proofs and key
// attestations.
func proofSigningAlgFinding(metadata map[string]any, configID string, requireHAIP bool) string {
	proofType := credentialProofType(metadata, configID)
	proof, _ := credentialProofTypes(metadata, configID)[proofType].(map[string]any)
	algs, ok := proof["proof_signing_alg_values_supported"].([]any)
	if !ok {
		return ""
	}
	for _, alg := range algs {
		if alg == jws.AlgES256 {
			return ""
		}
	}
	finding := fmt.Sprintf("OID4VCI 1.0 Appendix F: the %s proof type lists proof_signing_alg_values_supported %v without ES256. This wallet signs its proofs with ES256", proofType, algs)
	if requireHAIP {
		finding += " (HAIP 1.0 §7: issuers MUST support ES256 for key proofs and key attestations)"
	}
	return finding
}

// credentialKeyAttestationRequirement returns the key attestation requirement
// for the chosen proof type. The attestation proof type always carries a key
// attestation and falls back to the requirement on the jwt entry. For a jwt
// proof, a key_attestations_required entry requires attestation even when it is
// empty or malformed.
func credentialKeyAttestationRequirement(metadata map[string]any, configID string) (map[string]any, bool) {
	proofTypes := credentialProofTypes(metadata, configID)
	proofType := credentialProofType(metadata, configID)
	proof, _ := proofTypes[proofType].(map[string]any)
	raw, ok := proof["key_attestations_required"]
	if proofType == "attestation" {
		if !ok {
			jwtProof, _ := proofTypes["jwt"].(map[string]any)
			raw = jwtProof["key_attestations_required"]
		}
		requirement, _ := raw.(map[string]any)
		return requirement, true
	}
	requirement, _ := raw.(map[string]any)
	return requirement, ok
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return format.EncodeBase64URL(sum[:])
}

func randomBase64URL(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return format.EncodeBase64URL(buf)
}

func createClientAssertionJWT(key *ecdsa.PrivateKey, clientID, audience string) (string, error) {
	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": "JWT",
		"kid": mock.KeyIDForPublicKey(&key.PublicKey),
	}
	payload := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(signedJWTLifetime).Unix(),
		"jti": randomBase64URL(18),
	}
	return signJWT(header, payload, key)
}

func createDPoPProofJWT(key *ecdsa.PrivateKey, method, targetURL, nonce, accessToken string) (string, error) {
	jwk := mock.SigningJWKMap(&key.PublicKey)
	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": "dpop+jwt",
		"jwk": jwk,
	}
	payload := map[string]any{
		"jti": randomBase64URL(18),
		"htm": strings.ToUpper(method),
		"htu": dpopTargetURI(targetURL),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = format.EncodeBase64URL(sum[:])
	}
	return signJWT(header, payload, key)
}

// dpopTargetURI returns the htu claim of a DPoP proof. RFC 9449 §4.2: "The HTTP
// target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is
// attached, without query and fragment parts." Issuer endpoints may carry a
// query, such as a tenant or an API version.
func dpopTargetURI(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String()
}

func formRequestLogDetails(endpoint, endpointName string, form url.Values) map[string]any {
	return map[string]any{
		"direction": "outbound",
		"method":    "POST",
		"url":       endpoint,
		"endpoint":  endpointName,
		"request":   form,
	}
}

func responseMapLogDetails(endpoint, endpointName string, response map[string]any, err error) map[string]any {
	details := map[string]any{
		"direction": "inbound",
		"url":       endpoint,
		"endpoint":  endpointName,
	}
	if response != nil {
		details["response"] = response
	}
	if err != nil {
		details["error"] = err.Error()
		var refusal *serverRefusal
		if errors.As(err, &refusal) {
			if refusal.StatusCode != 0 {
				details["status_code"] = refusal.StatusCode
			}
			if refusal.Body != "" && !strings.Contains(refusal.Message, refusal.Body) {
				details["response_body"] = refusal.Body
			}
		}
	}
	return details
}

// checkTokenType reports a missing or unknown token_type, which RFC 6749 §5.1
// requires. A missing type is taken as DPoP when a proof was sent and Bearer
// otherwise. An unknown type is taken as Bearer.
func (w *Wallet) checkTokenType(tokenResp map[string]any, sentDPoP bool) error {
	tokenType, _ := tokenResp["token_type"].(string)
	if tokenType == "" {
		return w.reportServerDeviation(fmt.Sprintf("the token response omitted token_type, which RFC 6749 §5.1 requires (assuming %s)", accessTokenScheme(tokenResp, sentDPoP)))
	}
	if !strings.EqualFold(tokenType, "Bearer") && !strings.EqualFold(tokenType, "DPoP") {
		return w.reportServerDeviation(fmt.Sprintf("the token response token_type %q is neither Bearer (RFC 6749) nor DPoP (RFC 9449), treating it as Bearer", tokenType))
	}
	return nil
}

// accessTokenScheme picks the HTTP authorization scheme for an access token.
// RFC 9449 §5 returns token_type "DPoP" for a DPoP-bound token, so a "Bearer"
// answer to a proof means a plain bearer token. Without token_type, the scheme
// follows whether a proof was sent.
func accessTokenScheme(tokenResp map[string]any, sentDPoP bool) string {
	tokenType, _ := tokenResp["token_type"].(string)
	if strings.EqualFold(tokenType, "DPoP") {
		return "DPoP"
	}
	if tokenType == "" && sentDPoP {
		return "DPoP"
	}
	return "Bearer"
}

// serverRefusal keeps the status and body of a refusal for diagnostics,
// including refusals outside the OAuth error format.
type serverRefusal struct {
	StatusCode int
	Body       string
	Message    string
	Cause      error
}

func (e *serverRefusal) Error() string { return e.Message }

func (e *serverRefusal) Unwrap() error { return e.Cause }

func postFormWithDPoP(client *http.Client, target string, form url.Values, key *ecdsa.PrivateKey, accessToken string, nonce *string, authenticator *clientAuthenticator, payloads ...*LogPayload) (map[string]any, error) {
	body := []byte(form.Encode())
	respBody, status, err := doDPoPRequest("POST", target, "application/x-www-form-urlencoded", "", body, "", accessToken, key, nonce, authenticator, client)
	if payload := firstLogPayload(payloads); payload != nil {
		payload.Label, payload.Body = "Response", string(respBody)
	}
	if err != nil {
		message := oauthErrorMessage(respBody)
		if message == "" {
			message = err.Error()
		}
		return nil, &serverRefusal{StatusCode: status, Body: string(respBody), Message: message, Cause: err}
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}
	// Some servers answer 200 with an error document.
	if refusal := oauthErrorMessage(respBody); refusal != "" {
		return nil, &serverRefusal{StatusCode: status, Body: string(respBody), Message: refusal}
	}
	return out, nil
}

// oauthErrorMessage formats an RFC 6749 §5.2 error as code and description.
// Some servers put the details in a message field. A body without an error
// field is no refusal.
func oauthErrorMessage(body []byte) string {
	var doc struct {
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
		Message     json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Error == "" {
		return ""
	}
	reason := doc.Description
	if reason == "" {
		reason = errorBodyMessage(doc.Message)
	}
	if reason == "" || reason == doc.Error {
		return doc.Error
	}
	return doc.Error + ": " + reason
}

// Servers can return message as a string or a list of validation errors.
func errorBodyMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return strings.TrimSpace(single)
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return strings.TrimSpace(strings.Join(many, ", "))
	}
	return ""
}

func credentialRequestBody(proofs credentialProofs, credentialIdentifier, credentialConfigurationID string, credentialResponseEncryption map[string]any) map[string]any {
	reqBody := map[string]any{
		"proofs": map[string]any{proofs.Type: proofs.Values},
	}
	if credentialIdentifier != "" {
		reqBody["credential_identifier"] = credentialIdentifier
	} else if credentialConfigurationID != "" {
		reqBody["credential_configuration_id"] = credentialConfigurationID
	}
	if credentialResponseEncryption != nil {
		reqBody["credential_response_encryption"] = credentialResponseEncryption
	}
	return reqBody
}

type credentialExchangeLog struct {
	Request  func(*LogPayload)
	Response *LogPayload
}

func (w *Wallet) requestCredentialWithDPoP(a credentialRequestAttempt, proofs credentialProofs, trace *credentialExchangeLog) (map[string]any, error) {
	reqBody := credentialRequestBody(proofs, a.credentialIdentifier, a.credentialConfigurationID, a.responseEncryption)
	body, contentType, err := prepareCredentialRequestBody(w.Mode(), a.metadata, reqBody)
	var responsePayload *LogPayload
	if trace != nil {
		payload := &LogPayload{Label: "Request", Body: string(body)}
		if contentType == "application/jwt" {
			payload.Body, payload.Wire, payload.Encrypted = reqBody, string(body), true
		}
		if err != nil {
			payload.Label, payload.Body = "Request (not sent)", reqBody
		}
		if trace.Request != nil {
			trace.Request(payload)
		}
		trace.Response = &LogPayload{Label: "Response"}
		responsePayload = trace.Response
	}
	if err != nil {
		return nil, err
	}
	respBody, statusCode, reqErr := doDPoPRequest("POST", a.endpoint, contentType, credentialAccept(a.responseEncryption), body, a.authScheme, a.accessToken, a.dpopKey, a.nonce, nil, w.HTTPClient())
	out, encrypted, parseErr := parseCredentialResponseBody(respBody, w.HolderKeyPair(), responsePayload)
	if parseErr == nil {
		// The caller acts on the code of a Credential Error Response
		// (§8.3.1.2), so it is returned in place of the HTTP error.
		if code, _ := out["error"].(string); code != "" {
			desc, _ := out["error_description"].(string)
			return out, credentialErrorResponse{code: code, description: desc}
		}
	}
	if reqErr != nil {
		return out, reqErr
	}
	if parseErr != nil {
		return nil, parseErr
	}
	if err := w.checkResponseEncryption(a.responseEncryption, encrypted, out, a.endpoint); err != nil {
		return nil, err
	}
	if pending, _ := deferredIssuancePending(out); pending {
		if err := w.checkDeferral(out, statusCode, a.endpoint, ""); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// credentialErrorResponse is a Credential Error Response (§8.3.1.2). The code
// is a separate field because the wallet acts on it.
type credentialErrorResponse struct {
	code        string
	description string
}

func (e credentialErrorResponse) Error() string {
	if e.description == "" {
		return "credential error: " + e.code
	}
	return "credential error: " + e.code + ": " + e.description
}

func isInvalidNonceError(err error) bool {
	var credErr credentialErrorResponse
	return errors.As(err, &credErr) && credErr.code == "invalid_nonce"
}

const deferredPollInterval = 5 * time.Second

// stillPendingError reports a valid transaction that is not issued yet.
// interval sets the next attempt.
type stillPendingError struct {
	transactionID string
	interval      time.Duration
}

func (e stillPendingError) Error() string {
	return fmt.Sprintf("credential is not ready yet: retry in %s with transaction_id %s",
		e.interval, e.transactionID)
}

// deferredCredentialAttempt makes one deferred credential request. A
// still-pending issuer returns a stillPendingError with its interval, and the
// caller decides whether to wait.
//
// §9.1: the client "MUST" encrypt the request when encryption_required is true.
// The encryption parameters in the Deferred Credential Request decide the
// response encryption "regardless of what was sent in the initial Credential
// Request".
func (w *Wallet) deferredCredentialAttempt(mode ValidationMode, metadata map[string]any, endpoint, accessToken, authScheme, transactionID string, responseEncryption map[string]any, dpopKey, holderKey *ecdsa.PrivateKey, nonce *string) (out map[string]any, err error) {
	reqBody := map[string]any{"transaction_id": transactionID}
	if responseEncryption != nil {
		reqBody["credential_response_encryption"] = responseEncryption
	}
	body, contentType, err := prepareCredentialRequestBody(mode, metadata, reqBody)
	requestPayload := &LogPayload{Label: "Request", Body: string(body)}
	if contentType == "application/jwt" {
		requestPayload.Body, requestPayload.Wire, requestPayload.Encrypted = reqBody, string(body), true
	}
	requestDetails := map[string]any{
		"direction": "outbound", "method": "POST", "url": endpoint,
		"endpoint": "deferred_credential", "transaction_id": transactionID,
	}
	if err != nil {
		requestPayload.Label, requestPayload.Body = "Request (not sent)", reqBody
		requestDetails["error"] = err.Error()
	}
	w.addProtocolLog("issuance", "deferred_credential_request", fmt.Sprintf("Request deferred credential from %s", endpoint), err == nil, requestDetails, requestPayload)
	if err != nil {
		return nil, err
	}
	respBody, statusCode, reqErr := doDPoPRequest("POST", endpoint, contentType, credentialAccept(responseEncryption), body, authScheme, accessToken, dpopKey, nonce, nil, w.HTTPClient())
	responsePayload := &LogPayload{Label: "Response"}
	defer func() {
		logErr := err
		var pending stillPendingError
		if errors.As(err, &pending) {
			logErr = nil
		}
		details := responseMapLogDetails(endpoint, "deferred_credential", nil, logErr)
		details["method"], details["status_code"], details["transaction_id"] = "POST", statusCode, transactionID
		w.addProtocolLog("issuance", "deferred_credential_response", fmt.Sprintf("Deferred credential response from %s", endpoint), logErr == nil && statusCode < 400, details, responsePayload)
	}()
	out, encrypted, parseErr := parseCredentialResponseBody(respBody, holderKey, responsePayload)
	switch {
	case parseErr != nil && statusCode >= 400:
		return nil, deferredCredentialError{status: statusCode, description: truncateBody(string(respBody))}
	case parseErr != nil && reqErr != nil:
		return nil, reqErr
	case parseErr != nil:
		return nil, fmt.Errorf("parsing deferred credential response: %w", parseErr)
	}
	if code, _ := out["error"].(string); code != "" {
		description, _ := out["error_description"].(string)
		return nil, deferredCredentialError{status: statusCode, code: code, description: description}
	}
	if reqErr != nil {
		return nil, deferredCredentialError{status: statusCode, description: truncateBody(string(respBody))}
	}
	if err := w.checkResponseEncryption(responseEncryption, encrypted, out, endpoint); err != nil {
		return nil, finalDeferredError{err}
	}
	if pending, interval := deferredIssuancePending(out); pending {
		if err := w.checkDeferral(out, statusCode, endpoint, transactionID); err != nil {
			return nil, finalDeferredError{err}
		}
		return nil, stillPendingError{transactionID: transactionID, interval: interval}
	}
	return out, nil
}

// checkDeferral checks an answer that defers the credential. requested is the
// transaction_id of a Deferred Credential Request and empty for the first
// answer. §8.3: "the Credential Issuer MUST also use the HTTP status code 202
// for the response", and interval is "REQUIRED if transaction_id is
// present". §9.2 applies the same to an answer that defers again and adds
// "The value of transaction_id MUST be same as the value of transaction_id in
// the Deferred Credential Request."
func (w *Wallet) checkDeferral(out map[string]any, statusCode int, endpoint, requested string) error {
	var problems []string
	if statusCode != http.StatusAccepted {
		problems = append(problems, fmt.Sprintf("answered with HTTP %d instead of 202", statusCode))
	}
	if _, ok := out["interval"]; !ok {
		problems = append(problems, "left out interval")
	}
	section := "§8.3"
	if requested != "" {
		section = "§9.2"
		if got, _ := out["transaction_id"].(string); got != requested {
			problems = append(problems, fmt.Sprintf("returned the transaction_id %q for the request's %q", got, requested))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	detail := fmt.Sprintf("%s deferred the credential but %s (OID4VCI 1.0 %s)", endpoint, strings.Join(problems, " and "), section)
	return w.reportDeviation(deviation{
		action: "issuance", event: "deferred_response_deviation", detail: detail,
		details: map[string]any{"endpoint": endpoint, "status_code": statusCode},
	})
}

// deferredCredentialError is a refusal from the Deferred Credential Endpoint
// (§9.3). code is empty when the body carries no error code.
type deferredCredentialError struct {
	status      int
	code        string
	description string
}

func (e deferredCredentialError) Error() string {
	message := fmt.Sprintf("deferred credential request refused (HTTP %d)", e.status)
	if e.code != "" {
		message += ": " + e.code
	}
	if e.description != "" {
		message += ": " + e.description
	}
	return message
}

// authorizationRejected reports a refused access token (RFC 6750 §3.1).
func (e deferredCredentialError) authorizationRejected() bool {
	return e.status == http.StatusUnauthorized || e.status == http.StatusForbidden || e.code == "invalid_token"
}

// final reports a refusal that a retry would only repeat. §9.3 answers an
// invalid request with the 400 error codes of §8.3.1.2 and invalid_transaction_id,
// and every poll sends the same request. After credential_request_denied "A
// wallet upon receiving this error SHOULD stop making requests to the deferred
// credential endpoint for the given transaction_id."
func (e deferredCredentialError) final() bool {
	return e.authorizationRejected() || e.code == "credential_request_denied" || (e.status == http.StatusBadRequest && e.code != "")
}

// finalDeferredError is a deferred response the wallet refuses. Asking again
// gets the same answer.
type finalDeferredError struct{ error }

func (e finalDeferredError) Unwrap() error { return e.error }

// deferredIssuancePending reports whether a deferred credential response is
// still pending and how long to wait. OpenID4VCI 1.0 §9.2 answers that case
// with a 202 carrying interval and transaction_id.
func deferredIssuancePending(out map[string]any) (bool, time.Duration) {
	if txID, _ := out["transaction_id"].(string); txID != "" && len(credentialStringsFromResponse(out)) == 0 {
		return true, deferredInterval(out)
	}
	return false, 0
}

// notifyCredentialAccepted reports a stored credential to the issuer's
// Notification Endpoint. §11: "Support for this endpoint is OPTIONAL. The
// Issuer cannot assume that a notification will be sent for every issued
// Credential since the use of this Endpoint is not mandatory for the Wallet."
// The credential is already stored, so an unanswered notification is only
// logged.
func (w *Wallet) notifyCredentialAccepted(metadata, credResp map[string]any, accessToken, authScheme string, dpopKey *ecdsa.PrivateKey, nonce *string) {
	notificationID, _ := credResp["notification_id"].(string)
	notificationEndpoint, _ := metadata["notification_endpoint"].(string)
	if notificationID == "" || notificationEndpoint == "" {
		return
	}
	w.addProtocolLog("issuance", "notification_request", fmt.Sprintf("Send credential notification to %s", notificationEndpoint), true, map[string]any{
		"direction":          "outbound",
		"method":             "POST",
		"url":                notificationEndpoint,
		"endpoint":           "notification",
		"notification_id":    notificationID,
		"notification_event": "credential_accepted",
	}, &LogPayload{Label: "Request", Body: notificationRequestBody(notificationID)})
	status, respBody, err := sendNotificationWithDPoP(notificationEndpoint, accessToken, authScheme, notificationID, dpopKey, nonce, w.HTTPClient())
	if err != nil {
		w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), false, map[string]any{
			"direction": "inbound",
			"url":       notificationEndpoint,
			"endpoint":  "notification",
			"error":     err.Error(),
		}, &LogPayload{Label: "Response", Body: string(respBody)})
		reading, code := readNotificationRefusal(status, respBody)
		details := map[string]any{
			"url":             notificationEndpoint,
			"notification_id": notificationID,
			"status":          status,
			"error":           err.Error(),
		}
		if code != "" {
			details["error_code"] = code
		}
		w.addProtocolWarning("issuance", "notification_failed",
			"The issuer did not accept the notification for this credential. The credential is stored anyway. "+reading,
			details)
		return
	}
	w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), true, map[string]any{
		"direction": "inbound",
		"url":       notificationEndpoint,
		"endpoint":  "notification",
	}, &LogPayload{Label: "Response", Body: string(respBody)})
}

// readNotificationRefusal explains a Notification Endpoint answer against
// §11.3. It defines an Authorization Error Response (RFC 6750 §3) for a missing
// or invalid Access Token, and a 400 with a JSON error whose value SHOULD be
// invalid_notification_id or invalid_notification_request. It returns the
// explanation and the issuer's error code, if any.
func readNotificationRefusal(status int, body []byte) (string, string) {
	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	code := strings.TrimSpace(parsed.Error)

	switch {
	case status < 100:
		return "There was no answer, so the endpoint is unreachable.", code
	case status >= 200 && status < 300:
		return "The issuer accepted it (§11.2 makes any 2xx a success). Reading the response failed.", code
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "This is an Authorization Error Response (§11.3, RFC 6750 §3). The endpoint did not accept the access token of this issuance.", code
	// RFC 6750 §3.1 gives invalid_request a 400, so this 400 is an
	// Authorization Error Response.
	case status == http.StatusBadRequest && code == "invalid_request":
		return "This is an Authorization Error Response (§11.3, and RFC 6750 §3.1 gives invalid_request a 400).", code
	case status == http.StatusBadRequest && (code == "invalid_notification_id" || code == "invalid_notification_request"):
		return "This is a Notification Error Response (§11.3, " + code + ").", code
	case status == http.StatusBadRequest && code != "":
		return "§11.3 lists invalid_notification_id and invalid_notification_request for a 400. This response has " + code + ".", code
	case status == http.StatusBadRequest:
		return "§11.3 requires a 400 to carry a JSON error (invalid_notification_id or invalid_notification_request). This response has none.", code
	default:
		return fmt.Sprintf("§11.3 defines no response with status %d for this endpoint. An invalid access token gets an RFC 6750 §3 error, and an invalid notification_id gets a 400.", status), code
	}
}

func notificationRequestBody(notificationID string) map[string]any {
	return map[string]any{"notification_id": notificationID, "event": "credential_accepted"}
}

func sendNotificationWithDPoP(endpoint, accessToken, authScheme, notificationID string, dpopKey *ecdsa.PrivateKey, nonce *string, client *http.Client) (int, []byte, error) {
	body, err := json.Marshal(notificationRequestBody(notificationID))
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling notification request: %w", err)
	}
	// §11.2 requires a 2xx and only RECOMMENDS 204, so any 2xx is a success.
	respBody, statusCode, err := doDPoPRequest("POST", endpoint, "application/json", "", body, authScheme, accessToken, dpopKey, nonce, nil, client)
	if err != nil {
		return statusCode, respBody, err
	}
	if statusCode < 200 || statusCode >= 300 {
		return statusCode, respBody, fmt.Errorf("notification endpoint returned HTTP %d", statusCode)
	}
	return statusCode, respBody, nil
}

// fetchNonce requests a c_nonce from the Nonce Endpoint and logs the exchange.
// §7.1 makes the request an HTTP POST. When the POST gets a 405, debug mode
// retries with GET and warns. The caller decides whether an empty result stops
// the flow. §7.2 lets the issuer return a DPoP nonce here, so the DPoP nonce
// state is passed in.
func (w *Wallet) fetchNonce(metadata map[string]any, nonce *string) string {
	ep, _ := metadata["nonce_endpoint"].(string)
	if ep == "" {
		return ""
	}
	w.addProtocolLog("issuance", "nonce_request", fmt.Sprintf("Request nonce from %s", ep), true, map[string]any{
		"direction": "outbound",
		"method":    "POST",
		"url":       ep,
		"endpoint":  "nonce",
	})

	noncePayload := &LogPayload{}
	cNonce, status, err := nonceRequest(w.HTTPClient(), "POST", ep, nonce, noncePayload)
	reason := nonceFailureReason(status, err)
	if cNonce == "" && status == http.StatusMethodNotAllowed && w.Mode() == ValidationModeDebug {
		if getNonce, getStatus, getErr := nonceRequest(w.HTTPClient(), "GET", ep, nonce, noncePayload); getNonce != "" {
			w.AddWarning("issuance", fmt.Sprintf("The nonce endpoint %s answers a POST with 405 and serves a c_nonce only over GET. OID4VCI 1.0 §7.1 requires POST. Debug mode uses GET.", ep), nil)
			cNonce, reason = getNonce, ""
		} else {
			reason = nonceFailureReason(getStatus, getErr)
		}
	}

	details := map[string]any{
		"direction": "inbound",
		"url":       ep,
		"endpoint":  "nonce",
		"c_nonce":   cNonce,
	}
	if cNonce == "" {
		details["error"] = reason
	}
	w.addProtocolLog("issuance", "nonce_response", fmt.Sprintf("Nonce response from %s", ep), cNonce != "", details, noncePayload)
	return cNonce
}

// nonceRequest sends one Nonce Endpoint request and reads c_nonce from a 2xx
// response (§7.2). It returns the HTTP status so the caller can detect a 405.
func nonceRequest(client *http.Client, method, ep string, nonce *string, payloads ...*LogPayload) (string, int, error) {
	respBody, status, err := doDPoPRequest(method, ep, "", "", nil, "", "", nil, nonce, nil, client)
	if payload := firstLogPayload(payloads); payload != nil {
		payload.Label, payload.Body = "Response", string(respBody)
	}
	if err != nil {
		return "", status, err
	}
	var resp map[string]any
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", status, err
	}
	value, _ := resp["c_nonce"].(string)
	return value, status, nil
}

// nonceFailureReason reports the HTTP status of a failed request because error
// pages can be long. A transport failure keeps its error message.
func nonceFailureReason(status int, err error) string {
	if status >= 400 {
		return fmt.Sprintf("HTTP %d", status)
	}
	if err != nil {
		return err.Error()
	}
	return "the response carried no c_nonce"
}

// credentialAccept returns the Accept header for a credential request. It lists
// application/jwt only for encrypted responses. Given application/jwt on a
// plain request, an issuer may answer with a signed metadata JWT.
func credentialAccept(credentialResponseEncryption map[string]any) string {
	if credentialResponseEncryption != nil {
		return "application/json, application/jwt"
	}
	return "application/json"
}

// doDPoPRequest retries once for a DPoP nonce challenge and once for an
// attestation challenge (RFC 9449 §8, ABCA §6.2 and §7.4). One retry does not
// use up the other.
func doDPoPRequest(method, target, contentType, accept string, body []byte, authScheme, token string, key *ecdsa.PrivateKey, nonce *string, authenticator *clientAuthenticator, client *http.Client) ([]byte, int, error) {
	if accept == "" {
		accept = "application/json, application/jwt"
	}
	dpopRetried := false
	attestationRetried := false
	for {
		reqBody := body
		if authenticator != nil {
			var err error
			if reqBody, err = authenticator.formBody(contentType, body); err != nil {
				return nil, 0, err
			}
		}
		req, err := http.NewRequest(method, target, bytes.NewReader(reqBody))
		if err != nil {
			return nil, 0, fmt.Errorf("creating request: %w", err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", accept)
		if token != "" && authScheme != "" {
			req.Header.Set("Authorization", authScheme+" "+token)
		}
		if authenticator != nil {
			headers, err := authenticator.headers()
			if err != nil {
				return nil, 0, err
			}
			for headerName, headerValue := range headers {
				req.Header.Set(headerName, headerValue)
			}
		}
		if key != nil {
			dpopNonce := derefString(nonce)
			if authenticator != nil {
				challenge, err := authenticator.dpopChallenge()
				if err != nil {
					return nil, 0, err
				}
				if challenge != "" {
					dpopNonce = challenge
				}
			}
			dpopJWT, err := createDPoPProofJWT(key, method, target, dpopNonce, token)
			if err != nil {
				return nil, 0, fmt.Errorf("creating DPoP proof: %w", err)
			}
			req.Header.Set("DPoP", dpopJWT)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("request: %w", err)
		}
		respBody, readErr := format.ReadRemoteBody(resp.Body, "issuer response")
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("reading response: %w", readErr)
		}
		updateDPoPNonce(nonce, resp.Header)
		if authenticator != nil {
			authenticator.observe(resp.Header)
		}
		if needsDPoPRetry(resp.StatusCode, resp.Header, respBody) && !dpopRetried {
			dpopRetried = true
			continue
		}
		if resp.StatusCode >= 400 && authenticator != nil && authenticator.retryAfterRefusal(respBody) && !attestationRetried {
			attestationRetried = true
			continue
		}
		if resp.StatusCode >= 400 {
			// The caller needs the body. A Credential Error Response (§8.3.1.2)
			// carries an error code such as invalid_nonce, and the caller acts on it.
			return respBody, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return respBody, resp.StatusCode, nil
	}
}

func updateDPoPNonce(target *string, headers http.Header) {
	if target == nil {
		return
	}
	if value := strings.TrimSpace(headers.Get("DPoP-Nonce")); value != "" {
		*target = value
	}
}

// needsDPoPRetry reports a use_dpop_nonce refusal. An authorization server
// sends it as the error of a 400 (RFC 9449 §8), a resource server in the
// WWW-Authenticate challenge of a 401 (§9). Other refusals may carry a
// DPoP-Nonce as well (§8.2), and a retry would only repeat them.
func needsDPoPRetry(statusCode int, headers http.Header, body []byte) bool {
	if statusCode < 400 {
		return false
	}
	for _, challenge := range headers.Values("WWW-Authenticate") {
		if strings.Contains(challenge, `error="use_dpop_nonce"`) {
			return true
		}
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	errCode, _ := parsed["error"].(string)
	return errCode == "use_dpop_nonce"
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// runAuthorizationCodeRequest uses the authorization URL exactly once, because
// RFC 9126 §4 allows one use of a request_uri. A browser opens it when the
// callback reaches this wallet. Otherwise the wallet calls the endpoint itself.
func runAuthorizationCodeRequest(w *Wallet, endpoint, clientID, requestURI string, params url.Values, redirectURI, expectedState, expectedIssuer string, route consent.AuthorizationPrompt, issRequired bool) (url.Values, error) {
	authURL, err := authorizationRequestURL(endpoint, clientID, requestURI, params)
	if err != nil {
		return nil, err
	}

	if canUseInteractiveAuthorizationCallback(w, redirectURI) {
		callbackCh, unregister := w.Consents().RegisterAuthorizationCodeCallback(expectedState)
		defer unregister()

		// The user's browser opens the URL. A browser opened on a hosted wallet
		// server would not reach the user.
		route.URL = authURL
		if !w.Consents().NotifyAuthorization(route) {
			return nil, fmt.Errorf("this offer needs an interactive sign-in at %s, but no wallet UI is open to show it", authURL)
		}
		select {
		case values := <-callbackCh:
			if err := w.validateAuthorizationCodeResponse(values, expectedState, expectedIssuer, issRequired); err != nil {
				return nil, err
			}
			return values, nil
		case <-time.After(config.AuthorizationCallbackWait):
			return nil, fmt.Errorf("timed out waiting for authorization callback at %s", redirectURI)
		}
	}

	location, body, err := callAuthorizationEndpoint(authURL, w.HTTPClient())
	if err != nil {
		return nil, err
	}
	if location != "" {
		valuesOut, err := parseRedirectQuery(location)
		if err == nil {
			// An auth_via_web redirect carries auth_session when the
			// authorization continues at the challenge endpoint (OpenID4VCI 1.1
			// §6.2.1.2).
			if valuesOut.Get("code") != "" || valuesOut.Get("error") != "" || valuesOut.Get("auth_session") != "" {
				if err := w.validateAuthorizationCodeResponse(valuesOut, expectedState, expectedIssuer, issRequired); err != nil {
					return nil, err
				}
				return valuesOut, nil
			}
		}
	}

	if location != "" {
		return nil, fmt.Errorf("authorization requires interactive browser login at %q, but redirect_uri %q is not handled by the running wallet server", location, redirectURI)
	}
	return nil, fmt.Errorf("authorization requires interactive browser login, but redirect_uri %q is not handled by the running wallet server (body: %s)", redirectURI, truncateBody(body))
}

// validateAuthorizationCodeResponse checks the state and issuer of an
// authorization response through reportServerDeviation. A missing iss is a
// deviation only when the server advertised iss support (RFC 9207).
func (w *Wallet) validateAuthorizationCodeResponse(values url.Values, expectedState, expectedIssuer string, issRequired bool) error {
	if values == nil {
		return fmt.Errorf("authorization response is empty")
	}
	if expectedState = strings.TrimSpace(expectedState); expectedState != "" {
		switch state := values.Get("state"); {
		case state == "":
			if err := w.reportServerDeviation("the authorization response omitted state, which RFC 6749 §4.1.2 returns when the request carried one"); err != nil {
				return err
			}
		case state != expectedState:
			if err := w.reportServerDeviation(fmt.Sprintf("the authorization response state %q does not match the request's %q", state, expectedState)); err != nil {
				return err
			}
		}
	}

	// RFC 9207 §2.4: "This comparison MUST use simple string comparison as
	// defined in Section 6.2.1 of [RFC3986]."
	issuer := values.Get("iss")
	switch {
	case issuer == "" && issRequired:
		return w.reportServerDeviation("the authorization response omitted iss, which RFC 9207 requires when the authorization server advertises authorization_response_iss_parameter_supported, and FAPI 2.0 §5.3.2.2 requires under HAIP 1.0 §4")
	case issuer != "" && expectedIssuer != "" && !sameIdentifier(issuer, expectedIssuer):
		return w.reportServerDeviation(fmt.Sprintf("the authorization response iss %q does not match the expected issuer %q", issuer, expectedIssuer))
	}
	return nil
}

// authorizationRequestURL builds the authorization request. After PAR it sends
// only client_id and request_uri (RFC 9126 §4). Otherwise the parameters go in
// the query string (RFC 6749 §4.1.1). RFC 6749 §3.1: the endpoint's own query
// component "MUST be retained when adding additional query parameters".
func authorizationRequestURL(endpoint, clientID, requestURI string, params url.Values) (string, error) {
	// A javascript: or data: endpoint from issuer metadata would run in the
	// wallet's origin.
	if endpoint == "" {
		return "", fmt.Errorf("authorization server metadata did not include authorization_endpoint")
	}
	if err := format.ValidateAbsoluteURI("authorization_endpoint", endpoint); err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parsing authorization_endpoint: %w", err)
	}
	values := parsed.Query()
	if requestURI != "" {
		values.Set("request_uri", requestURI)
	} else {
		for key, entries := range params {
			values[key] = entries
		}
	}
	values.Set("client_id", clientID)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func callAuthorizationEndpoint(authURL string, baseClient *http.Client) (string, string, error) {
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("creating authorization request: %w", err)
	}

	client := *baseClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("authorization request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
	if resp.StatusCode == http.StatusOK {
		return "", string(body), nil
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("authorization endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", "", fmt.Errorf("authorization response missing Location header")
	}
	return location, string(body), nil
}

func parseRedirectQuery(location string) (url.Values, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parsing redirect URL: %w", err)
	}
	return parsed.Query(), nil
}

func canUseInteractiveAuthorizationCallback(w *Wallet, redirectURI string) bool {
	if w == nil {
		return false
	}
	// A wallet started without --base-url still serves /callback. The serve
	// command records the origin it answers on, and the default redirect URI
	// comes from that origin.
	base := strings.TrimSpace(w.BaseURL)
	if base == "" {
		base = strings.TrimSpace(w.ServingOrigin)
	}
	if base == "" {
		return false
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return false
	}
	if !sameLoopbackHost(redirectURL.Hostname(), baseURL.Hostname()) {
		return false
	}
	if redirectURL.Port() != baseURL.Port() {
		return false
	}
	return strings.HasSuffix(strings.TrimRight(redirectURL.Path, "/"), "/callback")
}

func sameLoopbackHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) || netaddr.IsLoopback(a) && netaddr.IsLoopback(b)
}

func truncateBody(body string) string {
	return format.Truncate(strings.TrimSpace(body), 200)
}

func tokenGrantRenewal(tokenResp map[string]any) (refreshToken string, expiresIn int) {
	refreshToken, _ = tokenResp["refresh_token"].(string)
	if seconds, ok := tokenResp["expires_in"].(float64); ok && seconds > 0 {
		expiresIn = int(seconds)
	}
	return refreshToken, expiresIn
}
