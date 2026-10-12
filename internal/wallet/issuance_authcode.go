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

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
)

type dpopNonceState struct {
	authzServer string
	resource    string
}

func (w *Wallet) processAuthorizationCodeOffer(
	offer *oid4vc.CredentialOffer,
	metadata map[string]any,
	oauthMeta map[string]any,
	tokenEndpoint string,
	credentialEndpoint string,
	opts OfferOptions,
) (*IssuanceResult, error) {
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
	dpopKey := w.dpopKeyFor(oauthMeta)

	configID := ""
	if len(offer.CredentialConfigurationIDs) > 0 {
		configID = offer.CredentialConfigurationIDs[0]
	}
	scope := resolveCredentialScope(metadata, configID)
	if scope == "" {
		return nil, fmt.Errorf("credential configuration %q did not expose a scope for authorization_code flow", configID)
	}

	state := randomBase64URL(18)
	codeVerifier := randomBase64URL(32)
	codeChallenge := codeChallengeS256(codeVerifier)
	nonces := &dpopNonceState{}
	parForm := url.Values{}
	parForm.Set("response_type", "code")
	parForm.Set("client_id", clientID)
	parForm.Set("redirect_uri", redirectURI)
	parForm.Set("scope", scope)
	parForm.Set("state", state)
	parForm.Set("code_challenge", codeChallenge)
	parForm.Set("code_challenge_method", "S256")
	if offer.Grants.IssuerState != "" {
		parForm.Set("issuer_state", offer.Grants.IssuerState)
	}
	authCtx := clientAuthContext{oauthMeta: oauthMeta, clientID: clientID, tokenEndpoint: tokenEndpoint}
	clientAuth := w.resolveClientAuthentication(clientAuthMethod, authCtx)
	if err := applyClientAuthentication(parForm, clientAuth, w.HolderKey); err != nil {
		return nil, err
	}

	setup := authorizationCodeSetup{
		clientID:              clientID,
		redirectURI:           redirectURI,
		scope:                 scope,
		state:                 state,
		codeVerifier:          codeVerifier,
		codeChallenge:         codeChallenge,
		clientAuth:            clientAuth,
		dpopKey:               dpopKey,
		nonces:                nonces,
		authorizationEndpoint: authorizationEndpoint,
		issuer:                oauthIssuer(oauthMeta, ""),
		issRequired:           issAdvertised(oauthMeta),

		presentationConsented: opts.PresentationConsented,
		owner:                 opts.Owner,
	}
	issuance := authorizationCodeIssuance{
		offer:              offer,
		metadata:           metadata,
		tokenEndpoint:      tokenEndpoint,
		credentialEndpoint: credentialEndpoint,
		clientID:           clientID,
		codeVerifier:       codeVerifier,
		clientAuth:         clientAuth,
		dpopKey:            dpopKey,
		nonces:             nonces,
		configID:           configID,
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
			// The browser sign-in uses the server's pushed request when it
			// supplies one.
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
		parResp, err := postFormWithDPoP(w.HTTPClient(), parEndpoint, parForm, dpopKey, "", &nonces.authzServer, w.attestorFor(clientAuth), parPayload)
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
	callbackValues, err := runAuthorizationCodeRequest(w, authorizationEndpoint, clientID, requestURI, parForm, redirectURI, state, oauthIssuer(oauthMeta, ""), opts.Owner, issAdvertised(oauthMeta))
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
	clientID      string
	redirectURI   string
	scope         string
	state         string
	codeVerifier  string
	codeChallenge string
	clientAuth    *ClientAuthentication
	dpopKey       *ecdsa.PrivateKey
	nonces        *dpopNonceState
	// The auth_via_web interaction (OpenID4VCI 1.1 §6.2.1.2) takes the
	// request_uri to authorizationEndpoint and checks the redirect back against
	// issuer.
	authorizationEndpoint string
	issuer                string
	// issRequired is set when the authorization server advertises
	// authorization_response_iss_parameter_supported. RFC 9207 then makes iss
	// REQUIRED in the response.
	issRequired bool
	// presentationConsented is set when the caller already consented to a
	// presentation the issuer asks for.
	presentationConsented bool
	// owner identifies the browser the issuance belongs to.
	owner string
}

// authorizationCodeIssuance holds what the token and credential requests need,
// whichever flow produced the code.
type authorizationCodeIssuance struct {
	offer              *oid4vc.CredentialOffer
	metadata           map[string]any
	tokenEndpoint      string
	credentialEndpoint string
	clientID           string
	// redirectURI is empty when the flow that produced the code had none. The
	// token request then omits it (RFC 6749 §4.1.3).
	redirectURI  string
	codeVerifier string
	clientAuth   *ClientAuthentication
	dpopKey      *ecdsa.PrivateKey
	nonces       *dpopNonceState
	configID     string
}

func (w *Wallet) completeAuthorizationCodeIssuance(ctx authorizationCodeIssuance, code string) (*IssuanceResult, error) {
	offer := ctx.offer
	metadata := ctx.metadata
	tokenEndpoint := ctx.tokenEndpoint
	credentialEndpoint := ctx.credentialEndpoint
	clientID := ctx.clientID
	clientAuth := ctx.clientAuth
	dpopKey := ctx.dpopKey
	nonces := ctx.nonces
	configID := ctx.configID

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("client_id", clientID)
	if ctx.redirectURI != "" {
		tokenForm.Set("redirect_uri", ctx.redirectURI)
	}
	tokenForm.Set("code_verifier", ctx.codeVerifier)
	if err := applyClientAuthentication(tokenForm, clientAuth, w.HolderKey); err != nil {
		return nil, err
	}

	attestor := w.attestorFor(clientAuth)
	tokenDetails := formRequestLogDetails(tokenEndpoint, "token", tokenForm)
	tokenDetails["client_attestation"] = attestor != nil
	tokenDetails["dpop"] = dpopKey != nil
	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", tokenEndpoint), true, tokenDetails, &LogPayload{Label: "Request", Body: tokenForm.Encode()})
	tokenPayload := &LogPayload{}
	tokenResp, err := postFormWithDPoP(w.HTTPClient(), tokenEndpoint, tokenForm, dpopKey, "", &nonces.authzServer, attestor, tokenPayload)
	w.addProtocolLog("issuance", "token_response", fmt.Sprintf("Token response from %s", tokenEndpoint), err == nil, responseMapLogDetails(tokenEndpoint, "token", tokenResp, err), tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	accessToken, _ := tokenResp["access_token"].(string)
	refreshToken, expiresIn := tokenGrantRenewal(tokenResp)
	if accessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	if err := w.checkTokenType(tokenResp, dpopKey != nil); err != nil {
		return nil, err
	}
	authScheme := accessTokenScheme(tokenResp, dpopKey != nil)

	cNonce, err := w.issuanceChallenge(metadata, tokenResp, offer.CredentialIssuer, &nonces.resource)
	if err != nil {
		return nil, err
	}

	proofKeys, err := issuanceProofKeys(w.HolderKey, metadata)
	if err != nil {
		return nil, fmt.Errorf("preparing proof keys: %w", err)
	}

	credentialIdentifier, authorizedOther := resolveCredentialIdentifier(tokenResp, configID)
	w.reportAuthorizedConfiguration(offer.CredentialIssuer, configID, authorizedOther)
	credentialConfigurationID := ""
	if credentialIdentifier == "" && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(w.Mode(), metadata, w.HolderKey)
	if err != nil {
		return nil, err
	}

	attempt := credentialRequestAttempt{
		metadata:                  metadata,
		endpoint:                  credentialEndpoint,
		issuer:                    offer.CredentialIssuer,
		configID:                  configID,
		accessToken:               accessToken,
		authScheme:                authScheme,
		credentialIdentifier:      credentialIdentifier,
		credentialConfigurationID: credentialConfigurationID,
		responseEncryption:        responseEncryption,
		dpopKey:                   dpopKey,
		proofKeys:                 proofKeys,
		// The authorization code flow always identifies the client. The key
		// proof carries it as iss for issuers that bind the token to the
		// client.
		clientID: clientID,
		nonce:    &nonces.resource,
	}
	proofs, err := w.buildCredentialProofs(attempt, cNonce)
	if err != nil {
		return nil, err
	}

	credResp, err := w.requestCredentialWithNonceRetry(attempt, proofs)
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	credResp, pending, err := w.resolveDeferredCredential(credResp, deferredContext{
		metadata:      metadata,
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		clientAuth:    clientAuth,
		refreshToken:  refreshToken,
		expiresIn:     expiresIn,
		issuer:        offer.CredentialIssuer,
		configID:      configID,
		format:        resolveCredentialFormat(metadata, credentialConfigurationID),
		accessToken:   accessToken,
		authScheme:    authScheme,
		dpopKey:       dpopKey,
		proofKeys:     proofKeys,
		nonce:         &nonces.resource,
	})
	if err != nil {
		return nil, err
	}
	display := w.resolveCredentialDisplay(metadata, configID)
	if pending != nil {
		pending.Display = display
		return w.recordDeferredIssuance(pending), nil
	}

	credential, err := selectPrimaryCredential(credResp, proofKeys)
	if err != nil {
		return nil, err
	}

	imported, err := w.importPrimaryCredential(credential, proofKeys)
	if err != nil {
		return nil, fmt.Errorf("importing received credential: %w", err)
	}
	importDetails := credentialImportLogDetails(imported, credential)
	w.rememberRenewal(imported.ID, refreshToken, CredentialRenewal{
		Issuer:             offer.CredentialIssuer,
		TokenEndpoint:      tokenEndpoint,
		CredentialEndpoint: credentialEndpoint,
		ConfigurationID:    configID,
		ClientID:           clientID,
		UseDPoP:            dpopKey != nil,
		ClientAuth:         clientAuth,
	})
	w.rememberDisplay(imported, display)
	stored := w.storeBatchSiblings(imported, credResp, proofKeys, display)
	w.logCredentialImport(imported, offer.CredentialIssuer, importDetails, stored)

	w.notifyCredentialAccepted(metadata, credResp, accessToken, authScheme, dpopKey, &nonces.resource)

	credFormat := resolveCredentialFormat(metadata, credentialConfigurationID)
	if credFormat == "" {
		credFormat = imported.Format
	}
	verificationStatus, verificationDetail := verifyImportedJWTMetadataSignature(credential, w.HTTPClient())
	return &IssuanceResult{
		CredentialID:       imported.ID,
		Format:             credFormat,
		Issuer:             offer.CredentialIssuer,
		VerificationStatus: verificationStatus,
		VerificationDetail: verificationDetail,
		Imported:           imported,
	}, nil
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
	details := map[string]any{"deviation": detail}
	if w.Mode() == ValidationModeStrict {
		w.addProtocolLog("issuance", "server_deviation", detail, false, details)
		return fmt.Errorf("%s", detail)
	}
	w.addProtocolWarning("issuance", "server_deviation", detail, details)
	log.Printf("[VCI] WARNING: %s", detail)
	return nil
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

// issAdvertised reports whether the authorization server advertises
// authorization_response_iss_parameter_supported. RFC 9207 then makes iss
// REQUIRED in the authorization response.
func issAdvertised(oauthMeta map[string]any) bool {
	supported, _ := oauthMeta["authorization_response_iss_parameter_supported"].(bool)
	return supported
}

// attestsClient reports whether to authenticate with the wallet attestation.
// The wallet attests when the server advertises it
// (draft-ietf-oauth-attestation-based-client-auth §8) or when
// ForceClientAttestation is set.
//
// HAIP 1.0 §4.4.1 says "Wallets MUST use, and Issuers MUST require, an OAuth2
// Client authentication mechanism". Under HAIP the wallet also attests when no
// method is advertised, since §10.1 makes advertising only a SHOULD. When only
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
	if !w.RequireHAIP {
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
	clientID      string
	tokenEndpoint string
}

// resolveClientAuthentication returns the client authentication to store with
// the credential for refresh requests. It returns nil for unauthenticated
// access.
func (w *Wallet) resolveClientAuthentication(method string, ctx clientAuthContext) *ClientAuthentication {
	if method == ClientAuthPrivateKeyJWT {
		return &ClientAuthentication{
			Method:   ClientAuthPrivateKeyJWT,
			ClientID: ctx.clientID,
			Audience: oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		}
	}
	if w.attestsClient(ctx.oauthMeta) {
		// §10.1 lets an issuer require attestation without advertising it. The
		// wallet attests and warns about the missing advertisement.
		if w != nil && w.RequireHAIP && w.Mode() != ValidationModeStrict &&
			!w.ForceClientAttestation &&
			detectTokenEndpointAuthMethod(ctx.oauthMeta) == "" {
			w.addProtocolWarning("issuance", "client_authentication_not_advertised",
				"The issuer's authorization server advertises no token endpoint client authentication method (draft-ietf-oauth-attestation-based-client-auth §10.1 recommends it). Attesting anyway, since HAIP requires client authentication.",
				map[string]any{"token_endpoint": ctx.tokenEndpoint})
		}
		return w.attestationClientAuth(ctx)
	}
	if w != nil && w.RequireHAIP && !w.ForceClientAttestation {
		w.addProtocolWarning("issuance", "haip_client_authentication_unavailable",
			"HAIP 1.0 §4.4.1 requires client authentication at the token endpoint, but this issuer's authorization server offers only unauthenticated access. Proceeding without it.",
			map[string]any{"token_endpoint": ctx.tokenEndpoint})
	}
	return nil
}

func (w *Wallet) attestationClientAuth(ctx clientAuthContext) *ClientAuthentication {
	challengeEndpoint, _ := ctx.oauthMeta["challenge_endpoint"].(string)
	auth := &ClientAuthentication{
		Method:            ClientAuthAttestation,
		ClientID:          ctx.clientID,
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
// combined possession proof (draft-10 §5.2).
func usesDPoP(oauthMeta map[string]any) bool {
	return supportsDPoP(oauthMeta) || usesCombinedPoP(oauthMeta)
}

// dpopKeyFor returns the DPoP signing key for this authorization server. It is
// nil when the server uses neither DPoP nor the combined possession proof. RFC
// 9449 makes the metadata optional, so the wallet treats a server without it as
// issuing bearer tokens.
func (w *Wallet) dpopKeyFor(oauthMeta map[string]any) *ecdsa.PrivateKey {
	if usesDPoP(oauthMeta) {
		return w.HolderKey
	}
	return nil
}

func (w *Wallet) attestorFor(auth *ClientAuthentication) *clientAttestor {
	if auth == nil || auth.Method != ClientAuthAttestation {
		return nil
	}
	return &clientAttestor{wallet: w, auth: auth}
}

// clientAttestor adds the wallet attestation to requests and tracks the
// server's challenges. Every supported ABCA draft lets a server return a fresh
// challenge in the OAuth-Client-Attestation-Challenge header of any response.
// The client MUST send it in the next PoP.
type clientAttestor struct {
	wallet *Wallet
	auth   *ClientAuthentication
	// challenge is the server-provided challenge for the next PoP.
	challenge string
}

// headers creates the attestation headers for one request. In combined mode the
// challenge goes in the DPoP proof instead (see dpopChallenge).
func (a *clientAttestor) headers() (map[string]string, error) {
	challenge := ""
	if !a.auth.CombinedPoP {
		var err error
		challenge, err = a.requestChallenge()
		if err != nil {
			return nil, err
		}
	}
	headers, err := createClientAttestationHeaders(a.wallet, a.auth, challenge)
	if err != nil {
		return nil, fmt.Errorf("creating client attestation headers: %w", err)
	}
	return headers, nil
}

// requestChallenge returns the challenge for one request. A challenge from a
// response header is single use, so it is consumed here. Without one the wallet
// fetches a fresh challenge from the challenge endpoint.
func (a *clientAttestor) requestChallenge() (string, error) {
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
func (a *clientAttestor) dpopChallenge() (string, error) {
	if !a.auth.CombinedPoP {
		return "", nil
	}
	return a.requestChallenge()
}

func (a *clientAttestor) observe(headers http.Header) {
	if value := strings.TrimSpace(headers.Get("OAuth-Client-Attestation-Challenge")); value != "" {
		a.challenge = value
	}
}

// retryAfterRefusal reports whether a refusal asks for a retry with fresh
// attestation material. use_attestation_challenge comes with the challenge for
// the retry (§6.2 requires the header alongside it). use_fresh_attestation
// needs no extra step because the wallet creates a new attestation per request.
func (a *clientAttestor) retryAfterRefusal(body []byte) bool {
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

// private_key_jwt uses form fields. Attestation authentication uses headers.
func applyClientAuthentication(form url.Values, auth *ClientAuthentication, holderKey *ecdsa.PrivateKey) error {
	if auth == nil || auth.Method != ClientAuthPrivateKeyJWT {
		return nil
	}
	assertion, err := createClientAssertionJWT(holderKey, auth.ClientID, auth.Audience)
	if err != nil {
		return fmt.Errorf("creating client assertion: %w", err)
	}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return nil
}

// createClientAttestationHeaders creates the attestation and, outside combined
// mode, the PoP for the attested key. Both carry the union of the claims the
// supported drafts define (the draft-07 shape). Every draft lets a JWT carry
// claims it does not define (§5.1 and §5.2 rule 1), so one shape verifies under
// all of them.
func createClientAttestationHeaders(w *Wallet, auth *ClientAuthentication, challenge string) (map[string]string, error) {
	if w == nil || w.IssuerKey == nil || len(w.CertChain) == 0 {
		return nil, fmt.Errorf("wallet issuer signing material is not configured")
	}

	signingKey, chain, err := w.WalletProviderSigningMaterial()
	if err != nil {
		return nil, err
	}

	x5c := buildJWSX5C(chain)
	holderJWK := mock.SigningJWKMap(&w.HolderKey.PublicKey)
	clientAttestationHeader := map[string]any{
		"alg": "ES256",
		"typ": "oauth-client-attestation+jwt",
		"x5c": x5c,
	}
	if kid := mock.KeyIDForPublicKey(&signingKey.PublicKey); kid != "" {
		clientAttestationHeader["kid"] = kid
	}
	clientAttestationPayload := map[string]any{
		"sub": auth.ClientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
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
		"alg": "ES256",
		"typ": "oauth-client-attestation-pop+jwt",
		"jwk": holderJWK,
	}
	popPayload := map[string]any{
		"aud": auth.Audience,
		"iat": time.Now().Unix(),
		"jti": randomBase64URL(18),
		// Draft-07 §5.2 requires iss and defines nbf. Later drafts allow extra
		// claims (§5.2 rule 1).
		"iss": auth.ClientID,
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if challenge != "" {
		popPayload["challenge"] = challenge
	}
	clientAttestationPoP, err := signJWT(popHeader, popPayload, w.HolderKey)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"OAuth-Client-Attestation":     clientAttestationJWT,
		"OAuth-Client-Attestation-PoP": clientAttestationPoP,
	}, nil
}

func fetchAttestationChallenge(endpoint string, clients ...*http.Client) (string, error) {
	if endpoint == "" {
		return "", nil
	}
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating challenge request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := doIssuanceRequest(req, clients...)
	if err != nil {
		return "", fmt.Errorf("challenge request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
		return "", fmt.Errorf("challenge endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
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
	if w == nil || w.IssuerKey == nil || len(w.CertChain) == 0 {
		return "", fmt.Errorf("wallet issuer signing material is not configured")
	}
	signingKey, chain, err := w.WalletProviderSigningMaterial()
	if err != nil {
		return "", err
	}

	if len(proofKeys) == 0 {
		proofKeys = []*ecdsa.PrivateKey{w.HolderKey}
	}
	attestedKeys := make([]any, 0, len(proofKeys))
	for _, key := range proofKeys {
		attestedKeys = append(attestedKeys, mock.SigningJWKMap(&key.PublicKey))
	}
	header := map[string]any{
		"alg": "ES256",
		"typ": "key-attestation+jwt",
		"x5c": buildJWSX5C(chain),
	}
	if kid := mock.KeyIDForPublicKey(&signingKey.PublicKey); kid != "" {
		header["kid"] = kid
	}
	payload := map[string]any{
		"iat":           time.Now().Unix(),
		"nbf":           time.Now().Unix(),
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
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

// keyAttestationLevelValues are the values Appendix D.2 defines for those
// claims.
var keyAttestationLevelValues = []string{"iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"}

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
		w.AddWarning("issuance", "The key attestation claims key storage levels this wallet's file-held keys cannot back (a test setting, see --key-attestation-level)", claims)
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

// proofSigningAlgFinding reports a proof type whose
// proof_signing_alg_values_supported lacks ES256, the only algorithm this
// wallet signs with. Appendix F.1 and F.3 require the proof alg to be in that
// list. HAIP 1.0 §7 also requires issuers to support ES256 for key proofs and
// key attestations.
func proofSigningAlgFinding(metadata map[string]any, configID string, requireHAIP bool) string {
	proofType := credentialProofType(metadata, configID)
	proof, _ := credentialProofTypes(metadata, configID)[proofType].(map[string]any)
	algs, ok := proof["proof_signing_alg_values_supported"].([]any)
	if !ok {
		return ""
	}
	for _, alg := range algs {
		if alg == "ES256" {
			return ""
		}
	}
	finding := fmt.Sprintf("OID4VCI 1.0 Appendix F: the %s proof type lists proof_signing_alg_values_supported %v without ES256, the algorithm this wallet signs with", proofType, algs)
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
		"alg": "ES256",
		"typ": "JWT",
		"kid": mock.KeyIDForPublicKey(&key.PublicKey),
	}
	payload := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"jti": randomBase64URL(18),
	}
	return signJWT(header, payload, key)
}

func createDPoPProofJWT(key *ecdsa.PrivateKey, method, targetURL, nonce, accessToken, challenge string) (string, error) {
	jwk := mock.SigningJWKMap(&key.PublicKey)
	header := map[string]any{
		"alg": "ES256",
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
	// The challenge for combined mode attestation-based client authentication
	// (draft-10 §5.2), where this proof is the possession proof.
	if challenge != "" {
		payload["challenge"] = challenge
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
			// Skip the body when the message already contains it.
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

func postFormWithDPoP(client *http.Client, target string, form url.Values, key *ecdsa.PrivateKey, accessToken string, nonce *string, attestor *clientAttestor, payloads ...*LogPayload) (map[string]any, error) {
	body := []byte(form.Encode())
	respBody, status, err := doDPoPRequest("POST", target, "application/x-www-form-urlencoded", "", body, "", accessToken, key, nonce, attestor, client)
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

func requestCredentialWithDPoP(client *http.Client, mode ValidationMode, metadata map[string]any, endpoint, accessToken, authScheme string, proofs credentialProofs, credentialIdentifier, credentialConfigurationID string, credentialResponseEncryption map[string]any, dpopKey, holderKey *ecdsa.PrivateKey, nonce *string, traces ...*credentialExchangeLog) (map[string]any, error) {
	reqBody := credentialRequestBody(proofs, credentialIdentifier, credentialConfigurationID, credentialResponseEncryption)
	body, contentType, err := prepareCredentialRequestBody(mode, metadata, reqBody)
	var responsePayload *LogPayload
	if len(traces) > 0 && traces[0] != nil {
		trace := traces[0]
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
	respBody, _, reqErr := doDPoPRequest("POST", endpoint, contentType, credentialAccept(credentialResponseEncryption), body, authScheme, accessToken, dpopKey, nonce, nil, client)
	out, parseErr := parseCredentialResponseBody(respBody, holderKey, responsePayload)
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

// deferredContext holds the request settings for collecting a deferred
// credential after the issuance flow ends.
type deferredContext struct {
	metadata         map[string]any
	tokenEndpoint    string
	clientID         string
	clientAuth       *ClientAuthentication
	refreshToken     string
	expiresIn        int
	issuer           string
	configID         string
	format           string
	deferredEndpoint string
	accessToken      string
	authScheme       string
	dpopKey          *ecdsa.PrivateKey
	proofKeys        []*ecdsa.PrivateKey
	nonce            *string
}

// resolveDeferredCredential returns a completed response unchanged. A
// transaction_id response becomes a DeferredIssuance for background collection.
func (w *Wallet) resolveDeferredCredential(credResp map[string]any, ctx deferredContext) (map[string]any, *DeferredIssuance, error) {
	txID, _ := credResp["transaction_id"].(string)
	if txID == "" {
		return credResp, nil, nil
	}
	ctx.deferredEndpoint, _ = ctx.metadata["deferred_credential_endpoint"].(string)
	if ctx.deferredEndpoint == "" {
		return nil, nil, fmt.Errorf("issuer deferred the credential but published no deferred_credential_endpoint")
	}

	// The poller collects the credential, so the caller (a consent dialog, a
	// CLI run) does not wait out the issuer's interval.
	interval := deferredPollInterval
	if seconds, ok := numericValue(credResp["interval"]); ok && seconds >= 1 {
		interval = time.Duration(seconds) * time.Second
	}
	pending, err := newDeferredIssuance(ctx, txID, interval)
	if err != nil {
		return nil, nil, err
	}
	return nil, pending, nil
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
	out, parseErr := parseCredentialResponseBody(respBody, holderKey, responsePayload)
	if parseErr != nil {
		if reqErr != nil {
			return nil, reqErr
		}
		return nil, fmt.Errorf("parsing deferred credential response: %w", parseErr)
	}

	if pending, interval := deferredIssuancePending(out); pending {
		return nil, stillPendingError{transactionID: transactionID, interval: interval}
	}
	if errMsg, _ := out["error"].(string); errMsg != "" {
		desc, _ := out["error_description"].(string)
		return nil, fmt.Errorf("deferred credential error: %s: %s", errMsg, desc)
	}
	if reqErr != nil {
		return nil, reqErr
	}
	return out, nil
}

// deferredIssuancePending reports whether a deferred credential response is
// still pending and how long to wait. OpenID4VCI 1.0 §9.2 answers that case
// with a 202 carrying interval and transaction_id.
func deferredIssuancePending(out map[string]any) (bool, time.Duration) {
	interval := deferredPollInterval
	if seconds, ok := numericValue(out["interval"]); ok && seconds >= 1 {
		interval = time.Duration(seconds) * time.Second
	}
	if txID, _ := out["transaction_id"].(string); txID != "" && len(credentialStringsFromResponse(out)) == 0 {
		return true, interval
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
			"The issuer did not accept the notification for this credential, which is stored either way. "+reading,
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
		return "Nothing was answered, so this is the endpoint being unreachable rather than the issuer refusing.", code
	case status >= 200 && status < 300:
		return "The status says the issuer took it (§11.2 makes any 2xx a success), so what failed is reading the response.", code
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "That is the Authorization Error Response §11.3 points at (RFC 6750 §3): the endpoint did not accept the access token this issuance was granted.", code
	// RFC 6750 §3.1 gives invalid_request a 400, so this 400 is an
	// Authorization Error Response.
	case status == http.StatusBadRequest && code == "invalid_request":
		return "That is the Authorization Error Response §11.3 points at (RFC 6750 §3.1 gives invalid_request a 400).", code
	case status == http.StatusBadRequest && (code == "invalid_notification_id" || code == "invalid_notification_request"):
		return "That is a Notification Error Response of §11.3 (" + code + ").", code
	case status == http.StatusBadRequest && code != "":
		return "§11.3 lists invalid_notification_id and invalid_notification_request for a 400, and this names " + code + " instead.", code
	case status == http.StatusBadRequest:
		return "§11.3 requires a 400 to carry a JSON error, whose value SHOULD be invalid_notification_id or invalid_notification_request. This one carries no error at all.", code
	default:
		return fmt.Sprintf("§11.3 defines no response with status %d for this endpoint: an invalid access token is answered per RFC 6750 §3, an invalid notification_id with 400.", status), code
	}
}

func notificationRequestBody(notificationID string) map[string]any {
	return map[string]any{"notification_id": notificationID, "event": "credential_accepted"}
}

func sendNotificationWithDPoP(endpoint, accessToken, authScheme, notificationID string, dpopKey *ecdsa.PrivateKey, nonce *string, clients ...*http.Client) (int, []byte, error) {
	body, err := json.Marshal(notificationRequestBody(notificationID))
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling notification request: %w", err)
	}
	// §11.2 requires a 2xx and only RECOMMENDS 204, so any 2xx is a success.
	respBody, statusCode, err := doDPoPRequest("POST", endpoint, "application/json", "", body, authScheme, accessToken, dpopKey, nonce, nil, clients...)
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
			w.AddWarning("issuance", fmt.Sprintf("The nonce endpoint %s answered the HTTP POST that OID4VCI 1.0 §7.1 requires with 405 and serves a c_nonce only over GET. Debug mode uses GET as a workaround.", ep), nil)
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
func doDPoPRequest(method, target, contentType, accept string, body []byte, authScheme, token string, key *ecdsa.PrivateKey, nonce *string, attestor *clientAttestor, clients ...*http.Client) ([]byte, int, error) {
	if accept == "" {
		accept = "application/json, application/jwt"
	}
	dpopRetried := false
	attestationRetried := false
	for {
		reqBody := bytes.NewReader(body)
		req, err := http.NewRequest(method, target, reqBody)
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
		if attestor != nil {
			headers, err := attestor.headers()
			if err != nil {
				return nil, 0, err
			}
			for headerName, headerValue := range headers {
				req.Header.Set(headerName, headerValue)
			}
		}
		if key != nil {
			challenge := ""
			if attestor != nil {
				var err error
				challenge, err = attestor.dpopChallenge()
				if err != nil {
					return nil, 0, err
				}
			}
			dpopJWT, err := createDPoPProofJWT(key, method, target, derefString(nonce), token, challenge)
			if err != nil {
				return nil, 0, fmt.Errorf("creating DPoP proof: %w", err)
			}
			req.Header.Set("DPoP", dpopJWT)
		}

		resp, err := doIssuanceRequest(req, clients...)
		if err != nil {
			return nil, 0, fmt.Errorf("request: %w", err)
		}
		respBody, readErr := format.ReadRemoteBody(resp.Body, "issuer response")
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("reading response: %w", readErr)
		}
		updateDPoPNonce(nonce, resp.Header)
		if attestor != nil {
			attestor.observe(resp.Header)
		}
		if needsDPoPRetry(resp.StatusCode, resp.Header, respBody) && !dpopRetried {
			dpopRetried = true
			continue
		}
		if resp.StatusCode >= 400 && attestor != nil && attestor.retryAfterRefusal(respBody) && !attestationRetried {
			attestationRetried = true
			continue
		}
		if resp.StatusCode >= 400 {
			// The caller needs the body. A Credential Error Response (§8.3.1.2)
			// carries the code it acts on, such as invalid_nonce.
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

func needsDPoPRetry(statusCode int, headers http.Header, body []byte) bool {
	if statusCode < 400 {
		return false
	}
	if strings.TrimSpace(headers.Get("DPoP-Nonce")) != "" {
		return true
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
func runAuthorizationCodeRequest(w *Wallet, endpoint, clientID, requestURI string, params url.Values, redirectURI, expectedState, expectedIssuer, owner string, issRequired bool) (url.Values, error) {
	authURL, err := authorizationRequestURL(endpoint, clientID, requestURI, params)
	if err != nil {
		return nil, err
	}

	if canUseInteractiveAuthorizationCallback(w, redirectURI) {
		callbackCh, unregister := w.RegisterAuthorizationCodeCallback(expectedState)
		defer unregister()

		// The user's browser opens the URL. A browser opened on a hosted wallet
		// server would not reach the user.
		if !w.NotifyAuthorization(AuthorizationPrompt{URL: authURL, Owner: owner}) {
			return nil, fmt.Errorf("this offer needs an interactive sign-in at %s, and nothing is attached to this wallet that can open it", authURL)
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

	expectedIssuer = normalizeIssuerURL(expectedIssuer)
	issuer := normalizeIssuerURL(values.Get("iss"))
	switch {
	case issuer == "" && issRequired:
		return w.reportServerDeviation("the authorization response omitted iss, which RFC 9207 requires when the authorization server advertises authorization_response_iss_parameter_supported")
	case issuer != "" && expectedIssuer != "" && issuer != expectedIssuer:
		return w.reportServerDeviation(fmt.Sprintf("the authorization response iss %q does not match the expected issuer %q", values.Get("iss"), expectedIssuer))
	}
	return nil
}

// authorizationRequestURL builds the authorization request. After PAR it sends
// only client_id and request_uri (RFC 9126 §4). Otherwise the parameters go in
// the query string (RFC 6749 §4.1.1).
func authorizationRequestURL(endpoint, clientID, requestURI string, params url.Values) (string, error) {
	values := url.Values{}
	if requestURI != "" {
		values.Set("client_id", clientID)
		values.Set("request_uri", requestURI)
	} else {
		for key, entries := range params {
			for _, entry := range entries {
				values.Add(key, entry)
			}
		}
		values.Set("client_id", clientID)
	}
	// A javascript: or data: endpoint from issuer metadata would run in the
	// wallet's origin.
	authURL := endpoint + "?" + values.Encode()
	if err := validateAbsoluteURI("authorization_endpoint", authURL); err != nil {
		return "", err
	}
	return authURL, nil
}

func callAuthorizationEndpoint(authURL string, clients ...*http.Client) (string, string, error) {
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("creating authorization request: %w", err)
	}

	baseClient := format.HTTPClientForURL(req.URL.String(), clients...)
	if httpClient != defaultHTTPClient {
		if overridden, ok := httpClient.(*http.Client); ok && overridden != nil {
			baseClient = overridden
		}
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
	a = strings.TrimSpace(strings.ToLower(a))
	b = strings.TrimSpace(strings.ToLower(b))
	if a == b {
		return true
	}
	loopback := map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
		"::1":       true,
	}
	return loopback[a] && loopback[b]
}

func truncateBody(body string) string {
	body = strings.TrimSpace(body)
	if len(body) <= 200 {
		return body
	}
	return body[:200] + "..."
}

func tokenGrantRenewal(tokenResp map[string]any) (refreshToken string, expiresIn int) {
	refreshToken, _ = tokenResp["refresh_token"].(string)
	if seconds, ok := tokenResp["expires_in"].(float64); ok && seconds > 0 {
		expiresIn = int(seconds)
	}
	return refreshToken, expiresIn
}
