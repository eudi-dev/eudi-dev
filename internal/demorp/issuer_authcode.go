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
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

// The demo has one fixed account. The login page shows its credentials. A
// sign-in is valid only for one issuance flow.
const (
	demoAccountUsername  = "alice"
	demoAccountPassword  = "alice"
	demoAccountGivenName = "Alice"
	demoAccountFamily    = "Anderson"

	authCodeGrant = "authorization_code"

	// requestURIPrefix is the URN form RFC 9126 requires for a PAR request URI.
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	authRequestTTL   = 5 * time.Minute

	// draft-ietf-oauth-attestation-based-client-auth-10 has two methods. One
	// uses a dedicated PoP JWT. In the other the DPoP proof is the only PoP
	// (§5.2). unauthenticatedClientAuth is the registered method name for no
	// client authentication.
	attestationClientAuth     = "attest_jwt_client_auth"
	attestationDPoPClientAuth = "attest_jwt_client_auth_dpop"
	unauthenticatedClientAuth = "none"
)

// ClientAuthMode controls authentication at the PAR and token endpoints.
type ClientAuthMode string

const (
	// ClientAuthRequired is the default, and what HAIP 1.0 §4.4.1 asks for:
	// "Wallets MUST use, and Issuers MUST require, an OAuth2 Client
	// authentication mechanism at OAuth2 Endpoints that support client
	// authentication (such as the PAR and Token Endpoints)."
	ClientAuthRequired ClientAuthMode = "required"
	// ClientAuthOptional also accepts a wallet without client authentication.
	// OpenID4VCI 1.0 §6.1 allows that and HAIP forbids it. A wallet without an
	// attestation can then run the whole flow. A presented attestation is
	// still verified.
	ClientAuthOptional ClientAuthMode = "optional"
)

func ParseClientAuthMode(value string) (ClientAuthMode, error) {
	switch ClientAuthMode(strings.TrimSpace(value)) {
	case "", ClientAuthRequired:
		return ClientAuthRequired, nil
	case ClientAuthOptional:
		return ClientAuthOptional, nil
	}
	return "", fmt.Errorf("unknown client authentication mode %q, want %q or %q", value, ClientAuthRequired, ClientAuthOptional)
}

func (d *DemoRP) clientAuthMode() ClientAuthMode {
	if d.clientAuth == ClientAuthOptional {
		return ClientAuthOptional
	}
	return ClientAuthRequired
}

// authGrant is what an authorization flow carries from its start to the
// token: the client, its PKCE challenge, where the code goes and what the
// token issues. PAR, the browser sign-in and interactive authorization share
// it, and the code takes it over whole.
type authGrant struct {
	clientID      string
	codeChallenge string
	// redirectURI and state go with a code delivered by redirect.
	redirectURI string
	state       string
	// issuerState names the offer whose settings the flow issues. A flow
	// started by scope has none.
	issuerState string
	// dpopJKT is the DPoP key the code is bound to (RFC 9449 §10), if any.
	dpopJKT  string
	settings offerSettings
	// withDetails records that the request used authorization_details, so the
	// token response returns credential identifiers (OpenID4VCI 1.0 §6.2).
	withDetails bool
}

// resolveAuthGrant resolves what an authorization flow issues: the settings
// of the offer that issuer_state names, else the configurations that the
// authorization_details and the scope name (OpenID4VCI 1.0 §5.1.1, §5.1.2).
// authorization_details next to an issuer_state narrow the offer. A request
// that names none gets the ticket, the default scope of this server (RFC 6749
// §3.3). It returns the OAuth error of an unknown name.
func (d *DemoRP) resolveAuthGrant(grant authGrant, scope, authorizationDetails string) (authGrant, map[string]string) {
	detailIDs, errResp := parseAuthorizationDetails(authorizationDetails)
	if errResp != nil {
		return grant, errResp
	}
	grant.withDetails = detailIDs != nil
	if grant.issuerState != "" {
		d.mu.Lock()
		offer := d.offerLocked(grant.issuerState, issuerStateKey)
		if offer != nil {
			grant.settings = offer.offerSettings
		}
		d.mu.Unlock()
		if offer == nil {
			return grant, oauthError("invalid_request", "unknown or expired issuer_state")
		}
		if grant.withDetails {
			grant.settings.configIDs, errResp = narrowConfigIDs(grant.settings.configIDs, detailIDs)
		}
		return grant, errResp
	}
	configIDs, err := d.offerConfigurationIDs(append(strings.Fields(scope), detailIDs...))
	if err != nil {
		return grant, oauthError("invalid_scope", err.Error())
	}
	grant.settings = offerSettings{configIDs: configIDs, authorization: authorizationBrowser}
	return grant, nil
}

// parseAuthorizationDetails reads the credential_configuration_id of each
// openid_credential entry (OpenID4VCI 1.0 §5.1.1). An absent parameter or an
// empty array gives nil.
func parseAuthorizationDetails(raw string) ([]string, map[string]string) {
	if raw == "" {
		return nil, nil
	}
	var details []struct {
		Type                      string `json:"type"`
		CredentialConfigurationID string `json:"credential_configuration_id"`
	}
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return nil, oauthError("invalid_authorization_details", "authorization_details is not a JSON array: "+err.Error())
	}
	var ids []string
	for _, detail := range details {
		if detail.Type != "openid_credential" {
			return nil, oauthError("invalid_authorization_details", fmt.Sprintf("authorization_details type %q is not openid_credential", detail.Type))
		}
		if detail.CredentialConfigurationID == "" {
			return nil, oauthError("invalid_authorization_details", "an openid_credential entry has no credential_configuration_id")
		}
		ids = append(ids, detail.CredentialConfigurationID)
	}
	return ids, nil
}

// narrowConfigIDs keeps the granted configurations that authorization_details
// ask for. OpenID4VCI 1.0 §6.1.1 recommends that the authorization server
// accepts "a subset of credential_configuration_id parameters received in the
// original Authorization Request and issue a token for the reduced set".
func narrowConfigIDs(granted, requested []string) ([]string, map[string]string) {
	narrowed := make([]string, 0, len(requested))
	for _, id := range requested {
		if !slices.Contains(granted, id) {
			return nil, oauthError("invalid_authorization_details", fmt.Sprintf("this grant covers %s, not %s", strings.Join(granted, ", "), id))
		}
		if !slices.Contains(narrowed, id) {
			narrowed = append(narrowed, id)
		}
	}
	return narrowed, nil
}

func issuerStateKey(o *offerState) string { return o.issuerState }

type authRequestState struct {
	requestURI string
	authGrant
	// clientAttestation and clientAttestationPoP are the raw compact JWTs that
	// the wallet sent to the PAR endpoint. The sign-in page shows them in its
	// debug panel.
	clientAttestation    string
	clientAttestationPoP string
	// codeIssued reports that the request yielded its authorization code,
	// which spends the request_uri.
	codeIssued bool
	codeUsed   bool
	// holderClaims name the holder of the code: the account's names after
	// the sign-in, or the requested claims of a presented credential.
	holderClaims map[string]any
	expires      time.Time
}

// authorizationServerMetadata lists the accepted client authentication
// methods, together with PAR, PKCE S256 and DPoP for HAIP.
func (d *DemoRP) authorizationServerMetadata() map[string]any {
	issuer := d.issuerID()
	authMethods := []string{attestationClientAuth, attestationDPoPClientAuth}
	popMethods := []string{"attestation_pop_jwt", "dpop_combined"}
	anonymous := d.clientAuthMode() == ClientAuthOptional
	if anonymous {
		authMethods = append(authMethods, unauthenticatedClientAuth)
		popMethods = append(popMethods, "none")
	}
	metadata := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"pushed_authorization_request_endpoint": issuer + "/par",
		"require_pushed_authorization_requests": true,
		"token_endpoint":                        issuer + "/token",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		// redirectWithCode sends iss (RFC 9207 §2.3).
		"authorization_response_iss_parameter_supported": true,
		"grant_types_supported":                          []string{authCodeGrant, preAuthGrant},
		// Each credential configuration has its id as scope.
		"scopes_supported":                                 d.offeredConfigurationIDs(),
		"code_challenge_methods_supported":                 []string{"S256"},
		"dpop_signing_alg_values_supported":                []string{jws.AlgES256},
		"token_endpoint_auth_methods_supported":            authMethods,
		"token_endpoint_auth_signing_alg_values_supported": []string{jws.AlgES256},
		// draft-ietf-oauth-attestation-based-client-auth-10 §8 requires these
		// two from a server that supports the method. They are the only place
		// a wallet learns the accepted signature algorithms.
		"client_attestation_signing_alg_values_supported":     []string{jws.AlgES256},
		"client_attestation_pop_signing_alg_values_supported": []string{jws.AlgES256},
		// In optional mode, none means the client may omit the attestation.
		"client_attestation_pop_methods_supported": popMethods,
		// OpenID4VCI 1.0 §12.3: whether a Token Request with a Pre-Authorized
		// Code may come without a client_id.
		"pre-authorized_grant_anonymous_access_supported": anonymous,
	}
	// OpenID4VCI 1.1 only. Publishing the endpoint is the server side of the
	// negotiation (§13.3). The server omits require_interactive_authorization
	// because it also accepts the redirect flow.
	if d.wallet != nil && d.wallet.VCIFeatureVersion() == wallet.VCIVersion11 {
		metadata["authorization_challenge_endpoint"] = d.challengeEndpoint()
	}
	return metadata
}

// AuthorizationServerMetadataHandler serves the OAuth authorization server
// metadata. Also register it at /.well-known/oauth-authorization-server/issuer
// on the server root, because RFC 8414 puts the well-known segment before the
// issuer path.
func (d *DemoRP) AuthorizationServerMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.authorizationServerMetadata())
	}
}

// The user signs in while redeeming the offer, between PAR and the token exchange.
func (d *DemoRP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	request, err := d.lookupAuthRequest(r.URL.Query().Get("request_uri"))
	if err != nil {
		writeAuthorizeError(w, err.Error())
		return
	}
	if clientID := r.URL.Query().Get("client_id"); clientID != "" && clientID != request.clientID {
		writeAuthorizeError(w, "client_id does not match the pushed authorization request")
		return
	}
	renderLoginPage(w, loginPageData{
		Action:         "authorize",
		RequestURI:     request.requestURI,
		RedirectURI:    request.redirectURI,
		ClientID:       request.clientID,
		Attestation:    request.clientAttestation,
		AttestationPoP: request.clientAttestationPoP,
		Title:          "Sign in",
		Explanation:    "Your wallet is collecting a Demo Event Ticket. Sign in to approve it.",
	})
}

// handlePushedAuthorizationRequest implements RFC 9126. Client authentication
// is verified before the request is stored. RFC 9449 §10 makes binding the
// code to a DPoP key OPTIONAL, and §10.1 allows a DPoP header at the PAR
// endpoint. A DPoP proof that is sent must verify. It can also be the
// attestation PoP (dpop_combined).
func (d *DemoRP) handlePushedAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "could not read the request body"))
		return
	}
	clientID := r.PostFormValue("client_id")
	// RFC 6749 §4.1.1 makes client_id REQUIRED in an authorization request.
	// An unauthenticated client has no attestation sub, so client_id is its
	// only identifier.
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "client_id is required"))
		return
	}
	jkt, errResp := d.dpopKey(r, d.issuerID()+"/par")
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	// RFC 9449 §10: a DPoP key at PAR, or dpop_jkt, binds the code to it.
	codeKey := r.PostFormValue("dpop_jkt")
	if codeKey != "" && jkt != "" && codeKey != jkt {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", "dpop_jkt does not match the key of the DPoP proof"))
		return
	}
	if codeKey == "" {
		codeKey = jkt
	}
	// RFC 9126 §2.3 answers errors as RFC 6749 §5.2 does, which lets the
	// server answer a failed client authentication with 401.
	if _, authErr := d.authenticateClient(r, clientID, jkt); authErr != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError(authErr.code, authErr.description))
		return
	}
	if r.PostFormValue("response_type") != "code" {
		writeJSON(w, http.StatusBadRequest, oauthError("unsupported_response_type", "only response_type=code is supported"))
		return
	}
	if r.PostFormValue("code_challenge_method") != "S256" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "PKCE with S256 is required"))
		return
	}
	challenge := r.PostFormValue("code_challenge")
	redirectURI := r.PostFormValue("redirect_uri")
	if challenge == "" || redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "code_challenge and redirect_uri are required"))
		return
	}

	grant, errResp := d.resolveAuthGrant(authGrant{
		clientID:      clientID,
		codeChallenge: challenge,
		redirectURI:   redirectURI,
		state:         r.PostFormValue("state"),
		issuerState:   r.PostFormValue("issuer_state"),
		dpopJKT:       codeKey,
	}, r.PostFormValue("scope"), r.PostFormValue("authorization_details"))
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	request := &authRequestState{
		requestURI:           requestURIPrefix + randToken(),
		authGrant:            grant,
		clientAttestation:    strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation")),
		clientAttestationPoP: strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation-PoP")),
		expires:              time.Now().Add(authRequestTTL),
	}
	d.mu.Lock()
	d.pruneLocked()
	makeRoom(d.authRequests, func(r *authRequestState) time.Time { return r.expires })
	d.authRequests[request.requestURI] = request
	d.mu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": request.requestURI,
		"expires_in":  int(authRequestTTL.Seconds()),
	})
}

// handleAuthorizeSubmit completes the login and redirects with the
// authorization code.
func (d *DemoRP) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthorizeError(w, "could not read the form")
		return
	}
	request, err := d.lookupAuthRequest(r.PostFormValue("request_uri"))
	if err != nil {
		writeAuthorizeError(w, err.Error())
		return
	}
	if !validDemoAccount(r.PostFormValue("username"), r.PostFormValue("password")) {
		renderLoginPage(w, loginPageData{
			Action:         "authorize",
			RequestURI:     request.requestURI,
			RedirectURI:    request.redirectURI,
			ClientID:       request.clientID,
			Attestation:    request.clientAttestation,
			AttestationPoP: request.clientAttestationPoP,
			Title:          "Sign in",
			Error:          "Wrong account. The demo accepts alice / alice.",
		})
		return
	}
	// The account that signed in is the holder.
	d.redirectWithCode(w, r, request, map[string]any{"given_name": demoAccountGivenName, "family_name": demoAccountFamily})
}

// redirectWithCode issues the authorization code and redirects to the wallet
// redirect URI. It includes the iss parameter (RFC 9207) because a wallet in
// strict mode requires it.
func (d *DemoRP) redirectWithCode(w http.ResponseWriter, r *http.Request, request *authRequestState, holderClaims map[string]any) {
	// Issue under the lock because the token endpoint reads the same struct
	// concurrently and two sign-ins may race for the request.
	code := randToken()
	d.mu.Lock()
	if request.codeIssued {
		d.mu.Unlock()
		writeAuthorizeError(w, errRequestURIUsed.Error())
		return
	}
	request.codeIssued = true
	request.holderClaims = holderClaims
	makeRoom(d.codes, func(r *authRequestState) time.Time { return r.expires })
	d.codes[code] = request
	redirectURI, state := request.redirectURI, request.state
	d.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		writeAuthorizeError(w, "the pushed redirect_uri is not a valid URL")
		return
	}
	query := target.Query()
	query.Set("code", code)
	query.Set("iss", d.issuerID())
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleAuthorizationCodeToken exchanges the code for an access token. It
// checks PKCE, the redirect URI, the client attestation and the DPoP key.
func (d *DemoRP) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	jkt, errResp := d.dpopKey(r, d.issuerID()+"/token")
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	clientID := r.PostFormValue("client_id")
	clientAuth, ok := d.authenticateTokenClient(w, r, clientID, jkt)
	if !ok {
		return
	}
	// RFC 6749 §4.1.3 has client_id "REQUIRED, if the client is not
	// authenticating with the authorization server". An authenticated client
	// may omit it and is identified by its attestation sub. The code check
	// below ensures "that the authorization code was issued to the
	// authenticated confidential client".
	if clientID == "" {
		clientID = clientAuth.clientID
	}

	code := r.PostFormValue("code")
	d.mu.Lock()
	request, known := d.codes[code]
	if known && (time.Now().After(request.expires) || request.codeUsed) {
		delete(d.codes, code)
		known = false
	}
	// Copy under the lock because the authorization endpoint writes to the
	// same struct when it issues a code.
	var granted authRequestState
	if known {
		// An authorization code is single use (RFC 6749 §4.1.2).
		request.codeUsed = true
		granted = *request
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "unknown, used or expired authorization code"))
		return
	}
	if clientID != granted.clientID {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "client_id does not match the authorization request"))
		return
	}
	if redirect := r.PostFormValue("redirect_uri"); redirect != granted.redirectURI {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "redirect_uri does not match the authorization request"))
		return
	}
	if !pkceMatches(r.PostFormValue("code_verifier"), granted.codeChallenge) {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "code_verifier does not match the code_challenge"))
		return
	}
	if granted.dpopJKT != "" && jkt != granted.dpopJKT {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", "the code is bound to another DPoP key (RFC 9449 §10)"))
		return
	}

	d.issueToken(w, r, tokenState{
		offerSettings: granted.settings,
		holderClaims:  granted.holderClaims,
		jkt:           jkt,
		clientAuth:    &clientAuth,
	}, granted.withDetails)
}

func (d *DemoRP) lookupAuthRequest(requestURI string) (*authRequestState, error) {
	requestURI = strings.TrimSpace(requestURI)
	if requestURI == "" {
		return nil, fmt.Errorf("request_uri is required, this authorization server requires pushed authorization requests")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	request, ok := d.authRequests[requestURI]
	if !ok || time.Now().After(request.expires) {
		delete(d.authRequests, requestURI)
		return nil, fmt.Errorf("unknown or expired request_uri")
	}
	if request.codeIssued {
		return nil, errRequestURIUsed
	}
	return request, nil
}

// errRequestURIUsed refuses a request_uri that already yielded a code. RFC
// 9126 §4 lets the server "allow for duplicate requests due to a user
// reloading/refreshing their user agent", so showing the login page again is
// fine. §7.3 asks to "make the request URIs one-time use", so a request_uri
// yields one authorization code.
var errRequestURIUsed = errors.New("request_uri has already been used, RFC 9126 §4 gives a client one use of it")

func validDemoAccount(username, password string) bool {
	return strings.TrimSpace(username) == demoAccountUsername && password == demoAccountPassword
}

func pkceMatches(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return format.EncodeBase64URL(sum[:]) == challenge
}

func oauthError(code, description string) map[string]string {
	return map[string]string{"error": code, "error_description": oid4vc.ErrorDescription(description)}
}

// dpopKey verifies the DPoP proof of a request to an endpoint that issues a
// code or a token. A proof binds what the endpoint issues to its key (RFC
// 9449). Without one it issues a bearer value. HAIP 1.0 §4 asks the issuer to
// support DPoP, and every issuing endpoint applies this one rule.
func (d *DemoRP) dpopKey(r *http.Request, endpoint string) (string, map[string]string) {
	if len(r.Header.Values("DPoP")) == 0 {
		return "", nil
	}
	jkt, err := d.verifyDPoPProof(r, endpoint, "")
	if err != nil {
		return "", oauthError("invalid_dpop_proof", err.Error())
	}
	return jkt, nil
}

// verifyDPoPProof applies the checks of RFC 9449 §4.3 to the DPoP header. It
// returns the thumbprint of the proof key.
func (d *DemoRP) verifyDPoPProof(r *http.Request, expectedURL, accessToken string) (string, error) {
	headers := r.Header.Values("DPoP")
	switch {
	case len(headers) == 0 || strings.TrimSpace(headers[0]) == "":
		return "", fmt.Errorf("a DPoP proof is required")
	case len(headers) > 1:
		return "", fmt.Errorf("the request carries %d DPoP header fields, RFC 9449 §4.3 allows one", len(headers))
	}
	proof, err := parseCompactJWT(headers[0])
	if err != nil {
		return "", fmt.Errorf("parsing DPoP proof: %w", err)
	}
	if typ, _ := proof.header["typ"].(string); !format.JOSETypeIs(typ, "dpop+jwt") {
		return "", fmt.Errorf("DPoP proof has typ %q, expected dpop+jwt", typ)
	}
	if alg, _ := proof.header["alg"].(string); alg != jws.AlgES256 {
		return "", fmt.Errorf("DPoP proof alg %q is not among the supported algorithms (ES256)", alg)
	}
	// §4.2: the payload "MUST contain at least" jti, htm, htu and iat.
	if jti, _ := proof.payload["jti"].(string); jti == "" {
		return "", fmt.Errorf("DPoP proof has no jti claim")
	}
	jwk, ok := proof.header["jwk"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("DPoP proof header has no jwk")
	}
	key, err := holderKeyFromJWK(jwk)
	if err != nil {
		return "", fmt.Errorf("parsing DPoP jwk: %w", err)
	}
	if !verifyES256(key, proof.signingInput, proof.signature) {
		return "", fmt.Errorf("DPoP proof signature does not verify")
	}
	if htm, _ := proof.payload["htm"].(string); !strings.EqualFold(htm, r.Method) {
		return "", fmt.Errorf("DPoP htm %q does not match the request method", htm)
	}
	if htu, _ := proof.payload["htu"].(string); htu != expectedURL {
		return "", fmt.Errorf("DPoP htu %q does not match %q", htu, expectedURL)
	}
	// A DPoP proof has no expiry, so freshness comes from iat. Otherwise a
	// captured proof would stay usable forever.
	if err := checkTimeClaims(proof.payload, true, false); err != nil {
		return "", fmt.Errorf("DPoP proof %w", err)
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if ath, _ := proof.payload["ath"].(string); ath != format.EncodeBase64URL(sum[:]) {
			return "", fmt.Errorf("DPoP ath does not match the access token")
		}
	}
	if err := d.firstUseOfDPoPProof(expectedURL, proof.payload); err != nil {
		return "", err
	}
	return jwkThumbprint(key)
}

// jwkThumbprint is the JWK SHA-256 Thumbprint of RFC 7638 that RFC 9449 §6.1
// binds a token to.
func jwkThumbprint(key *ecdsa.PublicKey) (string, error) {
	sum, err := keys.PublicKeyThumbprint(key)
	if err != nil {
		return "", fmt.Errorf("computing the DPoP key thumbprint: %w", err)
	}
	return format.EncodeBase64URL(sum), nil
}

// firstUseOfDPoPProof records the jti of an accepted proof for its target
// URI. RFC 9449 §11.1: "servers can store the jti value of each DPoP proof
// for the time window in which the respective DPoP proof JWT would be
// accepted". It suggests storing "only a hash thereof" against memory
// exhaustion.
// A full cache refuses new proofs. Forgetting a live jti would let its proof
// be replayed.
func (d *DemoRP) firstUseOfDPoPProof(targetURI string, payload map[string]any) error {
	jti, _ := payload["jti"].(string)
	iat, _ := payload["iat"].(float64)
	sum := sha256.Sum256([]byte(targetURI + " " + jti))
	seen := string(sum[:])

	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if expires, ok := d.dpopJTIs[seen]; ok && now.Before(expires) {
		return fmt.Errorf("DPoP proof jti was already used at %s", targetURI)
	}
	if len(d.dpopJTIs) >= maxDPoPProofs {
		for key, expires := range d.dpopJTIs {
			if now.After(expires) {
				delete(d.dpopJTIs, key)
			}
		}
	}
	if len(d.dpopJTIs) >= maxDPoPProofs {
		return fmt.Errorf("the issuer holds too many recent DPoP proofs. Retry in a few minutes")
	}
	d.dpopJTIs[seen] = time.Unix(int64(iat), 0).Add(freshnessWindow)
	return nil
}

// clientAuthentication records how a client authenticated and who attested it.
type clientAuthentication struct {
	// method is attest_jwt_client_auth, attest_jwt_client_auth_dpop or none.
	method string
	// clientID is the sub claim of the attestation. A request can rely on it
	// in place of a client_id parameter (RFC 6749 §3.2.1). It is empty for an
	// unauthenticated client.
	clientID string
	// attester is the iss claim of the wallet attestation. Drafts -08 and
	// later omit iss, so the signing certificate subject is the fallback.
	attester string
	// trusted reports whether the attestation chains to a provider on the
	// wallet provider lists.
	trusted bool
}

type clientAuthError struct {
	code        string
	description string
}

// authenticateTokenClient logs an unknown attester here because the token
// exchange is the step that leads to a credential.
func (d *DemoRP) authenticateTokenClient(w http.ResponseWriter, r *http.Request, clientID, jkt string) (clientAuthentication, bool) {
	clientAuth, authErr := d.authenticateClient(r, clientID, jkt)
	if authErr != nil {
		// RFC 6749 §5.2 answers a token endpoint refusal "with an HTTP 400
		// (Bad Request) status code (unless specified otherwise)". It requires
		// 401 only for a client that "attempted to authenticate via the
		// Authorization request header field", and the attestation headers are
		// different headers.
		writeJSON(w, http.StatusBadRequest, oauthError(authErr.code, authErr.description))
		return clientAuthentication{}, false
	}
	if clientAuth.method != unauthenticatedClientAuth && !clientAuth.trusted {
		log.Printf("[Demo issuer] client attestation from %q accepted on its own certificate, which does not chain to a wallet provider CA this issuer knows", clientAuth.attester)
	}
	return clientAuth, true
}

// attestationFailed reports a problem with a presented attestation as
// invalid_client_attestation (draft-ietf-oauth-attestation-based-client-auth-10
// §7.4). A client without an attestation gets invalid_client.
func attestationFailed(format string, args ...any) *clientAuthError {
	return &clientAuthError{code: "invalid_client_attestation", description: fmt.Sprintf(format, args...)}
}

// authenticateClient checks a Client Attestation with a PoP JWT or the DPoP
// proof (draft-ietf-oauth-attestation-based-client-auth-10). jkt is the DPoP
// key thumbprint.
//
// Attestations from unknown wallet provider CAs are accepted for interop
// tests and marked untrusted on the ticket. The wallet provider list is
// published at /api/trustlists/wallet-provider.
func (d *DemoRP) authenticateClient(r *http.Request, clientID, jkt string) (clientAuthentication, *clientAuthError) {
	// The validation checklist requires "precisely one" of each header field.
	// A second attestation would otherwise pass unverified.
	if len(r.Header.Values("OAuth-Client-Attestation")) > 1 {
		return clientAuthentication{}, attestationFailed("precisely one OAuth-Client-Attestation header field is allowed")
	}
	if len(r.Header.Values("OAuth-Client-Attestation-PoP")) > 1 {
		return clientAuthentication{}, attestationFailed("precisely one OAuth-Client-Attestation-PoP header field is allowed")
	}
	rawAttestation := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation"))
	rawPoP := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation-PoP"))
	if rawAttestation == "" {
		if rawPoP != "" {
			return clientAuthentication{}, attestationFailed("OAuth-Client-Attestation-PoP was sent without the OAuth-Client-Attestation it proves possession for")
		}
		if d.clientAuthMode() == ClientAuthOptional {
			return clientAuthentication{method: unauthenticatedClientAuth}, nil
		}
		return clientAuthentication{}, &clientAuthError{
			code:        "invalid_client",
			description: "this authorization server requires attestation-based client authentication (OAuth-Client-Attestation and OAuth-Client-Attestation-PoP)",
		}
	}

	attestation, err := parseCompactJWT(rawAttestation)
	if err != nil {
		return clientAuthentication{}, attestationFailed("parsing client attestation: %v", err)
	}
	if typ, _ := attestation.header["typ"].(string); !format.JOSETypeIs(typ, format.TypeClientAttestation) {
		return clientAuthentication{}, attestationFailed("client attestation has typ %q, expected oauth-client-attestation+jwt", typ)
	}
	if alg, _ := attestation.header["alg"].(string); alg != jws.AlgES256 {
		return clientAuthentication{}, attestationFailed("client attestation alg %q is not among the supported algorithms (ES256)", alg)
	}
	attester, err := d.attestationSigner(attestation.header)
	if err != nil {
		return clientAuthentication{}, attestationFailed("%v", err)
	}
	if !verifyES256(attester.key, attestation.signingInput, attestation.signature) {
		return clientAuthentication{}, attestationFailed("client attestation signature does not verify with its certificate")
	}
	// §7.1: "If a client_id was provided, verify that it matches the sub claim
	// of the Client Attestation." The sub claim is REQUIRED and identifies the
	// client. The pre-authorized code grant has no client_id.
	sub, _ := attestation.payload["sub"].(string)
	if sub == "" {
		return clientAuthentication{}, attestationFailed("client attestation has no sub claim")
	}
	if clientID != "" && sub != clientID {
		return clientAuthentication{}, attestationFailed("client attestation sub %q does not match client_id %q", sub, clientID)
	}
	// exp is REQUIRED in the attestation. Without it a leaked attestation
	// would be usable forever.
	if err := checkTimeClaims(attestation.payload, false, true); err != nil {
		return clientAuthentication{}, attestationFailed("client attestation: %v", err)
	}
	cnf, _ := attestation.payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if cnfJWK == nil {
		return clientAuthentication{}, attestationFailed("client attestation has no cnf.jwk")
	}
	clientKey, err := holderKeyFromJWK(cnfJWK)
	if err != nil {
		return clientAuthentication{}, attestationFailed("parsing client attestation cnf.jwk: %v", err)
	}
	// A message valid under another supported ABCA draft is accepted. The
	// difference from the configured draft is logged.
	draft := d.abcaDraft()
	if _, hasISS := attestation.payload["iss"]; draft <= 7 && !hasISS {
		log.Printf("[Demo issuer] client attestation omits iss, which draft-07 (the configured OpenID4VCI 1.0 pin) requires. Accepted, since draft-08 and draft-10 define the shape without it")
	}

	authenticated := clientAuthentication{
		method:   attestationClientAuth,
		clientID: sub,
		attester: attester.name(attestation.payload),
		trusted:  attester.trusted,
	}
	if rawPoP == "" {
		// attest_jwt_client_auth_dpop: the DPoP proof is the only PoP, so §7.3
		// asks that "the public key in the jwk header parameter of the DPoP
		// proof MUST be identical to the public key in the cnf claim of the
		// Client Attestation JWT".
		authenticated.method = attestationDPoPClientAuth
		if jkt == "" {
			return clientAuthentication{}, attestationFailed("no OAuth-Client-Attestation-PoP and no DPoP proof, so nothing proves possession of the attested key")
		}
		if attested, err := jwkThumbprint(clientKey); err != nil || jkt != attested {
			return clientAuthentication{}, attestationFailed("the DPoP proof is signed by a different key than the one the client attestation attests")
		}
		if draft < 10 {
			log.Printf("[Demo issuer] the DPoP proof serves as the attestation's possession proof (dpop_combined), a draft-10 mechanism, while the configured OpenID4VCI version pins draft-0%d. Accepted, since draft-10 is always supported alongside the pinned drafts", draft)
		}
		return authenticated, nil
	}

	pop, err := parseCompactJWT(rawPoP)
	if err != nil {
		return clientAuthentication{}, attestationFailed("parsing client attestation PoP: %v", err)
	}
	if typ, _ := pop.header["typ"].(string); !format.JOSETypeIs(typ, format.TypeClientAttestationPoP) {
		return clientAuthentication{}, attestationFailed("client attestation PoP has typ %q, expected oauth-client-attestation-pop+jwt", typ)
	}
	if alg, _ := pop.header["alg"].(string); alg != jws.AlgES256 {
		return clientAuthentication{}, attestationFailed("client attestation PoP alg %q is not among the supported algorithms (ES256)", alg)
	}
	if !verifyES256(clientKey, pop.signingInput, pop.signature) {
		return clientAuthentication{}, attestationFailed("client attestation PoP is not signed by the attested key")
	}
	if aud, _ := pop.payload["aud"].(string); aud != d.issuerID() {
		return clientAuthentication{}, attestationFailed("client attestation PoP aud %q is not this authorization server", aud)
	}
	// §5.1 requires jti and iat in the PoP. exp is optional and drafts -08 and
	// later omit iss. An iss that differs from the client_id means the proof
	// was made for another client.
	if jti, _ := pop.payload["jti"].(string); jti == "" {
		return clientAuthentication{}, attestationFailed("client attestation PoP has no jti claim")
	}
	iss, hasPoPISS := pop.payload["iss"].(string)
	if hasPoPISS && clientID != "" && iss != clientID {
		return clientAuthentication{}, attestationFailed("client attestation PoP iss %q does not match client_id %q", iss, clientID)
	}
	if draft <= 7 && !hasPoPISS {
		log.Printf("[Demo issuer] client attestation PoP omits iss, which draft-07 (the configured OpenID4VCI 1.0 pin) requires. Accepted, since draft-08 and draft-10 define the shape without it")
	}
	// §5.1 requires iat. exp is optional.
	if err := checkTimeClaims(pop.payload, true, false); err != nil {
		return clientAuthentication{}, attestationFailed("client attestation PoP: %v", err)
	}
	return authenticated, nil
}

// abcaDraft is the draft pinned by the configured OpenID4VCI version. It is
// checked first, before the other supported drafts.
func (d *DemoRP) abcaDraft() int {
	if d.wallet == nil {
		return wallet.VCIVersion10.ABCADraft()
	}
	return d.wallet.VCIFeatureVersion().ABCADraft()
}

type attestationSigner struct {
	key     *ecdsa.PublicKey
	leaf    *x509.Certificate
	trusted bool
}

// name identifies the attester on the issued credential. The iss claim is
// optional from draft -08 on, so the certificate subject is the fallback.
func (s attestationSigner) name(payload map[string]any) string {
	if iss, _ := payload["iss"].(string); iss != "" {
		return iss
	}
	if s.leaf != nil && s.leaf.Subject.CommonName != "" {
		return s.leaf.Subject.CommonName
	}
	return "unnamed attester"
}

// The draft leaves key resolution to the deployment. This issuer reads the
// key from the x5c leaf and checks the chain against the wallet provider
// lists.
func (d *DemoRP) attestationSigner(header map[string]any) (attestationSigner, error) {
	certs, err := certchain.FromX5C(header["x5c"])
	if err != nil {
		return attestationSigner{}, err
	}
	if len(certs) == 0 {
		return attestationSigner{}, fmt.Errorf("client attestation header has no x5c certificate")
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return attestationSigner{}, fmt.Errorf("client attestation certificate does not hold an EC key")
	}
	return attestationSigner{key: key, leaf: certs[0], trusted: d.chainsToWalletProviderCA(certs)}, nil
}

// The wallet provider list of the local wallet anchors the attestation (ETSI
// TS 119 602 V1.1.1 Annex E).
func (d *DemoRP) chainsToWalletProviderCA(certs []*x509.Certificate) bool {
	_, err := certchain.Verify(certs, d.wallet.TrustedLists().WalletProviderAnchors())
	return err == nil
}

// ticketClaim records the client authentication on the ticket, so an
// untrusted wallet attestation stays visible.
func (c *clientAuthentication) ticketClaim() string {
	switch {
	case c == nil || c.method == "" || c.method == unauthenticatedClientAuth:
		return "none"
	case c.trusted:
		return "trusted"
	default:
		return "untrusted"
	}
}

type loginPageData struct {
	Action      string
	RequestURI  string
	Title       string
	Explanation string
	Error       string
	// ClientID, Attestation and AttestationPoP are shown in the debug panel.
	// Attestation and AttestationPoP are raw compact JWTs. They are empty for
	// an unauthenticated client.
	ClientID       string
	Attestation    string
	AttestationPoP string
	IssuerName     string
	// RedirectURI is not rendered. It is added to the form-action of the page
	// so the post-login redirect is allowed.
	RedirectURI string
}

var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/svg+xml" href="../favicon.svg?v=2">
<title>{{.IssuerName}}</title>
<link rel="stylesheet" href="tokens.css">
<script src="theme.js"></script>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:var(--font-mono); background:var(--bg); color:var(--text); min-height:100vh; padding:40px 20px; }
.card { max-width:520px; margin:0 auto; background:var(--bg-surface); border:1px solid var(--border); border-radius:8px; padding:24px; }
h1 { font-size:16px; color:var(--accent); margin-bottom:10px; }
p { font-size:12px; line-height:1.6; color:var(--text-dim); margin-bottom:14px; }
label { display:block; font-size:11px; color:var(--text-dim); margin:10px 0 4px; }
input { font:inherit; font-size:12px; width:100%; padding:8px; background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:4px; }
.btn { font:inherit; font-size:12px; margin-top:16px; padding:8px 16px; border:1px solid var(--accent); border-radius:4px; background:var(--bg); color:var(--accent); cursor:pointer; }
.note { margin-top:16px; padding-top:12px; border-top:1px solid var(--border); font-size:10px; line-height:1.5; color:var(--text-dim); }
.debug { margin-bottom:14px; border:1px solid var(--border); border-radius:4px; }
.debug summary { font-size:11px; color:var(--text-dim); padding:8px 10px; cursor:pointer; }
.debug .body { padding:0 10px 8px; }
.debug .field { margin-top:8px; }
.debug .field span { display:block; font-size:10px; color:var(--text-dim); margin-bottom:2px; }
.debug .field code { display:block; font-size:11px; color:var(--text); word-break:break-all; max-height:120px; overflow:auto; padding:6px 8px; background:var(--bg); border:1px solid var(--border); border-radius:4px; }
.debug .empty { font-size:10px; color:var(--text-dim); margin-top:8px; }
.error { color:var(--red); font-size:12px; margin-top:12px; }
</style>
</head>
<body>
<div class="card">
  <h1 id="login-title">{{.Title}}</h1>
  <p id="login-explanation">{{.Explanation}}</p>
  <details class="debug" id="login-debug">
    <summary id="login-debug-summary">Client authentication (debug)</summary>
    <div class="body">
      <div class="field" id="login-debug-client-id"><span id="login-debug-client-id-name">client_id</span><code id="login-debug-client-id-value">{{.ClientID}}</code></div>
      {{if .Attestation}}<div class="field" id="login-debug-attestation"><span id="login-debug-attestation-name">OAuth-Client-Attestation</span><code id="login-debug-attestation-value">{{.Attestation}}</code></div>{{end}}
      {{if .AttestationPoP}}<div class="field" id="login-debug-attestation-pop"><span id="login-debug-attestation-pop-name">OAuth-Client-Attestation-PoP</span><code id="login-debug-attestation-pop-value">{{.AttestationPoP}}</code></div>{{end}}
      {{if not .Attestation}}<p class="empty" id="login-debug-empty">The wallet sent no attestation (unauthenticated client).</p>{{end}}
    </div>
  </details>
  <form id="login-form" method="POST" action="{{.Action}}">
    {{if .RequestURI}}<input type="hidden" id="login-request-uri" name="request_uri" value="{{.RequestURI}}">{{end}}
    <label for="username" id="username-label">Username</label>
    <input id="username" name="username" value="alice" autocomplete="off">
    <label for="password" id="password-label">Password</label>
    <input id="password" name="password" type="password" value="alice" autocomplete="off">
    <button class="btn" id="login-submit" type="submit">Sign in</button>
  </form>
  {{if .Error}}<div class="error" id="login-error">{{.Error}}</div>{{end}}
  <div class="note" id="login-note">
    Demo only. One hardcoded account, alice / alice. No user data is stored, everything issued here is test data.
  </div>
</div>
</body>
</html>
`))

func renderLoginPage(w http.ResponseWriter, data loginPageData) {
	if data.Explanation == "" {
		data.Explanation = "Sign in with the demo account."
	}
	// The login page has its own policy so the post-login redirect to the
	// client redirect_uri is allowed.
	w.Header().Set("Content-Security-Policy", loginContentSecurityPolicy(data.RedirectURI))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if data.Error != "" {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	data.IssuerName = wallet.DemoIssuerName
	_ = loginPageTemplate.Execute(w, data)
}

// Browsers apply form-action to the post-login redirect too. The policy must
// list the client redirect_uri, or external origins and custom schemes are
// blocked.
func loginContentSecurityPolicy(redirectURI string) string {
	formAction := "'self'"
	if src := redirectFormActionSource(redirectURI); src != "" {
		formAction += " " + src
	}
	return "default-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"form-action " + formAction + "; " +
		"frame-ancestors 'none'"
}

// redirectFormActionSource turns a redirect_uri into a CSP form-action source.
// An http(s) URI gives its origin. A custom scheme gives the scheme.
func redirectFormActionSource(redirectURI string) string {
	u, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil || u.Scheme == "" {
		return ""
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		if u.Host == "" {
			return ""
		}
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + ":"
}

func writeAuthorizeError(w http.ResponseWriter, message string) {
	// No redirect_uri is trusted yet, so the error is shown on this endpoint.
	writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", message))
}
