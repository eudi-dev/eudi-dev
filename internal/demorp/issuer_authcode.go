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
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

// The demo has one fixed account. The login page shows its credentials. A
// sign-in is valid only for one issuance flow.
const (
	demoAccountUsername  = "alice"
	demoAccountPassword  = "alice"
	demoAccountGivenName = "Alice"
	demoAccountFamily    = "Anderson"

	authCodeGrant = "authorization_code"
	ticketScope   = "demo-ticket"

	// requestURIPrefix is the URN form RFC 9126 requires for a PAR request URI.
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	authRequestTTL   = 5 * time.Minute
	clockSkew        = time.Minute
	// dpopProofMaxAge is the maximum age of a DPoP proof. Clients create a
	// proof per request, so it only has to cover the round trip.
	dpopProofMaxAge = 5 * time.Minute

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

type authRequestState struct {
	requestURI    string
	clientID      string
	redirectURI   string
	state         string
	scope         string
	codeChallenge string
	issuerState   string
	// clientAttestation and clientAttestationPoP are the raw compact JWTs the
	// wallet sent to the PAR endpoint. The sign-in page shows them in its
	// debug panel.
	clientAttestation    string
	clientAttestationPoP string
	code                 string
	codeUsed             bool
	resolved             bool
	subject              string
	// holderClaims are the claims of the credential presented to obtain this
	// code. Only interactive authorization sets them.
	holderClaims map[string]any
	expires      time.Time
}

// authorizationServerMetadata lists the client authentication methods the
// endpoints accept, together with PAR, PKCE S256 and DPoP for HAIP.
func (d *DemoRP) authorizationServerMetadata() map[string]any {
	issuer := d.issuerID()
	authMethods := []string{attestationClientAuth, attestationDPoPClientAuth}
	popMethods := []string{"attestation_pop_jwt", "dpop_combined"}
	if d.clientAuthMode() == ClientAuthOptional {
		authMethods = append(authMethods, unauthenticatedClientAuth)
		popMethods = append(popMethods, "none")
	}
	metadata := map[string]any{
		"issuer":                                           issuer,
		"authorization_endpoint":                           issuer + "/authorize",
		"pushed_authorization_request_endpoint":            issuer + "/par",
		"require_pushed_authorization_requests":            true,
		"token_endpoint":                                   issuer + "/token",
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query"},
		"grant_types_supported":                            []string{authCodeGrant, preAuthGrant},
		"scopes_supported":                                 []string{ticketScope},
		"code_challenge_methods_supported":                 []string{"S256"},
		"dpop_signing_alg_values_supported":                []string{"ES256"},
		"token_endpoint_auth_methods_supported":            authMethods,
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"},
		// draft-ietf-oauth-attestation-based-client-auth-10 §8 requires these
		// two from a server that supports the method. They are the only place
		// a wallet learns the accepted signature algorithms.
		"client_attestation_signing_alg_values_supported":     []string{"ES256"},
		"client_attestation_pop_signing_alg_values_supported": []string{"ES256"},
		// In optional mode, none means the client may omit the attestation.
		"client_attestation_pop_methods_supported": popMethods,
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
	// RFC 9126 §4: "the client MUST only use a request_uri value once". The
	// login form posts it again, and that post comes from this server's own
	// page.
	if err := d.resolveAuthRequest(request.requestURI); err != nil {
		writeAuthorizeError(w, err.Error())
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
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
	var jkt string
	if strings.TrimSpace(r.Header.Get("DPoP")) != "" {
		var err error
		jkt, err = d.verifyDPoPProof(r, d.issuerID()+"/par", "")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
	}
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

	request := &authRequestState{
		requestURI:           requestURIPrefix + randToken(),
		clientID:             clientID,
		redirectURI:          redirectURI,
		state:                r.PostFormValue("state"),
		scope:                r.PostFormValue("scope"),
		codeChallenge:        challenge,
		issuerState:          r.PostFormValue("issuer_state"),
		clientAttestation:    strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation")),
		clientAttestationPoP: strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation-PoP")),
		expires:              time.Now().Add(authRequestTTL),
	}
	d.mu.Lock()
	d.pruneLocked()
	if len(d.authRequests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, oauthError("temporarily_unavailable", "too many open authorization requests"))
		return
	}
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
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
	d.redirectWithCode(w, r, request, demoAccountUsername)
}

// redirectWithCode issues the authorization code and redirects to the wallet
// redirect URI. It includes the iss parameter (RFC 9207) because a wallet in
// strict mode requires it.
func (d *DemoRP) redirectWithCode(w http.ResponseWriter, r *http.Request, request *authRequestState, subject string) {
	// Read the shared request under the lock because the token endpoint reads
	// the same struct concurrently.
	code := randToken()
	d.mu.Lock()
	request.code = code
	request.subject = subject
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
	jkt, err := d.verifyDPoPProof(r, d.issuerID()+"/token", "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
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

	offer := &offerState{
		id:           randToken(),
		issuerState:  granted.issuerState,
		subject:      granted.subject,
		holderClaims: granted.holderClaims,
		accessToken:  randToken(),
		jkt:          jkt,
		clientAuth:   &clientAuth,
		expires:      time.Now().Add(entryTTL),
	}
	// issuer_state links the offer to the token state.
	if src := d.offerByIssuerState(granted.issuerState); src != nil {
		offer.withStatus = src.withStatus
		offer.deferred = src.deferred
		offer.batchSize = src.batchSize
	}

	d.mu.Lock()
	d.tokens[offer.accessToken] = offer
	d.mu.Unlock()

	// OpenID4VCI 1.0 §6.2 defines no c_nonce in the token response. The wallet
	// gets it from the Nonce Endpoint (§7).
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": offer.accessToken,
		"token_type":   "DPoP",
		"expires_in":   int(entryTTL.Seconds()),
	})
}

// offerByIssuerState finds the offer that issued issuerState.
func (d *DemoRP) offerByIssuerState(issuerState string) *offerState {
	if issuerState == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, offer := range d.offers {
		if offer.issuerState == issuerState {
			return offer
		}
	}
	return nil
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
	return request, nil
}

// resolveAuthRequest marks a pushed request as answered by the authorization
// endpoint. A second client asking for the same request is refused.
func (d *DemoRP) resolveAuthRequest(requestURI string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	request, ok := d.authRequests[requestURI]
	if !ok {
		return fmt.Errorf("unknown or expired request_uri")
	}
	if request.resolved {
		return fmt.Errorf("request_uri has already been used, RFC 9126 §4 gives a client one use of it")
	}
	request.resolved = true
	return nil
}

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
	return map[string]string{"error": code, "error_description": description}
}

// verifyDPoPProof checks the signature, HTTP method and URL of a DPoP proof
// under RFC 9449. It returns the key thumbprint the token is bound to.
func (d *DemoRP) verifyDPoPProof(r *http.Request, expectedURL, accessToken string) (string, error) {
	raw := strings.TrimSpace(r.Header.Get("DPoP"))
	if raw == "" {
		return "", fmt.Errorf("a DPoP proof is required")
	}
	proof, err := parseCompactJWT(raw)
	if err != nil {
		return "", fmt.Errorf("parsing DPoP proof: %w", err)
	}
	if typ, _ := proof.header["typ"].(string); typ != "dpop+jwt" {
		return "", fmt.Errorf("DPoP proof has typ %q, expected dpop+jwt", typ)
	}
	jwk, ok := proof.header["jwk"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("DPoP proof header has no jwk")
	}
	// RFC 9449 §4.3: the jwk header holds the public key, never a private one.
	if _, holdsPrivate := jwk["d"]; holdsPrivate {
		return "", fmt.Errorf("DPoP proof jwk carries private key material, it must hold a public key")
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
	iat, ok := proof.payload["iat"].(float64)
	if !ok {
		return "", fmt.Errorf("DPoP proof has no iat claim")
	}
	age := time.Since(time.Unix(int64(iat), 0))
	if age > dpopProofMaxAge || age < -clockSkew {
		return "", fmt.Errorf("DPoP proof iat is not within the accepted window")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if ath, _ := proof.payload["ath"].(string); ath != format.EncodeBase64URL(sum[:]) {
			return "", fmt.Errorf("DPoP ath does not match the access token")
		}
	}
	return mock.KeyIDForPublicKey(key), nil
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
	// trusted reports whether the certificate chains to the known wallet
	// provider CA.
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
		// (Bad Request) status code (unless specified otherwise)". It keeps 401
		// for a client that "attempted to authenticate via the Authorization
		// request header field". The attestation headers are different headers.
		// The PAR endpoint answers 401 as RFC 9126 §2.3 says.
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
// tests and marked untrusted on the ticket. The known CA is published at
// /api/trustlists/wallet-provider.
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
	if typ, _ := attestation.header["typ"].(string); typ != "oauth-client-attestation+jwt" {
		return clientAuthentication{}, attestationFailed("client attestation has typ %q, expected oauth-client-attestation+jwt", typ)
	}
	if alg, _ := attestation.header["alg"].(string); alg != "ES256" {
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
	// exp is REQUIRED in the attestation.
	if err := checkJWTValidity(attestation.payload); err != nil {
		return clientAuthentication{}, attestationFailed("client attestation: %v", err)
	}
	cnf, _ := attestation.payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if cnfJWK == nil {
		return clientAuthentication{}, attestationFailed("client attestation has no cnf.jwk")
	}
	// The checklist requires that the confirmation key is not a private key.
	if _, holdsPrivate := cnfJWK["d"]; holdsPrivate {
		return clientAuthentication{}, attestationFailed("client attestation cnf.jwk carries private key material, the confirmation key must be a public key")
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
		if jkt != mock.KeyIDForPublicKey(clientKey) {
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
	if typ, _ := pop.header["typ"].(string); typ != "oauth-client-attestation-pop+jwt" {
		return clientAuthentication{}, attestationFailed("client attestation PoP has typ %q, expected oauth-client-attestation-pop+jwt", typ)
	}
	if alg, _ := pop.header["alg"].(string); alg != "ES256" {
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
	if err := checkPoPFreshness(pop.payload); err != nil {
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
// key from the x5c leaf and checks the chain against the wallet provider CA.
func (d *DemoRP) attestationSigner(header map[string]any) (attestationSigner, error) {
	rawChain, _ := header["x5c"].([]any)
	if len(rawChain) == 0 {
		return attestationSigner{}, fmt.Errorf("client attestation header has no x5c certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawChain))
	for _, entry := range rawChain {
		encoded, _ := entry.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return attestationSigner{}, fmt.Errorf("decoding x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return attestationSigner{}, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return attestationSigner{}, fmt.Errorf("client attestation certificate does not hold an EC key")
	}
	return attestationSigner{key: key, leaf: certs[0], trusted: d.chainsToWalletProviderCA(certs)}, nil
}

// The attestation has only its leaf. The wallet provider CA of the local
// wallet is the trust anchor.
func (d *DemoRP) chainsToWalletProviderCA(certs []*x509.Certificate) bool {
	anchor := d.wallet.TrustAnchorCertificate()
	if anchor == nil || len(certs) == 0 {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// checkPoPFreshness checks the age of a Client Attestation PoP from its iat.
// draft-ietf-oauth-attestation-based-client-auth-10 §5.1 requires aud, jti
// and iat. exp is optional and checked if present.
func checkPoPFreshness(payload map[string]any) error {
	iat, ok := payload["iat"].(float64)
	if !ok {
		return fmt.Errorf("has no iat claim")
	}
	age := time.Since(time.Unix(int64(iat), 0))
	if age > dpopProofMaxAge || age < -clockSkew {
		return fmt.Errorf("iat is not within the accepted window")
	}
	if exp, ok := payload["exp"].(float64); ok && time.Now().After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("expired")
	}
	if nbf, ok := payload["nbf"].(float64); ok && time.Now().Add(clockSkew).Before(time.Unix(int64(nbf), 0)) {
		return fmt.Errorf("not valid yet")
	}
	return nil
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

func checkJWTValidity(payload map[string]any) error {
	now := time.Now()
	// Without exp a leaked attestation would be usable forever.
	exp, ok := payload["exp"].(float64)
	if !ok {
		return fmt.Errorf("has no exp claim")
	}
	if now.After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("expired")
	}
	if nbf, ok := payload["nbf"].(float64); ok && now.Add(clockSkew).Before(time.Unix(int64(nbf), 0)) {
		return fmt.Errorf("not valid yet")
	}
	return nil
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
<title>EUDI Test Demo Issuer</title>
<style>
:root { --bg:#1a1b26; --bg-surface:#24283b; --text:#c0caf5; --text-dim:#8b93b8; --border:#3b4261; --accent:#7aa2f7; }
@media (prefers-color-scheme: light) {
  :root { --bg:#f5f5f5; --bg-surface:#ffffff; --text:#343b58; --text-dim:#6b6f7b; --border:#d0d0d0; --accent:#2569d6; }
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:"SF Mono","Cascadia Code","Fira Code",Menlo,Consolas,monospace; background:var(--bg); color:var(--text); min-height:100vh; padding:40px 20px; }
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
.error { color:#f7768e; font-size:12px; margin-top:12px; }
</style>
</head>
<body>
<div class="card">
  <h1>{{.Title}}</h1>
  <p>{{.Explanation}}</p>
  <details class="debug">
    <summary>Client authentication (debug)</summary>
    <div class="body">
      <div class="field"><span>client_id</span><code>{{.ClientID}}</code></div>
      {{if .Attestation}}<div class="field"><span>OAuth-Client-Attestation</span><code>{{.Attestation}}</code></div>{{end}}
      {{if .AttestationPoP}}<div class="field"><span>OAuth-Client-Attestation-PoP</span><code>{{.AttestationPoP}}</code></div>{{end}}
      {{if not .Attestation}}<p class="empty">The wallet sent no attestation (unauthenticated client).</p>{{end}}
    </div>
  </details>
  <form method="POST" action="{{.Action}}">
    {{if .RequestURI}}<input type="hidden" name="request_uri" value="{{.RequestURI}}">{{end}}
    <label for="username">Username</label>
    <input id="username" name="username" value="alice" autocomplete="off">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" value="alice" autocomplete="off">
    <button class="btn" type="submit">Sign in</button>
  </form>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <div class="note">
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
