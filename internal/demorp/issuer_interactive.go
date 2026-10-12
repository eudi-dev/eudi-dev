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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// Interactive Authorization (OpenID4VCI 1.1 §6). The issuer asks for a PID at
// the Authorization Challenge Endpoint before it issues. It verifies that
// presentation itself.
const (
	interactionTypePresentation = "urn:openid:dcp:ia:openid4vp_presentation"

	// interactionTypeAuthViaWeb is the browser interaction of §6.2.1.2. The
	// wallet gets a request_uri and the user signs in at the authorization
	// endpoint.
	interactionTypeAuthViaWeb = "urn:openid:dcp:ia:auth_via_web"

	challengePath = "/authorize-challenge"
)

// Each offer has its own authorization mode.
const (
	// authorizationPresentation requires a PID at the Authorization Challenge
	// Endpoint (OpenID4VCI 1.1 §6).
	authorizationPresentation = "presentation"
	// authorizationBrowser sends the user to the sign-in page. A wallet using
	// interactive authorization learns about it from redirect_to_web.
	authorizationBrowser = "browser"
)

// Browser sign-in is the default because every wallet supports it.
func normalizeAuthorizationMode(value string) string {
	if strings.TrimSpace(value) == authorizationPresentation {
		return authorizationPresentation
	}
	return authorizationBrowser
}

// interactiveSession is one presentation conversation at the Authorization
// Challenge Endpoint. It holds the request to verify.
type interactiveSession struct {
	id string
	authGrant
	request *requestState
	expires time.Time
}

// challengeEndpoint is the advertised URL. Every presentation made through it
// is bound to this value.
func (d *DemoRP) challengeEndpoint() string {
	return d.issuerID() + challengePath
}

// handleAuthorizationChallenge is the Authorization Challenge Endpoint of
// §6.1. The first answer is the presentation request (§6.2.1.1). The request
// that carries the presentation gets an authorization code.
func (d *DemoRP) handleAuthorizationChallenge(w http.ResponseWriter, r *http.Request) {
	// DPoP and client authentication work as at the token endpoint. §6.1 says
	// a Wallet Attestation "has to be included in this request" if the server
	// requires one.
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "the request body is not a form: "+err.Error()))
		return
	}
	jkt, errResp := d.dpopKey(r, d.challengeEndpoint())
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	clientID := r.PostFormValue("client_id")
	if _, authErr := d.authenticateClient(r, clientID, jkt); authErr != nil {
		writeClientAuthError(w, authErr)
		return
	}

	if session := strings.TrimSpace(r.PostFormValue("auth_session")); session != "" {
		d.continueInteractiveAuthorization(w, r, session, clientID, jkt)
		return
	}
	d.startInteractiveAuthorization(w, r, clientID, jkt)
}

// startInteractiveAuthorization answers an Initial Request (§6.1.1) with the
// Interaction Required Response of §6.2.1.
func (d *DemoRP) startInteractiveAuthorization(w http.ResponseWriter, r *http.Request, clientID, jkt string) {
	if got := r.PostFormValue("response_type"); got != "code" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", fmt.Sprintf("response_type must be code, got %q", got)))
		return
	}
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "client_id is required"))
		return
	}
	codeChallenge := r.PostFormValue("code_challenge")
	if codeChallenge == "" || r.PostFormValue("code_challenge_method") != "S256" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "code_challenge with code_challenge_method S256 is required"))
		return
	}

	grant, errResp := d.resolveAuthGrant(authGrant{
		clientID:      clientID,
		codeChallenge: codeChallenge,
		redirectURI:   r.PostFormValue("redirect_uri"),
		state:         r.PostFormValue("state"),
		issuerState:   r.PostFormValue("issuer_state"),
		dpopJKT:       jkt,
	}, r.PostFormValue("scope"), r.PostFormValue("authorization_details"))
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}

	// Use auth_via_web if the wallet supports it (OpenID4VCI 1.1 §6.2.1.2).
	// Other wallets get redirect_to_web from first-party-apps §5.2.2.1.1,
	// which needs no advertised interaction type.
	offered := r.PostFormValue("interaction_types_supported")
	if grant.settings.authorization == authorizationBrowser {
		if offersInteractionType(offered, interactionTypeAuthViaWeb) {
			d.startAuthViaWebInteraction(w, grant)
			return
		}
		d.redirectChallengeToWeb(w, grant)
		return
	}

	// §6.2.2: the wallet supports none of the offered interaction types.
	if !offersInteractionType(offered, interactionTypePresentation) {
		writeJSON(w, http.StatusBadRequest, oauthError("missing_interaction_type",
			"interaction_types_supported in the request is missing the required interaction type '"+interactionTypePresentation+"'"))
		return
	}

	// The challenge response carries the code, so no redirect_uri belongs to
	// it, and the token request has none (RFC 6749 §4.1.3).
	grant.redirectURI, grant.state = "", ""
	request := d.newInteractivePIDRequest()
	session := &interactiveSession{
		id:        newAuthSession(),
		authGrant: grant,
		request:   request,
		expires:   time.Now().Add(entryTTL),
	}

	d.mu.Lock()
	d.pruneLocked()
	makeRoom(d.interactive, func(s *interactiveSession) time.Time { return s.expires })
	d.interactive[session.id] = session
	d.mu.Unlock()

	presentationRequest, err := d.interactivePresentationRequest(request)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", err.Error()))
		return
	}
	log.Printf("[Demo issuer] interactive authorization: asking %q for a PID before issuing", clientID)
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":                     "insufficient_authorization",
		"interaction_type_required": interactionTypePresentation,
		"auth_session":              session.id,
		"openid4vp_request":         presentationRequest,
	})
}

// continueInteractiveAuthorization verifies the presentation in an
// Intermediate Request (§6.1.2) and issues an authorization code.
func (d *DemoRP) continueInteractiveAuthorization(w http.ResponseWriter, r *http.Request, sessionID, clientID, jkt string) {
	session, errResp := d.takeInteractiveSession(sessionID, clientID, jkt)
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(r.PostFormValue("openid4vp_response")), &response); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "openid4vp_response is not a JSON object: "+err.Error()))
		return
	}
	// §6.2.1.1: a wallet that cannot satisfy the request answers with an
	// Authorization Error Response.
	if refusal, _ := response["error"].(string); refusal != "" {
		writeJSON(w, http.StatusBadRequest, oauthError("access_denied", "the wallet did not present a credential: "+refusal))
		return
	}

	vpToken, err := json.Marshal(response["vp_token"])
	if err != nil || response["vp_token"] == nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "openid4vp_response carried no vp_token"))
		return
	}

	// §6.2.1.4 requires the presentation to be bound to the authorization
	// session. The session nonce provides that binding.
	claims, _, verifyErr := d.verifyPresentation(session.request, string(vpToken))
	if verifyErr != nil {
		log.Printf("[Demo issuer] interactive authorization: presentation refused: %v", verifyErr)
		writeJSON(w, http.StatusBadRequest, oauthError("access_denied", "the presentation could not be verified: "+verifyErr.Error()))
		return
	}

	code := randToken()
	granted := &authRequestState{
		authGrant:    session.authGrant,
		codeIssued:   true,
		holderClaims: requestedClaims(claims, wallet.IdentityCheckClaims()),
		expires:      time.Now().Add(entryTTL),
	}
	d.mu.Lock()
	makeRoom(d.codes, func(r *authRequestState) time.Time { return r.expires })
	d.codes[code] = granted
	d.mu.Unlock()

	log.Printf("[Demo issuer] interactive authorization: presentation verified, issuing an authorization code to %s", session.clientID)
	noStore(w)
	writeJSON(w, http.StatusOK, map[string]any{"authorization_code": code})
}

// takeInteractiveSession finds the session that an Intermediate Request names.
// It checks the client and the DPoP key under the same lock that takes the
// session out, so a session yields at most one authorization code. The error
// codes are those of first-party-apps §5.2.2.1.
func (d *DemoRP) takeInteractiveSession(sessionID, clientID, jkt string) (*interactiveSession, map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	session, known := d.interactive[sessionID]
	if !known || time.Now().After(session.expires) {
		delete(d.interactive, sessionID)
		return nil, oauthError("invalid_session", "unknown, used or expired auth_session")
	}
	if clientID != "" && clientID != session.clientID {
		return nil, oauthError("invalid_session", "client_id does not match the authorization session")
	}
	// first-party-apps §9.5.1: the server "MUST reject subsequent
	// Authorization Challenge Requests [...] unless a DPoP proof for the same
	// key presented in the original Authorization Challenge Request is
	// provided".
	if session.dpopJKT != "" && jkt != session.dpopJKT {
		return nil, oauthError("invalid_dpop_proof", "the authorization session is bound to another DPoP key")
	}
	delete(d.interactive, sessionID)
	return session, nil
}

// newAuthSession returns an auth_session value. first-party-apps §5.3.1:
// "the value SHOULD have a minimum of 256 bits of entropy".
func newAuthSession() string {
	return hex.EncodeToString(randomBytes(32))
}

// pushChallengeAuthRequest stores a pushed authorization request for browser
// sign-in, like the PAR endpoint.
func (d *DemoRP) pushChallengeAuthRequest(grant authGrant) *authRequestState {
	request := &authRequestState{
		requestURI: requestURIPrefix + randToken(),
		authGrant:  grant,
		expires:    time.Now().Add(authRequestTTL),
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	makeRoom(d.authRequests, func(r *authRequestState) time.Time { return r.expires })
	d.authRequests[request.requestURI] = request
	return request
}

// startAuthViaWebInteraction answers with the browser interaction of
// §6.2.1.2. The wallet uses the request_uri for an authorization request
// (RFC 9126 §4). The redirect from the authorization endpoint completes the
// authorization with a code, which the token endpoint redeems with the
// code_verifier. §6.2.1.2: "the Authorization Server MUST omit auth_session
// parameter in the response".
func (d *DemoRP) startAuthViaWebInteraction(w http.ResponseWriter, grant authGrant) {
	if grant.redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request",
			"the auth_via_web interaction continues at the authorization endpoint, which needs a redirect_uri in the authorization challenge request"))
		return
	}
	request := d.pushChallengeAuthRequest(grant)
	log.Printf("[Demo issuer] interactive authorization: this offer wants the browser sign-in, asking for the auth_via_web interaction")
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":                     "insufficient_authorization",
		"interaction_type_required": interactionTypeAuthViaWeb,
		"request_uri":               request.requestURI,
		"expires_in":                int(authRequestTTL.Seconds()),
	})
}

// redirectChallengeToWeb answers a wallet without auth_via_web support. It
// returns redirect_to_web with a pushed authorization request for the
// browser sign-in.
func (d *DemoRP) redirectChallengeToWeb(w http.ResponseWriter, grant authGrant) {
	if grant.redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request",
			"this offer is redeemed with a browser sign-in, which needs a redirect_uri in the authorization challenge request"))
		return
	}

	request := d.pushChallengeAuthRequest(grant)
	log.Printf("[Demo issuer] interactive authorization: this offer wants the browser sign-in, answering redirect_to_web")
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":       "redirect_to_web",
		"request_uri": request.requestURI,
		"expires_in":  int(authRequestTTL.Seconds()),
	})
}

// newInteractivePIDRequest asks for a PID in either format, bound to the
// Authorization Challenge Endpoint. verifyPresentation accepts only
// credentials under the issuer CA, so trusted_authorities names that CA and
// the wallet can pick a matching credential.
func (d *DemoRP) newInteractivePIDRequest() *requestState {
	var authorities []map[string]any
	if aki := d.trustAnchorAKI(); aki != "" {
		authorities = []map[string]any{{"type": "aki", "values": []string{aki}}}
	}
	return &requestState{
		id: randToken(),
		queries: []credentialQuery{
			{id: "pid", format: credtype.FormatSDJWT, vct: PIDVCT, paths: namePaths("", wallet.IdentityCheckClaims()), trustedAuthorities: authorities},
			{id: "pid_mdoc", format: credtype.FormatMDOC, docType: PIDDocType, paths: namePaths(PIDDocType, wallet.IdentityCheckClaims()), trustedAuthorities: authorities},
		},
		// Either format satisfies the request.
		sets:                []credentialSet{{options: [][]string{{"pid"}, {"pid_mdoc"}}}},
		nonce:               randToken(),
		clientID:            d.issuerID(),
		interactiveEndpoint: d.challengeEndpoint(),
		status:              "pending",
		expires:             time.Now().Add(entryTTL),
	}
}

// OpenID4VCI 1.1 §6.2.1.1 uses the Digital Credentials API request form. The
// request is signed with an x509_hash client ID.
func (d *DemoRP) interactivePresentationRequest(req *requestState) (map[string]any, error) {
	claims := map[string]any{
		"response_type":    "vp_token",
		"response_mode":    "ia_post",
		"nonce":            req.nonce,
		"expected_origins": []string{originOf(d.challengeEndpoint())},
		"dcql_query":       req.dcqlQuery(),
	}

	signingKey, chain, err := d.wallet.AccessSigningMaterial()
	if err != nil {
		return nil, fmt.Errorf("loading the access certificate: %w", err)
	}

	// The registration certificate of the identity check goes in
	// verifier_info (OpenID4VP 1.0 §5.1). Its intended use registers the
	// requested claims (ARF RPRC_21).
	info, err := d.wallet.DemoIdentityCheckVerifierInfo()
	if err != nil {
		return nil, err
	}
	if info != nil {
		claims["verifier_info"] = info
	}

	// The x509_hash client ID binds the request to its signing certificate.
	claims["client_id"] = oid4vp.X509HashClientID(chain[0])
	jar, err := oid4vp.SignRequestObjectJWT(claims, signingKey, chain)
	if err != nil {
		return nil, fmt.Errorf("signing the presentation request: %w", err)
	}
	return map[string]any{"request": jar}, nil
}

// trustAnchorAKI is the base64url key identifier of the issuer CA. Wallets
// match it against the AuthorityKeyIdentifier of a leaf certificate. It is
// empty without a CA.
func (d *DemoRP) trustAnchorAKI() string {
	ca := d.wallet.Signer().TrustAnchor()
	if ca == nil || len(ca.SubjectKeyId) == 0 {
		return ""
	}
	return format.EncodeBase64URL(ca.SubjectKeyId)
}

// offersInteractionType reports whether the comma-separated
// interaction_types_supported list contains want (§6.1.1).
func offersInteractionType(list, want string) bool {
	for _, entry := range strings.Split(list, ",") {
		if strings.TrimSpace(entry) == want {
			return true
		}
	}
	return false
}

// requestedClaims are the presented claims the identity check asks for. The
// issued credential takes them over its template, and nothing else of the
// presented credential, such as its vct.
func requestedClaims(claims map[string]any, names []string) map[string]any {
	requested := map[string]any{}
	for _, name := range names {
		if value, ok := claims[name]; ok {
			requested[name] = value
		}
	}
	return requested
}
