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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
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

// interactiveSession is one Authorization Challenge conversation. A
// presentation session holds the request to verify. A browser session holds
// the data needed to repeat the auth_via_web answer.
type interactiveSession struct {
	id            string
	clientID      string
	scope         string
	codeChallenge string
	issuerState   string
	request       *requestState
	expires       time.Time

	// browser marks an auth_via_web session (§6.2.1.2). The sign-in finishes
	// at the authorization endpoint. A wallet that comes back here with this
	// auth_session gets the interaction again.
	browser     bool
	redirectURI string
	state       string
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
	jkt, err := d.verifyDPoPProof(r, d.challengeEndpoint(), "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
		return
	}
	clientID := r.PostFormValue("client_id")
	if _, authErr := d.authenticateClient(r, clientID, jkt); authErr != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError(authErr.code, authErr.description))
		return
	}

	if session := strings.TrimSpace(r.PostFormValue("auth_session")); session != "" {
		d.continueInteractiveAuthorization(w, r, session, clientID)
		return
	}
	d.startInteractiveAuthorization(w, r, clientID)
}

// startInteractiveAuthorization answers an Initial Request (§6.1.1) with the
// Interaction Required Response of §6.2.1.
func (d *DemoRP) startInteractiveAuthorization(w http.ResponseWriter, r *http.Request, clientID string) {
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

	// Use auth_via_web if the wallet supports it (OpenID4VCI 1.1 §6.2.1.2).
	// Other wallets get redirect_to_web from first-party-apps §5.2.2.1.1,
	// which needs no advertised interaction type.
	issuerState := r.PostFormValue("issuer_state")
	offered := r.PostFormValue("interaction_types_supported")
	if d.offerAuthorization(issuerState) == authorizationBrowser {
		if offersInteractionType(offered, interactionTypeAuthViaWeb) {
			d.startAuthViaWebInteraction(w, r, clientID, codeChallenge, issuerState)
			return
		}
		d.redirectChallengeToWeb(w, r, clientID, codeChallenge, issuerState)
		return
	}

	// §6.2.2: the wallet supports none of the interaction types this server
	// offers.
	if !offersInteractionType(offered, interactionTypePresentation) {
		writeJSON(w, http.StatusBadRequest, oauthError("missing_interaction_type",
			"interaction_types_supported in the request is missing the required interaction type '"+interactionTypePresentation+"'"))
		return
	}

	request := d.newInteractivePIDRequest()
	session := &interactiveSession{
		id:            randToken(),
		clientID:      clientID,
		scope:         r.PostFormValue("scope"),
		codeChallenge: codeChallenge,
		issuerState:   r.PostFormValue("issuer_state"),
		request:       request,
		expires:       time.Now().Add(entryTTL),
	}

	d.mu.Lock()
	d.pruneLocked()
	if len(d.interactive) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open authorization sessions, try again later"})
		return
	}
	d.interactive[session.id] = session
	d.requests[request.id] = request
	d.mu.Unlock()

	log.Printf("[Demo issuer] interactive authorization: asking %q for a PID before issuing", clientID)
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":                     "insufficient_authorization",
		"interaction_type_required": interactionTypePresentation,
		"auth_session":              session.id,
		"openid4vp_request":         d.interactivePresentationRequest(request),
	})
}

// continueInteractiveAuthorization verifies the presentation in an
// Intermediate Request (§6.1.2) and issues an authorization code.
func (d *DemoRP) continueInteractiveAuthorization(w http.ResponseWriter, r *http.Request, sessionID, clientID string) {
	d.mu.Lock()
	session, known := d.interactive[sessionID]
	if known && time.Now().After(session.expires) {
		delete(d.interactive, sessionID)
		known = false
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "unknown or expired auth_session"))
		return
	}
	if clientID != "" && clientID != session.clientID {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "client_id does not match the authorization session"))
		return
	}
	// A browser session finishes at the authorization endpoint. A wallet
	// returning here with its auth_session gets the interaction again.
	if session.browser {
		d.answerAuthViaWeb(w, session)
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
		detail, _ := response["error_description"].(string)
		d.finishRequest(session.request, nil, nil, fmt.Errorf("the wallet refused: %s", strings.TrimSpace(refusal+" "+detail)))
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
	claims, checks, verifyErr := d.verifyPresentation(session.request, string(vpToken))
	d.finishRequest(session.request, claims, checks, verifyErr)
	if verifyErr != nil {
		log.Printf("[Demo issuer] interactive authorization: presentation refused: %v", verifyErr)
		writeJSON(w, http.StatusBadRequest, oauthError("access_denied", "the presentation could not be verified: "+verifyErr.Error()))
		return
	}

	code := randToken()
	granted := &authRequestState{
		clientID:      session.clientID,
		scope:         session.scope,
		codeChallenge: session.codeChallenge,
		issuerState:   session.issuerState,
		code:          code,
		subject:       presentedHolder(claims),
		holderClaims:  claims,
		expires:       time.Now().Add(entryTTL),
	}
	d.mu.Lock()
	d.codes[code] = granted
	delete(d.interactive, sessionID)
	d.mu.Unlock()

	log.Printf("[Demo issuer] interactive authorization: presentation verified, issuing an authorization code to %s", session.clientID)
	writeJSON(w, http.StatusOK, map[string]any{"authorization_code": code})
}

// An unknown issuer_state gets browser sign-in, which every wallet supports.
func (d *DemoRP) offerAuthorization(issuerState string) string {
	if issuerState == "" {
		return authorizationBrowser
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, offer := range d.offers {
		if offer.issuerState == issuerState {
			return normalizeAuthorizationMode(offer.authorization)
		}
	}
	return authorizationBrowser
}

// pushChallengeAuthRequest stores a pushed authorization request for browser
// sign-in. It uses the same entry limit as the PAR endpoint.
func (d *DemoRP) pushChallengeAuthRequest(clientID, codeChallenge, issuerState, redirectURI, state, scope string) (*authRequestState, bool) {
	request := &authRequestState{
		requestURI:    requestURIPrefix + randToken(),
		clientID:      clientID,
		redirectURI:   redirectURI,
		state:         state,
		scope:         scope,
		codeChallenge: codeChallenge,
		issuerState:   issuerState,
		expires:       time.Now().Add(authRequestTTL),
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	if len(d.authRequests) >= maxEntries {
		return nil, false
	}
	d.authRequests[request.requestURI] = request
	return request, true
}

// startAuthViaWebInteraction answers with the browser interaction of
// §6.2.1.2. The wallet uses the request_uri for an authorization request
// (RFC 9126 §4). The authorization code arrives with the redirect from the
// authorization endpoint.
func (d *DemoRP) startAuthViaWebInteraction(w http.ResponseWriter, r *http.Request, clientID, codeChallenge, issuerState string) {
	redirectURI := r.PostFormValue("redirect_uri")
	if redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request",
			"the auth_via_web interaction continues at the authorization endpoint, which needs a redirect_uri in the authorization challenge request"))
		return
	}

	// §6.2.1 has the wallet send auth_session on every later challenge
	// request. A wallet that abandoned the sign-in and comes back gets the
	// interaction again.
	session := &interactiveSession{
		id:            randToken(),
		clientID:      clientID,
		scope:         r.PostFormValue("scope"),
		codeChallenge: codeChallenge,
		issuerState:   issuerState,
		expires:       time.Now().Add(entryTTL),
		browser:       true,
		redirectURI:   redirectURI,
		state:         r.PostFormValue("state"),
	}
	d.mu.Lock()
	d.pruneLocked()
	if len(d.interactive) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open authorization sessions, try again later"})
		return
	}
	d.interactive[session.id] = session
	d.mu.Unlock()

	log.Printf("[Demo issuer] interactive authorization: this offer wants the browser sign-in, asking for the auth_via_web interaction")
	d.answerAuthViaWeb(w, session)
}

// answerAuthViaWeb answers a browser session with the Interaction Required
// Response of §6.2.1.2. Each answer pushes a fresh authorization request.
func (d *DemoRP) answerAuthViaWeb(w http.ResponseWriter, session *interactiveSession) {
	request, ok := d.pushChallengeAuthRequest(session.clientID, session.codeChallenge, session.issuerState, session.redirectURI, session.state, session.scope)
	if !ok {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open authorization requests, try again later"})
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":                     "insufficient_authorization",
		"interaction_type_required": interactionTypeAuthViaWeb,
		"auth_session":              session.id,
		"request_uri":               request.requestURI,
		"expires_in":                int(authRequestTTL.Seconds()),
	})
}

// redirectChallengeToWeb answers a wallet without auth_via_web support. It
// returns redirect_to_web with a pushed authorization request for the
// browser sign-in.
func (d *DemoRP) redirectChallengeToWeb(w http.ResponseWriter, r *http.Request, clientID, codeChallenge, issuerState string) {
	redirectURI := r.PostFormValue("redirect_uri")
	if redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request",
			"this offer is redeemed with a browser sign-in, which needs a redirect_uri in the authorization challenge request"))
		return
	}

	request, ok := d.pushChallengeAuthRequest(clientID, codeChallenge, issuerState, redirectURI, r.PostFormValue("state"), r.PostFormValue("scope"))
	if !ok {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open authorization requests, try again later"})
		return
	}
	log.Printf("[Demo issuer] interactive authorization: this offer wants the browser sign-in, answering redirect_to_web")
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":       "redirect_to_web",
		"request_uri": request.requestURI,
		"expires_in":  int(authRequestTTL.Seconds()),
	})
}

// newInteractivePIDRequest asks for a PID in either format, bound to the
// Authorization Challenge Endpoint.
func (d *DemoRP) newInteractivePIDRequest() *requestState {
	return &requestState{
		id:                  randToken(),
		queryID:             "pid",
		mdocQueryID:         "pid_mdoc",
		vct:                 PIDVCT,
		docType:             PIDDocType,
		want:                []string{"given_name", "family_name"},
		wantMDOC:            []string{"given_name", "family_name"},
		nonce:               randToken(),
		clientID:            d.issuerID(),
		interactiveEndpoint: d.challengeEndpoint(),
		status:              "pending",
		expires:             time.Now().Add(entryTTL),
	}
}

// OpenID4VCI 1.1 §6.2.1.1 uses the Digital Credentials API request form. The
// request is signed with an x509_hash client ID. Without signing material it
// is sent unsigned.
func (d *DemoRP) interactivePresentationRequest(req *requestState) map[string]any {
	sdjwtCred := map[string]any{
		"id":     req.queryID,
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []string{req.vct}},
		"claims": claimPaths(req.want),
	}
	mdocCred := map[string]any{
		"id":     req.mdocQueryID,
		"format": "mso_mdoc",
		"meta":   map[string]any{"doctype_value": req.docType},
		"claims": namespacedClaimPaths(req.docType, req.wantMDOC),
	}
	// verifyPresentation accepts only credentials under the issuer CA. Listing
	// that CA in trusted_authorities lets the wallet pick a matching credential.
	if aki := d.trustAnchorAKI(); aki != "" {
		authorities := []map[string]any{{"type": "aki", "values": []string{aki}}}
		sdjwtCred["trusted_authorities"] = authorities
		mdocCred["trusted_authorities"] = authorities
	}

	claims := map[string]any{
		"response_type":    "vp_token",
		"response_mode":    "ia_post",
		"nonce":            req.nonce,
		"expected_origins": []string{originOf(d.challengeEndpoint())},
		"dcql_query": map[string]any{
			"credentials": []map[string]any{sdjwtCred, mdocCred},
			// Either format satisfies the request.
			"credential_sets": []map[string]any{{
				"options": [][]string{{req.queryID}, {req.mdocQueryID}},
			}},
		},
	}

	signingKey, chain, err := d.wallet.AccessSigningMaterial()
	if err != nil || signingKey == nil || len(chain) == 0 {
		return claims
	}

	// The registration certificate (rc-wrp+jwt) goes in verifier_info
	// (OpenID4VP 1.0 §5.1). It registers the same credential queries as the
	// request, so the wallet over-asking check of ARF RPRC_21 passes.
	registrarKey, registrarChain, err := d.wallet.RegistrarSigningMaterial()
	if err != nil {
		return claims
	}
	registration, rerr := wallet.SignRegistrationCertificateJWT(
		d.registrationCertificateClaims(chain[0], "Demo Issuer",
			"Proving who you are before the ticket is issued",
			[]map[string]any{sdjwtCred, mdocCred}),
		registrarKey, registrarChain)
	if rerr == nil {
		claims["verifier_info"] = []map[string]any{{
			"format": "registration_cert",
			"data":   registration,
		}}
	}

	// The x509_hash client ID binds the request to its signing certificate.
	claims["client_id"] = wallet.X509HashClientID(chain[0])
	jar, jerr := wallet.SignRequestObjectJWT(claims, signingKey, chain)
	if jerr != nil {
		delete(claims, "client_id")
		return claims
	}
	return map[string]any{"request": jar}
}

// trustAnchorAKI is the base64url key identifier of the issuer CA. Wallets
// match it against the AuthorityKeyIdentifier of a leaf certificate. It is
// empty without a CA.
func (d *DemoRP) trustAnchorAKI() string {
	ca := d.wallet.TrustAnchorCertificate()
	if ca == nil || len(ca.SubjectKeyId) == 0 {
		return ""
	}
	return format.EncodeBase64URL(ca.SubjectKeyId)
}

func claimPaths(names []string) []map[string]any {
	paths := make([]map[string]any, 0, len(names))
	for _, name := range names {
		paths = append(paths, map[string]any{"path": []string{name}})
	}
	return paths
}

func namespacedClaimPaths(namespace string, names []string) []map[string]any {
	paths := make([]map[string]any, 0, len(names))
	for _, name := range names {
		paths = append(paths, map[string]any{"path": []string{namespace, name}})
	}
	return paths
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

// presentedHolder is the name from the presented PID. The credential is
// issued to that person.
func presentedHolder(claims map[string]any) string {
	given, _ := claims["given_name"].(string)
	family, _ := claims["family_name"].(string)
	if name := strings.TrimSpace(given + " " + family); name != "" {
		return name
	}
	return demoAccountUsername
}
