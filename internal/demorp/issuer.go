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
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v3/internal/webui"
)

//go:embed static
var staticFiles embed.FS

const (
	TicketVCT = credtype.DemoTicketVCT

	ticketConfigurationID = "demo-ticket"
	preAuthGrant          = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	// demoBatchSize is the batch_size of OpenID4VCI 1.0 §12.2.4.
	// Each copy is bound to its own proof key, as ARF method C requires.
	demoBatchSize        = wallet.MaxBatchSize
	demoDefaultBatchSize = 3
)

// parseBatchSize reads the batch query parameter. "true" asks for the default
// batch and a number asks for that many copies, up to demoBatchSize. Any other
// value means a single credential.
func parseBatchSize(value string) int {
	value = strings.TrimSpace(value)
	if value == "true" {
		return demoDefaultBatchSize
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 2 {
		return 0
	}
	if n > demoBatchSize {
		return demoBatchSize
	}
	return n
}

// offerState tracks one credential offer until the credential is collected.
// A pre-authorized offer has a pre-authorized code. An authorization code
// offer has the issuer_state that links it to a browser login.
type offerState struct {
	id string
	// offerSettings are what the offer was created with. Its grant issues
	// with them.
	offerSettings
	// preAuthCode is the grant of a pre-authorized offer and is redeemed
	// once, for one access token. issuerState only links an authorization
	// request to the offer (OpenID4VCI 1.0 §4.1.1), so it stays valid until
	// the offer expires, and the authorization code is the one-time grant.
	preAuthCode string
	issuerState string
	redeemed    bool
	expires     time.Time
}

// tokenState is what an access token grants. Both grants build it with
// issueToken.
type tokenState struct {
	offerSettings
	// holderClaims name the holder: the names of the account that signed in,
	// or the requested claims of the credential presented to authorize the
	// issuance (OpenID4VCI 1.1 §6). A pre-authorized code leaves them empty.
	holderClaims map[string]any
	// jkt is the thumbprint of the DPoP key that binds the token. It is
	// empty for a bearer token.
	jkt        string
	clientAuth *clientAuthentication
	// credentialIDs maps each granted configuration to the credential
	// identifier that the token response returned for it. It is nil when the
	// flow used no authorization_details.
	credentialIDs map[string]string
	expires       time.Time
}

// offerSettings are the choices of the demo issuer page for one offer.
type offerSettings struct {
	// configIDs are the credential configurations in the offer. An offer
	// that names none issues the ticket (offerConfigurationIDs).
	configIDs []string
	// withStatus adds a reference to the wallet status list so the
	// credential can be revoked.
	withStatus bool
	// deferred selects deferred issuance (OpenID4VCI 1.0 §9).
	deferred bool
	// batchSize is the number of copies to sign, each for its own key (§8.3).
	// 0 or 1 issues a single credential.
	batchSize int
	// authorization is authorizationPresentation or authorizationBrowser.
	authorization string
}

// IssuerHandler returns the demo issuer. Mount it with the /issuer prefix
// stripped.
func (d *DemoRP) IssuerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.servePage("static/issuer.html"))
	// The script is a separate file because the wallet Content-Security-Policy
	// has no script-src 'unsafe-inline'.
	mux.HandleFunc("GET /issuer.js", d.serveStatic("static/issuer.js"))
	for _, name := range webui.Names {
		mux.HandleFunc("GET /"+name, webui.Handler(name))
	}
	mux.HandleFunc("POST /api/offers", d.handleCreateOffer)
	mux.HandleFunc("GET /offer/{id}", d.handleOfferByReference)
	mux.HandleFunc("POST /token", d.handleToken)
	mux.HandleFunc("POST /credential", d.handleCredential)
	mux.HandleFunc("POST /deferred_credential", d.handleDeferredCredential)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", d.handleIssuerMetadata)
	mux.HandleFunc("GET /logo.svg", d.handleLogo)
	mux.HandleFunc("GET /templates/{id}/{field}", d.handleTemplateImage)

	// The issuer is its own authorization server. The user signs in at
	// /authorize while the wallet redeems the offer.
	mux.HandleFunc("POST /nonce", d.handleNonce)
	mux.HandleFunc("POST /par", d.handlePushedAuthorizationRequest)
	mux.HandleFunc("GET /authorize", d.handleAuthorize)
	mux.HandleFunc("POST /authorize-challenge", d.handleAuthorizationChallenge)
	mux.HandleFunc("POST /authorize", d.handleAuthorizeSubmit)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", d.AuthorizationServerMetadataHandler())
	// GuardAPI covers only /api/, which the page calls. Wallets on other
	// origins call the protocol endpoints.
	return httpsec.GuardAPI(limitBodies(mux), d.baseURL())
}

// IssuerMetadataHandler serves the issuer metadata. Also register it at
// /.well-known/openid-credential-issuer/issuer on the server root, because
// OpenID4VCI puts the well-known segment before the issuer path.
func (d *DemoRP) IssuerMetadataHandler() http.HandlerFunc {
	return d.handleIssuerMetadata
}

func (d *DemoRP) serveStatic(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	}
}

// pageData fills the demo pages with the registered names of the demo
// parties and the national PIDs of the wallet's templates.
type pageData struct {
	IssuerName, VerifierName string
	NationalPIDs             []nationalPID
}

// nationalPID is a PID type that extends the EUDI PID, as the verifier page
// offers it.
type nationalPID struct {
	ID, VCT, Label string
}

func (d *DemoRP) nationalPIDs() []nationalPID {
	var out []nationalPID
	for _, vct := range credtemplate.PIDTypes(d.wallet.Templates) {
		region, _, _ := strings.Cut(strings.TrimPrefix(vct, credtype.PIDVCTPrefix), ":")
		if vct == PIDVCT || region == "" {
			continue
		}
		label := vct
		if name, _, ok := credtemplate.PIDTemplateNames(vct, d.wallet.Templates); ok {
			if t, err := credtemplate.Load(name, d.wallet.Templates); err == nil && t.Display != nil && t.Display.Name != "" {
				label = t.Display.Name
			}
		}
		out = append(out, nationalPID{ID: "pid-" + region, VCT: vct, Label: label})
	}
	return out
}

// servePage renders an HTML page of static/ as a template.
func (d *DemoRP) servePage(name string) http.HandlerFunc {
	page := template.Must(template.ParseFS(staticFiles, name))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_ = page.Execute(w, pageData{IssuerName: wallet.DemoIssuerName, VerifierName: wallet.DemoVerifierName, NationalPIDs: d.nationalPIDs()})
	}
}

func (d *DemoRP) issuerID() string {
	return d.baseURL() + "/issuer"
}

func (d *DemoRP) handleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(wallet.LogoSVG())
}

func (d *DemoRP) handleIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := d.issuerID()
	metadata := map[string]any{
		"credential_issuer":            issuer,
		"credential_endpoint":          issuer + "/credential",
		"deferred_credential_endpoint": issuer + "/deferred_credential",
		// Wallets read client authentication, PAR and DPoP metadata from the
		// authorization server, so the issuer lists itself.
		"authorization_servers": []string{issuer},
		// A 1.0 wallet gets its key proof challenge from the Nonce Endpoint
		// (§7).
		"nonce_endpoint": issuer + "/nonce",
		// OpenID4VCI 1.0 §12.2.4: batch_size is "the maximum array size for the
		// proofs parameter in a Credential Request".
		"batch_credential_issuance": map[string]any{"batch_size": demoBatchSize},
		"display": []map[string]any{
			{
				"name":   wallet.DemoIssuerName,
				"locale": "en-US",
				"logo":   map[string]any{"uri": issuer + "/logo.svg", "alt_text": "eudi-dev logo"},
			},
		},
		"credential_configurations_supported": d.credentialConfigurations(),
	}
	// Without a registration the metadata has no issuer_info, and a wallet
	// with --arf reports that (ETSI TS 119 472-3 §4.2.3).
	info, err := d.wallet.DemoIssuerInfo()
	if err != nil {
		http.Error(w, "building issuer metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info != nil {
		metadata["issuer_info"] = info
	}
	if wallet.PrefersSignedIssuerMetadata(r.Header.Get("Accept")) {
		jwt, err := wallet.SignCredentialIssuerMetadata(d.wallet, issuer, metadata, time.Now().Add(time.Hour))
		if err != nil {
			http.Error(w, "signing issuer metadata: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jwt))
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

// handleCreateOffer creates a credential offer. Query parameters:
//
//   - grant=authorization_code makes an authorization code offer. Otherwise
//     the offer is pre-authorized.
//   - status=true adds a status list reference so the credential can be revoked.
//   - credential (repeatable) is a configuration id from the issuer metadata.
//     The default is the ticket.
//   - authorization=presentation asks for a PID at the Authorization Challenge
//     Endpoint (OpenID4VCI 1.1 §6). Any other value uses the browser sign-in.
//     A wallet without interactive authorization always gets the sign-in.
func (d *DemoRP) handleCreateOffer(w http.ResponseWriter, r *http.Request) {
	authCode := r.URL.Query().Get("grant") == authCodeGrant
	withStatus := r.URL.Query().Get("status") == "true"
	if withStatus && d.statusListURI() == "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "this wallet has no status list URL, so the ticket cannot carry a status reference",
		})
		return
	}

	configIDs, err := d.offerConfigurationIDs(r.URL.Query()["credential"])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	d.mu.Lock()
	d.pruneLocked()
	makeRoom(d.offers, func(o *offerState) time.Time { return o.expires })
	offer := &offerState{
		id: randToken(),
		offerSettings: offerSettings{
			configIDs:     configIDs,
			withStatus:    withStatus,
			deferred:      r.URL.Query().Get("deferred") == "true",
			batchSize:     parseBatchSize(r.URL.Query().Get("batch")),
			authorization: normalizeAuthorizationMode(r.URL.Query().Get("authorization")),
		},
		expires: time.Now().Add(entryTTL),
	}
	if authCode {
		offer.issuerState = randToken()
	} else {
		offer.preAuthCode = randToken()
	}
	d.offers[offer.id] = offer
	d.mu.Unlock()

	base := d.baseURL()
	offerURI := d.issuerID() + "/offer/" + offer.id
	params := url.Values{"credential_offer_uri": {offerURI}}.Encode()
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         offer.id,
		"offer_uri":  offerURI,
		"wallet_url": base + "/credential-offer?" + params,
		"scheme_uri": "openid-credential-offer://?" + params,
	})
}

func (d *DemoRP) handleOfferByReference(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	offer, ok := d.offers[id]
	if ok && time.Now().After(offer.expires) {
		delete(d.offers, id)
		ok = false
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired credential offer"})
		return
	}
	grants := map[string]any{}
	if offer.issuerState != "" {
		grants[authCodeGrant] = map[string]any{"issuer_state": offer.issuerState}
	} else {
		grants[preAuthGrant] = map[string]any{"pre-authorized_code": offer.preAuthCode}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_issuer":            d.issuerID(),
		"credential_configuration_ids": offer.configIDs,
		"grants":                       grants,
	})
}

func (d *DemoRP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	switch grant := r.PostFormValue("grant_type"); grant {
	case preAuthGrant:
	case authCodeGrant:
		d.handleAuthorizationCodeToken(w, r)
		return
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("only %s and %s are supported", preAuthGrant, authCodeGrant),
		})
		return
	}
	// HAIP 1.0 §4.4.1 requires client authentication at the token endpoint.
	// The metadata lists only attestation-based methods, so both grants
	// authenticate the same way.
	jkt, errResp := d.dpopKey(r, d.issuerID()+"/token")
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	clientAuth, ok := d.authenticateTokenClient(w, r, r.PostFormValue("client_id"), jkt)
	if !ok {
		return
	}
	d.mu.Lock()
	offer := d.redeemOfferLocked(r.PostFormValue("pre-authorized_code"), func(o *offerState) string { return o.preAuthCode })
	var settings offerSettings
	if offer != nil {
		settings = offer.offerSettings
	}
	d.mu.Unlock()
	if offer == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "unknown, used or expired pre-authorized code",
		})
		return
	}
	d.issueToken(w, r, tokenState{offerSettings: settings, jkt: jkt, clientAuth: &clientAuth}, false)
}

// redeemOfferLocked finds the offer whose grant key matches and consumes it.
// A pre-authorized code is "short lived and single use" (OpenID4VCI 1.0
// §4.1.1), and an empty key matches no offer. Callers hold d.mu.
func (d *DemoRP) redeemOfferLocked(key string, grantKey func(*offerState) string) *offerState {
	offer := d.offerLocked(key, grantKey)
	if offer == nil || offer.redeemed {
		return nil
	}
	offer.redeemed = true
	return offer
}

// offerLocked finds the live offer whose grant key matches. Callers hold d.mu.
func (d *DemoRP) offerLocked(key string, grantKey func(*offerState) string) *offerState {
	if key == "" {
		return nil
	}
	for _, offer := range d.offers {
		if grantKey(offer) == key && time.Now().Before(offer.expires) {
			return offer
		}
	}
	return nil
}

// issueToken applies the authorization_details of the token request (OpenID4VCI
// 1.0 §6.1.1), stores what the new access token grants and answers with it.
// withDetails reports that the authorization request used authorization_details.
func (d *DemoRP) issueToken(w http.ResponseWriter, r *http.Request, granted tokenState, withDetails bool) {
	detailIDs, errResp := parseAuthorizationDetails(r.PostFormValue("authorization_details"))
	if errResp == nil && detailIDs != nil {
		granted.configIDs, errResp = narrowConfigIDs(granted.configIDs, detailIDs)
		withDetails = true
	}
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	if withDetails {
		granted.credentialIDs = make(map[string]string, len(granted.configIDs))
		for _, id := range granted.configIDs {
			granted.credentialIDs[id] = randToken()
		}
	}
	token := randToken()
	granted.expires = time.Now().Add(entryTTL)
	d.mu.Lock()
	d.pruneLocked()
	makeRoom(d.tokens, func(t *tokenState) time.Time { return t.expires })
	d.tokens[token] = &granted
	d.mu.Unlock()
	writeTokenResponse(w, token, granted)
}

// writeTokenResponse answers a token request. OpenID4VCI 1.0 §6.2 defines no
// c_nonce in it. The wallet gets one from the Nonce Endpoint (§7). §6.2 makes
// authorization_details "REQUIRED when the authorization_details parameter
// [...] is used in either the Authorization Request or Token Request".
func writeTokenResponse(w http.ResponseWriter, token string, granted tokenState) {
	noStore(w)
	tokenType := bearerScheme
	if granted.jkt != "" {
		tokenType = dpopScheme
	}
	response := map[string]any{
		"access_token": token,
		"token_type":   tokenType,
		"expires_in":   int(entryTTL.Seconds()),
	}
	if granted.credentialIDs != nil {
		details := make([]map[string]any, 0, len(granted.configIDs))
		for _, id := range granted.configIDs {
			details = append(details, map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": id,
				"credential_identifiers":      []string{granted.credentialIDs[id]},
			})
		}
		response["authorization_details"] = details
	}
	writeJSON(w, http.StatusOK, response)
}

// accessTokenError refuses the access token of a request. scheme is the
// scheme the request used, or empty for a request without an access token.
type accessTokenError struct {
	scheme      string
	code        string
	description string
}

// writeAccessTokenError answers 401 with the WWW-Authenticate challenge that
// RFC 6750 §3 requires, in the DPoP form of RFC 9449 §7.1 for a DPoP request.
// A request without an access token gets both challenges and, as RFC 6750
// §3.1 asks, no error information.
func (d *DemoRP) writeAccessTokenError(w http.ResponseWriter, refused *accessTokenError) {
	algs := `algs="` + jws.AlgES256 + `"`
	if refused.scheme == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+d.issuerID()+`", DPoP `+algs)
		writeJSON(w, http.StatusUnauthorized, map[string]string{})
		return
	}
	body := oauthError(refused.code, refused.description)
	challenge := refused.scheme + ` error="` + body["error"] + `", error_description="` + body["error_description"] + `"`
	if refused.scheme == dpopScheme {
		challenge += ", " + algs
	}
	w.Header().Set("WWW-Authenticate", challenge)
	writeJSON(w, http.StatusUnauthorized, body)
}

// authorizeAccessToken checks the access token of a request to endpoint and
// returns the token with what it grants. A DPoP-bound token needs a proof with
// its key (RFC 9449 §7).
func (d *DemoRP) authorizeAccessToken(r *http.Request, endpoint string) (string, tokenState, *accessTokenError) {
	token, scheme, ok := accessToken(r)
	if !ok {
		return "", tokenState{}, &accessTokenError{}
	}
	refuse := func(code, description string) (string, tokenState, *accessTokenError) {
		return "", tokenState{}, &accessTokenError{scheme: scheme, code: code, description: description}
	}
	d.mu.Lock()
	granted, known := d.tokens[token]
	var copied tokenState
	if known && time.Now().Before(granted.expires) {
		copied = *granted
	} else {
		known = false
	}
	d.mu.Unlock()
	if !known {
		return refuse("invalid_token", "unknown or expired access token")
	}
	if copied.jkt != "" {
		// RFC 9449 §7.2: a server that also accepts bearer tokens "MUST reject
		// a DPoP-bound access token received as a bearer token".
		if scheme != dpopScheme {
			return refuse("invalid_token", "the access token is bound to a DPoP key and must be sent with the DPoP scheme")
		}
		presented, err := d.verifyDPoPProof(r, d.issuerID()+endpoint, token)
		if err != nil {
			return refuse("invalid_dpop_proof", err.Error())
		}
		if presented != copied.jkt {
			return refuse("invalid_token", "the access token is bound to a different DPoP key")
		}
	}
	return token, copied, nil
}

// credentialRequest is a Credential Request as defined in OpenID4VCI 1.0 §8.2.
// The key proofs are under proofs, which holds "exactly one parameter named as
// the proof type in Appendix F, the value set for this parameter is a
// non-empty array".
type credentialRequest struct {
	CredentialConfigurationID string `json:"credential_configuration_id"`
	CredentialIdentifier      string `json:"credential_identifier"`
	Proofs                    struct {
		JWT []string `json:"jwt"`
	} `json:"proofs"`
}

func (d *DemoRP) handleCredential(w http.ResponseWriter, r *http.Request) {

	token, tok, refused := d.authorizeAccessToken(r, "/credential")
	if refused != nil {
		d.writeAccessTokenError(w, refused)
		return
	}
	granted := ticketGrant{tokenState: tok}

	var req credentialRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_credential_request", err.Error()))
		return
	}
	configID, errResp := requestedConfiguration(req, tok)
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, errResp)
		return
	}
	granted.configID = configID
	if len(req.Proofs.JWT) == 0 {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_proof", "proofs.jwt is required"))
		return
	}
	if len(req.Proofs.JWT) > demoBatchSize {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_credential_request",
			fmt.Sprintf("this issuer signs at most %d copies in one request", demoBatchSize)))
		return
	}

	holderKeys := make([]*ecdsa.PublicKey, 0, len(req.Proofs.JWT))
	for _, proof := range req.Proofs.JWT {
		holderKey, err := d.verifyProofJWT(proof)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, oauthError(err.code, err.description))
			return
		}
		holderKeys = append(holderKeys, holderKey)
	}

	if granted.deferred {
		writeIssuancePending(w, d.deferIssuance(holderKeys, granted, token))
		return
	}

	credentials, signErr := d.signBatch(holderKeys, granted)
	if signErr != nil {
		// A signing failure is a server error. The OpenID4VCI 1.0 §8.3.1.2 codes
		// are for invalid requests, and credential_request_denied stops retries.
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", signErr.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": credentials})
}

// signBatch signs one credential per proof key, up to the granted batch size.
// A single-credential offer uses only the first proof key.
func (d *DemoRP) signBatch(holderKeys []*ecdsa.PublicKey, granted ticketGrant) ([]map[string]any, error) {
	want := granted.batchSize
	if want < 1 {
		want = 1
	}
	if want < len(holderKeys) {
		holderKeys = holderKeys[:want]
	}
	credentials := make([]map[string]any, 0, len(holderKeys))
	for _, key := range holderKeys {
		credential, err := d.signGranted(key, granted)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, map[string]any{"credential": credential})
	}
	return credentials, nil
}

// requestedConfiguration applies §8.2, where credential_identifier is
// "REQUIRED when an Authorization Details of type openid_credential was
// returned from the Token Response [...] MUST NOT be used otherwise" and
// excludes credential_configuration_id. It returns the configuration to issue.
// The error codes are those of §8.3.1.2.
func requestedConfiguration(req credentialRequest, granted tokenState) (string, map[string]string) {
	if req.CredentialIdentifier != "" && req.CredentialConfigurationID != "" {
		return "", oauthError("invalid_credential_request",
			"credential_identifier and credential_configuration_id must not both be present")
	}
	if granted.credentialIDs != nil {
		if req.CredentialIdentifier == "" {
			return "", oauthError("invalid_credential_request",
				"the token response returned credential_identifiers, so the request must name one in credential_identifier")
		}
		for configID, identifier := range granted.credentialIDs {
			if identifier == req.CredentialIdentifier {
				return configID, nil
			}
		}
		return "", oauthError("unknown_credential_identifier",
			fmt.Sprintf("%s is not among the credential_identifiers of the token response", req.CredentialIdentifier))
	}
	switch {
	case req.CredentialIdentifier != "":
		return "", oauthError("unknown_credential_identifier",
			"the token response returned no authorization_details, so no credential identifier is defined")
	case req.CredentialConfigurationID == "":
		return "", oauthError("invalid_credential_request", "credential_configuration_id is required")
	case !slices.Contains(granted.configIDs, req.CredentialConfigurationID):
		return "", oauthError("unknown_credential_configuration",
			fmt.Sprintf("this offer covers the %s configuration(s), not %s", strings.Join(granted.configIDs, ", "), req.CredentialConfigurationID))
	}
	return req.CredentialConfigurationID, nil
}

// handleNonce is the Nonce Endpoint of OpenID4VCI 1.0 §7. A 1.0 wallet gets
// its key proof challenge only from here.
func (d *DemoRP) handleNonce(w http.ResponseWriter, r *http.Request) {
	nonce := d.newNonce(time.Now().Add(entryTTL))

	// A cached response would hand the same challenge to another client.
	w.Header().Set("Cache-Control", "no-store")
	// §7.2 defines c_nonce as the only parameter of a Nonce Response.
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": nonce})
}

// newNonce issues a challenge that carries its expiry and a MAC under the
// issuer's nonce key. Visitors share the Nonce Endpoint, so the issuer keeps
// no list of nonces that one client could fill and push the others out of.
func (d *DemoRP) newNonce(expires time.Time) string {
	value := binary.BigEndian.AppendUint64(nil, uint64(expires.Unix())) //nolint:gosec // Expiry times are after 1970.
	value = append(value, randomBytes(16)...)
	return format.EncodeBase64URL(append(value, d.nonceMAC(value)...))
}

func (d *DemoRP) nonceMAC(value []byte) []byte {
	mac := hmac.New(sha256.New, d.nonceKey)
	mac.Write(value)
	return mac.Sum(nil)
}

// A nonce stays valid until it expires, so all proofs in a batch can use it.
func (d *DemoRP) nonceIssued(nonce string) bool {
	raw, err := format.DecodeBase64URL(nonce)
	if err != nil || len(raw) != 8+16+sha256.Size {
		return false
	}
	value := raw[:24]
	if !hmac.Equal(raw[24:], d.nonceMAC(value)) {
		return false
	}
	return time.Now().Before(time.Unix(int64(binary.BigEndian.Uint64(value[:8])), 0)) //nolint:gosec // The MAC covers the value.
}

// proofError is a rejected key proof with its §8.3.1.2 error code. A wallet
// retries with a fresh challenge after invalid_nonce. It does not retry after
// invalid_proof.
type proofError struct {
	code        string
	description string
}

func (e *proofError) Error() string { return e.code + ": " + e.description }

func invalidProof(format string, args ...any) *proofError {
	return &proofError{code: "invalid_proof", description: fmt.Sprintf(format, args...)}
}

// Key proofs are checked under OpenID4VCI 1.0 Appendix F.4. The aud check
// against the Credential Issuer Identifier (F.1) stops reuse of a proof made
// for another issuer.
func (d *DemoRP) verifyProofJWT(raw string) (*ecdsa.PublicKey, *proofError) {
	proof, err := parseCompactJWT(raw)
	if err != nil {
		return nil, invalidProof("parsing proof JWT: %v", err)
	}
	if typ, _ := proof.header["typ"].(string); !format.JOSETypeIs(typ, format.TypeKeyProof) {
		return nil, invalidProof("proof JWT typ is %q, want openid4vci-proof+jwt", typ)
	}
	if alg, _ := proof.header["alg"].(string); alg != jws.AlgES256 {
		return nil, invalidProof("proof JWT alg is %q, and this issuer advertises ES256 only", alg)
	}

	holderKey, keyErr := proofKeyMaterial(proof.header)
	if keyErr != nil {
		return nil, keyErr
	}
	if !verifyES256(holderKey, proof.signingInput, proof.signature) {
		return nil, invalidProof("proof JWT signature does not verify with the key in its header")
	}

	if aud, _ := proof.payload["aud"].(string); aud != d.issuerID() {
		return nil, invalidProof("proof JWT aud is %q, want the credential issuer identifier %q", aud, d.issuerID())
	}
	// Appendix F.4: "the creation time of the JWT [...] is within an
	// acceptable window (see Section 13.8)".
	if err := checkTimeClaims(proof.payload, true, false); err != nil {
		return nil, invalidProof("proof JWT %v", err)
	}

	// §8.2: "The c_nonce value is retrieved from the Nonce Endpoint as defined
	// in Section 7".
	nonce, _ := proof.payload["nonce"].(string)
	if nonce == "" {
		// §8.3.1.2 puts a missing challenge under invalid_proof: "(3) if at
		// least one of the key proofs does not contain a c_nonce value".
		return nil, invalidProof("proof JWT carries no nonce: request one from the nonce endpoint")
	}
	if !d.nonceIssued(nonce) {
		// §8.3.1.2 invalid_nonce: "at least one of the key proofs contains an
		// invalid c_nonce value. The wallet should retrieve a new c_nonce value
		// (refer to Section 7)."
		return nil, &proofError{code: "invalid_nonce", description: "proof JWT nonce is not one this issuer handed out"}
	}
	return holderKey, nil
}

// proofKeyMaterial reads the key that a proof is bound to. Appendix F.1
// allows exactly one of jwk, kid and x5c. A kid is a DID URL, and this issuer
// can't resolve DIDs, so the error says that kid is unsupported.
func proofKeyMaterial(header map[string]any) (*ecdsa.PublicKey, *proofError) {
	jwk, hasJWK := header["jwk"].(map[string]any)
	x5c, hasX5C := header["x5c"]
	kid, hasKID := header["kid"].(string)
	if hasKID && kid == "" {
		hasKID = false
	}

	present := 0
	for _, found := range []bool{hasJWK, hasX5C, hasKID} {
		if found {
			present++
		}
	}
	if present == 0 {
		return nil, invalidProof("proof JWT header carries none of jwk, x5c or kid")
	}
	if present > 1 {
		return nil, invalidProof("proof JWT header carries more than one of jwk, x5c and kid")
	}

	switch {
	case hasJWK:
		key, err := holderKeyFromJWK(jwk)
		if err != nil {
			return nil, invalidProof("parsing proof jwk: %v", err)
		}
		return key, nil
	case hasX5C:
		key, err := proofKeyFromX5C(x5c)
		if err != nil {
			return nil, invalidProof("%v", err)
		}
		return key, nil
	default:
		return nil, invalidProof("proof JWT identifies its key by kid, which this issuer cannot resolve: send jwk or x5c")
	}
}

// proofKeyFromX5C takes the key out of the first certificate of an x5c header,
// which Appendix F.1 defines as "at least one certificate where the first
// certificate contains the key that the Credential is to be bound to".
func proofKeyFromX5C(raw any) (*ecdsa.PublicKey, error) {
	certs, err := certchain.FromX5C(raw)
	if err != nil {
		return nil, fmt.Errorf("proof JWT %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("proof JWT x5c is not a non-empty array")
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("proof JWT x5c leaf does not carry an EC key")
	}
	return key, nil
}

// The demo issuer uses the wallet status list. The wallet UI can then revoke
// credentials and the demo verifier can check them.
func (d *DemoRP) statusListURI() string {
	return strings.TrimSpace(d.wallet.StatusListURL())
}

type ticketGrant struct {
	tokenState
	// configID is the configuration of the credential request, one of the
	// token's configIDs.
	configID string
}

// signGranted issues the template with the granted configuration id. The
// ticket is the demo-ticket template.
func (d *DemoRP) signGranted(holderKey *ecdsa.PublicKey, granted ticketGrant) (string, error) {
	cfg, ok := d.templateConfiguration(granted.configID)
	if !ok {
		return "", fmt.Errorf("this issuer has no credential configuration %q", granted.configID)
	}
	return d.signTemplate(cfg, holderKey, granted)
}

func decodeJSONBody(r *http.Request, target any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(target)
}

const (
	bearerScheme = "Bearer"
	dpopScheme   = "DPoP"
)

// noStore marks a response that carries a token or a code. RFC 6749 §5.1
// requires "Cache-Control" "no-store" "in any response containing tokens,
// credentials, or other sensitive information, as well as the "Pragma"
// response header field [RFC2616] with a value of "no-cache"".
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// accessToken reads the access token and its scheme, Bearer or DPoP, from the
// Authorization header.
func accessToken(r *http.Request) (token, scheme string, ok bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	for _, scheme := range []string{bearerScheme, dpopScheme} {
		prefix := scheme + " "
		if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
			return strings.TrimSpace(auth[len(prefix):]), scheme, true
		}
	}
	return "", "", false
}
