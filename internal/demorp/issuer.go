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
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

//go:embed static
var staticFiles embed.FS

const (
	TicketVCT = "urn:eudi-test:demo-ticket:1"

	ticketConfigurationID = "demo-ticket"
	preAuthGrant          = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	// demoBatchSize is the batch_size advertised under OpenID4VCI 1.0 §8.3.
	// Each copy is bound to its own proof key, as ARF method C requires.
	demoBatchSize        = 8
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

// ticketClaims records the wallet attester and its trust status on the ticket.
// The demo accepts attestations from unknown CAs, so the ticket shows it.
func ticketClaims(subject string, holder map[string]any, auth *clientAuthentication) map[string]any {
	claims := map[string]any{
		"event":       "EUDI Interop Fest",
		"tier":        "backstage",
		"seat":        "42A",
		"given_name":  "Erika",
		"family_name": "Mustermann",
	}
	if subject == demoAccountUsername {
		claims["given_name"] = demoAccountGivenName
		claims["family_name"] = demoAccountFamily
	}
	// Interactive authorization identifies the holder by the presented
	// credential. The ticket carries that holder's name.
	for _, name := range []string{"given_name", "family_name"} {
		if value, ok := holder[name].(string); ok && value != "" {
			claims[name] = value
		}
	}
	if auth != nil {
		claims["wallet_attestation"] = auth.ticketClaim()
	}
	return claims
}

// offerState tracks one credential offer until the credential is collected.
// A pre-authorized offer has a pre-authorized code. An authorization code
// offer has the issuer_state that links it to a browser login.
type offerState struct {
	id          string
	preAuthCode string
	// preAuthCodeUsed is set by the first token exchange. That exchange binds
	// the offer to the redeeming client.
	preAuthCodeUsed bool
	issuerState     string
	subject         string
	// holderClaims are the claims of the credential presented to authorize
	// this issuance (OpenID4VCI 1.1 §6). Other flows leave it empty.
	holderClaims map[string]any
	// authorization is authorizationPresentation or authorizationBrowser.
	authorization string
	accessToken   string
	// configIDs are the credential configurations in the offer. Nil means
	// the ticket.
	configIDs []string
	// jkt is the DPoP key thumbprint the access token is bound to. It is
	// empty for a bearer token.
	jkt string
	// withStatus adds a reference to the wallet status list so the
	// credential can be revoked.
	withStatus bool
	// deferred selects deferred issuance (OpenID4VCI 1.0 §9).
	deferred bool
	// batchSize is the number of copies to sign (§8.3), each for its own key.
	// 0 or 1 issues a single credential.
	batchSize int
	// clientAuth is how the wallet authenticated at the token exchange. It is
	// nil before the exchange.
	clientAuth *clientAuthentication
	expires    time.Time
}

// IssuerHandler returns the demo issuer. Mount it with the /issuer prefix
// stripped.
func (d *DemoRP) IssuerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.serveStatic("static/issuer.html"))
	// The script is a separate file because the wallet Content-Security-Policy
	// has no script-src 'unsafe-inline'.
	mux.HandleFunc("GET /issuer.js", d.serveStatic("static/issuer.js"))
	mux.HandleFunc("POST /api/offers", d.handleCreateOffer)
	mux.HandleFunc("GET /offer/{id}", d.handleOfferByReference)
	mux.HandleFunc("POST /token", d.handleToken)
	mux.HandleFunc("POST /credential", d.handleCredential)
	mux.HandleFunc("POST /deferred_credential", d.handleDeferredCredential)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", d.handleIssuerMetadata)
	mux.HandleFunc("GET /logo.svg", d.handleLogo)

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
	return httpsec.GuardAPI(mux, d.baseURL())
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
		contentType := "text/html; charset=utf-8"
		if strings.HasSuffix(name, ".js") {
			contentType = "text/javascript; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
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
		// §12.2.4 defines no token_endpoint parameter in Credential Issuer
		// Metadata. A 1.0 wallet gets its key proof challenge from the Nonce
		// Endpoint of §7.
		"nonce_endpoint": issuer + "/nonce",
		// OpenID4VCI 1.0 §8.3: one credential copy per key proof, up to batch_size.
		"batch_credential_issuance": map[string]any{"batch_size": demoBatchSize},
		"display": []map[string]any{
			{
				"name":   "EUDI Test Demo Issuer",
				"locale": "en-US",
				"logo":   map[string]any{"uri": issuer + "/logo.svg", "alt_text": "eudi-dev logo"},
			},
		},
		"credential_configurations_supported": d.credentialConfigurations(map[string]any{
			ticketConfigurationID: map[string]any{
				"format": "dc+sd-jwt",
				"vct":    TicketVCT,
				"scope":  ticketScope,
				"cryptographic_binding_methods_supported": []string{"jwk"},
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
				},
				// OpenID4VCI 1.0 §12.2.4 puts display and claims inside
				// credential_metadata.
				"credential_metadata": map[string]any{
					"display": []map[string]any{
						{
							"name":             "Demo Event Ticket",
							"description":      "A sample event ticket issued by the demo issuer",
							"locale":           "en-US",
							"logo":             map[string]any{"uri": issuer + "/logo.svg", "alt_text": "eudi-dev logo"},
							"background_color": "#0f766e",
							"text_color":       "#ffffff",
						},
					},
					"claims": []map[string]any{
						{"path": []string{"event"}},
						{"path": []string{"tier"}},
						{"path": []string{"seat"}},
						{"path": []string{"given_name"}},
						{"path": []string{"family_name"}},
						// Only tickets issued after wallet attestation have this claim.
						{"path": []string{"wallet_attestation"}},
					},
				},
			},
		}),
	}
	specs := []wallet.IssuedAttestationSpec{{Format: "dc+sd-jwt", VCT: TicketVCT}}
	for _, cfg := range d.templateConfigurations() {
		specs = append(specs, wallet.IssuedAttestationSpec{Format: cfg.format, VCT: cfg.vct, DocType: cfg.docType})
	}
	// The registrar API lives under the wallet base URL.
	info, err := wallet.IssuerInfo(d.wallet, d.baseURL(), specs)
	if err != nil {
		http.Error(w, "building issuer metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
	metadata["issuer_info"] = info
	if wallet.AcceptsOnlySignedIssuerMetadata(r.Header.Get("Accept")) {
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
	if len(d.offers) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open offers, try again later"})
		return
	}
	offer := &offerState{
		id:            randToken(),
		configIDs:     configIDs,
		withStatus:    withStatus,
		deferred:      r.URL.Query().Get("deferred") == "true",
		batchSize:     parseBatchSize(r.URL.Query().Get("batch")),
		authorization: normalizeAuthorizationMode(r.URL.Query().Get("authorization")),
		expires:       time.Now().Add(entryTTL),
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
		"scheme_uri": "eu-eaa-offer://?" + params,
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
		"credential_configuration_ids": offer.configurationIDs(),
		"grants":                       grants,
	})
}

func (d *DemoRP) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
	// authenticate the same way. A DPoP proof binds the token if the wallet
	// sends one.
	var jkt string
	if strings.TrimSpace(r.Header.Get("DPoP")) != "" {
		var err error
		jkt, err = d.verifyDPoPProof(r, d.issuerID()+"/token", "")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
	}
	clientAuth, ok := d.authenticateTokenClient(w, r, r.PostFormValue("client_id"), jkt)
	if !ok {
		return
	}
	code := r.PostFormValue("pre-authorized_code")

	d.mu.Lock()
	defer d.mu.Unlock()
	var offer *offerState
	for _, o := range d.offers {
		if o.preAuthCode == code {
			offer = o
			break
		}
	}
	if offer == nil || time.Now().After(offer.expires) || offer.preAuthCodeUsed {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "unknown, used or expired pre-authorized code",
		})
		return
	}
	// The token exchange binds the code to the client, so it is consumed here
	// (RFC 6749 §4.1.2).
	offer.preAuthCodeUsed = true
	offer.accessToken = randToken()
	offer.jkt = jkt
	offer.clientAuth = &clientAuth
	d.tokens[offer.accessToken] = offer
	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
	}
	// OpenID4VCI 1.0 §6.2 defines no c_nonce in the token response. The wallet
	// gets it from the Nonce Endpoint (§7).
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": offer.accessToken,
		"token_type":   tokenType,
		"expires_in":   int(entryTTL.Seconds()),
	})
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
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	token, ok := accessToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	d.mu.Lock()
	offer, known := d.tokens[token]
	if known && time.Now().After(offer.expires) {
		delete(d.tokens, token)
		known = false
	}
	// Copy under the lock because the token endpoint writes to the same struct.
	var granted ticketGrant
	if known {
		granted = ticketGrant{
			configIDs:    offer.configurationIDs(),
			subject:      offer.subject,
			holderClaims: offer.holderClaims,
			jkt:          offer.jkt,
			withStatus:   offer.withStatus,
			deferred:     offer.deferred,
			batchSize:    offer.batchSize,
			clientAuth:   offer.clientAuth,
		}
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	// A DPoP-bound token needs a DPoP proof with the same key here too.
	if granted.jkt != "" {
		presented, err := d.verifyDPoPProof(r, d.issuerID()+"/credential", token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
		if presented != granted.jkt {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_token", "the access token is bound to a different DPoP key"))
			return
		}
	}

	var req credentialRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_credential_request", err.Error()))
		return
	}
	if status, errResp := d.checkRequestedCredential(req, granted.configIDs); errResp != nil {
		writeJSON(w, status, errResp)
		return
	}
	granted.configID = req.CredentialConfigurationID
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

	// A deferred offer returns a transaction id here (§9).
	if granted.deferred {
		writeJSON(w, http.StatusOK, map[string]any{"transaction_id": d.deferIssuance(holderKeys, granted, token)})
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

// checkRequestedCredential applies §8.2, where credential_identifier is
// "REQUIRED when an Authorization Details of type openid_credential was
// returned from the Token Response [...] MUST NOT be used otherwise" and
// excludes credential_configuration_id.
//
// This issuer returns no authorization_details, so a request must use
// credential_configuration_id. The error codes are those of §8.3.1.2.
func (d *DemoRP) checkRequestedCredential(req credentialRequest, offered []string) (int, map[string]string) {
	if len(offered) == 0 {
		offered = []string{ticketConfigurationID}
	}
	switch {
	case req.CredentialIdentifier != "" && req.CredentialConfigurationID != "":
		return http.StatusBadRequest, oauthError("invalid_credential_request",
			"credential_identifier and credential_configuration_id must not both be present")
	case req.CredentialIdentifier != "":
		return http.StatusBadRequest, oauthError("unknown_credential_identifier",
			"this issuer returns no authorization_details, so no credential identifier is defined")
	case req.CredentialConfigurationID == "":
		return http.StatusBadRequest, oauthError("invalid_credential_request",
			"credential_configuration_id is required")
	case !slices.Contains(offered, req.CredentialConfigurationID):
		return http.StatusBadRequest, oauthError("unknown_credential_configuration",
			fmt.Sprintf("this offer covers the %s configuration(s), not %s", strings.Join(offered, ", "), req.CredentialConfigurationID))
	}
	return 0, nil
}

// handleNonce is the Nonce Endpoint of OpenID4VCI 1.0 §7. A 1.0 wallet gets
// its key proof challenge only from here.
func (d *DemoRP) handleNonce(w http.ResponseWriter, r *http.Request) {
	nonce := randToken()

	d.mu.Lock()
	d.pruneLocked()
	if len(d.nonces) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, oauthError("temporarily_unavailable", "too many outstanding nonces"))
		return
	}
	d.nonces[nonce] = time.Now().Add(entryTTL)
	d.mu.Unlock()

	// A cached response would hand the same challenge to another client.
	w.Header().Set("Cache-Control", "no-store")
	// §7.2 defines c_nonce as the only parameter of a Nonce Response.
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": nonce})
}

// A nonce stays valid until it expires, so all proofs in a batch can use it.
func (d *DemoRP) nonceIssued(nonce string) bool {
	if nonce == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	expires, ok := d.nonces[nonce]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(d.nonces, nonce)
		return false
	}
	return true
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

// proofClockSkew is the accepted window for the iat of a key proof. Appendix
// F.4 requires "the creation time of the JWT [...] is within an acceptable
// window (see Section 13.8)" and sets no value. This covers the round trip
// plus clock drift between two machines.
const proofClockSkew = 5 * time.Minute

// Key proofs are checked under OpenID4VCI 1.0 Appendix F.4. The aud check
// against the Credential Issuer Identifier (F.1) stops reuse of a proof made
// for another issuer.
func (d *DemoRP) verifyProofJWT(raw string) (*ecdsa.PublicKey, *proofError) {
	proof, err := parseCompactJWT(raw)
	if err != nil {
		return nil, invalidProof("parsing proof JWT: %v", err)
	}
	if typ, _ := proof.header["typ"].(string); typ != "openid4vci-proof+jwt" {
		return nil, invalidProof("proof JWT typ is %q, want openid4vci-proof+jwt", typ)
	}
	if alg, _ := proof.header["alg"].(string); alg != "ES256" {
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
	iat, ok := proof.payload["iat"].(float64)
	if !ok {
		return nil, invalidProof("proof JWT has no numeric iat")
	}
	if age := time.Since(time.Unix(int64(iat), 0)); age > proofClockSkew || age < -proofClockSkew {
		return nil, invalidProof("proof JWT iat is %s away from now, outside the %s window this issuer accepts", age.Round(time.Second), proofClockSkew)
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

// proofKeyMaterial reads the key a proof is bound to. Appendix F.1 allows
// exactly one of jwk, kid and x5c. A kid is a DID URL this issuer cannot
// resolve, so the error says that kid is unsupported.
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
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("proof JWT x5c is not a non-empty array")
	}
	encoded, ok := entries[0].(string)
	if !ok {
		return nil, fmt.Errorf("proof JWT x5c leaf is not a string")
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding proof JWT x5c leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing proof JWT x5c leaf: %w", err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
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
	// configIDs are the configurations in the offer. configID is the one in
	// the credential request. Empty means the ticket.
	configIDs []string
	configID  string
	subject   string
	// holderClaims are the claims of a credential presented to authorize this
	// issuance. Account sign-in leaves it empty.
	holderClaims map[string]any
	// jkt is the DPoP key thumbprint of the access token. It is empty for a
	// bearer token.
	jkt        string
	withStatus bool
	deferred   bool
	batchSize  int
	clientAuth *clientAuthentication
}

// signGranted issues the template with the granted configuration id. If no
// template has that id it issues the ticket.
func (d *DemoRP) signGranted(holderKey *ecdsa.PublicKey, granted ticketGrant) (string, error) {
	if cfg, ok := d.templateConfiguration(granted.configID); ok {
		return d.signTemplate(cfg, holderKey, granted)
	}
	return d.signTicket(holderKey, granted)
}

// configurationIDs returns the offer configurations. An empty offer means
// the ticket.
func (o *offerState) configurationIDs() []string {
	if len(o.configIDs) == 0 {
		return []string{ticketConfigurationID}
	}
	return append([]string(nil), o.configIDs...)
}

// signTicket signs with a leaf certificate of the ticket trust profile. The
// wallet trust list publishes the CA and credential type for that profile.
func (d *DemoRP) signTicket(holderKey *ecdsa.PublicKey, granted ticketGrant) (string, error) {
	spec, err := wallet.NormalizeIssuedAttestationSpec(wallet.IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    TicketVCT,
	}, "local")
	if err != nil {
		return "", fmt.Errorf("building ticket attestation spec: %w", err)
	}
	_ = d.wallet.RegisterIssuedAttestation(spec)
	signingKey, chain, err := d.wallet.SigningMaterialForIssuedAttestation(spec)
	if err != nil {
		return "", fmt.Errorf("building signing certificate chain: %w", err)
	}
	// Round iat to the hour. A precise issuance second in iat and exp would let
	// colluding verifiers correlate the copies of a batch (RFC 9901 §10.1).
	issuedAt := time.Now().Truncate(time.Hour)
	config := mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       TicketVCT,
		ExpiresIn: 24 * time.Hour,
		IssuedAt:  &issuedAt,
		Claims:    ticketClaims(granted.subject, granted.holderClaims, granted.clientAuth),
		Key:       signingKey,
		HolderKey: holderKey,
		CertChain: chain,
	}
	if granted.withStatus {
		uri := d.statusListURI()
		if uri == "" {
			return "", fmt.Errorf("this wallet has no status list URL")
		}
		config.StatusListURI = uri
		// Persist the reserved index before a request reloads the wallet. A reused
		// index would revoke two credentials at once.
		idx, err := d.wallet.NextStatusIndex()
		if err != nil {
			return "", err
		}
		config.StatusListIdx = idx
		d.saveWallet()
	}
	return mock.GenerateSDJWT(config)
}

func decodeJSONBody(r *http.Request, target any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(target)
}

// accessToken reads the access token from the Authorization header. It
// accepts the DPoP and Bearer schemes.
func accessToken(r *http.Request) (string, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	for _, scheme := range []string{"Bearer ", "DPoP "} {
		if len(auth) > len(scheme) && strings.EqualFold(auth[:len(scheme)], scheme) {
			return strings.TrimSpace(auth[len(scheme):]), true
		}
	}
	return "", false
}
