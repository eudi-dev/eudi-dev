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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/qr"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
	"github.com/eudi-dev/eudi-dev/v3/internal/typemetadata"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v3/internal/webui"
)

// The German PID extends the base SD-JWT PID type. It answers a request for
// the base type. A base PID does not answer a request for the German type.
const (
	PIDVCT     = credtype.PIDVCT
	PIDDocType = credtype.PIDDocType
)

type requestState struct {
	// id is the request-id of OpenID4VP 1.0 §13.3. It is the state of the
	// request and identifies it in the request and response URIs, so anyone
	// who sees the QR code knows it.
	id string
	// transactionID is the transaction-id of §13.3. Only the page that created
	// the request gets it. The page reads the result with it.
	transactionID string
	// responseCode is the "fresh, cryptographically random value" that §8.2
	// requires in the redirect_uri after the response. The device redirected
	// by the wallet reads the result with it.
	responseCode string
	// queries and sets are the DCQL query. The request sends them and the
	// response is checked against them.
	queries []credentialQuery
	sets    []credentialSet
	// rawDCQL is the DCQL query from the verifier page. The request sends it
	// unchanged.
	rawDCQL  map[string]any
	nonce    string
	clientID string
	// interactiveEndpoint is set for a request inside an OpenID4VCI 1.1 §6
	// exchange. The presentation is then bound to that Authorization Challenge
	// Endpoint (Appendix A.2.5, Appendix A.3.5).
	interactiveEndpoint string
	expires             time.Time
	answered            bool // any later response is a replay

	// requestObject is the signed JAR served from /verifier/request/{id}.
	// encKey decrypts the direct_post.jwt response. HAIP requires a signed
	// request and an encrypted response.
	requestObject string
	encKey        *ecdsa.PrivateKey
	// dcAPIOrigin is set for a request over the Digital Credentials API. It
	// is the origin of the verifier page, which the response binds to
	// (OpenID4VP 1.0 Appendix A).
	dcAPIOrigin string
	// dcAPIProtocol is the Digital Credentials API protocol of the request.
	dcAPIProtocol string

	// selection is the page's choice that created the request. The page
	// restores it after the wallet redirects there.
	selection requestSelection

	status string // pending | verified | failed
	err    string
	claims map[string]any
	checks []map[string]any
	// presentation is kept for the decoder even if verification fails.
	presentation string
}

// VerifierHandler returns the demo verifier. Mount it with the /verifier
// prefix stripped.
func (d *DemoRP) VerifierHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.servePage("static/verifier.html"))
	mux.HandleFunc("GET /verifier.js", d.serveStatic("static/verifier.js"))
	mux.HandleFunc("GET /link-qr.js", d.serveStatic("static/link-qr.js"))
	mux.HandleFunc("GET /link-qr.css", d.serveStatic("static/link-qr.css"))
	webui.Mount(mux)
	mux.HandleFunc("POST /api/requests", d.handleCreateRequest)
	mux.HandleFunc("GET /api/requests/{key}", d.handleRequestStatus)
	mux.HandleFunc("POST /api/requests/{key}/dc-api", d.handleDCAPIResponse)
	mux.HandleFunc("GET /request/{id}", d.handleRequestObject)
	mux.HandleFunc("POST /response/{id}", d.handlePresentationResponse)
	// GuardAPI covers only the page's calls to /api/. Wallets on other
	// origins call the protocol endpoints.
	return httpsec.GuardAPI(limitBodies(mux), d.baseURL())
}

func (d *DemoRP) handleRequestObject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	req, ok := d.requests[id]
	var jar string
	if ok {
		jar = req.requestObject
		ok = !time.Now().After(req.expires)
	}
	d.mu.Unlock()
	if !ok || jar == "" {
		apierror.WriteStatus(w, http.StatusNotFound, "unknown or expired request")
		return
	}
	w.Header().Set("Content-Type", format.MediaTypeRequestObject)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(jar))
}

type createRequestBody struct {
	Type string `json:"type"` // "ticket" (default), "pid", or "custom"
	// Format is "sd-jwt", "mdoc" or "both" (the default) for a PID request.
	// The ticket exists only as an SD-JWT VC.
	Format string `json:"format"`
	// VCT is the requested PID type. Empty requests urn:eudi:pid:1 together
	// with the national PID types. A national type such as urn:eudi:pid:de:1
	// is answered only by a credential of that type.
	VCT string `json:"vct"`
	// Ticket adds the demo ticket to a PID request. "combined" puts PID and
	// ticket in one option next to a PID-only option. "optional" adds a
	// second credential set with required: false.
	Ticket string `json:"ticket"`
	// Multiple sets multiple on every credential query (OpenID4VP 1.0 §6.1).
	Multiple bool `json:"multiple"`
	// Credentials are the DCQL credential queries of a "custom" request.
	Credentials []customCredentialTO `json:"credentials"`
	// DCQLQuery is the DCQL query from the verifier page. It replaces
	// Credentials.
	DCQLQuery map[string]any `json:"dcql_query"`
	// ClientIDScheme is the client identifier prefix of a custom request:
	// "x509_hash" (the default), "x509_san_dns", "redirect_uri" or
	// "pre-registered". Only the x509 prefixes sign the request object.
	ClientIDScheme string `json:"client_id_scheme"`
	// ClientID is the identifier for the pre-registered prefix. The other
	// prefixes derive it from the certificate or the response endpoint.
	ClientID string `json:"client_id"`
	// SigningKey is an optional PEM bundle with an EC private key and its
	// access certificate chain. The chain goes into the request object's x5c.
	// Empty uses the demo verifier's access certificate.
	SigningKey string `json:"signing_key"`
	// VerifierInfo is the verifier_info array (OpenID4VP 1.0 §5.1) that goes
	// with SigningKey. Empty sends none.
	VerifierInfo []any `json:"verifier_info"`
	// Delivery "dc_api" returns the argument for navigator.credentials.get()
	// (OpenID4VP 1.0 Appendix A). Empty or "redirect" returns the wallet URL
	// and the openid4vp:// URI.
	Delivery string `json:"delivery"`
	// Signing chooses the protocol of a dc_api request: "signed",
	// "unsigned" or "multisigned". Empty signs a request whose client_id
	// scheme signs.
	Signing string `json:"signing"`
	// Identity "unregistered" sends the demo verifier's access certificate
	// without its registration certificate. Without SigningKey, "registered"
	// or an empty value sends both.
	Identity string `json:"identity"`
}

// ticketClaimNames returns the claims of the ticket template. The demo
// verifier's registration certificate lists them.
func (d *DemoRP) ticketClaimNames() []string {
	cfg, ok := d.templateConfiguration(ticketConfigurationID)
	if !ok {
		return nil
	}
	return slices.Sorted(maps.Keys(cfg.template.Claims))
}

// requestSelection is the part of a createRequestBody that the page's
// controls set.
type requestSelection struct {
	Type     string `json:"type"`
	Format   string `json:"format,omitempty"`
	VCT      string `json:"vct,omitempty"`
	Ticket   string `json:"ticket,omitempty"`
	Multiple bool   `json:"multiple,omitempty"`
}

func (b createRequestBody) selection() requestSelection {
	if b.Type == "custom" {
		return requestSelection{Type: b.Type}
	}
	return requestSelection{Type: b.Type, Format: b.Format, VCT: b.VCT, Ticket: b.Ticket, Multiple: b.Multiple}
}

type customCredentialTO struct {
	Format  string  `json:"format"`  // dc+sd-jwt or mso_mdoc
	VCT     string  `json:"vct"`     // the type for dc+sd-jwt
	DocType string  `json:"doctype"` // the doctype for mso_mdoc
	Claims  [][]any `json:"claims"`  // each a DCQL claims path (strings, null, integers)
	// Multiple lets the wallet answer with several credentials (OpenID4VP 1.0
	// §6.1).
	Multiple bool `json:"multiple"`
}

// credentialQuery is one DCQL credential query (OpenID4VP 1.0 §6.1).
type credentialQuery struct {
	id      string
	format  string
	vct     string
	vcts    []string
	docType string
	paths   [][]any
	// claims and claimSets come from the page's DCQL query. They replace
	// paths.
	claims    []claimQuery
	claimSets [][]string
	multiple  bool
	// trustedAuthorities is the trusted_authorities value, if any.
	trustedAuthorities []map[string]any
	// resultKey is the key of this entry in the verified claims. An empty key puts the
	// claims of a single presentation at the top level.
	resultKey string
}

// credentialSet is one DCQL credential set. Each option lists query ids.
type credentialSet struct {
	options  [][]string
	optional bool
}

func (q credentialQuery) label() string {
	if q.resultKey != "" {
		return q.resultKey
	}
	return q.id
}

// dcqlQuery is the dcql_query parameter of the request.
func (r *requestState) dcqlQuery() map[string]any {
	if r.rawDCQL != nil {
		return r.rawDCQL
	}
	credentials := make([]map[string]any, 0, len(r.queries))
	for _, q := range r.queries {
		entry := map[string]any{"id": q.id, "format": q.format}
		if q.format == credtype.FormatMDOC {
			entry["meta"] = map[string]any{"doctype_value": q.docType}
		} else {
			entry["meta"] = map[string]any{"vct_values": q.typeValues()}
		}
		if len(q.paths) > 0 {
			claims := make([]map[string]any, 0, len(q.paths))
			for _, path := range q.paths {
				claims = append(claims, map[string]any{"path": path})
			}
			entry["claims"] = claims
		}
		if q.multiple {
			entry["multiple"] = true
		}
		if len(q.trustedAuthorities) > 0 {
			entry["trusted_authorities"] = q.trustedAuthorities
		}
		credentials = append(credentials, entry)
	}
	dcql := map[string]any{"credentials": credentials}
	if len(r.sets) > 0 {
		sets := make([]map[string]any, 0, len(r.sets))
		for _, set := range r.sets {
			entry := map[string]any{"options": set.options}
			if set.optional {
				entry["required"] = false
			}
			sets = append(sets, entry)
		}
		dcql["credential_sets"] = sets
	}
	return dcql
}

// unsatisfied explains why the answered query ids do not satisfy the request.
// Without credential_sets every query is required. With them, each required
// set needs one option whose queries are all answered.
func (r *requestState) unsatisfied(answered map[string]bool) error {
	if len(r.sets) == 0 {
		var missing []string
		for _, q := range r.queries {
			if !answered[q.id] {
				missing = append(missing, q.id)
			}
		}
		return errIf(len(missing) > 0, "no presentation for %s", strings.Join(missing, ", "))
	}
	for _, set := range r.sets {
		if set.optional || slices.ContainsFunc(set.options, func(option []string) bool {
			return !slices.ContainsFunc(option, func(id string) bool { return !answered[id] })
		}) {
			continue
		}
		var options []string
		for _, option := range set.options {
			options = append(options, "["+strings.Join(option, ", ")+"]")
		}
		return fmt.Errorf("no presentation answers any of the options %s", strings.Join(options, " or "))
	}
	return nil
}

func normalizePIDFormat(format string) (sdjwt, mdoc bool, err error) {
	switch strings.TrimSpace(format) {
	case "", "both":
		return true, true, nil
	case "sd-jwt", "sdjwt", credtype.FormatSDJWT:
		return true, false, nil
	case "mdoc", credtype.FormatMDOC:
		return false, true, nil
	default:
		return false, false, fmt.Errorf("format must be sd-jwt, mdoc or both")
	}
}

// ARF Annex 2 PID_14 defines PID types under urn:eudi:pid:. An empty value
// selects the base PID.
func normalizePIDVCT(vct string) (string, error) {
	vct = strings.TrimSpace(vct)
	if vct == "" {
		return PIDVCT, nil
	}
	if !strings.HasPrefix(vct, credtype.PIDVCTPrefix) {
		return "", fmt.Errorf("vct must be a PID type in %s", credtype.PIDVCTPrefix)
	}
	return vct, nil
}

func (d *DemoRP) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	var body createRequestBody
	if err := decodeJSONBody(r, &body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}

	if body.Identity != "" && body.Identity != "registered" && body.Identity != "unregistered" {
		apierror.WriteStatus(w, http.StatusBadRequest, `identity must be "registered" or "unregistered"`)
		return
	}

	signedScheme := body.Type != "custom" || signingScheme(customScheme(body))
	dcAPIOrigin, dcAPIProtocol, err := d.dcAPIDelivery(body, signedScheme)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusBadRequest, err)
		return
	}

	if body.Type == "custom" {
		d.createCustomRequest(w, body, dcAPIOrigin, dcAPIProtocol)
		return
	}

	var vct, docType string
	var claims, mdocClaims []string
	ticketMode := strings.TrimSpace(body.Ticket)
	if ticketMode != "" && ticketMode != "combined" && ticketMode != "optional" {
		apierror.WriteStatus(w, http.StatusBadRequest, `ticket must be "combined" or "optional"`)
		return
	}
	switch body.Type {
	case "", "ticket":
		body.Type = "ticket"
		if ticketMode != "" {
			apierror.WriteStatus(w, http.StatusBadRequest, "ticket applies only to pid requests. The request then asks for the ticket next to the PID")
			return
		}

		wantSDJWT, _, err := normalizePIDFormat(body.Format)
		if err != nil {
			apierror.WriteStatusErr(w, http.StatusBadRequest, err)
			return
		}
		// The ticket exists only as an SD-JWT VC.
		if !wantSDJWT {
			apierror.WriteStatus(w, http.StatusBadRequest, "the demo ticket only exists as an SD-JWT VC")
			return
		}
		vct = TicketVCT
		claims = d.ticketClaimNames()
	case "pid":
		// An explicit format tests how a wallet handles a request for a format
		// that it does not hold.
		wantSDJWT, wantMDOC, err := normalizePIDFormat(body.Format)
		if err != nil {
			apierror.WriteStatusErr(w, http.StatusBadRequest, err)
			return
		}
		requested, err := normalizePIDVCT(body.VCT)
		if err != nil {
			apierror.WriteStatusErr(w, http.StatusBadRequest, err)
			return
		}
		// ISO/IEC 18013-5 has no inheritance between document types. Every mdoc
		// PID has the same doctype and keeps national elements in a second
		// namespace. Any PID would answer a doctype request for a national PID.
		domestic := requested != PIDVCT
		if domestic && wantMDOC && !wantSDJWT {
			apierror.WriteStatus(w, http.StatusBadRequest, "this credential type has no mdoc form. Every PID uses the doctype "+PIDDocType+", so request the PID as mdoc instead")
			return
		}
		if wantSDJWT {
			vct = requested
			claims = wallet.IdentityCheckClaims()
		}
		if wantMDOC && !domestic {
			docType = PIDDocType
			mdocClaims = wallet.IdentityCheckClaims()
		}
		// The combined shape puts the ticket in the SD-JWT PID option.
		if ticketMode == "combined" && !wantSDJWT {
			apierror.WriteStatus(w, http.StatusBadRequest, "ticket: combined needs the SD-JWT PID in the request, so use format sd-jwt or both")
			return
		}
	default:
		apierror.WriteStatus(w, http.StatusBadRequest, "type must be ticket or pid")
		return
	}

	base := d.baseURL()
	req := &requestState{
		id:            randToken(),
		transactionID: randToken(),
		nonce:         randToken(),
		status:        "pending",
		expires:       time.Now().Add(entryTTL),
		selection:     body.selection(),
		dcAPIOrigin:   dcAPIOrigin,
		dcAPIProtocol: dcAPIProtocol,
	}
	// Only the requested formats get a query, so a response in another format
	// is not accepted.
	var sdjwtID, mdocID, ticketID string
	if vct != "" {
		sdjwtID = body.Type
		query := credentialQuery{id: sdjwtID, format: credtype.FormatSDJWT, vct: vct, paths: namePaths("", claims), multiple: body.Multiple}
		if vct == PIDVCT {
			query.vcts = credtemplate.PIDTypes(d.wallet.Templates)
		}
		req.queries = append(req.queries, query)
	}
	if docType != "" {
		mdocID = body.Type + "_mdoc"
		req.queries = append(req.queries, credentialQuery{id: mdocID, format: credtype.FormatMDOC, docType: docType, paths: namePaths(docType, mdocClaims), multiple: body.Multiple})
	}
	if ticketMode != "" {
		ticketID = "ticket"
		req.queries = append(req.queries, credentialQuery{id: ticketID, format: credtype.FormatSDJWT, vct: TicketVCT, paths: namePaths("", d.ticketClaimNames()), multiple: body.Multiple, resultKey: "ticket"})
	}

	// The credential set options make one PID format enough.
	var pidOptions [][]string
	for _, id := range []string{sdjwtID, mdocID} {
		if id != "" {
			pidOptions = append(pidOptions, []string{id})
		}
	}
	switch ticketMode {
	case "combined":
		options := append([][]string{{sdjwtID, ticketID}}, pidOptions...)
		req.sets = []credentialSet{{options: options}}
	case "optional":
		req.sets = []credentialSet{{options: pidOptions}, {options: [][]string{{ticketID}}, optional: true}}
	default:
		if len(pidOptions) > 1 {
			req.sets = []credentialSet{{options: pidOptions}}
		}
	}
	responseURI := base + "/verifier/response/" + req.id

	// HAIP requires x509_hash for signed requests.
	signingKey, chain, err := d.requestSigningMaterial(body)
	if err != nil {
		writeSigningMaterialError(w, body, err)
		return
	}
	req.clientID = oid4vp.X509HashClientID(chain[0])

	req.encKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "generating response encryption key: "+err.Error())
		return
	}

	if req.dcAPIProtocol == dcAPIUnsigned {
		d.deliverUnsignedRequest(w, req, responseURI, base)
		return
	}
	info, err := d.verifierInfo(body)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "registration certificate: "+err.Error())
		return
	}
	d.finalizeRequest(w, req, responseURI, base, signingKey, chain, info)
}

func (d *DemoRP) requestSigningMaterial(body createRequestBody) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if strings.TrimSpace(body.SigningKey) == "" {
		if d.configuredVerifier != nil {
			return d.configuredVerifier.Key, d.configuredVerifier.Chain, nil
		}
		key, chain, err := d.wallet.DemoVerifierAccessSigningMaterial()
		if err == nil && (key == nil || len(chain) == 0) {
			err = fmt.Errorf("the wallet has no access certificate")
		}
		return key, chain, err
	}
	return parseSigningKeyBundle(body.SigningKey)
}

// verifierInfo returns the verifier_info of a signed request. The demo
// verifier is registered with the wallet's registrar, so its own requests
// carry its registration certificate (rc-wrp+jwt, ETSI TS 119 475, OpenID4VP
// 1.0 §5.1).
func (d *DemoRP) verifierInfo(body createRequestBody) ([]any, error) {
	if strings.TrimSpace(body.SigningKey) != "" || body.Identity == "unregistered" {
		return body.VerifierInfo, nil
	}
	if d.configuredVerifier != nil {
		return d.configuredVerifier.Info, nil
	}
	return d.wallet.DemoVerifierInfo()
}

// A supplied bundle that does not parse is the client's error. Missing demo
// material is the server's.
func writeSigningMaterialError(w http.ResponseWriter, body createRequestBody, err error) {
	status := http.StatusBadRequest
	if strings.TrimSpace(body.SigningKey) == "" {
		status = http.StatusInternalServerError
	}
	apierror.WriteStatus(w, status, "signing material: "+err.Error())
}

// finalizeRequest signs the request object, stores the request and returns the
// wallet URL.
func (d *DemoRP) finalizeRequest(w http.ResponseWriter, req *requestState, responseURI, base string, signingKey *ecdsa.PrivateKey, chain []*x509.Certificate, verifierInfo []any) {
	now := time.Now()
	claims := map[string]any{
		"iss":             req.clientID,
		"aud":             oid4vp.SelfIssuedAudience,
		"iat":             now.Unix(),
		"exp":             req.expires.Unix(),
		"client_id":       req.clientID,
		"response_type":   "vp_token",
		"response_mode":   "direct_post.jwt",
		"response_uri":    responseURI,
		"nonce":           req.nonce,
		"state":           req.id,
		"dcql_query":      req.dcqlQuery(),
		"client_metadata": responseEncryptionMetadata(req.encKey),
	}
	if len(verifierInfo) > 0 {
		claims["verifier_info"] = verifierInfo
	}
	if req.dcAPIOrigin != "" {
		// OpenID4VP 1.0 Appendix A.2: the response goes back through the API,
		// and a signed request lists the origins it may come from. State isn't a
		// DC API parameter.
		claims["response_mode"] = "dc_api.jwt"
		claims["expected_origins"] = []string{req.dcAPIOrigin}
		delete(claims, "response_uri")
		delete(claims, "state")
	}
	if req.dcAPIProtocol == dcAPIMultiSigned {
		request, err := multiSignedRequest(claims, signingKey, chain, req.clientID, verifierInfo)
		if err != nil {
			apierror.WriteStatus(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.storeRequest(req)
		writeCreatedDCAPIRequest(w, req, dcAPIMultiSigned, map[string]any{"request": request})
		return
	}
	jar, err := oid4vp.SignRequestObjectJWT(claims, signingKey, chain)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "signing request object: "+err.Error())
		return
	}
	req.requestObject = jar
	d.storeRequest(req)

	if req.dcAPIOrigin != "" {
		writeCreatedDCAPIRequest(w, req, dcAPISigned, map[string]any{"request": jar})
		return
	}

	// The signed object is too long for a scheme URI or a QR code, so it is
	// passed by reference.
	params := url.Values{
		"client_id":   {req.clientID},
		"request_uri": {base + "/verifier/request/" + req.id},
	}.Encode()

	writeCreatedRequest(w, req, base+"/authorize?"+params, "openid4vp://?"+params)
}

func (d *DemoRP) storeRequest(req *requestState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	makeRoom(d.requests, func(r *requestState) time.Time { return r.expires })
	d.requests[req.id] = req
}

// writeCreatedRequest returns the transaction_id to the page that created the
// request. The page reads the result with it.
func writeCreatedRequest(w http.ResponseWriter, req *requestState, walletURL, schemeURI string) {
	doc := map[string]any{
		"id":             req.id,
		"transaction_id": req.transactionID,
		"wallet_url":     walletURL,
		"scheme_uri":     schemeURI,
	}
	addLinkQRCodes(doc, "wallet_url", "scheme_uri")
	writeJSON(w, http.StatusCreated, doc)
}

// addLinkQRCodes adds the QR code of each named link as <name>_qr, for a
// wallet on a phone. A link too long for a QR code stays a link.
func addLinkQRCodes(doc map[string]any, names ...string) {
	for _, name := range names {
		if svg, err := qr.SVG(doc[name].(string)); err == nil {
			doc[name+"_qr"] = svg
		}
	}
}

func (d *DemoRP) createCustomRequest(w http.ResponseWriter, body createRequestBody, dcAPIOrigin, dcAPIProtocol string) {
	var written []credentialQuery
	var writtenSets []credentialSet
	if body.DCQLQuery != nil {
		var err error
		if written, writtenSets, err = parseDCQLQuery(body.DCQLQuery); err != nil {
			apierror.WriteStatusErr(w, http.StatusBadRequest, err)
			return
		}
	} else if len(body.Credentials) == 0 {
		apierror.WriteStatus(w, http.StatusBadRequest, "a custom request needs at least one credential")
		return
	}
	signingKey, chain, err := d.requestSigningMaterial(body)
	if err != nil {
		writeSigningMaterialError(w, body, err)
		return
	}
	scheme := customScheme(body)
	signed := signingScheme(scheme) && dcAPIProtocol != dcAPIUnsigned
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "generating response encryption key: "+err.Error())
		return
	}
	base := d.baseURL()
	req := &requestState{
		id:            randToken(),
		transactionID: randToken(),
		nonce:         randToken(),
		status:        "pending",
		expires:       time.Now().Add(entryTTL),
		encKey:        encKey,
		selection:     body.selection(),
		dcAPIOrigin:   dcAPIOrigin,
		dcAPIProtocol: dcAPIProtocol,
	}
	responseURI := base + "/verifier/response/" + req.id
	req.clientID, err = customClientID(scheme, chain, responseURI, body.ClientID)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusBadRequest, err)
		return
	}
	if len(body.VerifierInfo) > 0 && !signed {
		apierror.WriteStatus(w, http.StatusBadRequest, "a custom verifier_info needs a signed request with the client_id scheme x509_hash or x509_san_dns")
		return
	}

	if body.DCQLQuery != nil {
		req.queries, req.sets, req.rawDCQL = written, writtenSets, body.DCQLQuery
	}
	for i, c := range body.Credentials {
		if body.DCQLQuery != nil {
			break
		}
		format := strings.TrimSpace(c.Format)
		switch {
		case format == credtype.FormatSDJWT && strings.TrimSpace(c.VCT) == "":
			apierror.WriteStatus(w, http.StatusBadRequest, "a dc+sd-jwt credential needs a vct")
			return
		case format == credtype.FormatMDOC && strings.TrimSpace(c.DocType) == "":
			apierror.WriteStatus(w, http.StatusBadRequest, "an mso_mdoc credential needs a doctype")
			return
		case format != credtype.FormatSDJWT && format != credtype.FormatMDOC:
			apierror.WriteStatus(w, http.StatusBadRequest, "format must be dc+sd-jwt or mso_mdoc")
			return
		}
		var paths [][]any
		for _, path := range c.Claims {
			if len(path) > 0 {
				paths = append(paths, path)
			}
		}
		id := fmt.Sprintf("cred_%d", i)
		req.queries = append(req.queries, credentialQuery{id: id, format: format, vct: c.VCT, docType: c.DocType, paths: paths, multiple: c.Multiple, resultKey: id})
	}

	if signed {
		info, err := d.verifierInfo(body)
		if err != nil {
			apierror.WriteStatus(w, http.StatusInternalServerError, "registration certificate: "+err.Error())
			return
		}
		d.finalizeRequest(w, req, responseURI, base, signingKey, chain, info)
		return
	}
	d.deliverUnsignedRequest(w, req, responseURI, base)
}

// customScheme returns the client identifier prefix of a custom request.
func customScheme(body createRequestBody) string {
	if scheme := strings.TrimSpace(body.ClientIDScheme); scheme != "" {
		return scheme
	}
	return "x509_hash"
}

// signingScheme reports a prefix that needs a signed request object
// (OpenID4VP 1.0 §5.9).
func signingScheme(scheme string) bool {
	return scheme == "x509_hash" || scheme == "x509_san_dns"
}

// customClientID builds the client identifier for the selected prefix
// (OpenID4VP 1.0 §5.9). The x509 prefixes use the signing certificate.
// redirect_uri uses the response endpoint. pre-registered is a plain
// identifier.
func customClientID(scheme string, chain []*x509.Certificate, responseURI, preRegistered string) (string, error) {
	switch scheme {
	case "x509_hash":
		if len(chain) == 0 {
			return "", fmt.Errorf("x509_hash needs a signing certificate")
		}
		return oid4vp.X509HashClientID(chain[0]), nil
	case "x509_san_dns":
		if len(chain) == 0 {
			return "", fmt.Errorf("x509_san_dns needs a signing certificate")
		}
		if len(chain[0].DNSNames) == 0 {
			return "", fmt.Errorf("x509_san_dns needs a certificate with a DNS SAN, so supply a signing key whose certificate carries one")
		}
		return "x509_san_dns:" + chain[0].DNSNames[0], nil
	case "redirect_uri":
		return "redirect_uri:" + responseURI, nil
	case "pre-registered":
		if id := strings.TrimSpace(preRegistered); id != "" {
			return id, nil
		}
		return "eudi-dev-demo-verifier", nil
	default:
		return "", fmt.Errorf("unknown client_id scheme %q, use x509_hash, x509_san_dns, redirect_uri or pre-registered", scheme)
	}
}

// deliverUnsignedRequest sends a redirect_uri or pre-registered request as
// plain query parameters (OpenID4VP 1.0 §5). The response is encrypted to
// the key in client_metadata.
func (d *DemoRP) deliverUnsignedRequest(w http.ResponseWriter, req *requestState, responseURI, base string) {
	dcqlJSON, err := json.Marshal(req.dcqlQuery())
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "encoding dcql_query: "+err.Error())
		return
	}
	metaJSON, err := json.Marshal(responseEncryptionMetadata(req.encKey))
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "encoding client_metadata: "+err.Error())
		return
	}
	d.storeRequest(req)

	if req.dcAPIOrigin != "" {
		// OpenID4VP 1.0 Appendix A.3.1: the data of an unsigned request holds
		// the request parameters as JSON.
		writeCreatedDCAPIRequest(w, req, dcAPIUnsigned, map[string]any{
			"response_type":   "vp_token",
			"response_mode":   "dc_api.jwt",
			"nonce":           req.nonce,
			"dcql_query":      req.dcqlQuery(),
			"client_metadata": responseEncryptionMetadata(req.encKey),
		})
		return
	}

	params := url.Values{
		"client_id":       {req.clientID},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"response_uri":    {responseURI},
		"nonce":           {req.nonce},
		"state":           {req.id},
		"dcql_query":      {string(dcqlJSON)},
		"client_metadata": {string(metaJSON)},
	}.Encode()

	writeCreatedRequest(w, req, base+"/authorize?"+params, "openid4vp://?"+params)
}

func parseSigningKeyBundle(pemBundle string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	var key *ecdsa.PrivateKey
	var chain []*x509.Certificate
	rest := []byte(pemBundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing EC private key: %w", err)
			}
			key = k
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing private key: %w", err)
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("the signing key must be an EC key")
			}
			key = ec
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing certificate: %w", err)
			}
			chain = append(chain, c)
		}
	}
	if key == nil {
		return nil, nil, fmt.Errorf("the signing key PEM carries no private key")
	}
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("the signing key PEM carries no certificate")
	}
	return key, chain, nil
}

// namePaths turns claim names into DCQL claims paths, prefixed with an mdoc
// namespace if one is given.
func namePaths(namespace string, names []string) [][]any {
	paths := make([][]any, 0, len(names))
	for _, name := range names {
		if namespace != "" {
			paths = append(paths, []any{namespace, name})
		} else {
			paths = append(paths, []any{name})
		}
	}
	return paths
}

// checkPresentationAudience expects the page origin for the Digital
// Credentials API. Otherwise it expects the OpenID4VP client ID or the
// Authorization Challenge Endpoint. OpenID4VCI 1.1 Appendix A.3.5 uses the
// endpoint origin. Its example, the other appendices and §6.2.1.5 use the
// full endpoint. Both ia: forms are accepted.
func checkPresentationAudience(req *requestState, aud string) error {
	// OpenID4VP 1.0 §5.9.3: over the Digital Credentials API "the audience of
	// the Credential Presentation is always the origin value prefixed by
	// origin:".
	if req.dcAPIOrigin != "" {
		want := "origin:" + req.dcAPIOrigin
		return errIf(aud != want, "aud is %q, want %q", aud, want)
	}
	if req.interactiveEndpoint == "" {
		return errIf(aud != req.clientID, "aud is %q, want %q", aud, req.clientID)
	}
	endpoint := "ia:" + req.interactiveEndpoint
	origin := "ia:" + originOf(req.interactiveEndpoint)
	return errIf(aud != endpoint && aud != origin, "aud is %q, want %q", aud, endpoint)
}

// rebuildSessionTranscript recomputes the session transcript that the holder
// signs. Interactive Authorization uses the handover of OpenID4VCI 1.1
// Appendix A.2.5.
func (d *DemoRP) rebuildSessionTranscript(req *requestState) ([]byte, error) {
	if req.interactiveEndpoint != "" {
		return mdoc.OID4VCIIAESessionTranscript(req.interactiveEndpoint, req.nonce, encryptionJWKThumbprint(req.encKey))
	}
	if req.dcAPIOrigin != "" {
		return mdoc.OID4VPDCAPISessionTranscript(req.dcAPIOrigin, req.nonce, encryptionJWKThumbprint(req.encKey))
	}
	return mdoc.OID4VPSessionTranscript(
		req.clientID, req.nonce, encryptionJWKThumbprint(req.encKey), d.baseURL()+"/verifier/response/"+req.id)
}

// originOf returns the origin of a URL (RFC 6454 §4).
func originOf(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

var responseEncValues = []string{jwe.EncA128GCM, jwe.EncA256GCM}

// responseEncryptionMetadata publishes the public per-request encryption key.
// The wallet needs a usable JWK with an explicit alg for direct_post.jwt.
func responseEncryptionMetadata(key *ecdsa.PrivateKey) map[string]any {
	jwk, _ := keys.PublicJWK(&key.PublicKey)
	jwk["use"], jwk["alg"], jwk["kid"] = "enc", jwe.AlgECDHES, "demo-verifier-response-enc"
	return map[string]any{
		"jwks": map[string]any{
			"keys": []map[string]any{jwk},
		},
		// HAIP 1.0 §5: "Verifiers MUST list both A128GCM and A256GCM in
		// encrypted_response_enc_values_supported in their client metadata."
		"encrypted_response_enc_values_supported": responseEncValues,
		"vp_formats_supported": map[string]any{
			credtype.FormatSDJWT: map[string]any{
				"sd-jwt_alg_values": []string{jws.AlgES256},
				"kb-jwt_alg_values": []string{jws.AlgES256},
			},
			// OpenID4VP 1.0 Appendix B.2.2 defines these two members for
			// mso_mdoc. Their values are COSE algorithm identifiers (-7 is ES256).
			credtype.FormatMDOC: map[string]any{
				"issuerauth_alg_values": []int{-7},
				"deviceauth_alg_values": []int{-7},
			},
		},
	}
}

// handleRequestStatus releases the result to the holder of the transaction_id
// or of the response_code.
func (d *DemoRP) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	d.mu.Lock()
	req := d.requestByKeyLocked(key)
	ok := req != nil
	var doc map[string]any
	if ok {
		status := req.status
		// Expire unanswered requests so the page stops polling.
		if status == "pending" && time.Now().After(req.expires) {
			status = "expired"
		}
		doc = map[string]any{
			"status":  status,
			"claims":  req.claims,
			"checks":  req.checks,
			"request": req.selection,
		}
		// The decoder input keeps key binding and device authentication.
		if req.presentation != "" {
			doc["presentation"] = req.presentation
		}
		if req.err != "" {
			doc["error"] = req.err
		}
		// A failure that did not answer the request leaves it open for the
		// wallet's response, so the page keeps polling.
		if (status == "failed" || status == "declined") && !req.answered && time.Now().Before(req.expires) {
			doc["open"] = true
		}
	}
	d.mu.Unlock()
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "unknown or expired request")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (d *DemoRP) requestByKeyLocked(key string) *requestState {
	if key == "" {
		return nil
	}
	for _, req := range d.requests {
		if req.transactionID == key || req.responseCode == key {
			return req
		}
	}
	return nil
}

func (d *DemoRP) handlePresentationResponse(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	d.mu.Lock()
	req, ok := d.requests[id]
	if ok && time.Now().After(req.expires) {
		delete(d.requests, id)
		ok = false
	}
	replay := ok && req.answered
	d.mu.Unlock()
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "unknown or expired request")
		return
	}
	if replay {
		writeAnswered(w)
		return
	}

	if req.dcAPIOrigin != "" {
		apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, "this request expects its response through the Digital Credentials API")
		return
	}

	// The request id is in the QR code, so anyone who sees it can post here.
	// A response that is not for this request changes nothing.
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	recorded, err := d.recordResponse(req, r.PostForm)
	switch {
	case err != nil:
		apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, err.Error())
	case !recorded:
		writeAnswered(w)
	default:
		// §8.2: "The Response URI MAY return the redirect_uri parameter in
		// response to successful Authorization Responses or for Error
		// Responses."
		d.answerResponse(w, req)
	}
}

// recordResponse checks a response and records its outcome. It returns false
// when an earlier response already answered the request.
func (d *DemoRP) recordResponse(req *requestState, form url.Values) (bool, error) {
	response, err := authorizationResponse(req, form)
	if err != nil {
		return false, err
	}
	// The state is the request id from the QR code, so an error response
	// leaves the request open like any response that does not verify.
	if refusal, _ := response["error"].(string); refusal != "" {
		reason := refusal
		if description, _ := response["error_description"].(string); description != "" {
			reason += " (" + description + ")"
		}
		return d.declineRequest(req, reason), nil
	}
	vpToken, err := json.Marshal(response["vp_token"])
	if err == nil && response["vp_token"] == nil {
		err = fmt.Errorf("the response carried no vp_token")
	}
	if err != nil {
		return false, err
	}

	// The page shows a failure. Anyone can encrypt a response to the request's
	// public key, so only a verified presentation answers the request.
	claims, checks, err := d.verifyPresentation(req, string(vpToken))
	return d.finishRequest(req, claims, checks, err, err == nil), nil
}

// writeAnswered refuses a second response. The nonce is fixed per request, so
// a captured response would verify again.
func writeAnswered(w http.ResponseWriter) {
	apierror.WriteStatus(w, http.StatusConflict, "this request was already answered")
}

// answerResponse answers a processed response with the redirect_uri of
// OpenID4VP 1.0 §8.2. The redirected page reads the result with its
// response_code.
func (d *DemoRP) answerResponse(w http.ResponseWriter, req *requestState) {
	code := randToken()
	d.mu.Lock()
	req.responseCode = code
	d.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": d.baseURL() + "/verifier/?response_code=" + code,
	})
}

// authorizationResponse reads the parameters of a direct_post.jwt response.
// OpenID4VP 1.0 §8.3.1 lets a wallet that cannot encrypt "send an error
// response without encryption as per Section 8.2". The state must be the one
// of this request (RFC 6749 §4.1.2), so a response for one request cannot be
// posted to another.
func authorizationResponse(req *requestState, form url.Values) (map[string]any, error) {
	params := map[string]any{}
	switch encrypted := strings.TrimSpace(form.Get("response")); {
	case encrypted != "":
		decrypted, err := decryptAuthorizationResponse(req, encrypted)
		if err != nil {
			return nil, err
		}
		params = decrypted
	case form.Get("error") != "":
		for _, name := range []string{"error", "error_description", "state"} {
			if value := form.Get(name); value != "" {
				params[name] = value
			}
		}
	default:
		return nil, fmt.Errorf("the response carried no response parameter, but the request asked for an encrypted response")
	}
	// Over the Digital Credentials API the page that created the request
	// returns the response, and state isn't a parameter (Appendix A.2).
	if state, _ := params["state"].(string); req.dcAPIOrigin == "" && state != req.id {
		return nil, fmt.Errorf("the response is for a different request")
	}
	return params, nil
}

// decryptAuthorizationResponse decrypts a response JWE with the key of the
// request.
func decryptAuthorizationResponse(req *requestState, encrypted string) (map[string]any, error) {
	if req.encKey == nil {
		return nil, fmt.Errorf("this request has no response encryption key")
	}
	header, err := jwe.ParseHeader(encrypted)
	if err != nil {
		return nil, fmt.Errorf("reading the response header: %w", err)
	}
	// OpenID4VP 1.0 §8.3: "The JWE enc content encryption algorithm used is
	// obtained from the encrypted_response_enc_values_supported parameter of
	// client metadata".
	if !slices.Contains(responseEncValues, header.Enc) {
		return nil, fmt.Errorf("the response is encrypted with %s, but the request offered %s", header.Enc, strings.Join(responseEncValues, " and "))
	}
	ecdhKey, err := req.encKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("converting the response encryption key: %w", err)
	}
	plaintext, err := jwe.Decrypt(encrypted, ecdhKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting the response: %w", err)
	}
	var params map[string]any
	if err := json.Unmarshal(plaintext, &params); err != nil {
		return nil, fmt.Errorf("parsing the decrypted response: %w", err)
	}
	return params, nil
}

// declineRequest records the wallet's error response unless a verified
// presentation answered the request first.
func (d *DemoRP) declineRequest(req *requestState, reason string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.answered {
		return false
	}
	req.status = "declined"
	req.err = reason
	req.claims, req.checks = nil, nil
	return true
}

func (d *DemoRP) recordPresentation(req *requestState, presentation string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	req.presentation = presentation
}

// finishRequest records the result of a response unless another response
// answered the request first. An answer ends the request, and it accepts no
// further response.
func (d *DemoRP) finishRequest(req *requestState, claims map[string]any, checks []map[string]any, err error, answer bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.answered {
		return false
	}
	req.answered = answer
	req.claims = claims
	req.checks = checks
	if err != nil {
		req.status = "failed"
		req.err = err.Error()
		return true
	}
	req.status = "verified"
	req.err = ""
	return true
}

// verifyPresentation validates the PID entry of the vp_token and the ticket
// entry if requested. Each issuer signature must chain to a trusted CA. Each
// key binding must cover the nonce and audience of this request.
func (d *DemoRP) verifyPresentation(req *requestState, vpToken string) (map[string]any, []map[string]any, error) {
	log := &checklist{}
	check := log.record

	if strings.TrimSpace(vpToken) == "" {
		return nil, log.entries, check("vp_token present", fmt.Errorf("the response carried no vp_token"))
	}
	var tokenDoc map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &tokenDoc); err != nil {
		return nil, log.entries, check("vp_token parses", fmt.Errorf("vp_token is not a JSON object of query id to presentations: %w", err))
	}

	answered := map[string]bool{}
	for id, presentations := range tokenDoc {
		i := slices.IndexFunc(req.queries, func(q credentialQuery) bool { return q.id == id })
		if i < 0 {
			return nil, log.entries, check("vp_token answers only requested queries", fmt.Errorf("the request has no credential query %q", id))
		}
		log.group = req.queries[i].label()
		err := check("vp_token entries hold presentations", errIf(len(presentations) == 0, "the vp_token entry %q is empty. OpenID4VP 1.0 §8.1 asks for an array of one or more presentations", id))
		log.group = ""
		if err != nil {
			return nil, log.entries, err
		}
		answered[id] = true
	}
	if err := check("vp_token satisfies the credential query", req.unsatisfied(answered)); err != nil {
		return nil, log.entries, err
	}

	result := map[string]any{}
	recorded := false
	for _, q := range req.queries {
		trust := d.credentialTrustFor(q)
		presentations := tokenDoc[q.id]
		log.group = q.label()
		if len(presentations) == 0 {
			_ = log.record(q.label()+": not presented (optional)", nil)
			continue
		}
		if !recorded {
			// Failed presentations stay available in the decoder.
			d.recordPresentation(req, presentations[0])
			recorded = true
		}
		label := ""
		if q.resultKey != "" {
			label = q.resultKey + ": "
		}
		// OpenID4VP 1.0 §8.1: "When multiple is omitted, or set to false, the
		// array MUST contain only one Presentation."
		if !q.multiple {
			if err := check(label+"vp_token holds exactly one presentation",
				errIf(len(presentations) != 1, "expected 1 presentation, got %d", len(presentations))); err != nil {
				return nil, log.entries, err
			}
		}
		var answers []any
		for i, presentation := range presentations {
			itemLabel := label
			if q.multiple {
				itemLabel = fmt.Sprintf("%s[%d]: ", q.label(), i)
				log.group = fmt.Sprintf("%s[%d]", q.label(), i)
			}
			var claims map[string]any
			var err error
			if q.format == credtype.FormatMDOC {
				claims, err = d.verifyMDOCPresentation(req, presentation, q, itemLabel, trust, log)
			} else {
				claims, err = d.verifySDJWTEntry(req, presentation, q, itemLabel, trust, log)
			}
			if err != nil {
				d.recordPresentation(req, presentation)
				return nil, log.entries, err
			}
			answers = append(answers, claims)
		}
		switch {
		case q.multiple:
			log.group = q.label()
			_ = check(fmt.Sprintf("%s: %d presentation(s) verified", q.label(), len(answers)), nil)
			result[q.label()] = answers
		case q.resultKey == "":
			maps.Copy(result, answers[0].(map[string]any))
		default:
			result[q.resultKey] = answers[0]
		}
	}
	log.group = ""
	return result, log.entries, nil
}

// verifySDJWTEntry runs the shared credential checks and checks the requested
// type, the key binding and the disclosed claims. The label prefix tells ticket
// checks apart from PID checks.
func (d *DemoRP) verifySDJWTEntry(req *requestState, presentation string, q credentialQuery, label string, trust validate.Trust, log *checklist) (map[string]any, error) {
	check := func(name string, err error) error {
		return log.record(label+name, err)
	}

	token, err := sdjwt.Parse(presentation)
	if err = check("presentation parses as SD-JWT", err); err != nil {
		return nil, err
	}
	for _, warning := range token.Warnings {
		log.warn(label+"credential is well-formed (RFC 9901)", fmt.Errorf("%s", warning))
	}

	// The wallet chose the credential, so check the type. A derived type
	// answers its base type, such as a German PID for a base PID query.
	gotVCT, _ := token.ResolvedClaims["vct"].(string)
	gotTypes := credtype.AkaVCTs(token.ResolvedClaims)
	expected := q.typeValues()
	answers := func(want string) bool { return credtype.Answers(gotVCT, gotTypes, want) }
	if !slices.ContainsFunc(expected, answers) && typemetadata.IsRetrievable(gotVCT) {
		// A type with an HTTPS vct can extend a requested type in its Type
		// Metadata (draft-ietf-oauth-sd-jwt-vc-19 §5.4).
		integrity, _ := token.ResolvedClaims["vct#integrity"].(string)
		metadata, err := typemetadata.Resolver{Client: d.wallet.HTTPClient()}.Resolve(gotVCT, integrity)
		var processing *typemetadata.ProcessingError
		switch {
		case errors.As(err, &processing):
			// §5.7 and §7.4 reject the credential.
			return nil, check("Type Metadata of the credential", err)
		case err != nil:
			log.warn(label+"Type Metadata of the credential", err)
		default:
			problems := metadata.ValidatePresentation(token.Payload, token.Disclosures)
			if err = check("credential follows its Type Metadata", errIf(len(problems) > 0, "%s", strings.Join(problems.Texts(), " "))); err != nil {
				return nil, err
			}
			gotTypes = append(gotTypes, metadata.Types...)
		}
	}
	if err = check("credential type matches the request",
		errIf(!slices.ContainsFunc(expected, answers),
			"vct is %q, requested %s", gotVCT, strings.Join(expected, " or "))); err != nil {
		return nil, err
	}

	if err = log.credential(label, validate.SDJWT(token, trust, credentialChecks)); err != nil {
		return nil, err
	}

	kb := token.KeyBindingJWT
	if err = check("key binding JWT present", errIf(kb == nil, "the presentation has no key binding JWT")); err != nil {
		return nil, err
	}
	cnf, _ := token.Payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if err = check("credential is holder bound (cnf.jwk)", errIf(cnfJWK == nil, "the credential carries no cnf.jwk")); err != nil {
		return nil, err
	}
	holderKey, err := holderKeyFromJWK(cnfJWK)
	if err = check("cnf.jwk parses", err); err != nil {
		return nil, err
	}
	kbJWT, err := parseCompactJWT(kb.Raw)
	if err = check("key binding JWT parses", err); err != nil {
		return nil, err
	}
	kbTyp, _ := kbJWT.header["typ"].(string)
	if err = check("key binding JWT is typed kb+jwt", errIf(!format.JOSETypeIs(kbTyp, sdjwt.TypeKeyBinding), "typ is %q", kbTyp)); err != nil {
		return nil, err
	}
	if err = check("key binding signature verifies with cnf key", errIf(!verifyES256(holderKey, kbJWT.signingInput, kbJWT.signature), "key binding signature is invalid")); err != nil {
		return nil, err
	}

	// RFC 9901 §7.3: "check that the creation time of the Key Binding JWT, as
	// determined by the iat claim, is within an acceptable window". The claim
	// is REQUIRED (§4.3).
	timeErr := checkTimeClaims(kbJWT.payload, true, false)
	if timeErr != nil {
		timeErr = fmt.Errorf("the key binding JWT %w", timeErr)
	}
	if err = check("key binding was created within an acceptable window", timeErr); err != nil {
		return nil, err
	}

	// RFC 9901 §4.3 hashes up to the final ~ with the _sd_alg of the
	// credential. Parse rejects unsupported algorithms.
	prefix := presentation[:strings.LastIndex(presentation, "~")+1]
	wantHash, hErr := sdjwt.SDHash(prefix, token.SDAlg())
	if hErr != nil {
		return nil, check("sd_hash algorithm is supported", hErr)
	}
	gotHash, _ := kbJWT.payload["sd_hash"].(string)
	if err = check("sd_hash matches the presentation", errIf(gotHash != wantHash, "sd_hash does not match")); err != nil {
		return nil, err
	}

	nonce, _ := kbJWT.payload["nonce"].(string)
	if err = check("nonce matches the request", errIf(nonce != req.nonce, "nonce mismatch")); err != nil {
		return nil, err
	}
	aud, _ := kbJWT.payload["aud"].(string)
	if err = check("audience is this verifier", checkPresentationAudience(req, aud)); err != nil {
		return nil, err
	}

	disclosed := disclosedClaims(token)
	if err = check(q.checkClaims(disclosed, "requested claims were disclosed")); err != nil {
		return nil, err
	}

	return disclosed, nil
}

// credentialChecks are the shared checks of a presented credential. The
// verifier fetches the status list and applies the HAIP 1.0 §6.1 rules.
var credentialChecks = validate.Options{Status: true, HAIP: true}

// credentialTrust anchors presented credentials. Issuer chains end in the
// issuance services and status lists in the revocation services of the
// wallet's credential provider lists (ETSI TS 119 602 V1.1.1 Table D.3). The
// anchors from SetVerifierTrustAnchors anchor both. Fetches use the wallet's
// HTTP client, so they follow --tls-ca, --tls-verify and the proxy settings.
func (d *DemoRP) credentialTrust() validate.Trust {
	return validate.Trust{
		Supplied:   true,
		Issuance:   append(d.wallet.TrustedLists().CredentialProviderAnchors(lote.IssuanceServices), d.verifierTrustAnchors...),
		Revocation: append(d.wallet.TrustedLists().CredentialProviderAnchors(lote.RevocationServices), d.verifierTrustAnchors...),
		HTTPClient: d.wallet.HTTPClient(),

		CertificateProblems: d.wallet.CertificateProblems,
	}
}

// credentialTrustFor anchors the credential that answers the query. Under
// --arf the category of the requested type picks the provider lists (ADR-0022).
// A PID chains to a PID provider list (ARF OIA_12) and a PuB-EAA to a PuB-EAA
// provider list (OIA_14), so a signer on the list of another category cannot
// issue an accepted credential. The note to OIA_15 expects the relying party
// to know the category of the requested type. The catalogue gives it. A type without a
// catalogue entry has no known category and chains to any provider list.
func (d *DemoRP) credentialTrustFor(q credentialQuery) validate.Trust {
	trust := d.credentialTrust()
	if !d.wallet.ARFChecks() {
		return trust
	}
	types := q.typeValues()
	if q.format == credtype.FormatMDOC {
		types = []string{q.docType}
	}
	category := d.wallet.CatalogueCategory(q.format, types)
	if category == "" {
		return trust
	}
	lists, listType := d.wallet.TrustedLists().Lists(), registrar.CategoryOf(category).LoTEType
	trust.Issuance = append(trustedlists.AnchorsOf(lists, listType, lote.IssuanceServices), d.verifierTrustAnchors...)
	trust.Revocation = append(trustedlists.AnchorsOf(lists, listType, lote.RevocationServices), d.verifierTrustAnchors...)
	return trust
}

func errIf(cond bool, format string, args ...any) error {
	if cond {
		return fmt.Errorf(format, args...)
	}
	return nil
}

// disclosedClaims leaves JWT protocol fields out of the displayed claims.
func disclosedClaims(token *sdjwt.Token) map[string]any {
	claims := make(map[string]any)
	for name, value := range token.ResolvedClaims {
		if !sdjwt.IsProtocolClaim(name) {
			claims[name] = value
		}
	}
	claims["vct"] = token.ResolvedClaims["vct"]
	return claims
}

// verifyMDOCPresentation validates an mdoc DeviceResponse. It runs the shared
// credential checks and checks the doctype, the holder signature over the
// session transcript and the requested elements.
func (d *DemoRP) verifyMDOCPresentation(req *requestState, presentation string, q credentialQuery, label string, trust validate.Trust, log *checklist) (map[string]any, error) {
	docType := q.docType
	check := func(name string, err error) error {
		return log.record(label+name, err)
	}
	doc, err := mdoc.Parse(presentation)
	if err = check("presentation parses as an mdoc DeviceResponse", err); err != nil {
		return nil, err
	}
	// Each presentation answers one credential query. The checks below read
	// only the first document, so a second one would pass unverified.
	if err = check("DeviceResponse holds one document",
		errIf(doc.Documents > 1, "the DeviceResponse holds %d documents", doc.Documents)); err != nil {
		return nil, err
	}

	// The wallet chose the credential, so check the doctype.
	if err = check("credential type matches the request",
		errIf(doc.DocType != docType, "doctype is %q, requested %q", doc.DocType, docType)); err != nil {
		return nil, err
	}

	result := validate.MDOC(doc, trust, credentialChecks)
	if err = log.credential(label, result); err != nil {
		return nil, err
	}
	if result.MDOCVerify != nil {
		for _, warning := range result.MDOCVerify.Warnings {
			log.warn(label+"mdoc MSO declares its required members", fmt.Errorf("%s", warning))
		}
	}

	// The holder signs the session transcript. Rebuilding it here binds the
	// response to this request.
	transcript, err := d.rebuildSessionTranscript(req)
	if err = check("session transcript rebuilds", err); err != nil {
		return nil, err
	}
	if err = check("holder signed this request", mdoc.VerifyDeviceAuth(doc, transcript)); err != nil {
		return nil, err
	}

	// Paths start with the namespace, so an element of another namespace
	// doesn't answer them.
	claims := map[string]any{}
	byNamespace := map[string]any{}
	for ns, items := range doc.NameSpaces {
		elements := map[string]any{}
		for _, item := range items {
			claims[item.ElementIdentifier] = item.ElementValue
			elements[item.ElementIdentifier] = item.ElementValue
		}
		byNamespace[ns] = elements
	}
	if err = check(q.checkClaims(byNamespace, "the requested elements are present")); err != nil {
		return nil, err
	}
	return claims, nil
}

// encryptionJWKThumbprint is the RFC 7638 thumbprint of the response
// encryption key in the OpenID4VP session transcript. It must match the
// wallet's thumbprint of the client_metadata JWK, so it uses the same members.
func encryptionJWKThumbprint(key *ecdsa.PrivateKey) []byte {
	if key == nil {
		return nil
	}
	sum, err := keys.PublicKeyThumbprint(&key.PublicKey)
	if err != nil {
		return nil
	}
	return sum
}

// checklist keeps each check result for the UI.
type checklist struct {
	entries []map[string]any
	// group is the credential query for the next checks.
	group string
}

func (c *checklist) add(entry map[string]any) {
	if c.group != "" {
		entry["credential"] = c.group
	}
	c.entries = append(c.entries, entry)
}

func (c *checklist) record(name string, err error) error {
	entry := map[string]any{"name": name, "ok": err == nil}
	if err != nil {
		entry["error"] = err.Error()
	}
	c.add(entry)
	return err
}

// warn records a profile finding. It never rejects the presentation.
func (c *checklist) warn(name string, err error) {
	entry := map[string]any{"name": name, "ok": true}
	if err != nil {
		entry["warning"] = err.Error()
	}
	c.add(entry)
}

// decidingChecks are the shared credential checks that decide whether the
// verifier accepts a credential.
var decidingChecks = map[string]bool{
	validate.CheckType:         true,
	validate.CheckExpiry:       true,
	validate.CheckIntegrity:    true,
	validate.CheckSignature:    true,
	validate.CheckStatus:       true,
	validate.CheckCertificates: true,
}

// credential records the shared credential checks. The signature must verify,
// and a fail of another deciding check rejects the credential. The findings of
// the other checks are warnings. Another check that was skipped did not apply,
// so the list leaves it out.
func (c *checklist) credential(label string, result *validate.Result) error {
	var rejection error
	for _, check := range result.Checks {
		name := label + check.Name
		decides := decidingChecks[check.Name]
		entry := map[string]any{"name": name, "ok": true}
		switch {
		case decides && (check.Status == validate.Fail || check.Name == validate.CheckSignature && check.Status != validate.Pass):
			entry["ok"], entry["error"] = false, check.Detail
			if rejection == nil {
				rejection = fmt.Errorf("%s: %s", name, check.Detail)
			}
		case check.Status == validate.Pass:
			entry["detail"] = check.Detail
		case check.Status == validate.Skipped && decides:
			entry["skipped"] = check.Detail
		case check.Status == validate.Skipped:
			continue
		default:
			entry["warning"] = check.Detail
		}
		c.add(entry)
	}
	return rejection
}
