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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

// The German PID extends the base SD-JWT PID type. It answers a request for
// the base type. A base PID does not answer a request for the German type.
const (
	PIDVCT       = credtype.PIDVCT
	GermanPIDVCT = credtype.GermanPIDVCT
	PIDDocType   = credtype.PIDDocType
)

type requestState struct {
	id      string
	queryID string
	vct     string
	// docType is set if the request also accepts the mdoc PID. wantMDOC then
	// holds the mdoc element names.
	docType     string
	mdocQueryID string
	wantMDOC    []string
	want        []string
	// ticketQueryID is set if a PID request also asks for the demo ticket.
	// ticketWant holds the requested ticket claims.
	ticketQueryID string
	ticketWant    []string
	// multiple is set when every credential query carries multiple.
	multiple bool
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

	// custom has one entry per DCQL credential query of a custom request. If
	// it is set, the preset query ids above are unused.
	custom []customEntry

	status string // pending | verified | failed
	err    string
	claims map[string]any
	checks []map[string]any
	// presentation is kept for the decoder even if verification fails.
	presentation string
}

// queryIDs lists the query ids of the PID entry. The ticket has its own
// entry.
func (r *requestState) queryIDs() []string {
	var ids []string
	for _, id := range []string{r.queryID, r.mdocQueryID} {
		if id != "" {
			ids = append(ids, fmt.Sprintf("%q", id))
		}
	}
	return ids
}

// VerifierHandler returns the demo verifier. Mount it with the /verifier
// prefix stripped.
func (d *DemoRP) VerifierHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.serveStatic("static/verifier.html"))
	mux.HandleFunc("GET /verifier.js", d.serveStatic("static/verifier.js"))
	mux.HandleFunc("POST /api/requests", d.handleCreateRequest)
	mux.HandleFunc("GET /api/requests/{id}", d.handleRequestStatus)
	mux.HandleFunc("GET /request/{id}", d.handleRequestObject)
	mux.HandleFunc("POST /response/{id}", d.handlePresentationResponse)
	// GuardAPI covers only /api/, which the page calls. Wallets on other
	// origins call the protocol endpoints.
	return httpsec.GuardAPI(mux, d.baseURL())
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
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(jar))
}

type createRequestBody struct {
	Type string `json:"type"` // "ticket" (default), "pid", or "custom"
	// Format is "sd-jwt", "mdoc" or "both" (the default) for a PID request.
	// The ticket exists only as an SD-JWT VC.
	Format string `json:"format"`
	// VCT is the requested PID type. Empty means urn:eudi:pid:1, which every
	// PID answers. A national type such as urn:eudi:pid:de:1 is answered only
	// by a credential of that type.
	VCT string `json:"vct"`
	// Ticket adds the demo ticket to a PID request. "combined" puts PID and
	// ticket in one option next to a PID-only option. "optional" adds a
	// second credential set with required: false.
	Ticket string `json:"ticket"`
	// Multiple sets multiple on every credential query (OpenID4VP 1.0 §6.1).
	Multiple bool `json:"multiple"`
	// Credentials are the DCQL credential queries of a "custom" request.
	Credentials []customCredentialTO `json:"credentials"`
	// ClientIDScheme is the client identifier prefix of a custom request:
	// "x509_hash" (the default), "x509_san_dns", "redirect_uri" or
	// "pre-registered". Only the x509 prefixes sign the request object.
	ClientIDScheme string `json:"client_id_scheme"`
	// ClientID is the identifier for the pre-registered prefix. The other
	// prefixes derive it from the certificate or the response endpoint.
	ClientID string `json:"client_id"`
	// SigningKey is an optional PEM bundle with an EC private key and its
	// certificate chain. Empty uses the demo verifier certificate.
	SigningKey string `json:"signing_key"`
	// VerifierInfo replaces the verifier_info array (OpenID4VP 1.0 §5.1). Empty
	// uses the demo registration certificate.
	VerifierInfo []any `json:"verifier_info"`
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

type customEntry struct {
	queryID  string
	format   string
	vct      string
	docType  string
	want     []string
	multiple bool
}

func normalizePIDFormat(format string) (sdjwt, mdoc bool, err error) {
	switch strings.TrimSpace(format) {
	case "", "both":
		return true, true, nil
	case "sd-jwt", "sdjwt", "dc+sd-jwt":
		return true, false, nil
	case "mdoc", "mso_mdoc":
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
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createRequestBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if body.Type == "custom" {
		d.createCustomRequest(w, body)
		return
	}

	var vct, docType string
	var claims, mdocClaims []string
	ticketMode := strings.TrimSpace(body.Ticket)
	if ticketMode != "" && ticketMode != "combined" && ticketMode != "optional" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `ticket must be "combined" or "optional"`})
		return
	}
	switch body.Type {
	case "", "ticket":
		body.Type = "ticket"
		if ticketMode != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket applies to pid requests, which then ask for the ticket next to the PID"})
			return
		}

		wantSDJWT, _, err := normalizePIDFormat(body.Format)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// The ticket exists only as an SD-JWT VC.
		if !wantSDJWT {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the demo ticket only exists as an SD-JWT VC"})
			return
		}
		vct = TicketVCT
		claims = []string{"event", "tier", "seat", "given_name", "family_name"}
	case "pid":
		// An explicit format tests how a wallet handles a request for a format
		// it does not hold.
		wantSDJWT, wantMDOC, err := normalizePIDFormat(body.Format)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		requested, err := normalizePIDVCT(body.VCT)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// ISO/IEC 18013-5 has no inheritance between document types. Every mdoc
		// PID has the same doctype and keeps national elements in a second
		// namespace. Any PID would answer a doctype request for a national PID.
		domestic := requested != PIDVCT
		if domestic && wantMDOC && !wantSDJWT {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "a credential type has no mdoc form: every PID carries the doctype " + PIDDocType + ", so ask for the PID in mdoc instead",
			})
			return
		}
		if wantSDJWT {
			vct = requested
			claims = []string{"given_name", "family_name"}
		}
		if wantMDOC && !domestic {
			docType = PIDDocType
			mdocClaims = []string{"given_name", "family_name"}
		}
		// The combined shape puts the ticket in the SD-JWT PID option.
		if ticketMode == "combined" && !wantSDJWT {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket: combined needs the SD-JWT PID in the request, so use format sd-jwt or both"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be ticket or pid"})
		return
	}

	base := d.baseURL()
	req := &requestState{
		id:       randToken(),
		vct:      vct,
		docType:  docType,
		want:     claims,
		wantMDOC: mdocClaims,
		nonce:    randToken(),
		multiple: body.Multiple,
		status:   "pending",
		expires:  time.Now().Add(entryTTL),
	}
	// Only the requested formats get a query id, so a response in another
	// format is not accepted.
	if vct != "" {
		req.queryID = body.Type
	}
	if docType != "" {
		req.mdocQueryID = body.Type + "_mdoc"
	}
	if ticketMode != "" {
		req.ticketQueryID = "ticket"
		req.ticketWant = []string{"event", "tier", "seat", "given_name", "family_name"}
	}
	responseURI := base + "/verifier/response/" + req.id

	// HAIP requires x509_hash for signed requests.
	signingKey, chain, err := d.wallet.AccessSigningMaterial()
	if err != nil || signingKey == nil || len(chain) == 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no signing certificate available"})
		return
	}
	req.clientID = wallet.X509HashClientID(chain[0])

	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generating response encryption key: " + err.Error()})
		return
	}
	req.encKey = encKey

	credentials := make([]map[string]any, 0, 2)
	if req.queryID != "" {
		dcqlClaims := make([]map[string]any, 0, len(claims))
		for _, c := range claims {
			dcqlClaims = append(dcqlClaims, map[string]any{"path": []string{c}})
		}
		credentials = append(credentials, map[string]any{
			"id":     req.queryID,
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []string{vct}},
			"claims": dcqlClaims,
		})
	}
	if req.mdocQueryID != "" {
		mdocDCQLClaims := make([]map[string]any, 0, len(mdocClaims))
		for _, c := range mdocClaims {
			mdocDCQLClaims = append(mdocDCQLClaims, map[string]any{"path": []string{docType, c}})
		}
		credentials = append(credentials, map[string]any{
			"id":     req.mdocQueryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": docType},
			"claims": mdocDCQLClaims,
		})
	}
	if req.ticketQueryID != "" {
		ticketDCQLClaims := make([]map[string]any, 0, len(req.ticketWant))
		for _, c := range req.ticketWant {
			ticketDCQLClaims = append(ticketDCQLClaims, map[string]any{"path": []string{c}})
		}
		credentials = append(credentials, map[string]any{
			"id":     req.ticketQueryID,
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []string{TicketVCT}},
			"claims": ticketDCQLClaims,
		})
	}
	if req.multiple {
		for _, q := range credentials {
			q["multiple"] = true
		}
	}
	dcql := map[string]any{"credentials": credentials}

	// The credential set options make one PID format enough.
	var sets []map[string]any
	switch ticketMode {
	case "combined":
		options := [][]string{{req.queryID, req.ticketQueryID}, {req.queryID}}
		if req.mdocQueryID != "" {
			options = append(options, []string{req.mdocQueryID})
		}
		sets = append(sets, map[string]any{"options": options})
	case "optional":
		var pidOptions [][]string
		if req.queryID != "" {
			pidOptions = append(pidOptions, []string{req.queryID})
		}
		if req.mdocQueryID != "" {
			pidOptions = append(pidOptions, []string{req.mdocQueryID})
		}
		sets = append(sets,
			map[string]any{"options": pidOptions},
			map[string]any{"options": [][]string{{req.ticketQueryID}}, "required": false})
	default:
		if req.queryID != "" && req.mdocQueryID != "" {
			sets = append(sets, map[string]any{"options": [][]string{{req.queryID}, {req.mdocQueryID}}})
		}
	}
	if len(sets) > 0 {
		dcql["credential_sets"] = sets
	}

	purpose := "Admission to the demo event: checking your ticket"
	if body.Type == "pid" {
		purpose = "Confirming your identity for the demo"
	}
	d.finalizeRequest(w, req, dcql, credentials, responseURI, base, purpose, signingKey, chain, nil)
}

// finalizeRequest signs the registration certificate and the request object,
// stores the request and returns the wallet URL. The wallet consent dialog
// reads the purpose from the registration certificate (rc-wrp+jwt, ETSI TS
// 119 475) in verifier_info (OpenID4VP 1.0 §5.1).
func (d *DemoRP) finalizeRequest(w http.ResponseWriter, req *requestState, dcql map[string]any, credentials []map[string]any, responseURI, base, purpose string, signingKey *ecdsa.PrivateKey, chain []*x509.Certificate, verifierInfo []any) {
	now := time.Now()
	if len(verifierInfo) == 0 {
		registrarKey, registrarChain, err := d.wallet.RegistrarSigningMaterial()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading registrar signer: " + err.Error()})
			return
		}
		registration, err := wallet.SignRegistrationCertificateJWT(
			d.registrationCertificateClaims(chain[0], "Demo Verifier", purpose, credentials),
			registrarKey, registrarChain)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing registration certificate: " + err.Error()})
			return
		}
		verifierInfo = []any{map[string]any{"format": "registration_cert", "data": registration}}
	}

	jar, err := wallet.SignRequestObjectJWT(map[string]any{
		"iss":             req.clientID,
		"aud":             "https://self-issued.me/v2",
		"iat":             now.Unix(),
		"exp":             req.expires.Unix(),
		"client_id":       req.clientID,
		"response_type":   "vp_token",
		"response_mode":   "direct_post.jwt",
		"response_uri":    responseURI,
		"nonce":           req.nonce,
		"state":           req.id,
		"dcql_query":      dcql,
		"client_metadata": responseEncryptionMetadata(req.encKey),
		"verifier_info":   verifierInfo,
	}, signingKey, chain)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing request object: " + err.Error()})
		return
	}
	req.requestObject = jar

	d.mu.Lock()
	d.pruneLocked()
	if len(d.requests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open requests, try again later"})
		return
	}
	d.requests[req.id] = req
	d.mu.Unlock()

	// The signed object is too long for a scheme URI or a QR code, so it is
	// passed by reference.
	params := url.Values{
		"client_id":   {req.clientID},
		"request_uri": {base + "/verifier/request/" + req.id},
	}.Encode()

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         req.id,
		"wallet_url": base + "/authorize?" + params,
		"scheme_uri": "openid4vp://?" + params,
	})
}

func (d *DemoRP) createCustomRequest(w http.ResponseWriter, body createRequestBody) {
	if len(body.Credentials) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a custom request needs at least one credential"})
		return
	}
	scheme := strings.TrimSpace(body.ClientIDScheme)
	if scheme == "" {
		scheme = "x509_hash"
	}
	signed := scheme == "x509_hash" || scheme == "x509_san_dns"

	signingKey, chain, err := d.customSigningMaterial(body.SigningKey)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.TrimSpace(body.SigningKey) != "" {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": "signing material: " + err.Error()})
		return
	}
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generating response encryption key: " + err.Error()})
		return
	}
	base := d.baseURL()
	req := &requestState{
		id:      randToken(),
		nonce:   randToken(),
		status:  "pending",
		expires: time.Now().Add(entryTTL),
		encKey:  encKey,
	}
	responseURI := base + "/verifier/response/" + req.id
	req.clientID, err = customClientID(scheme, chain, responseURI, body.ClientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body.VerifierInfo) > 0 && !signed {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a custom verifier_info needs a signed client_id scheme (x509_hash or x509_san_dns)"})
		return
	}

	credentials := make([]map[string]any, 0, len(body.Credentials))
	for i, c := range body.Credentials {
		format := strings.TrimSpace(c.Format)
		var meta map[string]any
		switch format {
		case "dc+sd-jwt":
			if strings.TrimSpace(c.VCT) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a dc+sd-jwt credential needs a vct"})
				return
			}
			meta = map[string]any{"vct_values": []string{c.VCT}}
		case "mso_mdoc":
			if strings.TrimSpace(c.DocType) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "an mso_mdoc credential needs a doctype"})
				return
			}
			meta = map[string]any{"doctype_value": c.DocType}
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be dc+sd-jwt or mso_mdoc"})
			return
		}

		dcqlClaims := make([]map[string]any, 0, len(c.Claims))
		seen := map[string]bool{}
		var want []string
		addWant := func(name string) {
			if name != "" && !seen[name] {
				seen[name] = true
				want = append(want, name)
			}
		}
		for _, path := range c.Claims {
			if len(path) == 0 {
				continue
			}
			dcqlClaims = append(dcqlClaims, map[string]any{"path": path})
			if format == "mso_mdoc" {
				addWant(lastStringComponent(path))
			} else if name, ok := path[0].(string); ok {
				addWant(name)
			}
		}

		id := fmt.Sprintf("cred_%d", i)
		q := map[string]any{"id": id, "format": format, "meta": meta}
		if c.Multiple {
			q["multiple"] = true
		}
		if len(dcqlClaims) > 0 {
			q["claims"] = dcqlClaims
		}
		credentials = append(credentials, q)
		req.custom = append(req.custom, customEntry{queryID: id, format: format, vct: c.VCT, docType: c.DocType, want: want, multiple: c.Multiple})
	}

	dcql := map[string]any{"credentials": credentials}
	if signed {
		d.finalizeRequest(w, req, dcql, credentials, responseURI, base, "A request built by hand for testing", signingKey, chain, body.VerifierInfo)
		return
	}
	d.deliverUnsignedRequest(w, req, dcql, responseURI, base)
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
		return wallet.X509HashClientID(chain[0]), nil
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
// plain query parameters (OpenID4VP 1.0 §5.10). The response is encrypted to
// the key in client_metadata.
func (d *DemoRP) deliverUnsignedRequest(w http.ResponseWriter, req *requestState, dcql map[string]any, responseURI, base string) {
	dcqlJSON, err := json.Marshal(dcql)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encoding dcql_query: " + err.Error()})
		return
	}
	metaJSON, err := json.Marshal(responseEncryptionMetadata(req.encKey))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encoding client_metadata: " + err.Error()})
		return
	}

	d.mu.Lock()
	d.pruneLocked()
	if len(d.requests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open requests, try again later"})
		return
	}
	d.requests[req.id] = req
	d.mu.Unlock()

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

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         req.id,
		"wallet_url": base + "/authorize?" + params,
		"scheme_uri": "openid4vp://?" + params,
	})
}

func (d *DemoRP) customSigningMaterial(pemBundle string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if strings.TrimSpace(pemBundle) == "" {
		return d.wallet.AccessSigningMaterial()
	}
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

func lastStringComponent(path []any) string {
	name := ""
	for _, p := range path {
		if s, ok := p.(string); ok {
			name = s
		}
	}
	return name
}

// The registration certificate lists the same DCQL claims as the request, so
// the ARF RPRC_21 over-asking check passes. The payload follows ETSI TS 119
// 475 §5.2.4.
func (d *DemoRP) registrationCertificateClaims(accessCertificate *x509.Certificate, name, purpose string, dcqlCredentials []map[string]any) map[string]any {
	registered := make([]map[string]any, 0, len(dcqlCredentials))
	for _, c := range dcqlCredentials {
		registered = append(registered, map[string]any{
			"format": c["format"],
			"meta":   c["meta"],
			"claim":  c["claims"],
		})
	}
	// TS 119 475 V1.2.1 §5.1.1 links registration and access certificates by
	// their identifier.
	identifier := accessCertificate.Subject.CommonName
	for _, attribute := range accessCertificate.Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			identifier, _ = attribute.Value.(string)
			break
		}
	}
	country := "EU"
	if len(accessCertificate.Subject.Country) > 0 {
		country = accessCertificate.Subject.Country[0]
	}
	legalName := name
	if len(accessCertificate.Subject.Organization) > 0 {
		legalName = accessCertificate.Subject.Organization[0]
	}
	now := time.Now()
	base := d.baseURL()
	return map[string]any{
		"sub":                   identifier,
		"sub_ln":                legalName,
		"name":                  name,
		"country":               country,
		"registry_uri":          base + "/api/registrar/wrp",
		"srv_description":       []map[string]any{{"lang": "en", "value": name}},
		"entitlements":          []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy":        base + "/privacy-policy",
		"support_uri":           base + "/support",
		"supervisory_authority": map[string]any{"email": "dpa@eudi-test.dev", "uri": base + "/supervisory-authority"},
		"iat":                   now.Unix(),
		"exp":                   now.AddDate(0, 6, 0).Unix(),
		"purpose":               []map[string]any{{"lang": "en", "value": purpose}},
		"credentials":           registered,
	}
}

// checkPresentationAudience expects the OpenID4VP client ID or the
// Authorization Challenge Endpoint. OpenID4VCI 1.1 Appendix A.3.5 uses the
// endpoint origin. Its example, the other appendices and §6.2.1.5 use the
// full endpoint. Both ia: forms are accepted.
func checkPresentationAudience(req *requestState, aud string) error {
	if req.interactiveEndpoint == "" {
		return errIf(aud != req.clientID, "aud is %q, want %q", aud, req.clientID)
	}
	endpoint := "ia:" + req.interactiveEndpoint
	origin := "ia:" + originOf(req.interactiveEndpoint)
	return errIf(aud != endpoint && aud != origin, "aud is %q, want %q", aud, endpoint)
}

// rebuildSessionTranscript recomputes the session transcript the holder
// signed. Interactive Authorization uses the handover of OpenID4VCI 1.1
// Appendix A.2.5.
func (d *DemoRP) rebuildSessionTranscript(req *requestState) ([]byte, error) {
	if req.interactiveEndpoint != "" {
		// ia_post: the response is unencrypted, so the third element is null.
		return wallet.BuildOID4VCIIAESessionTranscript(req.interactiveEndpoint, req.nonce, nil)
	}
	return wallet.BuildOID4VPSessionTranscript(
		req.clientID, req.nonce, encryptionJWKThumbprint(req.encKey), d.baseURL()+"/verifier/response/"+req.id)
}

// originOf is the derived origin of a URL as RFC 6454 §4 defines it.
func originOf(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// responseEncryptionMetadata publishes the public per-request encryption key.
// The wallet needs a usable JWK with an explicit alg for direct_post.jwt.
func responseEncryptionMetadata(key *ecdsa.PrivateKey) map[string]any {
	x, y, _ := format.ECPublicCoords(&key.PublicKey)
	return map[string]any{
		"jwks": map[string]any{
			"keys": []map[string]any{{
				"kty": "EC",
				"crv": "P-256",
				"use": "enc",
				"alg": "ECDH-ES",
				"kid": "demo-verifier-response-enc",
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
			}},
		},
		// HAIP 1.0 §5: "Verifiers MUST list both A128GCM and A256GCM in
		// encrypted_response_enc_values_supported in their client metadata."
		"encrypted_response_enc_values_supported": []string{"A128GCM", "A256GCM"},
		"vp_formats_supported": map[string]any{
			"dc+sd-jwt": map[string]any{
				"sd-jwt_alg_values": []string{"ES256"},
				"kb-jwt_alg_values": []string{"ES256"},
			},
			// OpenID4VP 1.0 Appendix B.2.2 defines these two members for
			// mso_mdoc. Their values are COSE algorithm identifiers (-7 is ES256).
			"mso_mdoc": map[string]any{
				"issuerauth_alg_values": []int{-7},
				"deviceauth_alg_values": []int{-7},
			},
		},
	}
}

func (d *DemoRP) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	req, ok := d.requests[id]
	var doc map[string]any
	if ok {
		status := req.status
		// Expire unanswered requests so the page stops polling.
		if status == "pending" && time.Now().After(req.expires) {
			status = "expired"
		}
		doc = map[string]any{
			"status": status,
			"claims": req.claims,
			"checks": req.checks,
		}
		// The decoder input keeps key binding and device authentication.
		if req.presentation != "" {
			doc["presentation"] = req.presentation
		}
		if req.err != "" {
			doc["error"] = req.err
		}
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (d *DemoRP) handlePresentationResponse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	id := r.PathValue("id")

	d.mu.Lock()
	req, ok := d.requests[id]
	if ok && time.Now().After(req.expires) {
		delete(d.requests, id)
		ok = false
	}
	replay := ok && req.answered
	if ok && !replay {
		req.answered = true
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	if replay {
		// The nonce is fixed per request, so a captured response would verify
		// again. Each request accepts one response.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this request was already answered"})
		return
	}

	if err := r.ParseForm(); err != nil {
		d.finishRequest(req, nil, nil, fmt.Errorf("parsing response form: %w", err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	response, err := authorizationResponse(req, r.PostForm)
	if err != nil {
		d.finishRequest(req, nil, nil, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	// §8.2: the Response URI answers 200 once it "has successfully processed
	// the Authorization Response or Authorization Error Response". The page
	// that created the request shows the error, so the wallet gets no
	// redirect_uri.
	if refusal, _ := response["error"].(string); refusal != "" {
		message := "the wallet answered with the error " + refusal
		if description, _ := response["error_description"].(string); description != "" {
			message += ": " + description
		}
		d.finishRequest(req, nil, nil, errors.New(message))
		writeJSON(w, http.StatusOK, map[string]string{})
		return
	}
	vpToken, err := json.Marshal(response["vp_token"])
	if err == nil && response["vp_token"] == nil {
		err = fmt.Errorf("the response carried no vp_token")
	}
	if err != nil {
		d.finishRequest(req, nil, nil, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	claims, checks, err := d.verifyPresentation(req, string(vpToken))
	d.finishRequest(req, claims, checks, err)

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": d.baseURL() + "/verifier/?result=" + url.QueryEscape(id),
	})
}

// authorizationResponse reads the parameters of a direct_post.jwt response.
// OpenID4VP 1.0 §8.3.1 lets a wallet that cannot encrypt "send an error
// response without encryption as per Section 8.2". It checks the state, so a
// response for one request cannot be posted to another.
func authorizationResponse(req *requestState, form url.Values) (map[string]any, error) {
	params := map[string]any{}
	switch encrypted := strings.TrimSpace(form.Get("response")); {
	case encrypted != "":
		if req.encKey == nil {
			return nil, fmt.Errorf("this request has no response encryption key")
		}
		plaintext, err := wallet.DecryptCompactJWE(encrypted, req.encKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting the response: %w", err)
		}
		if err := json.Unmarshal([]byte(plaintext), &params); err != nil {
			return nil, fmt.Errorf("parsing the decrypted response: %w", err)
		}
	case form.Get("error") != "":
		for _, name := range []string{"error", "error_description", "state"} {
			if value := form.Get(name); value != "" {
				params[name] = value
			}
		}
	default:
		return nil, fmt.Errorf("the response carried no encrypted response parameter (direct_post.jwt was requested)")
	}
	if state, _ := params["state"].(string); state != "" && state != req.id {
		return nil, fmt.Errorf("the response is for a different request")
	}
	return params, nil
}

func (d *DemoRP) recordPresentation(req *requestState, presentation string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	req.presentation = presentation
}

func (d *DemoRP) finishRequest(req *requestState, claims map[string]any, checks []map[string]any, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	req.claims = claims
	req.checks = checks
	if err != nil {
		req.status = "failed"
		req.err = err.Error()
		return
	}
	req.status = "verified"
	req.err = ""
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

	if len(req.custom) > 0 {
		return d.verifyCustomPresentation(req, tokenDoc, log)
	}

	// A PID request can offer both formats. The wallet answers under the query
	// id it can satisfy.
	var presentations []string
	if req.queryID != "" {
		presentations = tokenDoc[req.queryID]
	}
	answeredMDOC := false
	if len(presentations) == 0 && req.mdocQueryID != "" {
		presentations = tokenDoc[req.mdocQueryID]
		answeredMDOC = len(presentations) > 0
	}
	if len(presentations) > 0 {
		// Failed presentations stay available in the decoder.
		d.recordPresentation(req, presentations[0])
	}
	if err := check("vp_token holds one of the requested query ids",
		errIf(len(presentations) == 0, "no presentation for query id %s", strings.Join(req.queryIDs(), " or "))); err != nil {
		return nil, log.entries, err
	}

	// OpenID4VP 1.0 §8.1: "When multiple is omitted, or set to false, the array
	// MUST contain only one Presentation."
	if !req.multiple {
		if err := check("vp_token holds exactly one presentation",
			errIf(len(presentations) != 1, "expected 1 presentation, got %d", len(presentations))); err != nil {
			return nil, log.entries, err
		}
	}

	answered := req.queryID
	if answeredMDOC {
		answered = req.mdocQueryID
	}
	var verified []any
	for i, presentation := range presentations {
		label := ""
		if req.multiple {
			label = fmt.Sprintf("%s[%d]: ", answered, i)
		}
		var claims map[string]any
		var err error
		if answeredMDOC {
			claims, _, err = d.verifyMDOCPresentation(req, presentation, log)
		} else {
			claims, err = d.verifySDJWTEntry(req, presentation, req.vct, req.want, label, log)
		}
		if err != nil {
			d.recordPresentation(req, presentation)
			return nil, log.entries, err
		}
		verified = append(verified, claims)
	}
	// A multiple request lists the claims of each presentation under its
	// query id.
	resultClaims := verified[0].(map[string]any)
	if req.multiple {
		_ = check(fmt.Sprintf("%s: %d presentation(s) verified", answered, len(verified)), nil)
		resultClaims = map[string]any{answered: verified}
	}

	// A missing ticket entry is valid. The wallet chose a PID-only option or
	// skipped the optional set.
	if req.ticketQueryID != "" {
		ticketPresentations := tokenDoc[req.ticketQueryID]
		if len(ticketPresentations) == 0 {
			_ = log.record("ticket: not presented, which the request allows", nil)
		} else {
			if !req.multiple {
				if err := check("ticket: vp_token holds exactly one presentation",
					errIf(len(ticketPresentations) != 1, "expected 1 presentation, got %d", len(ticketPresentations))); err != nil {
					return nil, log.entries, err
				}
			}
			var tickets []any
			for i, presentation := range ticketPresentations {
				label := "ticket: "
				if req.multiple {
					label = fmt.Sprintf("ticket[%d]: ", i)
				}
				ticketClaims, err := d.verifySDJWTEntry(req, presentation, TicketVCT, req.ticketWant, label, log)
				if err != nil {
					// The decoder shows the failed ticket.
					d.recordPresentation(req, presentation)
					return nil, log.entries, err
				}
				tickets = append(tickets, ticketClaims)
			}
			if req.multiple {
				resultClaims["ticket"] = tickets
			} else {
				resultClaims["ticket"] = tickets[0]
			}
		}
	}

	return resultClaims, log.entries, nil
}

// verifyCustomPresentation verifies each credential query of a custom request
// by its format. An unanswered query is recorded and does not fail the
// request, because a custom request may ask for several credentials.
func (d *DemoRP) verifyCustomPresentation(req *requestState, tokenDoc map[string][]string, log *checklist) (map[string]any, []map[string]any, error) {
	check := log.record
	result := map[string]any{}
	recorded := false
	for _, entry := range req.custom {
		presentations := tokenDoc[entry.queryID]
		label := entry.queryID + ": "
		if len(presentations) == 0 {
			_ = check(label+"not presented", nil)
			continue
		}
		if !recorded {
			d.recordPresentation(req, presentations[0])
			recorded = true
		}
		// OpenID4VP 1.0 §8.1: "When multiple is omitted, or set to false, the
		// array MUST contain only one Presentation."
		if !entry.multiple {
			if err := check(label+"vp_token holds exactly one presentation",
				errIf(len(presentations) != 1, "expected 1 presentation, got %d", len(presentations))); err != nil {
				d.recordPresentation(req, presentations[0])
				return nil, log.entries, err
			}
		}
		var answers []any
		for i, presentation := range presentations {
			itemLabel := label
			if entry.multiple {
				itemLabel = fmt.Sprintf("%s[%d]: ", entry.queryID, i)
			}
			var claims map[string]any
			var err error
			if entry.format == "mso_mdoc" {
				req.docType, req.wantMDOC = entry.docType, entry.want
				claims, _, err = d.verifyMDOCPresentation(req, presentation, log)
			} else {
				claims, err = d.verifySDJWTEntry(req, presentation, entry.vct, entry.want, itemLabel, log)
			}
			if err != nil {
				// Failed presentations stay available in the decoder.
				d.recordPresentation(req, presentation)
				return nil, log.entries, err
			}
			answers = append(answers, claims)
		}
		if entry.multiple {
			_ = check(fmt.Sprintf("%s%d presentation(s) verified", label, len(answers)), nil)
			result[entry.queryID] = answers
		} else {
			result[entry.queryID] = answers[0]
		}
	}
	if len(result) == 0 {
		return nil, log.entries, check("vp_token answers a requested credential", fmt.Errorf("the response carried no presentation for any requested credential"))
	}
	return result, log.entries, nil
}

// verifySDJWTEntry checks type, issuer trust, revocation and key binding. The
// label prefix tells ticket checks apart from PID checks.
func (d *DemoRP) verifySDJWTEntry(req *requestState, presentation, expectedVCT string, want []string, label string, log *checklist) (map[string]any, error) {
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

	// SD-JWT VC requires typ dc+sd-jwt on the issuer-signed JWT (vc+sd-jwt
	// during the transition). A wrong typ is a warning.
	log.warn(label+"issuer-signed JWT declares an SD-JWT VC typ", sdjwt.ValidateVCType(token.Header))

	if err = check("every disclosure is referenced by the credential", checkDisclosuresReferenced(token)); err != nil {
		return nil, err
	}

	// The wallet chose the credential, so check the type. A derived type
	// answers its base type, such as a German PID for a base PID query.
	gotVCT, _ := token.ResolvedClaims["vct"].(string)
	gotAka := credtype.AkaVCTs(token.ResolvedClaims)
	if err = check("credential type matches the request",
		errIf(!credtype.Answers(gotVCT, gotAka, expectedVCT), "vct is %q, requested %q", gotVCT, expectedVCT)); err != nil {
		return nil, err
	}

	// HAIP 1.0 section 6.1.1 asks for the issuer signing certificate and trust
	// chain in x5c, without the trust anchor and with a leaf that is not
	// self-signed. This is a profile rule, so a violation is a warning.
	certs, _ := validate.X5CCertificates(token.Header)
	if violations := validate.HAIPCredentialChain(certs); len(violations) > 0 {
		log.warn(label+"issuer certificate chain follows HAIP", fmt.Errorf("%s", strings.Join(violations, ". ")))
	} else {
		log.warn(label+"issuer certificate chain follows HAIP", nil)
	}

	tlCerts := d.trustedIssuerCerts()
	if len(tlCerts) == 0 {
		return nil, check("issuer certificate chains to a trusted CA", fmt.Errorf("this verifier has no CA certificate"))
	}
	issuerKey, err := validate.ExtractAndValidateX5C(token.Header, tlCerts)
	if err == nil && issuerKey == nil {
		err = fmt.Errorf("the credential carries no x5c certificate chain")
	}
	if err = check("issuer certificate chains to a trusted CA", err); err != nil {
		return nil, err
	}
	result := sdjwt.Verify(token, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid")); err != nil {
		return nil, err
	}
	if err = check("credential is within its validity period",
		errIf(result.Expired || result.NotYetValid, "credential is expired or not yet valid")); err != nil {
		return nil, err
	}
	if err = d.checkRevocation(token, check); err != nil {
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
	if err = check("key binding JWT is typed kb+jwt", errIf(kbTyp != "kb+jwt", "typ is %q", kbTyp)); err != nil {
		return nil, err
	}
	if err = check("key binding signature verifies with cnf key", errIf(!verifyES256(holderKey, kbJWT.signingInput, kbJWT.signature), "key binding signature is invalid")); err != nil {
		return nil, err
	}

	// RFC 9901 §7.3: "check that the creation time of the Key Binding JWT, as
	// determined by the iat claim, is within an acceptable window". The claim
	// is REQUIRED (§4.3). The window is the same as for every per-request proof.
	kbIat, hasIat := kbJWT.payload["iat"].(float64)
	iatErr := errIf(!hasIat, "the key binding JWT has no numeric iat")
	if iatErr == nil {
		if age := time.Since(time.Unix(int64(kbIat), 0)); age > proofClockSkew || age < -proofClockSkew {
			iatErr = fmt.Errorf("the key binding JWT iat is %s away from now, outside the %s window this verifier accepts", age.Round(time.Second), proofClockSkew)
		}
	}
	if err = check("key binding was created within an acceptable window", iatErr); err != nil {
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
	var missing []string
	for _, name := range want {
		if _, ok := disclosed[name]; !ok {
			missing = append(missing, name)
		}
	}
	if err = check("requested claims were disclosed",
		errIf(len(missing) > 0, "missing: %s", strings.Join(missing, ", "))); err != nil {
		return nil, err
	}

	return disclosed, nil
}

// checkDisclosuresReferenced requires a digest for every disclosure in the
// issuer-signed payload or in another disclosure. An unreferenced or
// duplicate disclosure means the presentation was altered.
func checkDisclosuresReferenced(token *sdjwt.Token) error {
	referenced := sdjwt.ReferencedDigests(token)

	seen := make(map[string]bool, len(token.Disclosures))
	for _, d := range token.Disclosures {
		if !referenced[d.Digest] {
			name := d.Name
			if name == "" {
				name = "array element"
			}
			return fmt.Errorf("disclosure %q is not referenced by any digest in the credential", name)
		}
		if seen[d.Digest] {
			return fmt.Errorf("disclosure %q appears more than once", d.Name)
		}
		seen[d.Digest] = true
	}
	return nil
}

func (d *DemoRP) checkRevocation(token *sdjwt.Token, check func(string, error) error) error {
	ref := statuslist.ExtractStatusRef(token.ResolvedClaims)
	if ref == nil {
		return check("revocation status (credential references no status list)", nil)
	}

	// The status list JWT must chain to the same CAs as the credential. A
	// forged list could otherwise un-revoke a credential.
	anchors := d.trustedIssuerCerts()
	if len(anchors) == 0 {
		return check("credential is not revoked", fmt.Errorf("this verifier has no CA certificate"))
	}
	trustCerts := make([]statuslist.TrustCert, 0, len(anchors))
	for _, anchor := range anchors {
		trustCerts = append(trustCerts, statuslist.TrustCert{Raw: anchor.Raw})
	}
	result, err := statuslist.CheckWithOptions(ref, statuslist.CheckOptions{
		HTTPClient:     d.wallet.HTTPClient(),
		TrustListCerts: trustCerts,
	})
	if err != nil {
		return check("credential is not revoked", fmt.Errorf("checking the status list: %w", err))
	}
	if result.SignatureValid != nil && !*result.SignatureValid {
		return check("credential is not revoked", fmt.Errorf("the status list signature did not verify: %s", result.SignatureInfo))
	}
	return check("credential is not revoked", errIf(result.Status != 0, "the issuer's status list marks this credential as revoked"))
}

// trustedIssuerCerts returns the trust anchors for issuer chains. They are the
// wallet CA and the anchors from SetVerifierTrustAnchors.
func (d *DemoRP) trustedIssuerCerts() []trustlist.CertInfo {
	var anchors []*x509.Certificate
	if caCert := d.wallet.TrustAnchorCertificate(); caCert != nil {
		anchors = append(anchors, caCert)
	}
	anchors = append(anchors, d.verifierTrustAnchors...)
	certs := make([]trustlist.CertInfo, 0, len(anchors))
	for _, anchor := range anchors {
		certs = append(certs, trustlist.CertInfo{
			Subject:   anchor.Subject.String(),
			PublicKey: anchor.PublicKey,
			Raw:       anchor.Raw,
		})
	}
	return certs
}

func errIf(cond bool, format string, args ...any) error {
	if cond {
		return fmt.Errorf(format, args...)
	}
	return nil
}

// disclosedClaims leaves JWT protocol fields out of the displayed claims.
func disclosedClaims(token *sdjwt.Token) map[string]any {
	internal := map[string]bool{
		"iss": true, "iat": true, "exp": true, "nbf": true, "cnf": true,
		"vct": true, "status": true, "_sd_alg": true, "_sd": true,
	}
	claims := make(map[string]any)
	for name, value := range token.ResolvedClaims {
		if !internal[name] {
			claims[name] = value
		}
	}
	claims["vct"] = token.ResolvedClaims["vct"]
	return claims
}

// verifyMDOCPresentation validates an mdoc DeviceResponse. It checks the
// doctype, the issuer signature and element digests, the holder signature
// over the session transcript and the validity period.
func (d *DemoRP) verifyMDOCPresentation(req *requestState, presentation string, log *checklist) (map[string]any, []map[string]any, error) {
	check := log.record
	doc, err := mdoc.Parse(presentation)
	if err = check("presentation parses as an mdoc DeviceResponse", err); err != nil {
		return nil, log.entries, err
	}

	// The wallet chose the credential, so check the doctype.
	if err = check("credential type matches the request",
		errIf(doc.DocType != req.docType, "doctype is %q, requested %q", doc.DocType, req.docType)); err != nil {
		return nil, log.entries, err
	}

	tlCerts := d.trustedIssuerCerts()
	if len(tlCerts) == 0 {
		return nil, log.entries, check("issuer certificate chains to a trusted CA", fmt.Errorf("this verifier has no CA certificate"))
	}
	issuerKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err == nil && issuerKey == nil {
		err = fmt.Errorf("the credential carries no x5c certificate chain")
	}
	if err = check("issuer certificate chains to a trusted CA", err); err != nil {
		return nil, log.entries, err
	}

	result := mdoc.Verify(doc, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid: %s", strings.Join(result.Errors, ". "))); err != nil {
		return nil, log.entries, err
	}
	for _, warning := range result.Warnings {
		log.warn("mdoc MSO declares its required members", fmt.Errorf("%s", warning))
	}
	// ISO 18013-5 requires validityInfo and validUntil in the MSO. Without
	// validUntil the validity check is reported as unchecked.
	if result.ValidUntil == nil {
		log.warn("credential is within its validity period",
			fmt.Errorf("the mdoc MSO carries no validUntil, so its validity cannot be checked (ISO 18013-5 requires validityInfo)"))
	} else if err = check("credential is within its validity period",
		errIf(result.Expired || result.NotYetValid, "credential is expired or not yet valid")); err != nil {
		return nil, log.entries, err
	}

	// The issuer signature covers only the MSO. The digest check binds the
	// element values to it.
	if err = check("disclosed elements match the digests the issuer signed", mdoc.VerifyValueDigests(doc)); err != nil {
		return nil, log.entries, err
	}

	// The holder signs the session transcript. Rebuilding it here binds the
	// response to this request.
	transcript, err := d.rebuildSessionTranscript(req)
	if err = check("session transcript rebuilds", err); err != nil {
		return nil, log.entries, err
	}
	if err = check("holder signed this request", mdoc.VerifyDeviceAuth(doc, transcript)); err != nil {
		return nil, log.entries, err
	}

	claims := map[string]any{}
	for _, items := range doc.NameSpaces {
		for _, item := range items {
			claims[item.ElementIdentifier] = item.ElementValue
		}
	}
	var missing []string
	for _, want := range req.wantMDOC {
		if _, ok := claims[want]; !ok {
			missing = append(missing, want)
		}
	}
	if err = check("the requested elements are present",
		errIf(len(missing) > 0, "missing from the presentation: %s", strings.Join(missing, ", "))); err != nil {
		return nil, log.entries, err
	}
	return claims, log.entries, nil
}

// encryptionJWKThumbprint is the RFC 7638 thumbprint of the response
// encryption key in the OpenID4VP session transcript. It must match the
// wallet's thumbprint of the client_metadata JWK, so it uses the same members.
func encryptionJWKThumbprint(key *ecdsa.PrivateKey) []byte {
	if key == nil {
		return nil
	}
	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		return nil
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y))
	sum := sha256.Sum256([]byte(canonical))
	return sum[:]
}

// checklist keeps each check result for the UI.
type checklist struct {
	entries []map[string]any
}

func (c *checklist) record(name string, err error) error {
	entry := map[string]any{"name": name, "ok": err == nil}
	if err != nil {
		entry["error"] = err.Error()
	}
	c.entries = append(c.entries, entry)
	return err
}

// warn records a profile finding. It never rejects the presentation.
func (c *checklist) warn(name string, err error) {
	entry := map[string]any{"name": name, "ok": true}
	if err != nil {
		entry["warning"] = err.Error()
	}
	c.entries = append(c.entries, entry)
}
