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

package registrar

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

// Server answers the registrar API. The wallet server routes the requests to
// it and provides the registrar and a way to save changes.
type Server struct {
	// Registrar returns the registrar of the wallet's current state.
	Registrar func() *Registrar
	// Mutate runs change and saves the wallet when change reports a change.
	Mutate func(change func() bool)
	// Protected reports whether clients may not change a registration or its
	// certificates.
	Protected func(rp WalletRelyingParty) bool
	// KeepTemplateEntries reports whether clients may not delete the
	// catalogue entries of the predefined templates.
	KeepTemplateEntries func() bool
}

// refuseProtected resolves any form of the identifier to its registration,
// so the protection holds for every identifier of a party.
func (h *Server) refuseProtected(w http.ResponseWriter, identifier string) bool {
	if h.Protected == nil {
		return false
	}
	rp, ok := h.Registrar().RelyingParty(identifier)
	if !ok || !h.Protected(rp) {
		return false
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": fmt.Sprintf("%s is a registration of the public demo, and visitors can't change it. Register your own relying party instead", identifier)})
	return true
}

// Routes are the registrar API's patterns and handlers.
func (h *Server) Routes() map[string]http.HandlerFunc {
	routes := map[string]http.HandlerFunc{
		"GET /api/registrar/wrp":                                           h.handleRegistrarWRPList,
		"GET /api/registrar/wrp/check-intended-use":                        h.handleCheckIntendedUse,
		"GET /api/registrar/wrp/{identifier}":                              h.handleRegistrarWRPByIdentifier,
		"GET /api/registrar/wrp/{identifier}/services/{serviceidentifier}": h.handleRegistrarWRPService,
		"POST /api/registrar/wrp":                                          h.handleRegisterRelyingParty,
		"PUT /api/registrar/wrp":                                           h.handleUpdateRelyingParty,
		"DELETE /api/registrar/wrp/{identifier}":                           h.handleDeleteRelyingParty,
		"POST /api/registrar/enrolments":                                   h.handleEnrol(false),
		"PUT /api/registrar/enrolments":                                    h.handleEnrol(true),
		"POST /api/registrar/registration-certificates":                    h.handleIssueRegistrationCertificate,
		"GET /api/registrar/registration-certificates":                     h.handleRegistrationCertificateStatuses,
		"POST /api/registrar/registration-certificates/status":             h.handleSetRegistrationCertificateStatus,
		"GET " + RegistrationStatusListPath:                                h.handleRegistrationStatusList,
		"POST /api/registrar/access-certificates":                          h.handleIssueAccessCertificate,
		"GET " + catalogSchemaPath:                                         h.handleCatalogSchemas,
		"GET " + catalogSchemaPath + "/{id}":                               h.handleCatalogSchema,
		"PUT " + catalogSchemaPath + "/{id}":                               h.handleUpdateCatalogSchema,
		"DELETE " + catalogSchemaPath + "/{id}":                            h.handleDeleteCatalogSchema,
		"GET " + catalogSchemaPath + "/{id}/{format}":                      h.handleCatalogFormatSchema,
		"GET /api/catalog/attestations":                                    h.handleCatalogAttestations,
		"GET /api/catalog/categories":                                      h.handleCatalogCategories,
		"GET /api/catalog/schema-options":                                  h.handleCatalogSchemaOptions,
		"POST /api/catalog/attestations":                                   h.handleAddCatalogAttestation,
	}
	for path, page := range placeholderPages {
		routes["GET "+path] = page.handler()
	}
	return routes
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(data)
}

func signRegistrarResponseJWT(signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate, payload any) (string, error) {
	header := map[string]any{"alg": jws.AlgES256, "typ": "JWT"}
	if x5c := x5cChain(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return jws.Sign(header, payload, signingKey)
}

// handleRegisterRelyingParty stores a relying party (TS05 v1.5 §3.1, POST /wrp).
func (h *Server) handleRegisterRelyingParty(w http.ResponseWriter, r *http.Request) {
	rp, ok := decodeRelyingParty(w, r)
	if !ok {
		return
	}
	var stored WalletRelyingParty
	var err error
	h.Mutate(func() bool {
		stored, err = h.Registrar().RegisterRelyingParty(rp)
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// handleUpdateRelyingParty replaces a registration (TS05 v1.5 §3.1, PUT /wrp)
// and answers with the signed record, as the TS05 v1.5 OpenAPI defines.
func (h *Server) handleUpdateRelyingParty(w http.ResponseWriter, r *http.Request) {
	rp, ok := decodeRelyingParty(w, r)
	if !ok {
		return
	}
	for _, id := range rp.Identifier {
		if h.refuseProtected(w, id.Identifier) {
			return
		}
	}
	var stored WalletRelyingParty
	var err error
	h.Mutate(func() bool {
		stored, err = h.Registrar().UpdateRelyingParty(rp)
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	h.writeRegistrarResponse(w, r, map[string]any{"data": stored})
}

func (h *Server) handleDeleteRelyingParty(w http.ResponseWriter, r *http.Request) {
	if h.refuseProtected(w, r.PathValue("identifier")) {
		return
	}
	var err error
	h.Mutate(func() bool {
		err = h.Registrar().DeleteRelyingParty(r.PathValue("identifier"))
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleEnrol registers or changes a relying party and issues its
// certificates in one request, so a failed certificate leaves no half-done
// registration.
func (h *Server) handleEnrol(update bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var e Enrolment
		if err := json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&e); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid enrolment: " + err.Error()})
			return
		}
		if err := checkRegistrationSize(e.RelyingParty); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if update {
			for _, id := range e.RelyingParty.Identifier {
				if h.refuseProtected(w, id.Identifier) {
					return
				}
			}
		}
		var result *EnrolmentResult
		var err error
		h.Mutate(func() bool {
			result, err = h.Registrar().Enrol(e, update)
			return err == nil
		})
		if err != nil {
			writeRegistrarError(w, err)
			return
		}
		status := http.StatusCreated
		if update {
			status = http.StatusOK
		}
		writeJSON(w, status, result)
	}
}

func decodeRelyingParty(w http.ResponseWriter, r *http.Request) (WalletRelyingParty, bool) {
	var rp WalletRelyingParty
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid relying party: " + err.Error()})
		return rp, false
	}
	if err := checkRegistrationSize(rp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return rp, false
	}
	return rp, true
}

// handleRegistrarWRPList answers the TS05 v1.5 §3.2 search (GET /wrp) with the
// matching records, paged by limit and cursor.
func (h *Server) handleRegistrarWRPList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	matching := slices.DeleteFunc(h.Registrar().RegisteredRelyingParties(), func(rp WalletRelyingParty) bool { return !matchesWRPQuery(rp, q) })
	if service := strings.TrimSpace(q.Get("serviceidentifier")); service != "" && q.Get("isolateService") == "true" {
		for i := range matching {
			matching[i].Services = slices.DeleteFunc(matching[i].Services, func(s WalletRelyingPartyService) bool { return s.ServiceIdentifier != service })
		}
	}
	start, end, _, err := page(q, "cursor", len(matching))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pagination := map[string]any{"has_next_page": end < len(matching)}
	if end < len(matching) {
		pagination["next_cursor"] = strconv.Itoa(end)
	}
	h.writeRegistrarResponse(w, r, map[string]any{"data": matching[start:end], "pagination": pagination})
}

// page reads limit and the offset parameter and returns the bounds of the
// page in a list of total items, and the limit it applied.
func page(q url.Values, offsetParam string, total int) (start, end, limit int, err error) {
	limit, offset := 20, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, 0, 0, errors.New("limit must be a positive integer")
		}
		limit = min(n, maxPageSize)
	}
	if v := q.Get(offsetParam); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, 0, fmt.Errorf("%s must be a non-negative integer", offsetParam)
		}
		offset = n
	}
	start = min(offset, total)
	return start, start + min(limit, total-start), limit, nil
}

func (h *Server) handleRegistrarWRPByIdentifier(w http.ResponseWriter, r *http.Request) {
	rp, ok := h.Registrar().RelyingParty(r.PathValue("identifier"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "relying party not registered"})
		return
	}
	h.writeRegistrarResponse(w, r, map[string]any{"data": rp})
}

// handleRegistrarWRPService narrows a record to one service (TS05 v1.5 §3.2.2).
func (h *Server) handleRegistrarWRPService(w http.ResponseWriter, r *http.Request) {
	rp, ok := h.Registrar().RelyingParty(r.PathValue("identifier"))
	if ok {
		rp.Services = slices.DeleteFunc(slices.Clone(rp.Services), func(service WalletRelyingPartyService) bool {
			return service.ServiceIdentifier != r.PathValue("serviceidentifier")
		})
	}
	if !ok || len(rp.Services) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet relying party service not found"})
		return
	}
	h.writeRegistrarResponse(w, r, map[string]any{"data": rp})
}

// handleCheckIntendedUse answers whether a relying party registered an intended
// use for a credential and claim (TS05 v1.5 §3.2.2). Every parameter is
// optional. Without identifier it searches all registrations.
func (h *Server) handleCheckIntendedUse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	parties := h.Registrar().RegisteredRelyingParties()
	if identifier := strings.TrimSpace(q.Get("identifier")); identifier != "" {
		rp, ok := h.Registrar().RelyingParty(identifier)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "relying party not registered"})
			return
		}
		parties = []WalletRelyingParty{rp}
	}
	registered := slices.ContainsFunc(parties, func(rp WalletRelyingParty) bool { return registersIntendedUse(rp, q) })
	h.writeRegistrarResponse(w, r, map[string]any{"data": map[string]any{"isRegistered": registered}})
}

// writeRegistrarResponse adds iss and iat and signs the payload, as TS05 v1.5
// §3.2 requires. If the Accept header asks for application/json but not
// application/jwt, the payload is sent unsigned.
func (h *Server) writeRegistrarResponse(w http.ResponseWriter, r *http.Request, payload map[string]any) {
	payload["iss"] = h.Registrar().env.RegistrarBase()
	payload["iat"] = time.Now().Unix()
	if accept := r.Header.Get("Accept"); strings.Contains(accept, "application/json") && !strings.Contains(accept, "application/jwt") {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	key, chain, err := h.Registrar().env.RegistrarSigningMaterial()
	if err != nil {
		http.Error(w, "loading registrar signer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := signRegistrarResponseJWT(key, chain, payload)
	if err != nil {
		http.Error(w, "signing registrar response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = w.Write([]byte(signed))
}

// handleSetRegistrationCertificateStatus revokes or activates the
// registration certificates of an intended use, of a service, or of the whole
// relying party.
func (h *Server) handleSetRegistrationCertificateStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		RegistrationScope
		Revoked bool `json:"revoked"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if h.refuseProtected(w, req.Identifier) {
		return
	}
	var changed int
	var err error
	h.Mutate(func() bool {
		changed, err = h.Registrar().SetRegistrationCertificatesRevoked(req.Identifier, req.RegistrationScope, req.Revoked)
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"changed": changed})
}

func (h *Server) handleRegistrationCertificateStatuses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.Registrar().RegistrationCertificateViews(r.URL.Query().Get("identifier")))
}

// handleRegistrationStatusList serves the status list of the registration
// certificates as a Token Status List (ETSI TS 119 475 V1.2.1 §6.2.6.1),
// signed by the registrar key.
func (h *Server) handleRegistrationStatusList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	token, err := h.Registrar().RegistrationStatusListToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", statuslist.MediaTypeJWT)
	_, _ = w.Write([]byte(token))
}

func writeRegistrarError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errRelyingPartyNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errRelyingPartyExists), errors.Is(err, errRegistrarFull), errors.Is(err, errPartyCertificatesFull), errors.Is(err, errRegistrationChanged):
		status = http.StatusConflict
	case errors.Is(err, errRegistrarSigning):
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// handleCatalogSchemas answers GET /schemas of the catalogue of attestations
// API (EC TS11 v1.0 §5.3.1) with a signed, paginated list of SchemaMeta
// objects.
func (h *Server) handleCatalogSchemas(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var matching []AttestationSchema
	for _, entry := range h.Registrar().CatalogAttestations() {
		if matchesSchemaQuery(entry.Schema, q) {
			matching = append(matching, entry.Schema)
		}
	}
	start, end, limit, err := page(q, "offset", len(matching))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	schemas := matching[start:end]
	if schemas == nil {
		schemas = []AttestationSchema{}
	}
	h.writeRegistrarResponse(w, r, map[string]any{"data": map[string]any{
		"total": len(matching), "limit": limit, "offset": start, "data": schemas,
	}})
}

// matchesSchemaQuery applies the filters of TS11 v1.0 §5.3.1. supportedFormats
// takes a comma separated list, as the OpenAPI form style without explode
// does.
func matchesSchemaQuery(schema AttestationSchema, q map[string][]string) bool {
	get := func(name string) string {
		if values := q[name]; len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
		return ""
	}
	if v := get("id"); v != "" && v != schema.ID {
		return false
	}
	if v := get("supportedFormats"); v != "" {
		for _, format := range strings.Split(v, ",") {
			if !slices.Contains(schema.SupportedFormats, strings.TrimSpace(format)) {
				return false
			}
		}
	}
	if v := get("attestationLoS"); v != "" && v != schema.AttestationLoS {
		return false
	}
	if v := get("bindingType"); v != "" && v != schema.BindingType {
		return false
	}
	if v := get("trustedAuthoritiesFrameworkType"); v != "" && !slices.ContainsFunc(schema.TrustedAuthorities, func(a TrustAuthority) bool { return a.FrameworkType == v }) {
		return false
	}
	if v := get("trustedAuthoritiesValue"); v != "" && !slices.ContainsFunc(schema.TrustedAuthorities, func(a TrustAuthority) bool { return a.Value == v }) {
		return false
	}
	if v := get("schemaUri"); v != "" && !slices.ContainsFunc(schema.SchemaURIs, func(u SchemaURI) bool { return u.URI == v }) {
		return false
	}
	if v := get("rulebookUri"); v != "" && v != schema.RulebookURI {
		return false
	}
	return true
}

// handleCatalogSchema answers GET /schemas/{schemaId} (TS11 v1.0 §5.3.1).
func (h *Server) handleCatalogSchema(w http.ResponseWriter, r *http.Request) {
	entry, ok := h.Registrar().CatalogAttestation(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attestation schema not found"})
		return
	}
	h.writeRegistrarResponse(w, r, map[string]any{"data": entry.Schema})
}

// handleCatalogFormatSchema serves the format-specific schema behind a schema
// URI (TS11 v1.0 §4.3.4).
func (h *Server) handleCatalogFormatSchema(w http.ResponseWriter, r *http.Request) {
	entry, ok := h.Registrar().CatalogAttestation(r.PathValue("id"))
	var schema map[string]any
	if ok {
		schema, ok = entry.FormatSchema(r.PathValue("format"))
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attestation schema not found"})
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, schema)
}

// handleUpdateCatalogSchema replaces a SchemaMeta (TS11 v1.0 §5.3.2).
func (h *Server) handleUpdateCatalogSchema(w http.ResponseWriter, r *http.Request) {
	var schema AttestationSchema
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&schema); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation schema: " + err.Error()})
		return
	}
	var updated CatalogAttestation
	var err error
	h.Mutate(func() bool {
		updated, err = h.Registrar().UpdateCatalogSchema(r.PathValue("id"), schema)
		return err == nil
	})
	if err != nil {
		WriteCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated.Schema)
}

// handleDeleteCatalogSchema deletes an attestation schema (TS11 v1.0 §5.3.3).
func (h *Server) handleDeleteCatalogSchema(w http.ResponseWriter, r *http.Request) {
	if h.KeepTemplateEntries != nil && h.KeepTemplateEntries() && h.Registrar().IsTemplateCatalogID(r.PathValue("id")) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the entries of the predefined templates are part of the public demo, and visitors can't delete them"})
		return
	}
	var err error
	h.Mutate(func() bool {
		err = h.Registrar().DeleteCatalogAttestation(r.PathValue("id"))
		return err == nil
	})
	if err != nil {
		WriteCatalogError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCatalogAttestations lists the catalogue with the names and credential
// types the UI shows. TS11 has no such method, because its SchemaMeta leaves
// them to the format-specific schemas.
func (h *Server) handleCatalogAttestations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.Registrar().CatalogAttestations())
}

// handleCatalogCategories lists the credential categories with their
// entitlements, trust rules and default levels of security.
func (h *Server) handleCatalogCategories(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Categories())
}

// handleCatalogSchemaOptions lists the levels of security and holder bindings
// a catalogue entry can name, with their labels.
func (h *Server) handleCatalogSchemaOptions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"attestationLoS": AttestationLevels, "bindingType": BindingTypes})
}

// handleAddCatalogAttestation adds an attestation. TS11 v1.0 leaves
// registration to the European Commission's process (§4.5), so this method
// is the test catalogue's own.
func (h *Server) handleAddCatalogAttestation(w http.ResponseWriter, r *http.Request) {
	var entry CatalogAttestation
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation: " + err.Error()})
		return
	}
	var stored CatalogAttestation
	var err error
	h.Mutate(func() bool {
		stored, err = h.Registrar().AddCatalogAttestation(entry)
		return err == nil
	})
	if err != nil {
		WriteCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// WriteCatalogError answers a catalogue error with its HTTP status.
func WriteCatalogError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errCatalogNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errCatalogTemplate):
		status = http.StatusForbidden
	case errors.Is(err, errCatalogFull):
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// handleIssueRegistrationCertificate signs a registration certificate for a
// registered intended use with the wallet's registrar key.
func (h *Server) handleIssueRegistrationCertificate(w http.ResponseWriter, r *http.Request) {
	var req RegistrationCertificateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if h.refuseProtected(w, req.Identifier) {
		return
	}
	var result *RegistrationCertificateResult
	var err error
	h.Mutate(func() bool {
		result, err = h.Registrar().IssueRegistrationCertificate(req)
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

// handleIssueAccessCertificate signs an access certificate for the public key of
// a registered relying party's CSR.
func (h *Server) handleIssueAccessCertificate(w http.ResponseWriter, r *http.Request) {
	var req AccessCertificateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	// An access certificate for a protected party's identifier would let its
	// holder sign requests as that party.
	if h.refuseProtected(w, req.Identifier) {
		return
	}
	result, err := h.Registrar().IssueAccessCertificate(req)
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}
