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

// These handlers also serve remote CLI commands. They have no authentication. Demo
// mode disables destructive operations for public deployments.

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	summary, err := s.management().Credential(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, withPublicImagePaths(r, summary))
}

// Use the local status list for managed entries. Otherwise fetch the list referenced
// by the credential.
func (s *Server) handleGetCredentialStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cred, ok := s.wallet.GetCredential(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
		return
	}

	ref := CredentialStatusRef(cred)
	if entry, managed := s.wallet.StatusEntryFor(cred.ID); managed {
		info := map[string]any{
			"managed":    true,
			"status":     entry.Status,
			"statusName": statuslist.StatusName(entry.Status),
			"source":     "wallet",
		}
		if ref != nil && ref.Invalid == "" {
			info["uri"] = ref.URI
			info["idx"] = ref.Idx
		}
		writeJSON(w, http.StatusOK, info)
		return
	}
	if ref == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential has no status list reference"})
		return
	}
	if ref.Invalid != "" {
		// A malformed status_list object violates section 6.2. Report it as a
		// credential error.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": ref.Invalid})
		return
	}

	// For externally issued credentials, report whether the status issuer's key is
	// trusted. A valid signature alone does not establish trust. The revocation
	// service of the list that anchors the credential anchors its status list.
	statusAnchors := s.wallet.StatusListAnchors(cred.Raw)
	checkOpts := statuslist.CheckOptions{HTTPClient: s.wallet.HTTPClient(), Prefer: statuslist.FormatForCredential(cred.Format)}
	for _, anchor := range statusAnchors {
		checkOpts.CandidateAnchors = append(checkOpts.CandidateAnchors, statuslist.TrustCert{Raw: anchor.Raw})
	}
	result, err := statuslist.CheckWithOptions(ref, checkOpts)
	if err != nil {
		// The UI badge is temporary. Keep the failure reason in the activity log.
		s.wallet.addProtocolWarning("wallet", "status_list_check_failed",
			fmt.Sprintf("Status list of credential %s could not be checked: %s", credentialLabel(cred), err),
			map[string]any{
				"credential_id": cred.ID,
				"uri":           ref.URI,
				"idx":           ref.Idx,
				"error":         err.Error(),
			})
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "checking external status list: " + err.Error(),
			"uri":   ref.URI,
			"idx":   ref.Idx,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"managed":       false,
		"status":        result.Status,
		"statusName":    result.StatusName,
		"source":        "remote",
		"format":        result.Format,
		"uri":           ref.URI,
		"idx":           ref.Idx,
		"trustAnchored": result.TrustAnchored,
		"warnings":      result.Warnings,
	})
}

func (s *Server) handleDeleteAllCredentials(w http.ResponseWriter, r *http.Request) {
	removed, err := s.management().RemoveAllCredentials()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, removed)
}

// management persists each change under the reload lock, so a concurrent reload
// cannot drop it.
func (s *Server) management() *Management {
	return &Management{wallet: s.wallet, store: s.store.Load(), commit: func(change func() error) error {
		var err error
		s.saveMutation(func() bool {
			err = change()
			return err == nil
		})
		return err
	}}
}

// IssueAPIRequest is shared by HTTP and local CLI issuance so issue --wallet behaves
// consistently.
type IssueAPIRequest struct {
	Format          string         `json:"format"`
	Template        string         `json:"template"`
	Claims          map[string]any `json:"claims"`
	PID             bool           `json:"pid"`
	Omit            []string       `json:"omit"`
	AlwaysDisclosed []string       `json:"always_disclosed"`
	SaveAsTemplate  string         `json:"save_as_template"`
	// Catalog adds the saved template to the attestation catalogue.
	Catalog       *registrar.CatalogAttestation `json:"catalog,omitempty"`
	VCT           string                        `json:"vct"`
	DocType       string                        `json:"doctype"`
	Namespace     string                        `json:"namespace"`
	Exp           string                        `json:"exp"`
	NBF           string                        `json:"nbf"`
	StatusListURI *string                       `json:"status_list_uri"`
	StatusListIdx *int                          `json:"status_list_idx"`
	Category      string                        `json:"category"`
	Trust         IssuedAttestationSpec         `json:"trust"`
	Display       *IssueDisplay                 `json:"display"`
	Batch         int                           `json:"batch"`
	// Identifies the template containing display images that could not be included in
	// the form fields.
	DisplayTemplate string `json:"display_template"`
	// Defaults to binding the credential to the wallet's holder key.
	Unbound bool `json:"unbound"`
	// The private key accepts PEM or JWK. The certificate chain uses PEM with the leaf
	// first.
	SigningKey  string `json:"signing_key"`
	SigningCert string `json:"signing_cert"`
}

func (req IssueAPIRequest) Options() (IssueOptions, error) {
	opts := IssueOptions{
		Format:          req.Format,
		Template:        req.Template,
		Claims:          req.Claims,
		PID:             req.PID,
		Omit:            req.Omit,
		AlwaysDisclosed: req.AlwaysDisclosed,
		SaveTemplate:    req.SaveAsTemplate,
		Catalog:         req.Catalog,
		VCT:             req.VCT,
		DocType:         req.DocType,
		Namespace:       req.Namespace,
		StatusListURI:   req.StatusListURI,
		StatusListIdx:   req.StatusListIdx,
		Category:        req.Category,
		Trust:           req.Trust,
		Display:         req.Display,
		BatchSize:       req.Batch,
		DisplayTemplate: req.DisplayTemplate,
		Unbound:         req.Unbound,
	}
	if req.Exp != "" {
		expDuration, err := time.ParseDuration(req.Exp)
		if err != nil {
			return IssueOptions{}, fmt.Errorf("invalid exp duration: %w", err)
		}
		opts.ExpiresIn = expDuration
	}
	if req.NBF != "" {
		nbf, err := parseTimeOrDuration(req.NBF)
		if err != nil {
			return IssueOptions{}, err
		}
		opts.NotBefore = nbf
	}
	signingKey, signingCerts, err := ParseSigningOverride(req.SigningKey, req.SigningCert)
	if err != nil {
		return IssueOptions{}, err
	}
	opts.SigningKey = signingKey
	opts.SigningCertChain = signingCerts
	return opts, nil
}

// IssueSummary requires the caller to persist the wallet after issuance.
func (w *Wallet) IssueSummary(opts IssueOptions) (map[string]any, error) {
	result, err := w.IssueCredential(opts)
	if err != nil {
		return nil, err
	}
	summary := w.CredentialSummaryWithStatus(*result.Credential)
	if result.StatusRegistered {
		summary["status_list_idx"] = result.StatusIdx
	}
	if result.TemplatePath != "" {
		summary["template_path"] = result.TemplatePath
	}
	// Echo the override. A caller can then detect an older server that ignores it
	// and signs with its own key.
	if opts.SigningKey != nil {
		summary["signing_override"] = true
	}
	return summary, nil
}

func (s *Server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	var req IssueAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}

	// The API names templates of the wallet's template store. A path would
	// read a file of the server.
	for _, name := range []string{req.Template, req.SaveAsTemplate, req.DisplayTemplate} {
		if name = strings.TrimSpace(name); name != "" && !credtemplate.IsBareName(name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid template name %q", name)})
			return
		}
	}
	if s.demo != nil && (strings.TrimSpace(req.SigningKey) != "" || strings.TrimSpace(req.SigningCert) != "") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the public demo can't override the signing key"})
		return
	}

	summary, err := s.management().Issue(req)
	if err != nil {
		writeJSON(w, visitorLimitStatus(err, http.StatusBadRequest), map[string]string{"error": err.Error()})
		return
	}
	if req.SaveAsTemplate != "" {
		s.templatesChanged()
	}
	writeJSON(w, http.StatusCreated, withPublicImagePaths(r, summary))
}

// visitorLimitStatus answers 403 for a change the shared wallet refuses.
func visitorLimitStatus(err error, otherwise int) int {
	var limit *VisitorLimitError
	if errors.As(err, &limit) {
		return http.StatusForbidden
	}
	return otherwise
}

func credentialTypeLabel(summary map[string]any) string {
	for _, key := range []string{"vct", "doctype", "id"} {
		if v, ok := summary[key].(string); ok && v != "" {
			return v
		}
	}
	return "credential"
}

type generatePIDRequest struct {
	Claims map[string]any `json:"claims"`
	VCT    string         `json:"vct"`
}

// Deprecated: use POST /api/issue with a PID template. This endpoint will be removed
// together with wallet generate-pid.
func (s *Server) handleGeneratePID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Deprecation", "true")
	var req generatePIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}

	var genErr error
	s.saveMutation(func() bool {
		if genErr = s.wallet.GenerateDefaultCredentials(req.Claims, req.VCT); genErr != nil {
			return false
		}
		s.wallet.AddLog("management", "Regenerated default PID credentials", true)
		return true
	})
	if genErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": genErr.Error()})
		return
	}

	data, err := s.wallet.CredentialsJSON()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

func (s *Server) handleCACertificate(w http.ResponseWriter, r *http.Request) {
	store := s.currentStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "wallet store is not configured"})
		return
	}
	certPEM, err := store.LoadOrCreateSharedCACertificatePEM()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading wallet CA certificate: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, certPEM)
}

func (s *Server) handleCACertificateDER(w http.ResponseWriter, r *http.Request) {
	cert := s.wallet.TrustAnchorCertificate()
	if cert == nil {
		http.Error(w, "wallet has no CA certificate", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Write(cert.Raw)
}

func (s *Server) handleTLSCertificate(w http.ResponseWriter, r *http.Request) {
	store := s.currentStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "wallet store is not configured"})
		return
	}
	issuerURL := strings.TrimSpace(s.wallet.IssuerURL)
	if issuerURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "wallet issuer URL is not configured"})
		return
	}
	certPEM, err := store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading wallet TLS certificate: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, certPEM)
}

// handleRegistrarCertificate exports the certificate that signs registration
// certificates and registrar responses.
func (s *Server) handleRegistrarCertificate(w http.ResponseWriter, r *http.Request) {
	_, chain, err := s.wallet.RegistrarSigningMaterial()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading the registrar certificate: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0].Raw}))
}

func (s *Server) handleRelyingPartyAccessCA(w http.ResponseWriter, r *http.Request) {
	_, ca, err := s.wallet.RelyingPartyAccessCA()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading the relying party access CA: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
}

func (s *Server) handleRegistrarCA(w http.ResponseWriter, r *http.Request) {
	_, ca, err := s.wallet.RegistrarCA()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading the registrar CA: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
}

func writeCertificateExport(w http.ResponseWriter, r *http.Request, certPEM []byte) {
	switch r.URL.Query().Get("format") {
	case "", "pem":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(certPEM)
	case "jwks":
		jwks, err := keys.CertificatePEMToJWKS(certPEM)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "building JWKS: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: expected pem or jwks"})
	}
}

func (s *Server) currentStore() *WalletStore {
	return s.store.Load()
}

func parseTimeOrDuration(val string) (*time.Time, error) {
	if d, err := time.ParseDuration(val); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, fmt.Errorf("invalid nbf value %q: expected RFC3339 (e.g. 2025-01-15T00:00:00Z) or duration (e.g. -1h)", val)
	}
	return &t, nil
}
