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

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/publicpath"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
)

func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := FindTrustListGroupForWallet(s.wallet, "", r.URL.Query().Get("vct"), r.URL.Query().Get("doctype"))
	if !ok {
		http.Error(w, "wallet has no matching trust list", http.StatusNotFound)
		return
	}
	jwt, err := GenerateTrustListJWTForWalletGroup(s.wallet, s.wallet.IssuerURL, group, "/api/trustlist")
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleTrustListIndex(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(strings.TrimSpace(s.wallet.IssuerURL), "/")
	entries := BuildTrustListIndexEntries(s.wallet, issuer)
	for i := range entries {
		entries[i].Path = publicpath.Prefix(r) + entries[i].Path
	}
	writeJSON(w, http.StatusOK, map[string]any{"trust_lists": entries})
}

func (s *Server) handleTrustListByID(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := FindTrustListGroupForWallet(s.wallet, r.PathValue("id"), "", "")
	if !ok {
		http.Error(w, "trust list not found", http.StatusNotFound)
		return
	}
	jwt, err := GenerateTrustListJWTForWalletGroup(s.wallet, s.wallet.IssuerURL, group, "/api/trustlists/"+group.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleTrustListHistory(w http.ResponseWriter, r *http.Request) {
	group, ok := FindTrustListGroupForWallet(s.wallet, r.PathValue("id"), "", "")
	if !ok {
		http.NotFound(w, r)
		return
	}
	listPath := "/api/trustlist"
	if r.PathValue("id") != "" {
		listPath = "/api/trustlists/" + group.ID
	}
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if _, err := GenerateTrustListJWTForWalletGroup(s.wallet, issuer, group, listPath); err != nil {
		http.Error(w, "loading trust list history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	store := s.wallet.signingStore()
	dir := path.Join(store.trustListDir(issuer, listPath), "history")
	if raw := r.PathValue("sequence"); raw != "" {
		sequence, err := strconv.Atoi(raw)
		if err != nil || sequence < 1 {
			http.NotFound(w, r)
			return
		}
		jwt, err := store.backend.Read(path.Join(dir, strconv.Itoa(sequence)+".jwt"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.NotFound(w, r)
			} else {
				http.Error(w, "loading trust list history: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write(jwt)
		return
	}
	files, err := store.backend.List(dir)
	if err != nil {
		http.Error(w, "loading trust list history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type instance struct {
		Sequence int    `json:"sequence"`
		URL      string `json:"url"`
	}
	instances := make([]instance, 0, len(files))
	for _, file := range files {
		sequence, err := strconv.Atoi(strings.TrimSuffix(file, ".jwt"))
		if err == nil {
			instances = append(instances, instance{Sequence: sequence, URL: issuer + listPath + "/history/" + strconv.Itoa(sequence)})
		}
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].Sequence < instances[j].Sequence })
	writeJSON(w, http.StatusOK, map[string]any{"instances": instances})
}

func (s *Server) handleJWTVCIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	jwk := buildIssuerSigningJWK(s.wallet, s.signingKeyExpiry())
	if jwk == nil {
		http.Error(w, "wallet has no issuer signing key", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": issuer,
		"jwks": map[string]any{
			"keys": []any{jwk},
		},
	})
}

// OpenID4VCI 1.0 §12.2.2 requires unsigned JSON metadata and permits signed JWT
// metadata. Serve the signed form only when Accept requests application/jwt
// exclusively.
func (s *Server) handleOpenIDCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if !AcceptsOnlySignedIssuerMetadata(r.Header.Get("Accept")) {
		metadata, err := buildOpenIDCredentialIssuerMetadata(s.wallet, issuer)
		if err != nil {
			http.Error(w, "building issuer metadata: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, metadata)
		return
	}
	if len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no issuer certificate chain", http.StatusInternalServerError)
		return
	}
	jwt, err := signCredentialIssuerMetadataJWT(s.wallet, issuer, s.signingKeyExpiry())
	if err != nil {
		http.Error(w, fmt.Sprintf("signing issuer metadata: %v", err), http.StatusInternalServerError)
		return
	}
	// §12.2.2 gives application/jwt as the media type of the signed form. The
	// typ header inside it is openidvci-issuer-metadata+jwt (§12.2.3).
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

// AcceptsOnlySignedIssuerMetadata preserves unsigned discovery when JSON is accepted
// as OpenID4VCI 1.0 §12.2.2 requires.
func AcceptsOnlySignedIssuerMetadata(accept string) bool {
	wantsJWT := false
	for _, entry := range strings.Split(accept, ",") {
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(entry, ";")[0]))
		switch mediaType {
		case "":
		case "application/jwt":
			wantsJWT = true
		default:
			return false
		}
	}
	return wantsJWT
}

func (s *Server) handleRegistrarWRPList(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no registrar signing material", http.StatusInternalServerError)
		return
	}
	registrarKey, registrarChain, err := s.wallet.RegistrarSigningMaterial()
	if err != nil {
		http.Error(w, "loading registrar signer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	record := buildRegistrarDataset(s.wallet, issuer)
	if !matchesRegistrarQuery(record, r) {
		recordJWT, err := signRegistrarResponseJWT(registrarKey, registrarChain, []RegistrarDataset{})
		if err != nil {
			http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(recordJWT))
		return
	}
	recordJWT, err := signRegistrarResponseJWT(registrarKey, registrarChain, []RegistrarDataset{record})
	if err != nil {
		http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(recordJWT))
}

func (s *Server) handleRegistrarWRPByIdentifier(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no registrar signing material", http.StatusInternalServerError)
		return
	}
	registrarKey, registrarChain, err := s.wallet.RegistrarSigningMaterial()
	if err != nil {
		http.Error(w, "loading registrar signer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	record := buildRegistrarDataset(s.wallet, issuer)
	identifier := strings.TrimSpace(r.PathValue("identifier"))
	if identifier == "" || !recordHasIdentifier(record, identifier) {
		http.Error(w, "wallet relying party not found", http.StatusNotFound)
		return
	}
	recordJWT, err := signRegistrarResponseJWT(registrarKey, registrarChain, record)
	if err != nil {
		http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(recordJWT))
}

func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	// draft-ietf-oauth-status-list §8.1 recommends CORS so browser clients can read
	// status lists. GET with an Accept header needs no preflight.
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// §8.4 defines the time parameter for historical resolution: "If the
	// Server does not support the additional query parameter, it SHOULD return
	// a status code of 501 (Not Implemented)". This wallet keeps no history.
	if r.URL.Query().Has("time") {
		http.Error(w, "historical status list resolution (the time query parameter) is not implemented", http.StatusNotImplemented)
		return
	}

	bits, bitstring := s.wallet.BuildStatusList()
	signingKey, certChain, err := s.wallet.StatusListSigningMaterial()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading status list signing material: %v", err), http.StatusInternalServerError)
		return
	}
	cfg := statuslist.StatusListConfig{
		URI:       s.wallet.StatusListURL(),
		Issuer:    s.wallet.StatusListIssuer(),
		Bits:      bits,
		CertChain: certChain,
	}

	if statuslist.NegotiateMediaType(r.Header.Get("Accept")) == statuslist.MediaTypeCWT {
		token, err := statuslist.GenerateStatusListCWT(bitstring, signingKey, cfg)
		if err != nil {
			http.Error(w, fmt.Sprintf("generating status list: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", statuslist.MediaTypeCWT)
		w.Write(token)
		return
	}

	jwt, err := statuslist.GenerateStatusListJWT(bitstring, signingKey, cfg)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating status list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", statuslist.MediaTypeJWT)
	w.Write([]byte(jwt))
}

// Generated signing certificates reference this CRL (ISO/IEC 18013-5 Table B.3). The
// wallet does not revoke certificates, so it signs an empty list. Credential
// revocation uses the status list.
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	s.wallet.mu.RLock()
	caKey := s.wallet.CAKey
	chain := append([]*x509.Certificate(nil), s.wallet.CertChain...)
	s.wallet.mu.RUnlock()
	if caKey == nil || len(chain) == 0 {
		http.Error(w, "wallet has no CA certificate", http.StatusInternalServerError)
		return
	}
	caCert := chain[len(chain)-1]
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
	}, caCert, caKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating certificate revocation list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(der)
}

func matchesRegistrarQuery(record RegistrarDataset, r *http.Request) bool {
	q := r.URL.Query()
	if identifier := strings.TrimSpace(q.Get("identifier")); identifier != "" && !recordHasIdentifier(record, identifier) {
		return false
	}
	if entitlement := strings.TrimSpace(q.Get("entitlement")); entitlement != "" {
		match := false
		for _, candidate := range record.Entitlements {
			if candidate == entitlement {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if provides := strings.TrimSpace(q.Get("providesattestation")); provides != "" && !recordProvidesAttestation(record, provides) {
		return false
	}
	return true
}

func recordHasIdentifier(record RegistrarDataset, value string) bool {
	for _, identifier := range record.Identifier {
		if strings.TrimSpace(identifier.Identifier) == value {
			return true
		}
	}
	return false
}

func recordProvidesAttestation(record RegistrarDataset, value string) bool {
	for _, att := range record.ProvidesAttestations {
		switch att.Format {
		case "dc+sd-jwt":
			raw, ok := att.Meta["vct_values"].([]string)
			if ok {
				for _, candidate := range raw {
					if candidate == value {
						return true
					}
				}
			}
			if rawAny, ok := att.Meta["vct_values"].([]any); ok {
				for _, candidate := range rawAny {
					if s, ok := candidate.(string); ok && s == value {
						return true
					}
				}
			}
		case "mso_mdoc":
			if candidate, _ := att.Meta["doctype_value"].(string); candidate == value {
				return true
			}
		}
	}
	return false
}
