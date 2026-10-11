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
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/publicpath"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustedlists"
)

func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if _, chain := s.wallet.certificateAuthority(); len(chain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := s.wallet.TrustedLists().FindGroup("", r.URL.Query().Get("vct"), r.URL.Query().Get("doctype"))
	if !ok {
		http.Error(w, "wallet has no matching trusted list", http.StatusNotFound)
		return
	}
	// The selected list is the same instance as /api/trustlists/{id}.
	jwt, err := s.wallet.TrustedLists().SignedGroupList(s.wallet.IssuerURL, group, registrar.TrustListPath(group.ID))
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trusted list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt)) //nolint:gosec // G705: the query only selects one of the wallet's lists, served as application/jwt.
}

func (s *Server) handleTrustListIndex(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(strings.TrimSpace(s.wallet.IssuerURL), "/")
	entries := s.wallet.TrustedLists().IndexEntries(issuer)
	for i := range entries {
		entries[i].Path = publicpath.Prefix(r) + entries[i].Path
	}
	writeJSON(w, http.StatusOK, map[string]any{"trust_lists": entries})
}

func (s *Server) handleTrustListByID(w http.ResponseWriter, r *http.Request) {
	if _, chain := s.wallet.certificateAuthority(); len(chain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	if r.PathValue("id") == trustedlists.ListOfListsID {
		jwt, err := s.wallet.TrustedLists().ListOfLists(s.wallet.IssuerURL)
		if err != nil {
			http.Error(w, fmt.Sprintf("generating the list of trusted lists: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(jwt))
		return
	}
	group, ok := s.wallet.TrustedLists().FindGroup(r.PathValue("id"), "", "")
	if !ok {
		http.Error(w, "trusted list not found", http.StatusNotFound)
		return
	}
	jwt, err := s.wallet.TrustedLists().SignedGroupList(s.wallet.IssuerURL, group, registrar.TrustListPath(group.ID))
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trusted list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleTrustListHistory(w http.ResponseWriter, r *http.Request) {
	group, ok := s.wallet.TrustedLists().FindGroup(r.PathValue("id"), "", "")
	if !ok {
		http.NotFound(w, r)
		return
	}
	listPath := registrar.TrustListPath(group.ID)
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if _, err := s.wallet.TrustedLists().SignedGroupList(issuer, group, listPath); err != nil {
		http.Error(w, "loading trusted list history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	store := s.wallet.providerKeys()
	if raw := r.PathValue("sequence"); raw != "" {
		sequence, err := strconv.Atoi(raw)
		if err != nil || sequence < 1 {
			http.NotFound(w, r)
			return
		}
		jwt, err := store.TrustListHistory(issuer, listPath, sequence)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.NotFound(w, r)
			} else {
				http.Error(w, "loading trusted list history: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write(jwt)
		return
	}
	sequences, err := store.TrustListSequences(issuer, listPath)
	if err != nil {
		http.Error(w, "loading trusted list history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type instance struct {
		Sequence int    `json:"sequence"`
		URL      string `json:"url"`
	}
	instances := make([]instance, 0, len(sequences))
	for _, sequence := range sequences {
		instances = append(instances, instance{Sequence: sequence, URL: issuer + listPath + "/history/" + strconv.Itoa(sequence)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": instances})
}

func (s *Server) handleJWTVCIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	keys := issuerSigningJWKs(s.wallet, s.signingKeyExpiry())
	if len(keys) == 0 {
		http.Error(w, "wallet has no issuer signing key", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": issuer,
		"jwks":   map[string]any{"keys": keys},
	})
}

// OpenID4VCI 1.0 §12.2.2 requires unsigned JSON metadata and permits signed JWT
// metadata. Serve the signed form when Accept prefers application/jwt.
func (s *Server) handleOpenIDCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if !PrefersSignedIssuerMetadata(r.Header.Get("Accept")) {
		metadata, err := buildOpenIDCredentialIssuerMetadata(s.wallet, issuer)
		if err != nil {
			http.Error(w, "building issuer metadata: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, metadata)
		return
	}
	if _, chain := s.wallet.certificateAuthority(); len(chain) == 0 {
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

// PrefersSignedIssuerMetadata reports whether Accept ranks application/jwt
// above application/json. OpenID4VCI 1.0 §12.2.2 recommends answering with the
// requested content type. With equal preference the issuer answers with the
// unsigned form, which it must always support.
func PrefersSignedIssuerMetadata(accept string) bool {
	jwt, json := 0.0, 0.0
	for _, entry := range strings.Split(accept, ",") {
		params := strings.Split(entry, ";")
		mediaType := strings.ToLower(strings.TrimSpace(params[0]))
		q := 1.0
		for _, param := range params[1:] {
			name, value, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.EqualFold(name, "q") {
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
					q = parsed
				}
			}
		}
		switch mediaType {
		case "application/jwt":
			jwt = max(jwt, q)
		case "application/json", "application/*", "*/*":
			json = max(json, q)
		}
	}
	return jwt > 0 && jwt > json
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
	signingKey, certChain, err := s.wallet.Signer().StatusList()
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
	caKey, chain := s.wallet.certificateAuthority()
	if caKey == nil || len(chain) == 0 {
		http.Error(w, "wallet has no CA certificate", http.StatusInternalServerError)
		return
	}
	caCert := chain[len(chain)-1]
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		NextUpdate: now.Add(crlUpdateInterval),
	}, caCert, caKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating certificate revocation list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(der)
}
