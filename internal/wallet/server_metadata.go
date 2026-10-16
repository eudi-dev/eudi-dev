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
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/publicpath"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if _, chain := s.wallet.certificateAuthority(); len(chain) < 2 {
		apierror.WriteStatus(w, http.StatusInternalServerError, "wallet has no CA certificate chain")
		return
	}
	group, ok := s.wallet.TrustedLists().FindGroup("", r.URL.Query().Get("vct"), r.URL.Query().Get("doctype"))
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "wallet has no matching trusted list")
		return
	}
	// The selected list is the same instance as /api/trustlists/{id}.
	jwt, err := s.wallet.TrustedLists().SignedGroupList(s.wallet.IssuerURL, group, provider.TrustedListPath(group.ID))
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("generating trusted list: %v", err))
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
		apierror.WriteStatus(w, http.StatusInternalServerError, "wallet has no CA certificate chain")
		return
	}
	if r.PathValue("id") == trustedlists.ListOfListsID {
		jwt, err := s.wallet.TrustedLists().ListOfLists(s.wallet.IssuerURL)
		if err != nil {
			apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("generating the list of trusted lists: %v", err))
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(jwt))
		return
	}
	group, ok := s.wallet.TrustedLists().FindGroup(r.PathValue("id"), "", "")
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "trusted list not found")
		return
	}
	jwt, err := s.wallet.TrustedLists().SignedGroupList(s.wallet.IssuerURL, group, provider.TrustedListPath(group.ID))
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("generating trusted list: %v", err))
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
	listPath := provider.TrustedListPath(group.ID)
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if _, err := s.wallet.TrustedLists().SignedGroupList(issuer, group, listPath); err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "loading trusted list history: "+err.Error())
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
				apierror.WriteStatus(w, http.StatusInternalServerError, "loading trusted list history: "+err.Error())
			}
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write(jwt)
		return
	}
	sequences, err := store.TrustListSequences(issuer, listPath)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "loading trusted list history: "+err.Error())
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
		apierror.WriteStatus(w, http.StatusNotFound, "wallet issuer URL is not configured")
		return
	}
	keys := issuerSigningJWKs(s.wallet, s.signingKeyExpiry())
	if len(keys) == 0 {
		apierror.WriteStatus(w, http.StatusInternalServerError, "wallet has no issuer signing key")
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
		apierror.WriteStatus(w, http.StatusNotFound, "wallet issuer URL is not configured")
		return
	}
	if !PrefersSignedIssuerMetadata(r.Header.Get("Accept")) {
		metadata, err := buildOpenIDCredentialIssuerMetadata(s.wallet, issuer)
		if err != nil {
			apierror.WriteStatus(w, http.StatusInternalServerError, "building issuer metadata: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, metadata)
		return
	}
	if _, chain := s.wallet.certificateAuthority(); len(chain) == 0 {
		apierror.WriteStatus(w, http.StatusInternalServerError, "wallet has no issuer certificate chain")
		return
	}
	jwt, err := signCredentialIssuerMetadataJWT(s.wallet, issuer, s.signingKeyExpiry())
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("signing issuer metadata: %v", err))
		return
	}
	// §12.2.2 gives application/jwt as the media type of the signed form. The
	// typ header inside it is openidvci-issuer-metadata+jwt (§12.2.3).
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

// PrefersSignedIssuerMetadata reports whether Accept ranks application/jwt
// above application/json. OpenID4VCI 1.0 §12.2.2 recommends answering with the
// requested content type. The unsigned form is mandatory, so it wins on equal
// preference.
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
		apierror.WriteStatus(w, http.StatusNotImplemented, "historical status list resolution (the time query parameter) is not implemented")
		return
	}

	bits, bitstring := s.wallet.BuildStatusList()
	signingKey, certChain, err := s.wallet.Signer().StatusList()
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("loading status list signing material: %v", err))
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
			apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("generating status list: %v", err))
			return
		}
		w.Header().Set("Content-Type", statuslist.MediaTypeCWT)
		w.Write(token)
		return
	}

	jwt, err := statuslist.GenerateStatusListJWT(bitstring, signingKey, cfg)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, fmt.Sprintf("generating status list: %v", err))
		return
	}
	w.Header().Set("Content-Type", statuslist.MediaTypeJWT)
	w.Write([]byte(jwt))
}
