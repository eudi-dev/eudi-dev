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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
)

// TrustedListState is the answer to GET /api/trust: the providers added to the
// wallet's lists, and the external lists on its list of trusted lists.
type TrustedListState struct {
	Entities []TrustedEntity `json:"entities"`
	// EntityLists are the lists that take entities.
	EntityLists []string          `json:"entity_lists"`
	Lists       []TrustedListLink `json:"lists"`
	// ListsURL is the wallet's list of trusted lists.
	ListsURL string `json:"lists_url"`
	// RelyingPartyCAs and TrustedListCAs are the base64 DER certificates of
	// --relying-party-ca and --trusted-list-ca.
	RelyingPartyCAs []string `json:"relying_party_cas,omitempty"`
	TrustedListCAs  []string `json:"trusted_list_cas,omitempty"`
}

// TrustedListLink is an external list. Configured comes from --trusted-list
// and can't be removed through the API. Error says why the wallet can't use
// the list. Via names the list of trusted lists that points to it.
type TrustedListLink struct {
	URL        string `json:"url"`
	Configured bool   `json:"configured,omitempty"`
	Via        string `json:"via,omitempty"`
	Error      string `json:"error,omitempty"`
}

// TrustState describes the wallet's trusted lists for the API.
func (w *Wallet) TrustState() TrustedListState {
	w.mu.RLock()
	configured := slices.Clone(w.ConfiguredTrustedListURLs)
	relyingPartyCAs, trustedListCAs := w.RelyingPartyCAPEM, w.TrustListCAPEM
	w.mu.RUnlock()
	state := TrustedListState{
		Entities:        w.ListTrustedEntities(),
		EntityLists:     TrustedEntityLists(),
		ListsURL:        w.ownTrustListURL(listOfListsID),
		RelyingPartyCAs: base64Certificates(relyingPartyCAs),
		TrustedListCAs:  base64Certificates(trustedListCAs),
	}
	if state.Entities == nil {
		state.Entities = []TrustedEntity{}
	}
	state.Lists = []TrustedListLink{}
	external := w.ExternalTrustedLists()
	for _, tl := range w.trustedLists() {
		if tl.Via == "" && !slices.Contains(external, tl.URL) {
			continue
		}
		link := TrustedListLink{URL: tl.URL, Configured: slices.Contains(configured, tl.URL), Via: tl.Via}
		if tl.Err != nil {
			link.Error = tl.Err.Error()
		}
		state.Lists = append(state.Lists, link)
	}
	return state
}

func base64Certificates(bundle []byte) []string {
	certs, err := keys.ParseCertificatesPEM(bundle)
	if err != nil {
		return nil
	}
	out := make([]string, len(certs))
	for i, cert := range certs {
		out[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return out
}

func (s *Server) handleTrustState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.management().TrustState())
}

func (s *Server) handleAddTrustedEntity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		List         string `json:"list"`
		Name         string `json:"name"`
		Certificates string `json:"certificates"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	entity, err := s.management().AddTrustedEntity(body.List, body.Name, body.Certificates)
	if err != nil {
		writeTrustResult(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, entity)
}

func (s *Server) handleRemoveTrustedEntity(w http.ResponseWriter, r *http.Request) {
	writeTrustResult(w, s.management().RemoveTrustedEntity(r.PathValue("id")))
}

func (s *Server) handleAddTrustedList(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	added, err := s.management().AddTrustedList(body.URL)
	if err != nil {
		writeTrustResult(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, added)
}

func (s *Server) handleRemoveTrustedList(w http.ResponseWriter, r *http.Request) {
	writeTrustResult(w, s.management().RemoveTrustedList(r.URL.Query().Get("url")))
}

func writeTrustResult(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTrustNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrTrustFull):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
