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
	"encoding/json"
	"errors"
	"net/http"

	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

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
	case errors.Is(err, trustedlists.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, trustedlists.ErrFull):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
