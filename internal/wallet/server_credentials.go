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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/httpsec"
)

// An asset: reference loads an image from storage. Newly issued credentials can still
// contain an embedded data URI.
func (s *Server) resolveDisplayImage(uri string) (contentType string, data []byte, ok bool) {
	if strings.HasPrefix(uri, "asset:") {
		store := s.store.Load()
		if store == nil {
			return "", nil, false
		}
		return store.ReadDisplayAsset(uri)
	}
	return dataURIImage(uri)
}

// A credentials file entry keeps its ID across restarts while its image can
// change, so the browser revalidates every image with its content ETag.
func (s *Server) handleCredentialDisplayImage(w http.ResponseWriter, r *http.Request) {
	cred, ok := s.wallet.GetCredential(r.PathValue("id"))
	if !ok || cred.Display == nil {
		http.NotFound(w, r)
		return
	}
	var uri string
	switch r.PathValue("kind") {
	case "logo":
		uri = cred.Display.LogoURI
	case "background":
		uri = cred.Display.BackgroundURI
	default:
		http.NotFound(w, r)
		return
	}
	contentType, data, ok := s.resolveDisplayImage(uri)
	if !ok {
		http.NotFound(w, r)
		return
	}
	httpsec.ServeImage(w, r, contentType, data)
}

// Returns an array. X-Total-Count gives the total before applying limit and offset.
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit: " + err.Error()})
		return
	}
	offset, err := intParam(r, "offset", 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid offset: " + err.Error()})
		return
	}

	listing, total := s.management().CredentialListing(offset, limit)
	for _, summary := range listing {
		withPublicImagePaths(r, summary)
	}
	data, err := json.Marshal(listing)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func intParam(r *http.Request, name string, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", raw)
	}
	if value < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return value, nil
}

func (s *Server) handleImportCredential(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	raw := strings.TrimSpace(string(body))
	if raw == "" {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	summary, err := s.management().ImportCredential(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, withPublicImagePaths(r, summary))
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	switch err := s.management().RemoveCredential(r.PathValue("id")); {
	case errors.Is(err, ErrCredentialProtected):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrCredentialNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleSetCredentialStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	entry, err := s.management().SetCredentialStatus(r.PathValue("id"), body.Status)
	switch {
	case errors.Is(err, ErrStatusProtected):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrInvalidStatus):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrNoStatusEntry):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusOK, entry)
	}
}

func (s *Server) handleRenewCredential(w http.ResponseWriter, r *http.Request) {
	renewed, err := s.RenewCredential(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, withPublicImagePaths(r, CredentialSummary(*renewed)))
}
