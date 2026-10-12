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

// User templates are stored under templates/ in the wallet directory. PUT accepts a
// complete document, including templates shared by other users.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
)

// Include claims so clients can populate issuance forms without another request.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := credtemplate.List(s.wallet.Templates)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, templates)
}

// Accept only a bare name. credtemplate.Load also accepts paths for the CLI. Through
// this endpoint a path would allow arbitrary file reads.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid template name %q", name)})
		return
	}

	tpl, err := credtemplate.Load(name, s.wallet.Templates)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, tpl)
}

// The URL name overrides the name in the document.
func (s *Server) handlePutTemplate(w http.ResponseWriter, r *http.Request) {
	var tpl credtemplate.Template
	if err := json.NewDecoder(r.Body).Decode(&tpl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}
	tpl.Name = strings.TrimSpace(r.PathValue("name"))
	if _, err := credtemplate.Save(s.wallet.Templates, tpl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	saved, err := credtemplate.Load(tpl.Name, s.wallet.Templates)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// Deleting an override restores the bundled template. Bundled templates themselves
// cannot be deleted.
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if err := credtemplate.Delete(s.wallet.Templates, r.PathValue("name")); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": r.PathValue("name")})
}
