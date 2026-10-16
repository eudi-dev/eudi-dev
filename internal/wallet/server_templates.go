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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// Include claims so clients can populate issuance forms without another request.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.management().Templates()
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, templates)
}

// Accept only a bare name. credtemplate.Load also accepts paths for the CLI. Through
// this endpoint a path would allow arbitrary file reads.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !credtemplate.IsBareName(name) {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("invalid template name %q", name))
		return
	}

	tpl, err := s.management().Template(name)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, tpl)
}

// handleTemplateDisplayImage serves the logo or background image of a
// template, so the issue dialog can show the template's art.
func (s *Server) handleTemplateDisplayImage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !credtemplate.IsBareName(name) {
		http.NotFound(w, r)
		return
	}
	tpl, err := s.management().Template(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ServeTemplateImage(w, r, tpl.Display, r.PathValue("field"))
}

// templateSaveRequest is a template document. With catalog set, the template
// is also added to the attestation catalogue as a new entry.
type templateSaveRequest struct {
	credtemplate.Template
	Catalog *registrar.CatalogAttestation `json:"catalog,omitempty"`
}

// The URL name overrides the name in the document.
func (s *Server) handlePutTemplate(w http.ResponseWriter, r *http.Request) {
	var req templateSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, "parsing request body: "+err.Error())
		return
	}
	tpl := req.Template
	tpl.Name = strings.TrimSpace(r.PathValue("name"))
	if !credtemplate.IsBareName(tpl.Name) {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("invalid template name %q", tpl.Name))
		return
	}
	if _, err := s.management().SaveTemplate(tpl, req.Catalog); err != nil {
		if status := visitorLimitStatus(err, 0); status != 0 {
			apierror.WriteStatusErr(w, status, err)
			return
		}
		registrar.WriteCatalogError(w, err)
		return
	}
	s.templatesChanged()
	saved, err := s.management().Template(tpl.Name)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// Deleting an override restores the bundled template. Bundled templates themselves
// cannot be deleted.
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if !credtemplate.IsBareName(r.PathValue("name")) {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("invalid template name %q", r.PathValue("name")))
		return
	}
	if err := s.management().DeleteTemplate(r.PathValue("name")); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, credtemplate.ErrNotFound) {
			status = http.StatusNotFound
		}
		status = visitorLimitStatus(err, status)
		apierror.WriteStatusErr(w, status, err)
		return
	}
	s.templatesChanged()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": r.PathValue("name")})
}

// templatesChanged lets the demo registrations follow the templates.
func (s *Server) templatesChanged() {
	if err := s.syncDemoRegistrations(); err != nil {
		s.log("  WARNING: updating the demo registrations: %v", err)
	}
}
