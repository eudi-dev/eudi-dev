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
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
)

// transactionTemplateView is a template with the TS12 findings of its entry.
// A template may break TS12 on purpose, to test how a wallet refuses it.
type transactionTemplateView struct {
	txtemplate.Template
	Warnings []string `json:"warnings,omitempty"`
}

func newTransactionTemplateView(tpl txtemplate.Template) transactionTemplateView {
	return transactionTemplateView{Template: tpl, Warnings: oid4vp.TS12Findings(tpl.TransactionData).Texts()}
}

func (s *Server) handleListTransactionTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.management().TransactionTemplates()
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]transactionTemplateView, len(templates))
	for i, tpl := range templates {
		views[i] = newTransactionTemplateView(tpl)
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleGetTransactionTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !credtemplate.IsBareName(name) {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("invalid transaction template name %q", name))
		return
	}
	tpl, err := s.management().TransactionTemplate(name)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, newTransactionTemplateView(tpl))
}

// The URL name overrides the name in the document.
func (s *Server) handlePutTransactionTemplate(w http.ResponseWriter, r *http.Request) {
	var tpl txtemplate.Template
	if err := json.NewDecoder(r.Body).Decode(&tpl); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, "parsing request body: "+err.Error())
		return
	}
	tpl.Name = strings.TrimSpace(r.PathValue("name"))
	if err := s.management().SaveTransactionTemplate(tpl); err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, txtemplate.ErrConfigured):
			status = http.StatusConflict
		case credtemplate.IsStorageError(err):
			status = http.StatusInternalServerError
		}
		apierror.WriteStatusErr(w, visitorLimitStatus(err, status), err)
		return
	}
	saved, err := s.management().TransactionTemplate(tpl.Name)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, newTransactionTemplateView(saved))
}

// Deleting an override restores the predefined template.
func (s *Server) handleDeleteTransactionTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.management().DeleteTransactionTemplate(name); err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, txtemplate.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, txtemplate.ErrConfigured):
			status = http.StatusConflict
		case credtemplate.IsStorageError(err):
			status = http.StatusInternalServerError
		}
		apierror.WriteStatusErr(w, visitorLimitStatus(err, status), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

// handleListTransactionDataTypes lists the TS12 types and the types from
// --transaction-data-type.
func (s *Server) handleListTransactionDataTypes(w http.ResponseWriter, r *http.Request) {
	list, err := s.wallet.AcceptedTransactionDataTypes()
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}
