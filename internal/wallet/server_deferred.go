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
	"net/http"
)

func (s *Server) handleListDeferred(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.management().DeferredIssuances())
}

func (s *Server) handleCollectDeferred(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	attempt, ok := s.CollectDeferredNow(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no deferred issuance with that id"})
		return
	}
	out := map[string]any{
		"collected": attempt.Collected,
		"pending":   attempt.Pending,
		"abandoned": attempt.Abandoned,
	}
	if attempt.Credential != nil {
		out["credential_id"] = attempt.Credential.ID
		out["format"] = attempt.Credential.Format
	}
	if attempt.Pending {
		out["next_attempt_at"] = attempt.NextAttemptAt
		out["interval"] = attempt.Interval
	}
	if attempt.Reason != "" {
		out["reason"] = attempt.Reason
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAbandonDeferred(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.AbandonDeferredNow(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no deferred issuance with that id"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"abandoned":      true,
		"issuer":         pending.Issuer,
		"transaction_id": pending.TransactionID,
	})
}
