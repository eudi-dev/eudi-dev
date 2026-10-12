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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/news"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// Hash the running executable once at startup. Comparing it with the file on disk
// detects a server running an older build.
var processBuildID = sync.OnceValue(func() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
})

// SetImprint advertises the configured page to the UI through the config endpoint.
func (s *Server) SetImprint(page []byte) {
	s.imprintHTML = page
}

// protectedRelyingParty reports whether visitors of the public demo may not
// change a registration. They share the demo issuer and verifier.
func (s *Server) protectedRelyingParty(rp registrar.WalletRelyingParty) bool {
	return s.demo != nil && (registrar.HasIdentifier(rp, demoIdentifier(demoIssuer)) || registrar.HasIdentifier(rp, demoIdentifier(demoVerifier)))
}

// protectedRelyingParties lists the registrations shown without actions in the
// UI, by their first identifier.
func (s *Server) protectedRelyingParties() []string {
	protected := []string{}
	for _, rp := range s.wallet.Registrar().RegisteredRelyingParties() {
		if s.protectedRelyingParty(rp) {
			protected = append(protected, rp.Identifier[0].Identifier)
		}
	}
	return protected
}

// SetNews makes the news of a public demo available to the UI.
func (s *Server) SetNews(n *news.News) {
	s.news = n
}

func (s *Server) newsID() string {
	if s.news == nil {
		return ""
	}
	return s.news.ID
}

func (s *Server) handleNews(w http.ResponseWriter, r *http.Request) {
	if s.news == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.news)
}

func (s *Server) handleImprint(w http.ResponseWriter, r *http.Request) {
	if len(s.imprintHTML) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.imprintHTML)
}

// RFC 9116 requires Expires to be less than a year away. Compute it per request.
// Security reports go to the project regardless of who hosts the wallet.
func handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Contact: https://github.com/eudi-dev/eudi-dev/issues\n"+
		"Policy: https://github.com/eudi-dev/eudi-dev/blob/main/SECURITY.md\n"+
		"Preferred-Languages: en, de\n"+
		"Expires: %s\n", time.Now().UTC().AddDate(0, 6, 0).Format(time.RFC3339))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"build_id": processBuildID(),
		"version":  s.version,
	}
	if s.demo == nil {
		doc["pid"] = os.Getpid()
	}
	writeJSON(w, http.StatusOK, doc)
}

// handleHealth answers as long as the process serves HTTP, so a liveness probe
// does not restart the server while its storage is unreachable.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady lists the wallet's keys. This needs a working storage backend (a
// reachable database on the postgres backend).
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if store := s.store.Load(); store != nil {
		if _, err := store.backend.List(store.prefix); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "storage: " + err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetVersion receives the release version from the serve command.
func (s *Server) SetVersion(version string) {
	s.version = version
}

// Demo responses include only recent log entries. maxLogEntries separately limits the
// stored log.
const demoLogLimit = 50

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	log := s.wallet.GetLog()
	if s.demo != nil && len(log) > demoLogLimit {
		log = log[len(log)-demoLogLimit:]
	}
	if r.URL.Query().Get("view") != "activity" {
		for i := range log {
			log[i].Payload = nil
		}
	}
	writeJSON(w, http.StatusOK, log)
}

func (s *Server) handleClearLog(w http.ResponseWriter, r *http.Request) {
	if err := s.management().ClearLog(); err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// showsError reports whether a browser sees an error. The flow's browser sees
// its own errors. An error of a flow without an owner is shown to everyone,
// except on a public demo, where its text could come from anyone.
func (s *Server) showsError(owners []string, err consent.Error) bool {
	if err.Owner == "" {
		return s.demo == nil
	}
	return consent.OwnedBy(owners, err.Owner)
}

func (s *Server) handleLastError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Vary", "Cookie, "+OwnerHeader)
	owners := callerOwners(r)
	err := s.wallet.Consents().PeekLastError(owners)
	if err == nil || !s.showsError(owners, *err) {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, err)
}

func (s *Server) handleClearLastError(w http.ResponseWriter, r *http.Request) {
	s.wallet.Consents().ClearLastError(callerOwners(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// formDefaults are the server's limits and defaults for the UI forms: the
// lengths of a credential display, the default country of a registration and
// the validity of certificates issued by the registrar.
func formDefaults() map[string]any {
	return map[string]any{
		"display_name_max":          maxDisplayNameRunes,
		"display_description_max":   maxDisplayDescriptionRunes,
		"display_alt_text_max":      maxDisplayAltTextRunes,
		"country":                   mock.DefaultCertificateCountry,
		"registration_validity":     registrar.Hours(registrar.DefaultRegistrationValidity),
		"registration_validity_max": registrar.Hours(registrar.MaxRegistrationValidity),
		"access_validity":           registrar.Hours(registrar.MaxAccessCertificateValidity),
		"access_validity_max":       registrar.Hours(registrar.MaxAccessCertificateValidity),
	}
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := s.management().Config()
	config["port"] = s.port
	config["build_id"] = processBuildID()
	config["version"] = s.version
	config["imprint"] = len(s.imprintHTML) > 0
	config["protected_relying_parties"] = s.protectedRelyingParties()
	config["news_id"] = s.newsID()
	// False when an external TLS terminator serves the issuer URL. In that case
	// the built-in listener and its certificate are unused.
	config["tls_listener"] = s.issuerPort > 0
	if demo := s.demoConfig(); demo != nil {
		config["demo"] = demo
		// Demo visitors do not need the host's filesystem paths.
		delete(config, "wallet_dir")
		delete(config, "templates_dir")
	} else {
		config["pid"] = os.Getpid()
	}
	writeJSON(w, http.StatusOK, config)
}

// Send the response before shutting down. This management endpoint has no
// authentication, like the rest of the testing API.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	s.log("  Shutdown requested via API")
	writeJSON(w, http.StatusOK, map[string]any{"shutting_down": true, "pid": os.Getpid()})
	go func() {
		time.Sleep(200 * time.Millisecond)
		if s.ShutdownFunc != nil {
			s.ShutdownFunc()
			return
		}
		os.Exit(0)
	}()
}

func (s *Server) handleSetNextError(w http.ResponseWriter, r *http.Request) {
	var body consent.NextErrorOverride
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.wallet.Consents().SetNextError(&body)
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleClearNextError(w http.ResponseWriter, r *http.Request) {
	s.wallet.Consents().SetNextError(nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetPreferredFormat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.wallet.SetPreferredFormat(body.Format); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"format": body.Format})
}

// Runtime auto-accept applies to every flow until restart. Demo mode fixes its consent
// settings and rejects this change.
func (s *Server) handleSetAutoAccept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.wallet.SetAutoAccept(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"auto_accept": body.Enabled})
}

// Runtime conformance settings apply to every flow using this server. Demo mode keeps
// HAIP with debug validation and rejects changes. An unknown member is refused,
// so a misspelled setting does not pass unnoticed.
func (s *Server) handleSetConformance(w http.ResponseWriter, r *http.Request) {
	var patch ConformancePatch
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&patch); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, "invalid conformance settings: "+err.Error())
		return
	}
	if err := s.wallet.UpdateConformance(patch); err != nil {
		apierror.WriteStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeConformanceConfig(w)
}

func (s *Server) handleResetConformance(w http.ResponseWriter, r *http.Request) {
	s.wallet.restoreConformance(s.defaultConformance)
	s.writeConformanceConfig(w)
}

func (s *Server) writeConformanceConfig(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, s.wallet.ConformanceDocument())
}
