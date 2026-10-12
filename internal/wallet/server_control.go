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

	"github.com/eudi-dev/eudi-dev/v2/internal/news"
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

// handleReady lists the wallet's keys, which needs a working storage backend
// (a reachable database on the postgres backend).
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

// The entity backend's clear marker also removes entries appended by other servers.
func (s *Server) handleClearLog(w http.ResponseWriter, r *http.Request) {
	if store := s.store.Load(); store != nil && store.entityMode() {
		if err := store.writeLogCleanMarker(time.Now()); err != nil {
			s.log("  ERROR: clearing the stored log: %v", err)
		}
	}
	s.wallet.ClearLog()
	s.triggerSave()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLastError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Vary", "Cookie, "+OwnerHeader)
	err := s.wallet.PeekLastError(callerOwners(r))
	if err == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, err)
}

func (s *Server) handleClearLastError(w http.ResponseWriter, r *http.Request) {
	s.wallet.ClearLastError(callerOwners(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	walletDir, storageKind, seeded := "", "", false
	if store := s.currentStore(); store != nil {
		walletDir = store.Dir
		storageKind = store.Backend().Kind()
		seeded = store.Seeded()
	}
	templatesDir := s.wallet.Templates.String()
	// Read conformance settings together under the lock because PUT
	// /api/config/conformance can change them concurrently.
	mode, requireHAIP, requireEncrypted := s.wallet.ConformanceSettings()
	config := map[string]any{
		"port":                  s.port,
		"build_id":              processBuildID(),
		"storage":               storageKind,
		"seeded_keys":           seeded,
		"version":               s.version,
		"imprint":               len(s.imprintHTML) > 0,
		"news_id":               s.newsID(),
		"base_url":              s.wallet.BaseURL,
		"issuer_url":            s.wallet.IssuerURL,
		"status_list_url":       s.wallet.StatusListURL(),
		"preferred_format":      s.wallet.PreferredFormat,
		"key_attestation_level": s.wallet.KeyAttestationLevelSetting(),
		"tls_verify":            s.wallet.TLSVerification(),
		"tls_verify_override":   s.wallet.TLSVerificationOverride(),
		"validation_mode":       string(mode),
		"vci_version":           string(s.wallet.VCIFeatureVersion()),
		"auto_accept":           s.wallet.AutoAccept,
		"session_transcript":    string(s.wallet.SessionTranscript),
		"require_haip":          requireHAIP,
		// Report issuance and presentation settings separately even though they use
		// the same flag.
		"require_haip_issuance":     requireHAIP,
		"require_encrypted_request": requireEncrypted,
		"force_client_attestation":  s.wallet.ForceClientAttestation,
		"adhoc_display_images":      s.wallet.AdhocDisplayImages,
		"credential_count":          len(s.wallet.GetCredentials()),
		// False when an external TLS terminator serves the issuer URL. In that case
		// the built-in listener and its certificate are unused.
		"tls_listener": s.issuerPort > 0,
	}
	if demo := s.demoConfig(); demo != nil {
		config["demo"] = demo
	} else {
		// Demo visitors do not need the host's filesystem paths or process ID.
		config["pid"] = os.Getpid()
		config["wallet_dir"] = walletDir
		config["templates_dir"] = templatesDir
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
	var body NextErrorOverride
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.SetNextError(&body)
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleClearNextError(w http.ResponseWriter, r *http.Request) {
	s.wallet.SetNextError(nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetPreferredFormat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.mu.Lock()
	s.wallet.PreferredFormat = body.Format
	s.wallet.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"format": body.Format})
}

// Runtime auto-accept applies to every flow until restart. Demo mode fixes its consent
// settings and rejects this change.
func (s *Server) handleSetAutoAccept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.mu.Lock()
	s.wallet.AutoAccept = body.Enabled
	s.wallet.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"auto_accept": body.Enabled})
}

// Runtime conformance settings apply to every flow using this server. Demo mode keeps
// HAIP with debug validation and rejects changes.
func (s *Server) handleSetConformance(w http.ResponseWriter, r *http.Request) {
	if s.demo != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "conformance settings are fixed in public demo mode (run the wallet locally to change them)"})
		return
	}
	var body struct {
		TLSVerify           json.RawMessage `json:"tls_verify,omitempty"`
		Mode                *string         `json:"mode,omitempty"`
		HAIP                *bool           `json:"haip,omitempty"`
		Encrypted           *bool           `json:"encrypted,omitempty"`
		VCIVersion          *string         `json:"vci_version,omitempty"`
		KeyAttestationLevel *string         `json:"key_attestation_level,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var tlsVerify *bool
	if len(body.TLSVerify) > 0 {
		if err := json.Unmarshal(body.TLSVerify, &tlsVerify); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls_verify must be true, false or null (mode default)"})
			return
		}
	}
	var mode ValidationMode
	if body.Mode != nil {
		parsed, err := ParseValidationMode(*body.Mode)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		mode = parsed
	}
	var vciVersion VCIVersion
	if body.VCIVersion != nil {
		parsed, err := ParseVCIVersion(*body.VCIVersion)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		vciVersion = parsed
	}
	var keyAttestationLevel string
	if body.KeyAttestationLevel != nil {
		parsed, err := ParseKeyAttestationLevel(*body.KeyAttestationLevel)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		keyAttestationLevel = parsed
	}
	s.wallet.mu.Lock()
	if len(body.TLSVerify) > 0 {
		s.wallet.tlsVerify = tlsVerify
	}
	if body.Mode != nil {
		s.wallet.ValidationMode = mode
	}
	if body.KeyAttestationLevel != nil {
		s.wallet.KeyAttestationLevel = keyAttestationLevel
	}
	if body.VCIVersion != nil {
		s.wallet.VCIVersion = vciVersion
	}
	if body.HAIP != nil {
		s.wallet.RequireHAIP = *body.HAIP
	}
	if body.Encrypted != nil {
		s.wallet.RequireEncryptedRequest = *body.Encrypted
	}
	s.wallet.mu.Unlock()
	s.writeConformanceConfig(w)
}

// Demo mode rejects changes to conformance settings, including resets.
func (s *Server) handleResetConformance(w http.ResponseWriter, r *http.Request) {
	if s.demo != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "conformance settings are fixed in public demo mode"})
		return
	}
	s.wallet.mu.Lock()
	s.wallet.tlsVerify = s.defaultTLSVerify
	s.wallet.ValidationMode = s.defaultValidationMode
	s.wallet.RequireHAIP = s.defaultRequireHAIP
	s.wallet.RequireEncryptedRequest = s.defaultRequireEncryptedRequest
	s.wallet.VCIVersion = s.defaultVCIVersion
	s.wallet.KeyAttestationLevel = s.defaultKeyAttestationLevel
	s.wallet.mu.Unlock()
	s.writeConformanceConfig(w)
}

func (s *Server) writeConformanceConfig(w http.ResponseWriter) {
	// The lock is already held. Calling a locking accessor here would deadlock because
	// RWMutex is not reentrant.
	s.wallet.mu.RLock()
	vciVersion := s.wallet.VCIVersion
	if vciVersion == "" {
		vciVersion = VCIVersion10
	}
	resp := map[string]any{
		"tls_verify":                s.wallet.tlsVerificationLocked(),
		"tls_verify_override":       s.wallet.tlsVerify,
		"validation_mode":           string(s.wallet.ValidationMode),
		"require_haip":              s.wallet.RequireHAIP,
		"require_encrypted_request": s.wallet.RequireEncryptedRequest,
		"vci_version":               string(vciVersion),
		"key_attestation_level":     s.wallet.KeyAttestationLevel,
	}
	s.wallet.mu.RUnlock()
	writeJSON(w, http.StatusOK, resp)
}
