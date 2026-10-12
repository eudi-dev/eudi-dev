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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/news"
	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v2/internal/publicpath"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
	"github.com/eudi-dev/eudi-dev/v2/internal/webui"
)

type Server struct {
	wallet           *Wallet
	port             int
	mux              *http.ServeMux
	onSave           func()
	onConsentRequest func(req *ConsentRequest)
	onUIRequest      func(requestID string)
	logFunc          func(format string, args ...any)
	httpSrv          *http.Server
	issuerSrv        *http.Server
	issuerTLSCert    *tls.Certificate
	issuerPort       int
	parseOpts        oid4vc.ParseOptions
	// routeRoots holds the first path segment of every route and static file.
	// CheckBasePath tests --base-url against it.
	routeRoots map[string]bool
	// Read store without storeSyncMu. The log sink runs inside mutations that
	// already hold it.
	store       atomic.Pointer[WalletStore]
	storeSyncMu sync.Mutex
	// Skip reparsing unchanged files. Periodic reloads also catch writes that leave
	// the same modification time and size on filesystems with coarse timestamps.
	// Guarded by storeSyncMu.
	lastWalletStamp storage.Stamp
	lastReloadAt    time.Time
	staleClientOnce sync.Once
	demo            *demoState
	renewalBackoff  map[string]time.Time
	renewalMu       sync.Mutex
	// Prevents the background poller and explicit collection requests from collecting
	// the same deferred credential concurrently.
	deferredInFlight map[string]bool
	deferredMu       sync.Mutex
	// Keeps the outcome of offers waiting for interactive sign-in so callers can
	// retrieve it.
	pendingOffers map[string]*pendingOffer
	offerMu       sync.Mutex
	// tlsMu guards issuerTLSCert, which a renewal replaces under a live
	// listener.
	tlsMu       sync.RWMutex
	version     string
	imprintHTML []byte
	news        *news.News
	// ShutdownFunc runs after POST /api/shutdown has responded. The serve command
	// sets it to deregister the instance and exit. When nil the process exits
	// directly.
	ShutdownFunc func()
	// DELETE /api/config/conformance restores these startup settings. Demo mode
	// disables that endpoint.
	defaultTLSVerify               *bool
	defaultValidationMode          ValidationMode
	defaultRequireHAIP             bool
	defaultRequireEncryptedRequest bool
	defaultVCIVersion              VCIVersion
	defaultKeyAttestationLevel     string
}

// NewServer calls onSave after operations that change credentials.
func NewServer(w *Wallet, port int, onSave func()) *Server {
	processBuildID()
	s := &Server{
		wallet:                         w,
		port:                           port,
		onSave:                         onSave,
		defaultTLSVerify:               w.tlsVerify,
		defaultValidationMode:          w.ValidationMode,
		defaultRequireHAIP:             w.RequireHAIP,
		defaultRequireEncryptedRequest: w.RequireEncryptedRequest,
		defaultVCIVersion:              w.VCIFeatureVersion(),
		defaultKeyAttestationLevel:     w.KeyAttestationLevelSetting(),
	}
	w.SetLogSink(func(entry LogEntry) {
		if store := s.store.Load(); store != nil && store.entityMode() {
			if err := store.appendLogEntry(w, entry); err != nil {
				s.log("  ERROR: saving log entry: %v", err)
			}
			w.NotifyStateChanged()
			return
		}
		s.triggerSave()
	})
	if p := parseIssuerPort(w.IssuerURL); p > 0 {
		s.issuerPort = p
	} else if port > 0 {
		s.issuerPort = port + 1
	}
	s.mux = http.NewServeMux()
	s.routeRoots = map[string]bool{}
	s.setupRoutes()
	// Read logFunc lazily because SetLogger may run after NewServer.
	s.parseOpts = oid4vc.ParseOptions{
		FetchRequestURI: MakeFetchRequestURI(w, func(format string, args ...any) {
			s.log(format, args...)
		}),
	}
	return s
}

func (s *Server) setupRoutes() {
	s.routeFunc("GET /authorize", s.withFreshStore(s.handleAuthorize))
	s.routeFunc("POST /authorize", s.withFreshStore(s.handleAuthorize))

	// Issuers can use this URL when the platform cannot register the
	// openid-credential-offer:// scheme.
	s.routeFunc("GET /credential-offer", s.withFreshStore(s.handleCredentialOfferEndpoint))

	s.routeFunc("POST /api/presentations", s.withFreshStore(s.handlePresentationAPI))
	s.routeFunc("POST /api/dc-api", s.withFreshStore(s.handleBrowserPresentationAPI))

	s.routeFunc("POST /api/offers", s.withFreshStore(s.handleOfferAPI))
	s.routeFunc("GET /api/offers/{id}", s.handleOfferStatus)
	s.routeFunc("POST /api/credentials/{id}/refresh", s.withFreshStore(s.handleRefreshCredential))
	s.routeFunc("GET /callback", s.withFreshStore(s.handleAuthorizationCodeCallback))

	// The URL handler checks this endpoint to detect outdated servers.
	s.routeFunc("GET /api/version", s.handleVersion)
	s.routeFunc("GET /healthz", s.handleHealth)
	s.routeFunc("GET /readyz", s.handleReady)

	s.routeFunc("GET /api/credentials", s.withFreshStore(s.handleListCredentials))
	s.routeFunc("GET /api/deferred", s.withFreshStore(s.handleListDeferred))
	s.routeFunc("POST /api/deferred/{id}/collect", s.withFreshStore(s.handleCollectDeferred))
	s.routeFunc("DELETE /api/deferred/{id}", s.withFreshStore(s.handleAbandonDeferred))
	s.routeFunc("POST /api/credentials", s.withFreshStore(s.handleImportCredential))
	s.routeFunc("DELETE /api/credentials", s.withFreshStore(s.handleDeleteAllCredentials))
	s.routeFunc("GET /api/credentials/{id}", s.withFreshStore(s.handleGetCredential))
	// Credential images are static and cached, so this route skips reloading the
	// store.
	s.routeFunc("GET /api/credentials/{id}/display/{kind}", s.handleCredentialDisplayImage)
	s.routeFunc("DELETE /api/credentials/{id}", s.withFreshStore(s.handleDeleteCredential))

	s.routeFunc("POST /api/issue", s.withFreshStore(s.handleIssueCredential))
	s.routeFunc("POST /api/generate-pid", s.withFreshStore(s.handleGeneratePID))

	s.routeFunc("GET /api/templates", s.handleListTemplates)
	s.routeFunc("GET /api/templates/{name}", s.handleGetTemplate)
	s.routeFunc("PUT /api/templates/{name}", s.handlePutTemplate)
	s.routeFunc("DELETE /api/templates/{name}", s.handleDeleteTemplate)

	s.routeFunc("GET /api/certificates/ca", s.handleCACertificate)
	s.routeFunc("GET /api/certificates/ca.der", s.handleCACertificateDER)
	s.routeFunc("GET /api/certificates/providers/{role}/{country}", s.handleProviderCertificateDER)
	s.routeFunc("GET /api/certificates/signers/{certificate}", s.handleSigningCertificate)
	s.routeFunc("GET /api/crl/providers/{role}/{country}", s.handleProviderCRL)
	s.routeFunc("GET /api/certificates/tls", s.handleTLSCertificate)

	s.routeFunc("GET /api/requests", s.withFreshStore(s.handleListRequests))
	s.routeFunc("GET /api/requests/stream", s.withFreshStore(s.handleRequestStream))
	s.routeFunc("POST /api/requests/{id}/approve", s.withFreshStore(s.handleApproveRequest))
	s.routeFunc("POST /api/requests/{id}/deny", s.withFreshStore(s.handleDenyRequest))

	s.routeFunc("GET /api/trustlist", s.withFreshStore(s.handleTrustList))
	s.routeFunc("GET /api/trustlists", s.withFreshStore(s.handleTrustListIndex))
	s.routeFunc("GET /api/trustlists/{id}", s.withFreshStore(s.handleTrustListByID))
	s.routeFunc("GET /api/trustlist/history", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET /api/trustlist/history/{sequence}", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET /api/trustlists/{id}/history", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET /api/trustlists/{id}/history/{sequence}", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET /api/registrar/wrp", s.withFreshStore(s.handleRegistrarWRPList))
	s.routeFunc("GET /api/registrar/wrp/{identifier}", s.withFreshStore(s.handleRegistrarWRPByIdentifier))

	s.routeFunc("GET /api/statuslist", s.withFreshStore(s.handleStatusList))
	s.routeFunc("GET /api/crl", s.withFreshStore(s.handleCRL))
	s.routeFunc("GET /api/credentials/{id}/status", s.withFreshStore(s.handleGetCredentialStatus))
	s.routeFunc("POST /api/credentials/{id}/status", s.withFreshStore(s.handleSetCredentialStatus))

	s.routeFunc("GET /.well-known/jwt-vc-issuer", s.withFreshStore(s.handleJWTVCIssuerMetadata))
	s.routeFunc("GET /.well-known/openid-credential-issuer", s.withFreshStore(s.handleOpenIDCredentialIssuerMetadata))

	s.routeFunc("POST /api/next-error", s.withFreshStore(s.handleSetNextError))
	s.routeFunc("DELETE /api/next-error", s.withFreshStore(s.handleClearNextError))
	s.routeFunc("PUT /api/config/preferred-format", s.withFreshStore(s.handleSetPreferredFormat))
	s.routeFunc("PUT /api/config/auto-accept", s.withFreshStore(s.handleSetAutoAccept))
	s.routeFunc("PUT /api/config/conformance", s.withFreshStore(s.handleSetConformance))
	s.routeFunc("DELETE /api/config/conformance", s.withFreshStore(s.handleResetConformance))
	s.routeFunc("GET /api/config", s.withFreshStore(s.handleGetConfig))
	s.routeFunc("POST /api/shutdown", s.handleShutdown)

	s.routeFunc("GET /api/log", s.withFreshLog(s.handleLog))
	s.routeFunc("DELETE /api/log", s.withFreshLog(s.handleClearLog))

	s.routeFunc("GET /api/error", s.withFreshStore(s.handleLastError))
	s.routeFunc("DELETE /api/error", s.withFreshStore(s.handleClearLastError))

	// Returns 404 until SetImprint supplies a legal notice.
	s.routeFunc("GET /imprint", s.handleImprint)
	// Returns 404 until SetNews supplies the news of a public demo.
	s.routeFunc("GET /api/news", s.handleNews)
	s.routeFunc("GET /.well-known/security.txt", handleSecurityTxt)

	// Embedded files have no modification time, so http.FileServer cannot provide
	// cache validators. Require revalidation to prevent browsers from mixing HTML and
	// JS from different releases.
	sub, _ := fs.Sub(staticFiles, "static")
	if entries, err := fs.ReadDir(sub, "."); err == nil {
		for _, entry := range entries {
			s.routeRoots[entry.Name()] = true
		}
	}
	s.routeRoots[webui.Root] = true
	index, _ := fs.ReadFile(sub, "index.html")
	s.route("/", noStaleCache(s.withBrowserSession(publicpath.ServeIndex(index, http.FileServer(http.FS(webui.Overlay(sub)))))))
}

func (s *Server) route(pattern string, h http.Handler) {
	s.recordRouteRoot(pattern)
	s.mux.Handle(pattern, h)
}

func (s *Server) routeFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	s.recordRouteRoot(pattern)
	s.mux.HandleFunc(pattern, h)
}

func (s *Server) recordRouteRoot(pattern string) {
	if _, path, found := strings.Cut(pattern, " "); found {
		pattern = path
	}
	root, _, _ := strings.Cut(strings.TrimPrefix(pattern, "/"), "/")
	if root != "" {
		s.routeRoots[root] = true
	}
}

// CheckBasePath rejects a --base-url whose path starts with a segment the wallet
// serves, such as /api. Call after the last Mount or Handle.
func (s *Server) CheckBasePath() error {
	first, err := publicpath.FirstSegment(s.wallet.BaseURL)
	if err != nil {
		return err
	}
	if s.routeRoots[first] {
		return fmt.Errorf("the --base-url path cannot start with /%s because the wallet uses that path itself", first)
	}
	return nil
}

func noStaleCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, private")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  120 * time.Second,
	}
	if err := s.startIssuerTLSServer(); err != nil {
		return err
	}
	s.startDemoReset()
	defer s.StartBackgroundTasks()()
	return s.httpSrv.ListenAndServe()
}

func (s *Server) ListenAndServeBackground() (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return "", err
	}
	addr := fmt.Sprintf("http://localhost:%d", ln.Addr().(*net.TCPAddr).Port)
	s.httpSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  120 * time.Second,
	}
	if err := s.startIssuerTLSServer(); err != nil {
		if closeErr := ln.Close(); closeErr != nil {
			return "", errors.Join(err, fmt.Errorf("closing listener: %w", closeErr))
		}
		return "", err
	}
	s.startDemoReset()
	go func() { _ = s.httpSrv.Serve(ln) }()
	return addr, nil
}

func (s *Server) SetOnConsentRequest(fn func(req *ConsentRequest)) {
	s.onConsentRequest = fn
}

func (s *Server) SetOnUIRequest(fn func(requestID string)) {
	s.onUIRequest = fn
}

func (s *Server) SetLogger(fn func(format string, args ...any)) {
	s.logFunc = fn
}

// SetStore enables reloads at request boundaries to pick up changes from other commands.
func (s *Server) SetStore(store *WalletStore) {
	s.storeSyncMu.Lock()
	defer s.storeSyncMu.Unlock()
	s.store.Store(store)
}

func (s *Server) log(format string, args ...any) {
	if s.logFunc != nil {
		s.logFunc(format, args...)
	}
}

func (s *Server) triggerUIRequest(requestID string) {
	if s.onUIRequest == nil {
		return
	}
	s.onUIRequest(requestID)
}

func (s *Server) withFreshStore(handler http.HandlerFunc) http.HandlerFunc {
	return s.reloading(false, handler)
}

// Entity backends load the activity log only when requested.
func (s *Server) withFreshLog(handler http.HandlerFunc) http.HandlerFunc {
	return s.reloading(true, handler)
}

func (s *Server) reloading(withLog bool, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.storeSyncMu.Lock()
		err := s.reloadLocked(withLog)
		s.storeSyncMu.Unlock()
		if err != nil {
			s.log("  ERROR: reloading wallet store: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reloading wallet store: " + err.Error()})
			return
		}
		handler(w, r)
	}
}

// Force periodic reloads to catch changes with the same mtime and size on filesystems
// with coarse timestamps.
const reloadMaxStale = 2 * time.Second

func (s *Server) reloadFromStore() error {
	s.storeSyncMu.Lock()
	defer s.storeSyncMu.Unlock()
	return s.reloadLocked(false)
}

// Caller must hold storeSyncMu. Entity backends load changed sections and load the
// activity log only when withLog is true.
func (s *Server) reloadLocked(withLog bool) error {
	store := s.store.Load()
	if store == nil {
		return nil
	}
	if store.entityMode() {
		s.wallet.mu.RLock()
		loaded := s.wallet.persisted != nil
		s.wallet.mu.RUnlock()
		if !loaded {
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				return err
			}
			s.applyPersistedWalletState(reloaded)
			return nil
		}
		changed, err := store.changedSections(s.wallet, withLog)
		if err != nil {
			return err
		}
		if len(changed) == 0 {
			return nil
		}
		return store.loadSections(s.wallet, changed)
	}

	// Skip unchanged files briefly. The time limit catches changes hidden by coarse
	// timestamps.
	stamp, ok := store.WalletStamp()
	if ok && stamp == s.lastWalletStamp && time.Since(s.lastReloadAt) < reloadMaxStale {
		return nil
	}

	reloaded, err := store.LoadOrCreate()
	if err != nil {
		return err
	}
	s.applyPersistedWalletState(reloaded)
	s.lastReloadAt = time.Now()
	if ok {
		s.lastWalletStamp = stamp
	}
	return nil
}

func (s *Server) applyPersistedWalletState(reloaded *Wallet) {
	if reloaded == nil {
		return
	}

	s.wallet.mu.Lock()
	defer s.wallet.mu.Unlock()

	s.wallet.HolderKey = reloaded.HolderKey
	s.wallet.IssuerKey = reloaded.IssuerKey
	s.wallet.CAKey = reloaded.CAKey
	s.wallet.signers = reloaded.signers
	s.wallet.CertChain = append([]*x509.Certificate(nil), reloaded.CertChain...)
	s.wallet.IssuedAttestations = append([]IssuedAttestationSpec(nil), reloaded.IssuedAttestations...)
	s.wallet.Credentials = append([]StoredCredential(nil), reloaded.Credentials...)
	// The poller and issuance flow manage deferred issuances in memory. Reloading them
	// here could erase a new deferral before it has been saved.
	s.wallet.StatusEntries = cloneStatusEntries(reloaded.StatusEntries)
	s.wallet.StatusListCounter = reloaded.StatusListCounter
	s.wallet.Log = append([]LogEntry(nil), reloaded.Log...)
	// Copy the snapshot with the loaded state. Keep deferred rows in the existing
	// snapshot because the server manages them in memory.
	if store := s.store.Load(); reloaded.persisted != nil && store != nil {
		s.wallet.persisted = make(stateSnapshot, len(reloaded.persisted))
		for key, blob := range reloaded.persisted {
			if store.sectionOf(key) != deferredSection {
				s.wallet.persisted[key] = blob
			}
		}
		s.wallet.revisions = maps.Clone(reloaded.revisions)
		s.wallet.savedCredentials = maps.Clone(reloaded.savedCredentials)
		s.wallet.entitySeqs = maps.Clone(reloaded.entitySeqs)
	}
	s.wallet.allocateStatusIndex = reloaded.allocateStatusIndex
}

func (s *Server) Shutdown() {
	s.stopDemoReset()
	if s.httpSrv != nil {
		s.httpSrv.Close()
	}
	if s.issuerSrv != nil {
		s.issuerSrv.Close()
	}
}

// Mount strips the prefix before passing the request to the handler. Call before
// ListenAndServe.
func (s *Server) Mount(prefix string, h http.Handler) {
	s.route(prefix+"/", http.StripPrefix(prefix, h))
	// The bare prefix would otherwise fall through to the UI file server.
	s.route("GET "+prefix, http.RedirectHandler(prefix+"/", http.StatusMovedPermanently))
}

// Handle must be called before ListenAndServe.
func (s *Server) Handle(pattern string, h http.Handler) {
	s.route(pattern, h)
}

func (s *Server) triggerSave() {
	if s.onSave != nil {
		s.onSave()
	}
	s.wallet.NotifyStateChanged()
}

// Hold storeSyncMu across the mutation and save. Otherwise a concurrent reload could
// discard the unsaved change. A false result skips saving. Client I/O runs outside
// this lock so slow readers cannot block reloading.
func (s *Server) saveMutation(mutate func() bool) {
	s.storeSyncMu.Lock()
	changed := mutate()
	if changed && s.onSave != nil {
		s.onSave()
	}
	s.storeSyncMu.Unlock()
	if changed {
		s.wallet.NotifyStateChanged()
	}
}

// A concurrent reload may have dropped the newly issued credential. Restore and save
// it while holding the reload lock.
func (s *Server) saveIssuedCredential(result *IssuanceResult) {
	if result != nil && result.Imported != nil {
		s.storeSyncMu.Lock()
		if _, ok := s.wallet.GetCredential(result.Imported.ID); !ok {
			s.wallet.RestoreCredential(*result.Imported)
		}
		// A reload may also have removed the credential's local status entry.
		// Adoption is idempotent.
		s.wallet.adoptOwnStatusEntry(result.Imported)
		if s.onSave != nil {
			s.onSave()
		}
		s.storeSyncMu.Unlock()
		s.wallet.NotifyStateChanged()
		return
	}
	s.triggerSave()
}

// Restore the renewed credential while holding the reload lock, including its rotated
// refresh token.
func (s *Server) saveRenewedCredential(renewed *StoredCredential) {
	if renewed == nil {
		s.triggerSave()
		return
	}
	s.storeSyncMu.Lock()
	s.wallet.PutCredential(*renewed)
	// A reload may have removed or reverted the status entry. The renewed credential
	// starts with status 0.
	if ref := CredentialStatusRef(*renewed); ref != nil && ref.URI == strings.TrimSpace(s.wallet.StatusListURL()) {
		s.wallet.RegisterStatusEntry(renewed.ID, ref.Idx)
	}
	if s.onSave != nil {
		s.onSave()
	}
	s.storeSyncMu.Unlock()
	s.wallet.NotifyStateChanged()
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}
