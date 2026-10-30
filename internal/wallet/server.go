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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcextension"
	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
	"github.com/eudi-dev/eudi-dev/v3/internal/news"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/publicpath"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/webui"
)

type Server struct {
	wallet           *Wallet
	dcapi            dcAPICalls
	listenHost       string
	port             int
	mux              *http.ServeMux
	onSave           func()
	onConsentRequest func(req *consent.Request)
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
	// The log sink reads the store without storeSyncMu, because it also runs
	// inside mutations that hold it.
	store       atomic.Pointer[WalletStore]
	storeSyncMu sync.Mutex
	// Skips reparsing an unchanged wallet file. Guarded by storeSyncMu.
	lastWalletStamp storage.Stamp
	// unsavedLog holds log entries not yet saved by the file backend. A
	// reload before the save drops them from the wallet, and the save puts
	// them back.
	unsavedLog      []LogEntry
	unsavedLogMu    sync.Mutex
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
	// tlsMu guards issuerTLSCert. A renewal replaces it while the listener
	// runs.
	tlsMu       sync.RWMutex
	version     string
	imprintHTML []byte
	news        *news.News
	// operatorRelyingParties are the first identifiers of the registrations
	// from --relying-parties.
	operatorRelyingParties []string
	// ShutdownFunc runs after POST /api/shutdown has responded. The serve command
	// sets it to stop the server gracefully. When nil the process exits
	// directly.
	ShutdownFunc func()
	// DELETE /api/config/conformance restores these startup settings. Demo mode
	// disables that endpoint.
	defaultConformance ConformanceSettings
}

// NewServer calls onSave after operations that change the wallet. Without
// onSave the server saves to the store that SetStore sets.
func NewServer(w *Wallet, port int, onSave func()) *Server {
	processBuildID()
	s := &Server{
		wallet:             w,
		listenHost:         netaddr.DefaultListenHost,
		port:               port,
		onSave:             onSave,
		defaultConformance: w.Conformance(),
	}
	w.SetLogSink(func(entry LogEntry) {
		if store := s.store.Load(); store != nil && store.entityMode() {
			if err := store.appendLogEntry(w, entry); err != nil {
				s.log("  ERROR: saving log entry: %v", err)
			}
			w.Consents().NotifyStateChanged()
			return
		}
		s.unsavedLogMu.Lock()
		s.unsavedLog = append(s.unsavedLog, entry)
		// The log keeps the newest entries, so older unsaved ones are gone
		// anyway.
		if len(s.unsavedLog) > maxLogEntries {
			s.unsavedLog = slices.Clone(s.unsavedLog[len(s.unsavedLog)-maxLogEntries:])
		}
		s.unsavedLogMu.Unlock()
		s.flushLog()
		w.Consents().NotifyStateChanged()
	})
	if p := parseIssuerPort(w.IssuerURL); p > 0 {
		s.issuerPort = p
	} else if port > 0 {
		s.issuerPort = port + 1
	}
	s.mux = http.NewServeMux()
	s.routeRoots = map[string]bool{}
	s.setupRoutes()
	w.saveMutation = s.saveMutation
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
	s.routeFunc("POST /api/dc-api/refusals", s.handleDCAPIRefusal)
	s.routeFunc("POST /api/dc-api/cancel", s.handleDCAPICancel)
	s.routeFunc("GET /"+dcextension.ZipName, s.handleDCExtension)

	s.routeFunc("POST /api/offers", s.withFreshStore(s.handleOfferAPI))
	s.routeFunc("GET /api/offers/{id}", s.handleOfferStatus)
	s.routeFunc("POST /api/credentials/{id}/refresh", s.withFreshStore(s.handleRenewCredential))
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

	s.routeFunc("GET /api/templates", s.handleListTemplates)
	s.routeFunc("GET /api/templates/{name}", s.handleGetTemplate)
	s.routeFunc("GET /api/templates/{name}/display/{field}", s.handleTemplateDisplayImage)
	s.routeFunc("PUT /api/templates/{name}", s.withFreshStore(s.handlePutTemplate))
	s.routeFunc("DELETE /api/templates/{name}", s.handleDeleteTemplate)

	s.routeFunc("GET "+certificateRevocationsPath, s.withFreshStore(s.handleListCertificateRevocations))
	s.routeFunc("POST "+certificateRevocationsPath, s.withFreshStore(s.handleRevokeCertificate))
	s.routeFunc("DELETE "+certificateRevocationsPath+"/{serial}", s.withFreshStore(s.handleUndoCertificateRevocation))
	s.routeFunc("GET /api/crl/fault", s.handleGetCRLFault)
	s.routeFunc("PUT /api/crl/fault", s.handleSetCRLFault)
	s.routeFunc("DELETE /api/crl/fault", s.handleClearCRLFault)
	s.routeFunc("GET /api/certificates/ca", s.handleCACertificate)
	s.routeFunc("GET /api/certificates/ca.der", s.handleCACertificateDER)
	s.routeFunc("GET /api/certificates/providers/{role}/{country}", s.handleProviderCertificateDER)
	s.routeFunc("GET /api/certificates/signers/{certificate}", s.handleSigningCertificate)
	s.routeFunc("GET "+provider.ProviderCRLPath("{role}", "{country}"), s.withFreshStore(s.handleProviderCRL))
	s.routeFunc("GET "+provider.AccessCACRLPath, s.withFreshStore(s.handleAccessCACRL))
	s.routeFunc("GET "+provider.RegistrarCACRLPath, s.withFreshStore(s.handleRegistrarCACRL))
	s.routeFunc("GET /api/certificates/tls", s.handleTLSCertificate)
	s.routeFunc("GET /api/certificates/registrar", s.handleRegistrarCertificate)
	s.routeFunc("GET /api/certificates/relying-party-access-ca", s.handleRelyingPartyAccessCA)
	s.routeFunc("GET "+registrar.AccessCACertificatePath, s.handleRelyingPartyAccessCADER)
	s.routeFunc("GET /api/certificates/registrar-ca", s.handleRegistrarCA)

	s.routeFunc("GET /api/requests", s.withFreshStore(s.handleListRequests))
	s.routeFunc("GET /api/requests/stream", s.withFreshStore(s.handleRequestStream))
	s.routeFunc("POST /api/requests/{id}/approve", s.withFreshStore(s.handleApproveRequest))
	s.routeFunc("POST /api/requests/{id}/deny", s.withFreshStore(s.handleDenyRequest))

	s.routeFunc("GET "+provider.DefaultTrustListPath, s.withFreshStore(s.handleTrustList))
	s.routeFunc("GET "+provider.TrustedListsPath, s.withFreshStore(s.handleTrustListIndex))
	s.routeFunc("GET /api/trust", s.withFreshStore(s.handleTrustState))
	s.routeFunc("POST /api/trust/entities", s.withFreshStore(s.handleAddTrustedEntity))
	s.routeFunc("DELETE /api/trust/entities/{id}", s.withFreshStore(s.handleRemoveTrustedEntity))
	s.routeFunc("POST /api/trust/lists", s.withFreshStore(s.handleAddTrustedList))
	s.routeFunc("GET "+trustWithdrawalsPath, s.withFreshStore(s.handleListWithdrawals))
	s.routeFunc("POST "+trustWithdrawalsPath, s.withFreshStore(s.handleWithdrawCertificate))
	s.routeFunc("DELETE "+trustWithdrawalsPath+"/{id}", s.withFreshStore(s.handleRestoreCertificate))
	s.routeFunc("DELETE /api/trust/lists", s.withFreshStore(s.handleRemoveTrustedList))
	s.routeFunc("GET "+provider.TrustedListPath("{id}"), s.withFreshStore(s.handleTrustListByID))
	s.routeFunc("GET /api/trustlist/history", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET /api/trustlist/history/{sequence}", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET "+provider.TrustedListPath("{id}")+"/history", s.withFreshStore(s.handleTrustListHistory))
	s.routeFunc("GET "+provider.TrustedListPath("{id}")+"/history/{sequence}", s.withFreshStore(s.handleTrustListHistory))
	// On a public demo the demo registrations follow the catalogue.
	registrarAPI := &registrar.Server{Registrar: func() *registrar.Registrar { return s.wallet.Registrar() }, Mutate: func(change func() bool) {
		s.saveMutation(change)
		if err := s.syncDemoRegistrations(); err != nil {
			s.log("  WARNING: updating the demo registrations: %v", err)
		}
	}, Protected: s.protectedRelyingParty, KeepOperatorEntries: func() bool { return s.demo != nil }}
	for pattern, handler := range registrarAPI.Routes() {
		s.routeFunc(pattern, s.withFreshStore(handler))
	}

	s.routeFunc("GET /api/statuslist", s.withFreshStore(s.handleStatusList))
	s.routeFunc("GET "+provider.RootCRLPath, s.withFreshStore(s.handleCRL))
	s.routeFunc("GET /api/credentials/{id}/status", s.withFreshStore(s.handleGetCredentialStatus))
	s.routeFunc("GET /api/credentials/{id}/certificates", s.withFreshStore(s.handleCredentialCertificates))
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
	for _, name := range webui.Roots {
		s.routeRoots[name] = true
	}
	index, _ := fs.ReadFile(sub, "index.html")
	s.route("/", noStaleCache(s.withBrowserSession(publicpath.ServeIndex(index, webui.FileServer(sub)))))
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

// CheckBasePath rejects a --base-url whose path starts with a segment used by
// the wallet's own routes, such as /api. Call after the last Mount or Handle.
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

// SetListenHost sets the IP address for the HTTP and HTTPS listeners.
func (s *Server) SetListenHost(host string) {
	s.listenHost = host
}

func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{
		Addr:         netaddr.ListenAddr(s.listenHost, s.port),
		Handler:      s.Handler(),
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  config.ServerIdleTimeout,
	}
	if err := s.startIssuerTLSServer(); err != nil {
		return err
	}
	s.startDemoReset()
	defer s.StartBackgroundTasks()()
	return s.httpSrv.ListenAndServe()
}

func (s *Server) ListenAndServeBackground() (string, error) {
	ln, err := net.Listen("tcp", netaddr.ListenAddr(s.listenHost, s.port))
	if err != nil {
		return "", err
	}
	addr := netaddr.LocalURL(s.listenHost, ln.Addr().(*net.TCPAddr).Port)
	s.httpSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  config.ServerIdleTimeout,
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

func (s *Server) setOnConsentRequest(fn func(req *consent.Request)) {
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
	defer s.unlockStore()
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
		s.unlockStore()
		if err != nil {
			s.log("  ERROR: reloading wallet store: %v", err)
			apierror.WriteStatus(w, http.StatusInternalServerError, "reloading wallet store: "+err.Error())
			return
		}
		handler(w, r)
	}
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

	stored, err := store.readWallet()
	if err != nil {
		return err
	}
	if stored != nil && stored.Stamp == s.lastWalletStamp {
		return nil
	}

	reloaded, err := store.load(stored)
	if err != nil {
		return err
	}
	s.applyPersistedWalletState(reloaded)
	if stored != nil {
		s.lastWalletStamp = stored.Stamp
	}
	return nil
}

func (s *Server) applyPersistedWalletState(reloaded *Wallet) {
	s.wallet.adoptReloaded(reloaded, s.store.Load())
}

// Shutdown lets running requests finish for a moment. The response that ends a
// one-shot flow (a deny with its redirect_uri) then still reaches the browser.
// Open event streams are cut after that.
func (s *Server) Shutdown() {
	s.stopDemoReset()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, srv := range []*http.Server{s.httpSrv, s.issuerSrv} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil {
			srv.Close()
		}
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

// unlockStore releases storeSyncMu and saves the log entries logged while it
// was held.
func (s *Server) unlockStore() {
	s.storeSyncMu.Unlock()
	s.flushLog()
}

// flushLog saves the unsaved log entries when storeSyncMu is free. A holder
// of the lock flushes when it lets go, so no entry waits for the next save.
func (s *Server) flushLog() {
	for s.hasUnsavedLog() && s.storeSyncMu.TryLock() {
		s.saveLocked()
		s.storeSyncMu.Unlock()
	}
}

func (s *Server) hasUnsavedLog() bool {
	s.unsavedLogMu.Lock()
	defer s.unsavedLogMu.Unlock()
	return len(s.unsavedLog) > 0
}

// saveLocked persists the wallet. The caller holds storeSyncMu.
func (s *Server) saveLocked() {
	s.unsavedLogMu.Lock()
	unsaved := s.unsavedLog
	s.unsavedLog = nil
	s.unsavedLogMu.Unlock()
	s.wallet.restoreLogEntries(unsaved)
	if s.onSave != nil {
		s.onSave()
		return
	}
	store := s.store.Load()
	if store == nil {
		return
	}
	if err := store.Save(s.wallet); err != nil {
		s.log("  ERROR: saving the wallet: %v", err)
		return
	}
	// The next reload skips the file written by this save.
	if !store.entityMode() {
		if stamp, err := store.WalletStamp(); err == nil {
			s.lastWalletStamp = stamp
		}
	}
}

// saveMutation holds storeSyncMu across the mutation and the save, so a
// concurrent reload can't discard the unsaved change. A false result skips
// saving. Client I/O runs outside this lock so slow readers cannot block
// reloading.
func (s *Server) saveMutation(mutate func() bool) {
	s.saveMutationThen(mutate, nil)
}

// saveMutationThen also runs saved after a successful save, still under the
// lock.
func (s *Server) saveMutationThen(mutate func() bool, saved func()) {
	s.storeSyncMu.Lock()
	changed := mutate()
	if changed {
		s.saveLocked()
		if saved != nil {
			saved()
		}
	}
	s.unlockStore()
	if changed {
		s.wallet.Consents().NotifyStateChanged()
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}
