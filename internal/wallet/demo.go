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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v3/internal/publicpath"
)

// DemoOptions configures the demo profile for a shared, anonymous environment
// on the internet. Visitors keep the full credential flows (issue,
// present, decode, delete). Endpoints that control the process or write to
// the host are disabled.
type DemoOptions struct {
	// ResetInterval restores the wallet to a clean baseline (default PID
	// credentials, empty log) on this interval. 0 disables periodic resets.
	ResetInterval time.Duration
	// ResetDaily restores the baseline at a fixed wall-clock time. It takes
	// precedence over ResetInterval.
	ResetDaily *DailySchedule
	// Baseline adds the startup credentials again after a reset. When it is nil,
	// a reset restores the protected default PIDs.
	Baseline func() error
}

type DailySchedule struct {
	Hour     int
	Minute   int
	Location *time.Location
}

// Next returns the next occurrence strictly after now. It uses the calendar of
// the location, so a DST change keeps the configured local time.
func (d DailySchedule) Next(now time.Time) time.Time {
	local := now.In(d.Location)
	next := time.Date(local.Year(), local.Month(), local.Day(), d.Hour, d.Minute, 0, 0, d.Location)
	if !next.After(local) {
		next = time.Date(local.Year(), local.Month(), local.Day()+1, d.Hour, d.Minute, 0, 0, d.Location)
	}
	return next
}

func (d DailySchedule) String() string {
	zone, _ := time.Now().In(d.Location).Zone()
	return fmt.Sprintf("%02d:%02d %s", d.Hour, d.Minute, zone)
}

// ParseDailySchedule reads "HH:MM" (server local time) or "HH:MM <IANA zone>",
// for example "00:00 Europe/Berlin".
func ParseDailySchedule(value string) (*DailySchedule, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 || len(fields) > 2 {
		return nil, fmt.Errorf("expected \"HH:MM\" or \"HH:MM <timezone>\"")
	}
	var hour, minute int
	if _, err := fmt.Sscanf(fields[0], "%d:%d", &hour, &minute); err != nil {
		return nil, fmt.Errorf("invalid time of day %q", fields[0])
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return nil, fmt.Errorf("time of day %q is out of range", fields[0])
	}
	loc := time.Local
	if len(fields) == 2 {
		parsed, err := time.LoadLocation(fields[1])
		if err != nil {
			return nil, fmt.Errorf("unknown timezone %q: %w", fields[1], err)
		}
		loc = parsed
	}
	return &DailySchedule{Hour: hour, Minute: minute, Location: loc}, nil
}

type demoState struct {
	opts      DemoOptions
	mu        sync.Mutex
	nextReset time.Time
	stop      chan struct{}
	stopOnce  sync.Once
}

// Visitors share the demo wallet, so it holds at most this many entries
// between resets. Every check reads the added providers and lists.
const (
	maxDemoCredentials        = 500
	maxDemoDeferred           = 100
	maxDemoTrustedEntities    = 20
	maxDemoTrustedLists       = 5
	maxDemoIssuedAttestations = 100
	maxDemoTemplates          = 50
	maxDemoRelyingParties     = 500
	// Each request that waits for consent holds a flow for up to
	// config.ConsentTimeout.
	maxDemoPendingConsents = 30
)

// SetDemo turns on the public demo profile. Templates that visitors save are
// visitor templates. The operator's templates stay fixed, and a reset keeps
// them.
func (s *Server) SetDemo(opts DemoOptions) error {
	s.demo = &demoState{opts: opts}
	s.wallet.SetCapacity(Capacity{
		Credentials:        maxDemoCredentials,
		Deferred:           maxDemoDeferred,
		IssuedAttestations: maxDemoIssuedAttestations,
		Templates:          maxDemoTemplates,
		RelyingParties:     maxDemoRelyingParties,
	})
	// Added providers and lists are refused when full, because each one
	// changes what every check trusts.
	s.wallet.mu.Lock()
	s.wallet.TrustSettings.MaxEntities, s.wallet.TrustSettings.MaxLists = maxDemoTrustedEntities, maxDemoTrustedLists
	s.wallet.mu.Unlock()
	s.wallet.SetVisitorRules(VisitorRules{VisitorTemplates: true, BundledImagesOnly: true, OwnSigningKeys: true})
	s.wallet.Consents().SetMaxPending(maxDemoPendingConsents)
	return nil
}

// maxRequestBodyBytes limits request bodies on every server to bound memory use.
const maxRequestBodyBytes = 1 << 20

func (s *Server) Handler() http.Handler {
	secure := httpsec.Headers
	if s.wallet.AdhocDisplayImages {
		secure = httpsec.HeadersWithRemoteImages
	}
	inner := secure(s.guardAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.demo != nil && demoBlockedRoute(r) {
			apierror.WriteStatus(w, http.StatusForbidden, "the public demo disables this endpoint")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		s.mux.ServeHTTP(w, r)
	})))
	// This wrapper sits outside the API guard and the demo checks. They compare
	// paths such as /api/shutdown, so the prefix has to be stripped first.
	return publicpath.Wrap(publicpath.Options{
		BaseURL: s.wallet.BaseURL,
		OnMismatch: func(observed string) {
			s.log("Warning: a request came in with %s, but --base-url is %s. Check the proxy routes or --base-url.", observed, s.wallet.BaseURL)
		},
	}, inner)
}

// guardAPI wraps a handler with the cross-origin guard. It passes the wallet's
// public URLs, so a deployment behind a reverse proxy works when the proxy
// does not pass the public Host through.
func (s *Server) guardAPI(next http.Handler) http.Handler {
	// /api/dc-api is the Digital Credentials API endpoint. A verifier's page
	// invokes it from its own origin, so it is exempt. It relies on the origin
	// reported by the platform and on the consent dialog.
	return httpsec.GuardAPIExcept(next, []string{"/api/dc-api"}, s.wallet.BaseURL, s.wallet.IssuerURL)
}

// demoBlockedRoute reports whether the endpoint is closed to anonymous demo
// visitors. That covers process control and changes to settings that affect
// all visitors.
func demoBlockedRoute(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/api/shutdown":
		return true
	case (r.Method == http.MethodPost || r.Method == http.MethodDelete) && p == "/api/next-error":
		return true
	case r.Method == http.MethodPut && p == "/api/config/preferred-format":
		return true
	case r.Method == http.MethodPut && p == "/api/config/auto-accept":
		return true
	case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && p == "/api/config/conformance":
		return true
	// Clearing the shared history changes what every other visitor sees.
	// DELETE /api/error stays open: it clears only what its caller can read.
	case r.Method == http.MethodDelete && p == "/api/log":
		return true
	}
	return false
}

// ResetToBaseline drops all visitor-created state: credentials, activity
// log, status entries and the attestation registry. Keys, certificates and
// serving URLs stay, so trusted list and status list URLs are stable across
// resets.
func (w *Wallet) ResetToBaseline() {
	w.mu.Lock()
	defer w.mu.Unlock()
	// A pending deferral belongs to the wiped session too. The poller must not
	// carry it or its keys into the fresh baseline.
	w.PersistedState = PersistedState{}
}

func (s *Server) startDemoReset() {
	if s.demo == nil {
		return
	}
	daily := s.demo.opts.ResetDaily
	if daily == nil && s.demo.opts.ResetInterval <= 0 {
		return
	}

	// nextResetAfter runs every cycle so a daily schedule stays pinned to the
	// wall clock.
	nextResetAfter := func(now time.Time) time.Time {
		if daily != nil {
			return daily.Next(now)
		}
		return now.Add(s.demo.opts.ResetInterval)
	}

	s.demo.mu.Lock()
	s.demo.stop = make(chan struct{})
	s.demo.nextReset = nextResetAfter(time.Now())
	stop := s.demo.stop
	s.demo.mu.Unlock()

	go func() {
		for {
			s.demo.mu.Lock()
			wait := time.Until(s.demo.nextReset)
			s.demo.mu.Unlock()
			if wait < 0 {
				wait = 0
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				if err := s.demoReset(); err != nil {
					s.log("  ERROR: demo reset: %v", err)
				}
				s.demo.mu.Lock()
				s.demo.nextReset = nextResetAfter(time.Now())
				s.demo.mu.Unlock()
			case <-stop:
				timer.Stop()
				return
			}
		}
	}()
}

func (s *Server) stopDemoReset() {
	if s.demo == nil {
		return
	}
	s.demo.mu.Lock()
	stop := s.demo.stop
	s.demo.mu.Unlock()
	if stop != nil {
		s.demo.stopOnce.Do(func() { close(stop) })
	}
}

// demoReset holds storeSyncMu through the reset, so requests on this server see
// either the complete old baseline or the new one.
func (s *Server) demoReset() error {
	var err error
	s.saveMutationThen(func() bool {
		err = s.restoreBaselineLocked()
		return err == nil
	}, func() {
		// The reset leaves the assets issued since the last reset unreferenced.
		// They are pruned once the fresh baseline is saved.
		if store := s.store.Load(); store != nil {
			store.PruneUnreferencedAssets()
		}
	})
	if err != nil {
		return err
	}
	s.log("  Demo reset: baseline restored")
	return nil
}

func (s *Server) restoreBaselineLocked() error {
	// The reset clears the whole log, so an entity backend loads it first.
	if err := s.reloadLocked(true); err != nil {
		return err
	}
	s.wallet.ResetToBaseline()
	if err := s.deleteVisitorTemplates(); err != nil {
		return err
	}
	// Re-issue the signing leaf from the same CA. Leaves are valid for a year
	// and the CA stays pinnable.
	if err := s.wallet.RefreshSigningCertificate(); err != nil {
		return err
	}
	baseline := s.wallet.GenerateProtectedDefaults
	if s.demo.opts.Baseline != nil {
		baseline = s.demo.opts.Baseline
	}
	if err := baseline(); err != nil {
		return err
	}
	_, err := s.wallet.EnsureDemoRegistrations()
	return err
}

func (s *Server) demoConfig() map[string]any {
	if s.demo == nil {
		return nil
	}
	cfg := map[string]any{
		"enabled":                true,
		"reset_interval_seconds": int(s.demo.opts.ResetInterval / time.Second),
	}
	if s.demo.opts.ResetDaily != nil {
		cfg["reset_daily_at"] = s.demo.opts.ResetDaily.String()
		cfg["reset_interval_seconds"] = 0
	}
	s.demo.mu.Lock()
	if !s.demo.nextReset.IsZero() {
		cfg["next_reset"] = s.demo.nextReset.UTC().Format(time.RFC3339)
	}
	s.demo.mu.Unlock()
	return cfg
}

func (s *Server) deleteVisitorTemplates() error {
	templates, err := credtemplate.List(s.wallet.Templates)
	if err != nil {
		return err
	}
	for _, t := range templates {
		if !t.Visitor {
			continue
		}
		if err := credtemplate.Delete(s.wallet.Templates, t.Name); err != nil {
			return err
		}
	}
	return nil
}
