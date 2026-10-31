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

package consent

import (
	"cmp"
	"errors"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
)

// Keep resolved requests long enough for late polling, then prune them. Consent
// expires after five minutes, so an hour-old pending request has no waiter left.
const (
	resolvedConsentRetention = 10 * time.Minute
	consentRequestMaxAge     = time.Hour
)

// DefaultMaxPending caps the requests that wait for an answer. Each one holds
// a waiting flow until it times out.
const DefaultMaxPending = 100

// ErrTooManyPending refuses a flow while the maximum number of flows waits
// for the user.
var ErrTooManyPending = errors.New("too many flows are waiting for the user. Try again later")

// SetMaxPending sets how many requests may wait for an answer at once.
func (rt *Runtime) SetMaxPending(n int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.maxPending = n
}

// MaxPending returns how many requests may wait for an answer at once.
func (rt *Runtime) MaxPending() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.maxPending
}

// SetMaxPendingPerOwner sets how many requests of one owner may wait for an
// answer at once. Requests without an owner share one count. Zero means no
// limit per owner.
func (rt *Runtime) SetMaxPendingPerOwner(n int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.maxPendingPerOwner = n
}

// MaxPendingPerOwner returns how many requests of one owner may wait for an
// answer at once. Zero means no limit per owner.
func (rt *Runtime) MaxPendingPerOwner() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.maxPendingPerOwner
}

// Create registers a request that waits for an answer. It refuses one with
// ErrTooManyPending when the maximum number already waits, in total or for
// the request's owner.
func (rt *Runtime) Create(req *Request) error {
	rt.mu.Lock()
	now := time.Now()
	// Retention needs a creation time, so a request without one gets the registry clock.
	if req.CreatedAt.IsZero() {
		req.CreatedAt = now
	}
	pending, pendingForOwner := 0, 0
	for id, r := range rt.requests {
		age := now.Sub(r.CreatedAt)
		if age > consentRequestMaxAge || (r.Status != StatusPending && age > resolvedConsentRetention) {
			delete(rt.requests, id)
			continue
		}
		if r.Status == StatusPending {
			pending++
			if r.Owner == req.Owner {
				pendingForOwner++
			}
		}
	}
	if pending >= rt.maxPending || (rt.maxPendingPerOwner > 0 && pendingForOwner >= rt.maxPendingPerOwner) {
		rt.mu.Unlock()
		return ErrTooManyPending
	}
	rt.requests[req.ID] = req
	subs := make([]chan *Request, 0, len(rt.subscribers))
	for _, ch := range rt.subscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- req:
		default:
		}
	}
	return nil
}

// Pending returns the requests that wait for an answer.
func (rt *Runtime) Pending() []*Request {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var out []*Request
	for _, r := range rt.requests {
		if r.Status == StatusPending {
			out = append(out, r)
		}
	}
	return out
}

func (rt *Runtime) Get(id string) (*Request, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	req, ok := rt.requests[id]
	return req, ok
}

// UpdateOptions replaces the answers of a pending request and announces it
// again, so an open dialog shows them. Options returns them under the same lock.
func (rt *Runtime) UpdateOptions(id string, matches []Match, options *CredentialOptions) bool {
	rt.mu.Lock()
	req, ok := rt.requests[id]
	if !ok || req.Status != StatusPending {
		rt.mu.Unlock()
		return false
	}
	req.MatchedCreds = matches
	req.CredentialOptions = options
	req.Updated = true
	subs := make([]chan *Request, 0, len(rt.subscribers))
	for _, ch := range rt.subscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- req:
		default:
		}
	}
	return true
}

// Options returns the current answers of a request.
func (rt *Runtime) Options(req *Request) *CredentialOptions {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return req.CredentialOptions
}

// Resolve returns false for missing or resolved requests.
func (rt *Runtime) Resolve(id, status string) (*Request, bool) {
	rt.mu.Lock()
	req, ok := rt.requests[id]
	if !ok || req.Status != StatusPending {
		rt.mu.Unlock()
		return req, false
	}
	req.Status = status
	rt.mu.Unlock()
	// Tell open tabs to close resolved dialogs. NotifyStateChanged acquires the lock,
	// so call it after unlocking.
	rt.NotifyStateChanged()
	return req, true
}

// PendingDocsFor returns owned and unowned requests plus the redirect request
// ID for browsers without cookies. It marshals under the registry lock because
// resolution changes Status under that lock.
func (rt *Runtime) PendingDocsFor(owners []string, named string) []map[string]any {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	docs := make([]map[string]any, 0, len(rt.requests))
	for _, r := range rt.requests {
		if r.Status == StatusPending && Owns(owners, r, named) {
			docs = append(docs, marshalConsentRequestFor(r, owners))
		}
	}
	return docs
}

// DocFor marshals under the registry lock because resolution changes Status.
func (rt *Runtime) DocFor(r *Request, owners []string) map[string]any {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return marshalConsentRequestFor(r, owners)
}

// The UI uses the mine field to choose between a consent dialog and a banner.
func marshalConsentRequestFor(r *Request, owners []string) map[string]any {
	doc := marshal(r)
	doc["mine"] = OwnedBy(owners, r.Owner)
	return doc
}

// AttachedUIs counts event streams that can show consent without opening another tab.
func (rt *Runtime) AttachedUIs() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.subscribers)
}

func (rt *Runtime) Subscribe() (<-chan *Request, func()) {
	ch := make(chan *Request, 16)
	rt.mu.Lock()
	rt.subID++
	id := rt.subID
	rt.subscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.subscribers, id)
		rt.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

func (rt *Runtime) SubscribeErrors() (<-chan Error, func()) {
	ch := make(chan Error, 16)
	rt.mu.Lock()
	rt.errSubID++
	id := rt.errSubID
	rt.errSubscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.errSubscribers, id)
		rt.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// SubscribeAuthorization delivers the issuer sign-in prompts accepted by
// accept to the caller of a flow, between authorization and token exchange.
func (rt *Runtime) SubscribeAuthorization(accept func(AuthorizationPrompt) bool) (<-chan AuthorizationPrompt, func()) {
	return rt.subscribeAuthorization(authSubscriber{accept: accept})
}

// SubscribePageAuthorization delivers sign-in prompts to a wallet page of one
// of the owners. Each prompt goes to one page only: the page with the
// prompt's tab, else the newest page. RFC 9126 §4 allows one use of a
// request_uri, so a second page would start a second authorization, and it
// would fail.
func (rt *Runtime) SubscribePageAuthorization(owners []string, tab string) (<-chan AuthorizationPrompt, func()) {
	return rt.subscribeAuthorization(authSubscriber{page: true, owners: owners, tab: tab})
}

func (rt *Runtime) subscribeAuthorization(sub authSubscriber) (<-chan AuthorizationPrompt, func()) {
	ch := make(chan AuthorizationPrompt, 4)
	sub.ch = ch
	rt.mu.Lock()
	rt.authSubID++
	id := rt.authSubID
	rt.authSubscribers[id] = sub
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.authSubscribers, id)
		rt.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// NotifyAuthorization reports whether the prompt was delivered, to the caller
// of its flow or to one page of its owner.
func (rt *Runtime) NotifyAuthorization(prompt AuthorizationPrompt) bool {
	type page struct {
		id  int64
		sub authSubscriber
	}
	rt.mu.Lock()
	var callers []chan AuthorizationPrompt
	var pages []page
	for id, sub := range rt.authSubscribers {
		switch {
		case sub.page:
			if !prompt.CallerNavigates && OwnedBy(sub.owners, prompt.Owner) {
				pages = append(pages, page{id, sub})
			}
		case sub.accept(prompt):
			callers = append(callers, sub.ch)
		}
	}
	rt.mu.Unlock()

	delivered := false
	for _, ch := range callers {
		select {
		case ch <- prompt:
			delivered = true
		default:
		}
	}
	// Try the page with the prompt's tab first, then the newest pages.
	slices.SortFunc(pages, func(a, b page) int {
		aTab, bTab := prompt.Tab != "" && a.sub.tab == prompt.Tab, prompt.Tab != "" && b.sub.tab == prompt.Tab
		if aTab != bTab {
			if aTab {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.id, a.id)
	})
	for _, p := range pages {
		select {
		case p.sub.ch <- prompt:
			return true
		default:
		}
	}
	return delivered
}

func (rt *Runtime) NotifyError(err Error) {
	err.FindingDetails = err.Findings.Details()
	rt.mu.Lock()
	now := time.Now()
	// The empty key is the unowned slot, so it cannot also mark an unset oldest entry.
	var oldest string
	var haveOldest bool
	for owner, stored := range rt.lastErrors {
		if now.Sub(stored.at) > lastErrorRetention {
			delete(rt.lastErrors, owner)
			continue
		}
		if !haveOldest || stored.at.Before(rt.lastErrors[oldest].at) {
			oldest, haveOldest = owner, true
		}
	}
	// Caller-selected keys also require a count limit.
	if _, held := rt.lastErrors[err.Owner]; !held && len(rt.lastErrors) >= maxStoredErrors && haveOldest {
		delete(rt.lastErrors, oldest)
	}
	rt.lastErrors[err.Owner] = &storedError{err: err, at: now}
	subs := make([]chan Error, 0, len(rt.errSubscribers))
	for _, ch := range rt.errSubscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- err:
		default:
		}
	}
}

// PeekLastError leaves the error stored after reading.
func (rt *Runtime) PeekLastError(owners []string) *Error {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, owner := range errorSlots(owners) {
		if stored := rt.lastErrors[owner]; stored != nil && time.Since(stored.at) <= lastErrorRetention {
			err := stored.err
			return &err
		}
	}
	return nil
}

// ForgetError drops the error of one browser session if it was stored at or
// after since.
func (rt *Runtime) ForgetError(owner string, since time.Time) {
	if owner == "" {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if stored := rt.lastErrors[owner]; stored != nil && !stored.at.Before(since) {
		delete(rt.lastErrors, owner)
	}
}

// ClearLastError clears the caller's own error and the unowned error. A new flow
// then starts without an old failure on screen.
func (rt *Runtime) ClearLastError(owners []string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, slot := range errorSlots(owners) {
		delete(rt.lastErrors, slot)
	}
}

// Read the caller's own error first. Unowned errors remain visible to everyone for
// clients without browser sessions.
func errorSlots(owners []string) []string {
	return append(append([]string{}, owners...), "")
}

func (rt *Runtime) SetNextError(e *NextErrorOverride) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.nextError = e
}

func (rt *Runtime) ConsumeNextError() *NextErrorOverride {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e := rt.nextError
	rt.nextError = nil
	return e
}

// SubscribeState signals carry no payload. Subscribers reload the wallet data.
func (rt *Runtime) SubscribeState() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	rt.mu.Lock()
	rt.stateSubID++
	id := rt.stateSubID
	rt.stateSubscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.stateSubscribers, id)
		rt.mu.Unlock()
	}
}

// NotifyStateChanged uses one buffered slot to combine bursts without blocking senders.
func (rt *Runtime) NotifyStateChanged() {
	rt.mu.Lock()
	subs := make([]chan struct{}, 0, len(rt.stateSubscribers))
	for _, ch := range rt.stateSubscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// AuthorizationPrompt uses Owner to identify the browser handling issuance. Empty means
// the initiating client supplied no browser ID. Flow identifies the
// prompt's issuance. Tab identifies the wallet page that started the flow, if
// any.
type AuthorizationPrompt struct {
	URL   string
	Owner string
	Flow  string
	Tab   string
	// CallerNavigates is set when the caller opens the URL itself, for example
	// a redirected browser. No wallet page navigates then.
	CallerNavigates bool
	// Cancelled ends the wait for the sign-in when it closes.
	Cancelled <-chan struct{}
}

// An authSubscriber is a flow caller, which filters with accept, or a wallet
// page of the owners.
type authSubscriber struct {
	ch     chan AuthorizationPrompt
	accept func(AuthorizationPrompt) bool
	page   bool
	owners []string
	tab    string
}

// Prune unread errors because callers select the map keys.
type storedError struct {
	err Error
	at  time.Time
}

// Retain errors long enough for the browser to reload or reconnect.
const lastErrorRetention = 10 * time.Minute

// A caller can choose a new key on every request. A count limit bounds bursts before
// entries expire.
const maxStoredErrors = 64

// NextErrorOverride applies to the next presentation request only.
type NextErrorOverride struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Runtime shares flow state between wallets using the same store directory in this
// process.
type Runtime struct {
	mu                 sync.RWMutex
	requests           map[string]*Request
	maxPending         int
	maxPendingPerOwner int
	nextError          *NextErrorOverride
	subscribers        map[int64]chan *Request
	subID              int64
	errSubscribers     map[int64]chan Error
	errSubID           int64
	stateSubscribers   map[int64]chan struct{}
	stateSubID         int64
	authSubscribers    map[int64]authSubscriber
	authSubID          int64
	lastErrors         map[string]*storedError
	authCodeCallbacks  map[string]chan url.Values
}

func NewRuntime() *Runtime {
	return &Runtime{
		requests:          make(map[string]*Request),
		maxPending:        DefaultMaxPending,
		subscribers:       make(map[int64]chan *Request),
		errSubscribers:    make(map[int64]chan Error),
		stateSubscribers:  make(map[int64]chan struct{}),
		authSubscribers:   make(map[int64]authSubscriber),
		authCodeCallbacks: make(map[string]chan url.Values),
		lastErrors:        make(map[string]*storedError),
	}
}

// Error is a failed flow. The UI of the owning browser shows it.
type Error struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	// Findings are the failed checks behind a refusal, one per entry.
	// NotifyError fills FindingDetails.
	Findings       findings.List      `json:"findings,omitempty"`
	FindingDetails []findings.Finding `json:"finding_details,omitempty"`
	// Never serialize the owner because another caller could use it to claim the flow.
	Owner string `json:"-"`
}

func (rt *Runtime) RegisterAuthorizationCodeCallback(state string) (<-chan url.Values, func()) {
	ch := make(chan url.Values, 1)
	rt.mu.Lock()
	rt.authCodeCallbacks[state] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.authCodeCallbacks, state)
		rt.mu.Unlock()
	}
}

func (rt *Runtime) CompleteAuthorizationCodeCallback(values url.Values) bool {
	state := values.Get("state")
	if state == "" {
		return false
	}

	rt.mu.Lock()
	ch, ok := rt.authCodeCallbacks[state]
	if ok {
		delete(rt.authCodeCallbacks, state)
	}
	rt.mu.Unlock()
	if !ok {
		return false
	}

	select {
	case ch <- values:
	default:
	}
	return true
}
