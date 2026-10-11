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

import "time"

// Keep resolved requests long enough for late polling, then prune them. Consent
// expires after five minutes, so an hour-old pending request has no waiter left.
const (
	resolvedConsentRetention = 10 * time.Minute
	consentRequestMaxAge     = time.Hour
)

func (w *Wallet) CreateConsentRequest(req *ConsentRequest) {
	rt := w.runtimeState()
	rt.mu.Lock()
	now := time.Now()
	// Retention needs a creation time, so a request without one gets the registry clock.
	if req.CreatedAt.IsZero() {
		req.CreatedAt = now
	}
	for id, r := range rt.requests {
		age := now.Sub(r.CreatedAt)
		if age > consentRequestMaxAge || (r.Status != "pending" && age > resolvedConsentRetention) {
			delete(rt.requests, id)
		}
	}
	rt.requests[req.ID] = req
	subs := make([]chan *ConsentRequest, 0, len(rt.subscribers))
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
}

func (w *Wallet) GetRequest(id string) (*ConsentRequest, bool) {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	req, ok := rt.requests[id]
	return req, ok
}

// Distinguish timeout from denial when reporting why a late answer failed.
const statusExpired = "expired"

// ResolveRequest returns false for missing or resolved requests.
func (w *Wallet) ResolveRequest(id, status string) (*ConsentRequest, bool) {
	rt := w.runtimeState()
	rt.mu.Lock()
	req, ok := rt.requests[id]
	if !ok || req.Status != "pending" {
		rt.mu.Unlock()
		return req, false
	}
	req.Status = status
	rt.mu.Unlock()
	// Tell open tabs to close resolved dialogs. NotifyStateChanged acquires the lock,
	// so call it after unlocking.
	w.NotifyStateChanged()
	return req, true
}

// PendingRequestDocsFor returns owned and unowned requests plus the redirect request
// ID for browsers without cookies. It marshals under the registry lock because
// resolution changes Status under that lock.
func (w *Wallet) PendingRequestDocsFor(owners []string, named string) []map[string]any {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	docs := make([]map[string]any, 0, len(rt.requests))
	for _, r := range rt.requests {
		if r.Status == "pending" && ownsRequest(owners, r, named) {
			docs = append(docs, marshalConsentRequestFor(r, owners))
		}
	}
	return docs
}

// RequestDocFor marshals under the registry lock because resolution changes Status.
func (w *Wallet) RequestDocFor(r *ConsentRequest, owners []string) map[string]any {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return marshalConsentRequestFor(r, owners)
}

// The UI uses the mine field to choose between a consent dialog and a banner.
func marshalConsentRequestFor(r *ConsentRequest, owners []string) map[string]any {
	doc := MarshalConsentRequest(r)
	doc["mine"] = ownedBy(owners, r.Owner)
	return doc
}

// AttachedUIs counts event streams that can show consent without opening another tab.
func (w *Wallet) AttachedUIs() int {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.subscribers)
}

func (w *Wallet) Subscribe() (<-chan *ConsentRequest, func()) {
	ch := make(chan *ConsentRequest, 16)
	rt := w.runtimeState()
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

func (w *Wallet) SubscribeErrors() (<-chan WalletError, func()) {
	ch := make(chan WalletError, 16)
	rt := w.runtimeState()
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

// SubscribeAuthorization delivers the issuer sign-in prompts that accept
// takes, between authorization and token exchange. Hosted wallets deliver the
// URL to the existing browser tab. Local wallets can open it directly.
func (w *Wallet) SubscribeAuthorization(accept func(AuthorizationPrompt) bool) (<-chan AuthorizationPrompt, func()) {
	ch := make(chan AuthorizationPrompt, 4)
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.authSubID++
	id := rt.authSubID
	rt.authSubscribers[id] = authSubscriber{ch: ch, accept: accept}
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

// NotifyAuthorization reports whether a subscriber that takes the prompt
// received it: the caller of its flow or the browser that owns it.
func (w *Wallet) NotifyAuthorization(prompt AuthorizationPrompt) bool {
	rt := w.runtimeState()
	rt.mu.Lock()
	subs := make([]chan AuthorizationPrompt, 0, len(rt.authSubscribers))
	for _, sub := range rt.authSubscribers {
		if sub.accept(prompt) {
			subs = append(subs, sub.ch)
		}
	}
	rt.mu.Unlock()

	delivered := false
	for _, ch := range subs {
		select {
		case ch <- prompt:
			delivered = true
		default:
		}
	}
	return delivered
}

func (w *Wallet) NotifyError(err WalletError) {
	rt := w.runtimeState()
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
	subs := make([]chan WalletError, 0, len(rt.errSubscribers))
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
func (w *Wallet) PeekLastError(owners []string) *WalletError {
	rt := w.runtimeState()
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

// ClearLastError clears the caller's own error and the unowned error. A new flow
// then starts without an old failure on screen.
func (w *Wallet) ClearLastError(owners []string) {
	rt := w.runtimeState()
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

func (w *Wallet) SetNextError(e *NextErrorOverride) {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.nextError = e
}

func (w *Wallet) ConsumeNextError() *NextErrorOverride {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e := rt.nextError
	rt.nextError = nil
	return e
}

// SubscribeState signals carry no payload. Subscribers reload the wallet data.
func (w *Wallet) SubscribeState() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	rt := w.runtimeState()
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
func (w *Wallet) NotifyStateChanged() {
	rt := w.runtimeState()
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
// the initiating client supplied no browser ID. Flow names the issuance the
// prompt belongs to.
type AuthorizationPrompt struct {
	URL   string
	Owner string
	Flow  string
}

type authSubscriber struct {
	ch     chan AuthorizationPrompt
	accept func(AuthorizationPrompt) bool
}

// Prune unread errors because callers select the map keys.
type storedError struct {
	err WalletError
	at  time.Time
}

// Retain errors long enough for the browser to reload or reconnect.
const lastErrorRetention = 10 * time.Minute

// A caller can choose a new key on every request. A count limit bounds bursts before
// entries expire.
const maxStoredErrors = 64
