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
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// overrides holds the one-shot overrides of a shared wallet. A browser's
// override is stored under each of its owners, so a flow of its cookie and
// one of its X-Eudi-Owner both find it. The empty owner holds the override
// of a caller without a browser, such as CI or curl. A flow takes its
// owner's override first and then the one without an owner (ADR-0011).
type overrides[T any] map[string]*storedOverride[T]

type storedOverride[T any] struct {
	value  *T
	owners []string
	at     time.Time
}

// A browser that leaves its override unused would otherwise answer a flow
// much later. The override without an owner stays until it is used, as
// scripts set it before they start the flow.
func (s *storedOverride[T]) expired(now time.Time) bool {
	return !ownerless(s.owners) && now.Sub(s.at) > lastErrorRetention
}

func ownerless(owners []string) bool {
	return len(owners) == 1 && owners[0] == ""
}

func (o overrides[T]) drop(stored *storedOverride[T]) {
	for _, owner := range stored.owners {
		if o[owner] == stored {
			delete(o, owner)
		}
	}
}

// set replaces the override of owners. Nil clears it. No owners means the
// override without an owner.
func (o overrides[T]) set(owners []string, value *T, now time.Time) {
	if len(owners) == 0 {
		owners = []string{""}
	}
	for _, owner := range owners {
		if stored, held := o[owner]; held {
			o.drop(stored)
		}
	}
	if value == nil {
		return
	}
	o.put(&storedOverride[T]{value: value, owners: owners, at: now}, now)
}

// A caller can choose a new owner on every request, so the map is bounded
// like the stored errors.
func (o overrides[T]) put(stored *storedOverride[T], now time.Time) {
	for _, held := range o {
		if held.expired(now) {
			o.drop(held)
		}
	}
	for len(o)+len(stored.owners) > maxStoredErrors {
		var oldest *storedOverride[T]
		for _, held := range o {
			if !ownerless(held.owners) && (oldest == nil || held.at.Before(oldest.at)) {
				oldest = held
			}
		}
		if oldest == nil {
			break
		}
		o.drop(oldest)
	}
	for _, owner := range stored.owners {
		o[owner] = stored
	}
}

func (o overrides[T]) take(owner string, now time.Time) *storedOverride[T] {
	for _, slot := range []string{owner, ""} {
		if stored, ok := o[slot]; ok {
			o.drop(stored)
			if !stored.expired(now) {
				return stored
			}
		}
	}
	return nil
}

// putBack returns a taken override unless its owners set a new one since.
func (o overrides[T]) putBack(stored *storedOverride[T], now time.Time) {
	for _, owner := range stored.owners {
		if _, held := o[owner]; held {
			return
		}
	}
	o.put(stored, now)
}

// consume takes the override for a flow of owner. restore puts it back when
// the flow could not use it.
func consume[T any](rt *Runtime, o overrides[T], owner string) (value *T, restore func()) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	stored := o.take(owner, time.Now())
	if stored == nil {
		return nil, func() {}
	}
	return stored.value, func() {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		o.putBack(stored, time.Now())
	}
}

// SetNextError sets the error override for the next presentation of owners.
// Nil clears it.
func (rt *Runtime) SetNextError(owners []string, e *NextErrorOverride) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.nextErrors.set(owners, e, time.Now())
}

// ConsumeNextError takes the error override for a presentation of owner.
func (rt *Runtime) ConsumeNextError(owner string) (e *NextErrorOverride, restore func()) {
	return consume(rt, rt.nextErrors, owner)
}

// SetNextNotification sets the notification override for the next credential
// offer of owners. Nil clears it.
func (rt *Runtime) SetNextNotification(owners []string, n *oid4vc.Notification) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.nextNotifications.set(owners, n, time.Now())
}

// ConsumeNextNotification takes the notification override for an offer of
// owner.
func (rt *Runtime) ConsumeNextNotification(owner string) (n *oid4vc.Notification, restore func()) {
	return consume(rt, rt.nextNotifications, owner)
}
