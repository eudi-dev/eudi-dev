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
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRuntime_NotifyError(t *testing.T) {
	rt := NewRuntime()

	ch, unsub := rt.SubscribeErrors()
	defer unsub()

	rt.NotifyError(Error{Message: "test error", Detail: "details"})

	select {
	case received := <-ch:
		if received.Message != "test error" {
			t.Errorf("wrong message: %s", received.Message)
		}
		if received.Detail != "details" {
			t.Errorf("wrong detail: %s", received.Detail)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for error notification")
	}
}

func TestRuntime_LastError(t *testing.T) {
	rt := NewRuntime()

	if e := rt.PeekLastError(nil); e != nil {
		t.Error("expected nil before any error")
	}

	rt.NotifyError(Error{Message: "err1"})
	e := rt.PeekLastError(nil)
	if e == nil {
		t.Fatal("expected error")
	}
	if e.Message != "err1" {
		t.Errorf("wrong message: %s", e.Message)
	}

	// Polling leaves the error available until the browser dismisses it.
	if again := rt.PeekLastError(nil); again == nil {
		t.Error("expected the error to survive being read")
	}
	rt.ClearLastError(nil)
	if cleared := rt.PeekLastError(nil); cleared != nil {
		t.Error("expected nil once cleared")
	}
}

func TestRuntime_SetAndConsumeNextError(t *testing.T) {
	rt := NewRuntime()

	if e := rt.ConsumeNextError(); e != nil {
		t.Error("expected nil")
	}

	rt.SetNextError(&NextErrorOverride{Error: "test_error", ErrorDescription: "desc"})

	e := rt.ConsumeNextError()
	if e == nil {
		t.Fatal("expected error")
	}
	if e.Error != "test_error" {
		t.Errorf("wrong error: %s", e.Error)
	}
	if e.ErrorDescription != "desc" {
		t.Errorf("wrong description: %s", e.ErrorDescription)
	}

	if e2 := rt.ConsumeNextError(); e2 != nil {
		t.Error("expected nil after consume")
	}
}

func TestRuntime_CreateAndGetRequest(t *testing.T) {
	rt := NewRuntime()

	req := &Request{
		ID:       "test-id",
		Type:     "presentation",
		Status:   "pending",
		ClientID: "https://verifier.example",
	}
	rt.Create(req)

	got, ok := rt.Get("test-id")
	if !ok {
		t.Fatal("request not found")
	}
	if got.ID != "test-id" {
		t.Errorf("wrong ID: %s", got.ID)
	}
	if got.Type != "presentation" {
		t.Errorf("wrong type: %s", got.Type)
	}

	_, ok = rt.Get("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent request")
	}
}

func TestRuntime_ResolveRequest(t *testing.T) {
	rt := NewRuntime()

	rt.Create(&Request{ID: "r1", Status: "pending"})

	req, ok := rt.Resolve("r1", "approved")
	if !ok {
		t.Fatal("expected successful resolve")
	}
	if req.Status != "approved" {
		t.Errorf("expected approved, got %s", req.Status)
	}

	_, ok = rt.Resolve("r1", "denied")
	if ok {
		t.Error("expected failed resolve on non-pending request")
	}

	_, ok = rt.Resolve("nonexistent", "approved")
	if ok {
		t.Error("expected failed resolve for nonexistent request")
	}
}

func TestRuntime_Subscribe(t *testing.T) {
	rt := NewRuntime()

	ch, unsub := rt.Subscribe()
	defer unsub()

	req := &Request{ID: "sub-test", Status: "pending"}
	rt.Create(req)

	select {
	case received := <-ch:
		if received.ID != "sub-test" {
			t.Errorf("wrong ID: %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscription notification")
	}
}

func TestRuntime_Subscribe_Unsubscribe(t *testing.T) {
	rt := NewRuntime()

	ch, unsub := rt.Subscribe()
	unsub()

	rt.Create(&Request{ID: "after-unsub", Status: "pending"})

	select {
	case got := <-ch:
		t.Fatalf("received request %s after unsubscribing", got.ID)
	default:
	}
}

func TestRuntime_SubscribeErrors_Unsubscribe(t *testing.T) {
	rt := NewRuntime()

	ch, unsub := rt.SubscribeErrors()
	unsub()

	rt.NotifyError(Error{Message: "after unsub"})

	select {
	case got := <-ch:
		t.Fatalf("received error %q after unsubscribing", got.Message)
	default:
	}
}

func TestStateSubscription(t *testing.T) {
	rt := NewRuntime()
	ch, unsub := rt.SubscribeState()
	defer unsub()
	rt.NotifyStateChanged()
	select {
	case <-ch:
	default:
		t.Fatal("expected a state change signal")
	}
	rt.NotifyStateChanged()
	rt.NotifyStateChanged()
}

// Caller-selected keys must not allow the error map to grow without limit.
func TestStoredErrorsStayBounded(t *testing.T) {
	rt := NewRuntime()
	// Include the unowned slot when testing eviction.
	rt.NotifyError(Error{Message: "a client with no browser"})
	for i := 0; i < maxStoredErrors*3; i++ {
		rt.NotifyError(Error{Message: "failed", Owner: fmt.Sprintf("browser-%d", i)})
	}
	rt.mu.RLock()
	held := len(rt.lastErrors)
	rt.mu.RUnlock()
	if held > maxStoredErrors {
		t.Errorf("holding %d errors, want at most %d", held, maxStoredErrors)
	}
}

// An answered request stops waiting and frees its place under the cap.
func TestCreateRefusesRequestsBeyondTheCap(t *testing.T) {
	rt := NewRuntime()
	rt.SetMaxPending(1)
	if err := rt.Create(&Request{ID: "a", Status: StatusPending}); err != nil {
		t.Fatal(err)
	}
	if err := rt.Create(&Request{ID: "b", Status: StatusPending}); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("second request: %v, want ErrTooManyPending", err)
	}
	rt.Resolve("a", StatusExpired)
	if err := rt.Create(&Request{ID: "b", Status: StatusPending}); err != nil {
		t.Fatalf("after the first expired: %v", err)
	}
}

// One visitor cannot take every waiting slot. Requests without an owner share
// one count, and the total cap still applies.
func TestCreateRefusesRequestsBeyondTheOwnerCap(t *testing.T) {
	rt := NewRuntime()
	rt.SetMaxPending(5)
	rt.SetMaxPendingPerOwner(2)
	for _, owner := range []string{"alice", "alice", "", ""} {
		if err := rt.Create(NewRequest(TypePresentation, owner)); err != nil {
			t.Fatalf("request of %q: %v", owner, err)
		}
	}
	for _, owner := range []string{"alice", ""} {
		if err := rt.Create(NewRequest(TypePresentation, owner)); !errors.Is(err, ErrTooManyPending) {
			t.Errorf("third request of %q: %v, want ErrTooManyPending", owner, err)
		}
	}
	if err := rt.Create(NewRequest(TypePresentation, "bob")); err != nil {
		t.Fatalf("request of bob: %v", err)
	}
	if err := rt.Create(NewRequest(TypePresentation, "carol")); !errors.Is(err, ErrTooManyPending) {
		t.Errorf("request past the total cap: %v, want ErrTooManyPending", err)
	}
}
