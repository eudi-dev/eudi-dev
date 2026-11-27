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
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
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

// Forgetting one browser's error keeps the errors of the others and an error
// stored before the flow started.
func TestRuntime_ForgetError(t *testing.T) {
	rt := NewRuntime()
	rt.NotifyError(Error{Message: "older", Owner: "browser-1"})
	time.Sleep(2 * time.Millisecond)
	started := time.Now()
	rt.ForgetError("browser-1", started)
	if e := rt.PeekLastError([]string{"browser-1"}); e == nil || e.Message != "older" {
		t.Errorf("browser-1 sees %+v, want the older error", e)
	}

	rt.NotifyError(Error{Message: "mine", Owner: "browser-1"})
	rt.NotifyError(Error{Message: "theirs", Owner: "browser-2"})
	rt.NotifyError(Error{Message: "unowned"})

	rt.ForgetError("browser-1", started)
	if e := rt.PeekLastError([]string{"browser-1"}); e == nil || e.Message != "unowned" {
		t.Errorf("browser-1 sees %+v, want only the unowned error", e)
	}
	if e := rt.PeekLastError([]string{"browser-2"}); e == nil || e.Message != "theirs" {
		t.Errorf("browser-2 sees %+v, want its own error", e)
	}
}

func TestAnOverrideIsTakenOnce(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextError(nil, &NextErrorOverride{Error: "test_error", ErrorDescription: "desc"})

	if e, _ := rt.ConsumeNextError(""); e == nil || e.Error != "test_error" || e.ErrorDescription != "desc" {
		t.Fatalf("override = %+v, want test_error with its description", e)
	}
	if e, _ := rt.ConsumeNextError(""); e != nil {
		t.Errorf("second take = %+v, want none", e)
	}
}

// ADR-0011: visitors of a shared wallet keep their overrides apart. A caller
// without a browser, such as CI, sets the override for the next flow of any
// caller.
func TestAnOverrideGoesToTheOwnerThatSetIt(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextNotification([]string{"alice"}, &oid4vc.Notification{Event: oid4vc.NotificationFailure})

	if n, _ := rt.ConsumeNextNotification("bob"); n != nil {
		t.Fatalf("bob took %+v, want none", n)
	}
	if n, _ := rt.ConsumeNextNotification(""); n != nil {
		t.Fatalf("a flow without an owner took %+v, want none", n)
	}
	if n, _ := rt.ConsumeNextNotification("alice"); n == nil {
		t.Fatal("alice took nothing, want her override")
	}

	rt.SetNextError(nil, &NextErrorOverride{Error: "unowned"})
	rt.SetNextError([]string{"alice"}, &NextErrorOverride{Error: "alice"})
	if e, _ := rt.ConsumeNextError("alice"); e == nil || e.Error != "alice" {
		t.Fatalf("alice took %+v, want her own override first", e)
	}
	if e, _ := rt.ConsumeNextError("bob"); e == nil || e.Error != "unowned" {
		t.Fatalf("bob took %+v, want the override without an owner", e)
	}
}

// A page opened by the CLI has the browser's cookie and the CLI's owner. A
// flow of either takes the override once.
func TestAnOverrideOfTwoOwnersIsTakenOnce(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextError([]string{"cookie", "cli"}, &NextErrorOverride{Error: "both"})

	if e, _ := rt.ConsumeNextError("cli"); e == nil || e.Error != "both" {
		t.Fatalf("cli flow took %+v, want the override", e)
	}
	if e, _ := rt.ConsumeNextError("cookie"); e != nil {
		t.Errorf("cookie flow took %+v after the cli flow, want none", e)
	}
}

func TestClearingRemovesOnlyTheCallersOverride(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextError(nil, &NextErrorOverride{Error: "unowned"})
	rt.SetNextError([]string{"alice"}, &NextErrorOverride{Error: "alice"})
	rt.SetNextError([]string{"bob"}, nil)
	rt.SetNextError([]string{"alice"}, nil)

	if e, _ := rt.ConsumeNextError("alice"); e == nil || e.Error != "unowned" {
		t.Fatalf("alice took %+v after clearing, want the override without an owner", e)
	}
}

func TestAnUnusedOwnedOverrideExpires(t *testing.T) {
	o := make(overrides[NextErrorOverride])
	start := time.Now()
	o.set([]string{"alice"}, &NextErrorOverride{Error: "alice"}, start)
	o.set(nil, &NextErrorOverride{Error: "unowned"}, start)

	later := start.Add(lastErrorRetention + time.Second)
	if stored := o.take("alice", later); stored == nil || stored.value.Error != "unowned" {
		t.Fatalf("alice took %+v later, want the override without an owner", stored)
	}
}

func TestARestoreKeepsANewerOverride(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextError([]string{"alice"}, &NextErrorOverride{Error: "old"})
	_, restore := rt.ConsumeNextError("alice")
	rt.SetNextError([]string{"alice"}, &NextErrorOverride{Error: "new"})
	restore()

	if e, _ := rt.ConsumeNextError("alice"); e == nil || e.Error != "new" {
		t.Fatalf("alice took %+v, want the newer override", e)
	}
	if e, _ := rt.ConsumeNextError("alice"); e != nil {
		t.Errorf("alice took %+v after that, want none", e)
	}

	_, restore = rt.ConsumeNextError("alice")
	rt.SetNextError(nil, &NextErrorOverride{Error: "unowned"})
	restore()
	if e, _ := rt.ConsumeNextError("bob"); e == nil || e.Error != "unowned" {
		t.Fatalf("bob took %+v, want the override without an owner kept", e)
	}
}

func TestARestoredOverrideIsTakenAgain(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextError([]string{"alice"}, &NextErrorOverride{Error: "alice"})
	_, restore := rt.ConsumeNextError("alice")
	restore()

	if e, _ := rt.ConsumeNextError("alice"); e == nil || e.Error != "alice" {
		t.Fatalf("alice took %+v, want the restored override", e)
	}
}

func TestManyOwnersKeepTheOverrideWithoutAnOwner(t *testing.T) {
	rt := NewRuntime()
	rt.SetNextError(nil, &NextErrorOverride{Error: "unowned"})
	for i := range maxStoredErrors + 5 {
		rt.SetNextError([]string{fmt.Sprintf("visitor-%d", i), fmt.Sprintf("cli-%d", i)}, &NextErrorOverride{Error: "visitor"})
	}
	if len(rt.nextErrors) > maxStoredErrors {
		t.Errorf("%d overrides stored, want at most %d", len(rt.nextErrors), maxStoredErrors)
	}
	if e, _ := rt.ConsumeNextError(""); e == nil || e.Error != "unowned" {
		t.Errorf("override without an owner = %+v, want it kept", e)
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
		if received.Request.ID != "sub-test" {
			t.Errorf("wrong ID: %s", received.Request.ID)
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
		t.Fatalf("received request %s after unsubscribing", got.Request.ID)
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

// The consent dialog shows what the presentation authorizes (OpenID4VP 1.0
// §8.4).
func TestDocumentListsTransactionData(t *testing.T) {
	req := NewRequest(TypePresentation, "")
	req.TransactionData = []TransactionData{{Type: "urn:eudi:sca:payment:1", CredentialIDs: []string{"pid"}, Data: map[string]any{"payload": map[string]any{"transaction_id": "t1"}}}}
	got, _ := json.Marshal(marshal(req)["transaction_data"])
	if want := `[{"type":"urn:eudi:sca:payment:1","credential_ids":["pid"],"data":{"payload":{"transaction_id":"t1"}}}]`; string(got) != want {
		t.Errorf("transaction_data = %s, want %s", got, want)
	}
}

// An update can come before a stream reads the new request. The stream must
// still announce the request as new, or the page shows only a banner.
func TestARequestUpdatedBeforeItIsReadIsAnnouncedAsNew(t *testing.T) {
	rt := NewRuntime()
	ch, unsub := rt.Subscribe()
	defer unsub()

	if err := rt.Create(&Request{ID: "waiting", Status: StatusPending}); err != nil {
		t.Fatal(err)
	}
	rt.UpdateOptions("waiting", nil, &CredentialOptions{})

	if first := <-ch; first.Updated {
		t.Error("the new request was announced as an update")
	}
	if second := <-ch; !second.Updated {
		t.Error("the update was announced as a new request")
	}
}
