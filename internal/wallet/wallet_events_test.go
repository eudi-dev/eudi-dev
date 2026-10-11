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
	"testing"
	"time"
)

func TestWallet_AddAndGetLog(t *testing.T) {
	w := generateTestWallet(t)
	w.AddLog("presentation", "test log 1", true)
	w.AddLog("issuance", "test log 2", false)

	logs := w.GetLog()
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].Action != "presentation" {
		t.Errorf("wrong action: %s", logs[0].Action)
	}
	if logs[0].Detail != "test log 1" {
		t.Errorf("wrong detail: %s", logs[0].Detail)
	}
	if !logs[0].Success {
		t.Error("expected success=true")
	}
	if logs[1].Action != "issuance" {
		t.Errorf("wrong action: %s", logs[1].Action)
	}
	if logs[1].Success {
		t.Error("expected success=false")
	}
}

func TestWallet_GetLog_Empty(t *testing.T) {
	w := generateTestWallet(t)
	logs := w.GetLog()
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestWallet_NotifyError(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.SubscribeErrors()
	defer unsub()

	w.NotifyError(WalletError{Message: "test error", Detail: "details"})

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

func TestWallet_LastError(t *testing.T) {
	w := generateTestWallet(t)

	if e := w.PeekLastError(nil); e != nil {
		t.Error("expected nil before any error")
	}

	w.NotifyError(WalletError{Message: "err1"})
	e := w.PeekLastError(nil)
	if e == nil {
		t.Fatal("expected error")
	}
	if e.Message != "err1" {
		t.Errorf("wrong message: %s", e.Message)
	}

	// Polling leaves the error available until the browser dismisses it.
	if again := w.PeekLastError(nil); again == nil {
		t.Error("expected the error to survive being read")
	}
	w.ClearLastError(nil)
	if cleared := w.PeekLastError(nil); cleared != nil {
		t.Error("expected nil once cleared")
	}
}

func TestWallet_SetAndConsumeNextError(t *testing.T) {
	w := generateTestWallet(t)

	if e := w.ConsumeNextError(); e != nil {
		t.Error("expected nil")
	}

	w.SetNextError(&NextErrorOverride{Error: "test_error", ErrorDescription: "desc"})

	e := w.ConsumeNextError()
	if e == nil {
		t.Fatal("expected error")
	}
	if e.Error != "test_error" {
		t.Errorf("wrong error: %s", e.Error)
	}
	if e.ErrorDescription != "desc" {
		t.Errorf("wrong description: %s", e.ErrorDescription)
	}

	if e2 := w.ConsumeNextError(); e2 != nil {
		t.Error("expected nil after consume")
	}
}

func TestWallet_CreateAndGetRequest(t *testing.T) {
	w := generateTestWallet(t)

	req := &ConsentRequest{
		ID:       "test-id",
		Type:     "presentation",
		Status:   "pending",
		ClientID: "https://verifier.example",
	}
	w.CreateConsentRequest(req)

	got, ok := w.GetRequest("test-id")
	if !ok {
		t.Fatal("request not found")
	}
	if got.ID != "test-id" {
		t.Errorf("wrong ID: %s", got.ID)
	}
	if got.Type != "presentation" {
		t.Errorf("wrong type: %s", got.Type)
	}

	_, ok = w.GetRequest("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent request")
	}
}

func TestWallet_ResolveRequest(t *testing.T) {
	w := generateTestWallet(t)

	w.CreateConsentRequest(&ConsentRequest{ID: "r1", Status: "pending"})

	req, ok := w.ResolveRequest("r1", "approved")
	if !ok {
		t.Fatal("expected successful resolve")
	}
	if req.Status != "approved" {
		t.Errorf("expected approved, got %s", req.Status)
	}

	_, ok = w.ResolveRequest("r1", "denied")
	if ok {
		t.Error("expected failed resolve on non-pending request")
	}

	_, ok = w.ResolveRequest("nonexistent", "approved")
	if ok {
		t.Error("expected failed resolve for nonexistent request")
	}
}

func TestWallet_Subscribe(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.Subscribe()
	defer unsub()

	req := &ConsentRequest{ID: "sub-test", Status: "pending"}
	w.CreateConsentRequest(req)

	select {
	case received := <-ch:
		if received.ID != "sub-test" {
			t.Errorf("wrong ID: %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscription notification")
	}
}

func TestWallet_Subscribe_Unsubscribe(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.Subscribe()
	unsub()

	w.CreateConsentRequest(&ConsentRequest{ID: "after-unsub", Status: "pending"})

	select {
	case got := <-ch:
		t.Fatalf("received request %s after unsubscribing", got.ID)
	default:
	}
}

func TestWallet_SubscribeErrors_Unsubscribe(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.SubscribeErrors()
	unsub()

	w.NotifyError(WalletError{Message: "after unsub"})

	select {
	case got := <-ch:
		t.Fatalf("received error %q after unsubscribing", got.Message)
	default:
	}
}

func TestWalletStore_LoadOrCreateSharesRuntimeForSameStore(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	w1, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate w1: %v", err)
	}
	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate w2: %v", err)
	}

	errorCh, unsubErrors := w1.SubscribeErrors()
	defer unsubErrors()
	requestCh, unsubRequests := w1.Subscribe()
	defer unsubRequests()

	w2.NotifyError(WalletError{Message: "shared error", Detail: "details"})
	w2.CreateConsentRequest(&ConsentRequest{ID: "shared-request", Type: "presentation", Status: "pending"})

	select {
	case got := <-errorCh:
		if got.Message != "shared error" {
			t.Fatalf("expected shared error, got %q", got.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for shared error")
	}

	if got := w1.PeekLastError(nil); got == nil || got.Message != "shared error" {
		t.Fatalf("expected peeked shared error, got %#v", got)
	}

	select {
	case got := <-requestCh:
		if got.ID != "shared-request" {
			t.Fatalf("expected shared request, got %q", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for shared request")
	}

	if _, ok := w1.GetRequest("shared-request"); !ok {
		t.Fatal("expected request to be visible through first wallet instance")
	}
}

func TestWalletStore_LoadOrCreateRuntimeIsolatedByStore(t *testing.T) {
	store1 := NewWalletStore(t.TempDir())
	store2 := NewWalletStore(t.TempDir())
	w1, err := store1.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate w1: %v", err)
	}
	w2, err := store2.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate w2: %v", err)
	}

	errorCh, unsubErrors := w1.SubscribeErrors()
	defer unsubErrors()
	requestCh, unsubRequests := w1.Subscribe()
	defer unsubRequests()

	w2.NotifyError(WalletError{Message: "other store"})
	w2.CreateConsentRequest(&ConsentRequest{ID: "other-store-request", Type: "presentation", Status: "pending"})

	select {
	case got := <-errorCh:
		t.Fatalf("did not expect error from other store, got %#v", got)
	case <-time.After(50 * time.Millisecond):
	}

	select {
	case got := <-requestCh:
		t.Fatalf("did not expect request from other store, got %#v", got)
	case <-time.After(50 * time.Millisecond):
	}

	if got := w1.PeekLastError(nil); got != nil {
		t.Fatalf("did not expect last error from other store, got %#v", got)
	}
	if _, ok := w1.GetRequest("other-store-request"); ok {
		t.Fatal("did not expect request from other store")
	}
}

func TestStateSubscription(t *testing.T) {
	w := generateTestWallet(t)
	ch, unsub := w.SubscribeState()
	defer unsub()
	w.NotifyStateChanged()
	select {
	case <-ch:
	default:
		t.Fatal("expected a state change signal")
	}
	w.NotifyStateChanged()
	w.NotifyStateChanged()
}

func pendingRequests(w *Wallet) []*ConsentRequest {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var out []*ConsentRequest
	for _, r := range rt.requests {
		if r.Status == "pending" {
			out = append(out, r)
		}
	}
	return out
}

// waitForPendingRequest waits until a flow running in another goroutine asks
// for consent and returns that one request.
func waitForPendingRequest(t *testing.T, w *Wallet) *ConsentRequest {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		switch pending := pendingRequests(w); len(pending) {
		case 0:
			continue
		case 1:
			return pending[0]
		default:
			t.Fatalf("%d pending consent requests, want one", len(pending))
		}
	}
	t.Fatal("no pending consent request")
	return nil
}
