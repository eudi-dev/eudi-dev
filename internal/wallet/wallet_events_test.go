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

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
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

	errorCh, unsubErrors := w1.Consents().SubscribeErrors()
	defer unsubErrors()
	requestCh, unsubRequests := w1.Consents().Subscribe()
	defer unsubRequests()

	w2.Consents().NotifyError(consent.Error{Message: "shared error", Detail: "details"})
	w2.Consents().Create(&consent.Request{ID: "shared-request", Type: "presentation", Status: "pending"})

	select {
	case got := <-errorCh:
		if got.Message != "shared error" {
			t.Fatalf("expected shared error, got %q", got.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for shared error")
	}

	if got := w1.Consents().PeekLastError(nil); got == nil || got.Message != "shared error" {
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

	if _, ok := w1.Consents().Get("shared-request"); !ok {
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

	errorCh, unsubErrors := w1.Consents().SubscribeErrors()
	defer unsubErrors()
	requestCh, unsubRequests := w1.Consents().Subscribe()
	defer unsubRequests()

	w2.Consents().NotifyError(consent.Error{Message: "other store"})
	w2.Consents().Create(&consent.Request{ID: "other-store-request", Type: "presentation", Status: "pending"})

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

	if got := w1.Consents().PeekLastError(nil); got != nil {
		t.Fatalf("did not expect last error from other store, got %#v", got)
	}
	if _, ok := w1.Consents().Get("other-store-request"); ok {
		t.Fatal("did not expect request from other store")
	}
}

func pendingRequests(w *Wallet) []*consent.Request {
	return w.Consents().Pending()
}

// waitForPendingRequest waits until a flow running in another goroutine asks
// for consent and returns that one request.
func waitForPendingRequest(t *testing.T, w *Wallet) *consent.Request {
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
