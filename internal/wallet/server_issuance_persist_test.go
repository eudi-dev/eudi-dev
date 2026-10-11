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

// A reload must wait until a mutation has been saved. Otherwise it could replace the
// changed state with the old stored state.
func TestSaveMutationFencesOutAReload(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)
	srv.onSave = func() {}

	inside := make(chan struct{})
	release := make(chan struct{})
	reloadDone := make(chan struct{})

	go srv.saveMutation(func() bool {
		close(inside)
		<-release
		return true
	})

	<-inside
	go func() {
		_ = srv.reloadFromStore()
		close(reloadDone)
	}()

	select {
	case <-reloadDone:
		t.Fatal("a reload ran while a mutation held the store lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-reloadDone
}

// Issuance can overlap with request-triggered reloads. Saving must restore a
// credential if a reload discarded it after import.
func TestSaveIssuedCredential_SurvivesConcurrentStoreReload(t *testing.T) {
	srv := newTestServer(t, true)

	saved := 0
	srv.onSave = func() { saved++ }

	issued := StoredCredential{
		ID:     "issued-during-a-long-flow",
		Format: "dc+sd-jwt",
		VCT:    "urn:test:ticket:1",
		Raw:    "header.payload.signature",
		Claims: map[string]any{"given_name": "Alice"},
	}
	srv.wallet.RestoreCredential(issued)

	// Simulate a reload before the imported credential has been saved.
	persisted := &Wallet{PersistedState: PersistedState{Credentials: []StoredCredential{}}}
	srv.applyPersistedWalletState(persisted)
	if _, ok := srv.wallet.GetCredential(issued.ID); ok {
		t.Fatal("precondition failed: the reload should have dropped the credential")
	}

	srv.saveIssuance(&IssuanceResult{CredentialID: issued.ID, Imported: &issued})

	if _, ok := srv.wallet.GetCredential(issued.ID); !ok {
		t.Fatal("the issued credential was lost: issuance reported success and stored nothing")
	}
	if saved != 1 {
		t.Fatalf("expected exactly one save, got %d", saved)
	}
}

// Import adopts status entries for credentials on this wallet's status list. A reload
// must preserve the adopted entry so the credential can still be revoked.
func TestSaveIssuedCredential_KeepsTheAdoptedStatusEntry(t *testing.T) {
	srv := newTestServer(t, true)
	srv.onSave = func() {}
	srv.wallet.BaseURL = "https://wallet.example"
	// The wallet assigned index 22 when it issued the ticket.
	srv.wallet.StatusListCounter = 23

	issued := StoredCredential{
		ID:     "ticket-with-own-status",
		Format: "dc+sd-jwt",
		VCT:    "urn:test:ticket:1",
		Raw:    "header.payload.signature",
		Claims: map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": srv.wallet.StatusListURL(),
					"idx": 22,
				},
			},
		},
	}
	srv.wallet.RestoreCredential(issued)
	srv.wallet.adoptOwnStatusEntry(&issued)
	if _, ok := srv.wallet.StatusEntryFor(issued.ID); !ok {
		t.Fatal("precondition failed: the import should have adopted the status entry")
	}

	srv.applyPersistedWalletState(&Wallet{PersistedState: PersistedState{Credentials: []StoredCredential{}, StatusListCounter: 23}})
	if _, ok := srv.wallet.StatusEntryFor(issued.ID); ok {
		t.Fatal("precondition failed: the reload should have wiped the status entry")
	}

	srv.saveIssuance(&IssuanceResult{CredentialID: issued.ID, Imported: &issued})

	entry, ok := srv.wallet.StatusEntryFor(issued.ID)
	if !ok {
		t.Fatal("the adopted status entry was lost: the credential shows as externally governed")
	}
	if entry.Index != 22 {
		t.Fatalf("status entry index = %d, want the credential's own idx 22", entry.Index)
	}
}

func TestSaveIssuedCredential_DoesNotDuplicate(t *testing.T) {
	srv := newTestServer(t, true)
	srv.onSave = func() {}

	issued := StoredCredential{ID: "kept", Format: "dc+sd-jwt", VCT: "urn:test:ticket:1"}
	srv.wallet.RestoreCredential(issued)
	before := len(srv.wallet.GetCredentials())

	srv.saveIssuance(&IssuanceResult{CredentialID: issued.ID, Imported: &issued})

	if got := len(srv.wallet.GetCredentials()); got != before {
		t.Fatalf("credential count changed from %d to %d", before, got)
	}
}

// A reload between renewal and saving can restore the old credential and refresh
// token. Saving must recover the renewed credential and its rotated token.
func TestSaveRenewedCredential_SurvivesConcurrentStoreReload(t *testing.T) {
	srv := newTestServer(t, true)
	saved := 0
	srv.onSave = func() { saved++ }
	srv.wallet.BaseURL = "https://wallet.example"

	stale := StoredCredential{
		ID:     "renewed-mid-reload",
		Format: "dc+sd-jwt",
		VCT:    "urn:test:ticket:1",
		Raw:    "old.payload.signature",
	}
	srv.wallet.RestoreCredential(stale)

	renewed := stale
	renewed.Raw = "new.payload.signature"
	renewed.Claims = map[string]any{
		"status": map[string]any{
			"status_list": map[string]any{
				"uri": srv.wallet.StatusListURL(),
				"idx": 7,
			},
		},
	}
	renewed.Renewal = &CredentialRenewal{
		RefreshToken:       "rotated-token",
		TokenEndpoint:      "https://issuer.example/token",
		CredentialEndpoint: "https://issuer.example/credential",
	}

	srv.wallet.PutCredential(renewed)
	srv.applyPersistedWalletState(&Wallet{PersistedState: PersistedState{Credentials: []StoredCredential{stale}}})

	if err := srv.management().saveRenewed(renewed); err != nil {
		t.Fatal(err)
	}

	got, ok := srv.wallet.GetCredential(renewed.ID)
	if !ok {
		t.Fatal("the renewed credential is gone")
	}
	if got.Raw != "new.payload.signature" {
		t.Error("the reload reverted the renewal to the stale copy")
	}
	if got.Renewal == nil || got.Renewal.RefreshToken != "rotated-token" {
		t.Error("the rotated refresh token was lost")
	}
	entry, ok := srv.wallet.StatusEntryFor(renewed.ID)
	if !ok || entry.Index != 7 {
		t.Errorf("status entry = %+v (present %v), want the renewed credential's idx 7", entry, ok)
	}
	if saved != 1 {
		t.Fatalf("expected exactly one save, got %d", saved)
	}
}
