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
	"crypto/ecdsa"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/experimental"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

func testDelegationRecord(signed time.Time, expires *time.Time) DelegationRecord {
	return DelegationRecord{ID: newCredentialID(), Name: "Verifier", SignedAt: signed, Delegates: []DelegationDelegate{{ExpiresAt: expires}}}
}

func TestTheWalletRecordsEachSignedDelegation(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	agent := agentKey(t)
	m := newMandate(t, &agent.PublicKey, "sha-256")
	before := time.Now().Add(-time.Second)
	token, _, err := presentDelegation(t, w, cred, m.entry)
	if err != nil {
		t.Fatal(err)
	}

	stored, _ := w.GetCredential(cred.ID)
	if len(stored.Delegations) != 1 {
		t.Fatalf("the credential has %d delegation records, want 1", len(stored.Delegations))
	}
	record := stored.Delegations[0]
	if record.Chain != token || !delegate.IsChain(record.Chain) {
		t.Errorf("chain = %q, want the dSD-JWT of the answer", record.Chain)
	}
	if record.Name != "https://verifier.example" || record.ClientID != "https://verifier.example" || record.Audience != "https://verifier.example" {
		t.Errorf("name %q, client_id %q, aud %q, want the client_id of the request in each", record.Name, record.ClientID, record.Audience)
	}
	if record.Format != delegate.FormatDSDJWTKB {
		t.Errorf("format = %q, want the format of the entry", record.Format)
	}
	if record.SignedAt.Before(before) || record.SignedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("signed at %s, want the iat of the KB-SD-JWT", record.SignedAt)
	}
	if want := []string{"given_name", "family_name"}; !reflect.DeepEqual(record.Disclosed, want) {
		t.Errorf("disclosed = %v, want %v", record.Disclosed, want)
	}
	if len(record.Delegates) != 1 {
		t.Fatalf("the record has %d delegates, want 1", len(record.Delegates))
	}
	delegated := record.Delegates[0]
	thumbprint, err := keys.PublicKeyThumbprint(&agent.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if delegated.KeyThumbprint != format.EncodeBase64URL(thumbprint) || delegated.Key["kty"] != "EC" {
		t.Errorf("delegate key %q %v, want the cnf key of the payload", delegated.KeyThumbprint, delegated.Key)
	}
	if delegated.Payload["vct"] != "urn:example:agent-mandate:1" {
		t.Errorf("payload = %v, want the decoded delegate payload", delegated.Payload)
	}
	if delegated.ExpiresAt == nil || time.Until(*delegated.ExpiresAt) < 50*time.Minute {
		t.Errorf("expires at %v, want the exp of the payload", delegated.ExpiresAt)
	}
}

func TestSeveralDelegateEntriesAreOneRecord(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	first := newMandate(t, &agentKey(t).PublicKey, "sha-256")
	second := newMandate(t, &agentKey(t).PublicKey, "sha-256")
	if _, _, err := presentDelegation(t, w, cred, first.entry, second.entry); err != nil {
		t.Fatal(err)
	}
	stored, _ := w.GetCredential(cred.ID)
	if len(stored.Delegations) != 1 || len(stored.Delegations[0].Delegates) != 2 {
		t.Fatalf("records = %+v, want 1 record with 2 delegates", stored.Delegations)
	}
}

// The wallet answers with an SD-JWT+KB while Delegate SD-JWT is off.
func TestAPresentationWithoutADelegationLeavesNoRecord(t *testing.T) {
	w, cred := transactionDataWallet(t, "strict")
	if _, _, err := presentDelegation(t, w, cred, newMandate(t, &agentKey(t).PublicKey, "sha-256").entry); err != nil {
		t.Fatal(err)
	}
	stored, _ := w.GetCredential(cred.ID)
	if len(stored.Delegations) != 0 {
		t.Errorf("records = %+v, want none", stored.Delegations)
	}
	if summary := w.CredentialSummaryWithBatch(stored); summary["delegations"] != nil {
		t.Errorf("summary has delegations %v for a credential without records", summary["delegations"])
	}
}

func TestTheCredentialDetailListsActiveDelegationsFirst(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	now := time.Now().UTC().Truncate(time.Second)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	expired := testDelegationRecord(now.Add(-time.Minute), &past)
	active := testDelegationRecord(now.Add(-2*time.Hour), &future)
	unlimited := testDelegationRecord(now.Add(-3*time.Hour), nil)
	for _, record := range []DelegationRecord{expired, active, unlimited} {
		w.recordDelegation(cred.ID, record)
	}
	cred, _ = w.GetCredential(cred.ID)

	listed := w.CredentialSummaryWithBatch(cred)["delegations"]
	if want := map[string]any{"active": 2, "total": 3}; !reflect.DeepEqual(listed, want) {
		t.Errorf("listing = %v, want %v", listed, want)
	}

	detail, err := NewManagement(w, NewWalletStore(t.TempDir())).Credential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(detail["delegations"])
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Active  int
		Total   int
		Records []struct {
			ID        string
			Expired   bool
			ExpiresAt *time.Time `json:"expires_at"`
		}
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Active != 2 || got.Total != 3 || len(got.Records) != 3 {
		t.Fatalf("detail = %s, want 2 active of 3 records", encoded)
	}
	for i, want := range []struct {
		id      string
		expired bool
		expires *time.Time
	}{{active.ID, false, &future}, {unlimited.ID, false, nil}, {expired.ID, true, &past}} {
		record := got.Records[i]
		if record.ID != want.id || record.Expired != want.expired || (record.ExpiresAt == nil) != (want.expires == nil) || (want.expires != nil && !record.ExpiresAt.Equal(*want.expires)) {
			t.Errorf("record %d = %+v, want %s expired=%t expires=%v", i, record, want.id, want.expired, want.expires)
		}
	}
}

func TestACredentialKeepsALimitedNumberOfDelegationRecords(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	oldest := testDelegationRecord(now.Add(-3*time.Hour), &future)
	expired := testDelegationRecord(now.Add(-2*time.Hour), &past)
	w.recordDelegation(cred.ID, oldest)
	w.recordDelegation(cred.ID, expired)
	for range maxDelegationRecords - 2 {
		w.recordDelegation(cred.ID, testDelegationRecord(now, &future))
	}

	w.recordDelegation(cred.ID, testDelegationRecord(now, &future))
	stored, _ := w.GetCredential(cred.ID)
	if len(stored.Delegations) != maxDelegationRecords || stored.Delegations[0].ID != oldest.ID {
		t.Fatalf("%d records starting with %s, want %d without the expired one", len(stored.Delegations), stored.Delegations[0].ID, maxDelegationRecords)
	}

	w.recordDelegation(cred.ID, testDelegationRecord(now, &future))
	stored, _ = w.GetCredential(cred.ID)
	if len(stored.Delegations) != maxDelegationRecords || stored.Delegations[0].ID == oldest.ID {
		t.Fatalf("%d records, want %d without the oldest one", len(stored.Delegations), maxDelegationRecords)
	}
}

func TestABatchKeepsALimitedNumberOfDelegationRecords(t *testing.T) {
	w := generateTestWallet(t)
	storeTestBatch(t, w, []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)})
	copies := w.GetCredentials()
	future := time.Now().Add(time.Hour)
	for i := range maxDelegationRecords + 10 {
		w.recordDelegation(copies[i%len(copies)].ID, testDelegationRecord(time.Now(), &future))
	}
	if got := len(w.delegationRecords(copies[0])); got != maxDelegationRecords {
		t.Errorf("the batch has %d records, want %d", got, maxDelegationRecords)
	}
}

func TestDelegationRecordsSurviveAReload(t *testing.T) {
	backends := map[string]func(dir string) *WalletStore{
		"configured": NewWalletStore,
		"memory":     func(dir string) *WalletStore { return NewWalletStoreOn(dir, storage.NewMemory()) },
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			store := open(t.TempDir())
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			srv := NewServer(w, 0, nil)
			srv.SetStore(store)
			var id string
			srv.saveMutation(func() bool {
				id = newCredentialID()
				w.PutCredential(StoredCredential{ID: id, Format: "dc+sd-jwt", Raw: generateTestCredential(t, w)})
				return true
			})

			// The second save changes only the record.
			expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			record := testDelegationRecord(time.Now().UTC().Truncate(time.Second), &expires)
			record.Delegates[0].Payload = map[string]any{"purpose": "Order office supplies"}
			record.Chain = "a~b~~"
			w.saveChange(func() bool {
				w.recordDelegation(id, record)
				return w.takePresentationStateDirty()
			})

			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			stored, _ := reloaded.GetCredential(id)
			if !reflect.DeepEqual(stored.Delegations, []DelegationRecord{record}) {
				t.Errorf("reloaded records = %+v, want %+v", stored.Delegations, record)
			}
		})
	}
}

// Debug mode signs a delegate payload whose exp is out of range (RFC 7519
// §4.1.4). The record holds that exp to the year 9999, so the wallet still
// saves.
func TestADelegationWithAnExpOutOfRangeStillSaves(t *testing.T) {
	backends := map[string]func(dir string) *WalletStore{
		"configured": NewWalletStore,
		"memory":     func(dir string) *WalletStore { return NewWalletStoreOn(dir, storage.NewMemory()) },
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			store := open(t.TempDir())
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			mode, on := "debug", true
			if err := w.UpdateConformance(ConformancePatch{ValidationMode: &mode, Patch: experimental.Patch{TransactionData: &on, DelegateSDJWT: &on}}); err != nil {
				t.Fatal(err)
			}
			srv := NewServer(w, 0, nil)
			srv.SetStore(store)
			srv.saveMutation(func() bool {
				if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
					t.Fatal(err)
				}
				return true
			})
			i := slices.IndexFunc(w.GetCredentials(), func(c StoredCredential) bool { return c.Format == "dc+sd-jwt" })
			if i < 0 {
				t.Fatal("no SD-JWT credential")
			}
			cred := w.GetCredentials()[i]

			agent := agentKey(t)
			m := newMandate(t, &agent.PublicKey, "sha-256")
			payload := map[string]any{"vct": "urn:example:agent-mandate:1", "exp": 1e20, "cnf": map[string]any{"jwk": mock.SigningJWKMap(&agent.PublicKey)}}
			m.entry["delegate_payload_disclosure"] = testDisclosure(t, "salt-p", payload)
			delete(m.entry, "delegate_disclosures")
			w.saveChange(func() bool {
				if _, _, err := presentDelegation(t, w, cred, m.entry); err != nil {
					t.Fatal(err)
				}
				return w.takePresentationStateDirty()
			})

			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			stored, _ := reloaded.GetCredential(cred.ID)
			if len(stored.Delegations) != 1 {
				t.Fatalf("reloaded records = %+v, want 1", stored.Delegations)
			}
			if got := stored.Delegations[0].Delegates[0].ExpiresAt; got == nil || got.Year() != 9999 {
				t.Errorf("expires at %v, want the year 9999", got)
			}
		})
	}
}

func TestARenewedCredentialKeepsItsDelegationRecords(t *testing.T) {
	w := generateTestWallet(t)
	batchKeys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, batchKeys)
	rep := w.ListedCredentials()[0]
	future := time.Now().Add(time.Hour)
	var records []string
	for _, c := range w.GetCredentials() {
		record := testDelegationRecord(time.Now(), &future)
		w.recordDelegation(c.ID, record)
		records = append(records, record.ID)
	}
	if got := w.CredentialSummaryWithBatch(rep)["delegations"]; !reflect.DeepEqual(got, map[string]any{"active": 3, "total": 3}) {
		t.Fatalf("the batch lists %v, want the records of its 3 copies", got)
	}

	renewed := renewTestCredential(t, w, rep.ID, batchKeys, generateTestCredential(t, w))
	var kept []string
	for _, record := range renewed.Delegations {
		kept = append(kept, record.ID)
	}
	slices.Sort(kept)
	slices.Sort(records)
	if !reflect.DeepEqual(kept, records) {
		t.Errorf("the renewed credential has the records %v, want %v", kept, records)
	}
}

func TestARenewedBatchKeepsTheNewestDelegationRecords(t *testing.T) {
	w := generateTestWallet(t)
	batchKeys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, batchKeys)
	rep := w.ListedCredentials()[0]
	now := time.Now()
	future := now.Add(time.Hour)
	var newest []string
	for i := range 3 * 30 {
		c := w.GetCredentials()[i%3]
		record := testDelegationRecord(now.Add(time.Duration(i-90)*time.Minute), &future)
		w.recordDelegation(c.ID, record)
		if i >= 3*30-maxDelegationRecords {
			newest = append(newest, record.ID)
		}
	}

	renewed := renewTestCredential(t, w, rep.ID, batchKeys, generateTestCredential(t, w))
	var kept []string
	for _, record := range renewed.Delegations {
		kept = append(kept, record.ID)
	}
	if !reflect.DeepEqual(kept, newest) {
		t.Fatalf("the renewed credential keeps %d records %v, want the %d newest %v", len(kept), kept, maxDelegationRecords, newest)
	}

	latest := testDelegationRecord(now, &future)
	w.recordDelegation(rep.ID, latest)
	stored, _ := w.GetCredential(rep.ID)
	if got := stored.Delegations; len(got) != maxDelegationRecords || got[0].ID != newest[1] || got[len(got)-1].ID != latest.ID {
		t.Errorf("after one more delegation the records run from %s to %s, want %s to %s", got[0].ID, got[len(got)-1].ID, newest[1], latest.ID)
	}
}

// draft-ietf-oauth-status-list-21 §7.1: INVALID (0x01) means revoked, so the
// delegations of a revoked credential have ended.
func TestTheDelegationsOfARevokedCredentialHaveEnded(t *testing.T) {
	w, _ := delegateWallet(t, "strict")
	w.BaseURL = "https://wallet.example"
	issued, err := w.IssueCredential(IssueOptions{Format: "sdjwt"})
	if err != nil {
		t.Fatal(err)
	}
	cred := *issued.Credential
	future := time.Now().Add(time.Hour)
	w.recordDelegation(cred.ID, testDelegationRecord(time.Now(), &future))
	if _, managed := w.SetCredentialStatus(cred.ID, 1); !managed {
		t.Fatal("the credential has no status entry of the wallet")
	}
	detail, err := NewManagement(w, NewWalletStore(t.TempDir())).Credential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(detail["delegations"])
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Active  int
		Records []struct{ Expired, Revoked bool }
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Active != 0 || len(got.Records) != 1 || got.Records[0].Expired || !got.Records[0].Revoked {
		t.Errorf("detail = %s, want 1 revoked record and none active", encoded)
	}
}

// A shared wallet that drops the oldest copy of a batch keeps its records on
// another copy.
func TestARemovedBatchCopyKeepsItsDelegationRecords(t *testing.T) {
	w := generateTestWallet(t)
	w.Credentials = nil
	future := time.Now().Add(time.Hour)
	record := testDelegationRecord(time.Now(), &future)
	w.PutCredential(StoredCredential{ID: "a", BatchGroup: "batch", Delegations: []DelegationRecord{record}})
	w.PutCredential(StoredCredential{ID: "b", BatchGroup: "batch"})
	w.SetCapacity(Capacity{Credentials: 2})
	w.PutCredential(StoredCredential{ID: "c"})

	if _, ok := w.GetCredential("a"); ok {
		t.Fatal("the oldest copy is still stored")
	}
	kept, _ := w.GetCredential("b")
	if len(kept.Delegations) != 1 || kept.Delegations[0].ID != record.ID {
		t.Errorf("the remaining copy has the records %+v, want %s", kept.Delegations, record.ID)
	}
}
