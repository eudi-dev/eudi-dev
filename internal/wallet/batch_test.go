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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

const testBatchVCT = "urn:example:batch-pid"

// storeTestBatch stores the holder copy first and attaches copies with separate
// keys, as issuance does. keys[0] must be the wallet holder key.
func storeTestBatch(t *testing.T, w *Wallet, keys []*ecdsa.PrivateKey) {
	t.Helper()
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	credEntries := make([]any, 0, len(keys))
	var holderRaw string
	for i, k := range keys {
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:    "https://issuer.example",
			VCT:       testBatchVCT,
			Claims:    map[string]any{"family_name": "Doe", "given_name": "Jane"},
			Key:       issuerKey,
			HolderKey: &k.PublicKey,
		})
		if err != nil {
			t.Fatalf("generating batch copy %d: %v", i, err)
		}
		credEntries = append(credEntries, map[string]any{"credential": raw})
		if i == 0 {
			holderRaw = raw
		}
	}
	primary := storeTestResponse(t, w, keys, map[string]any{"credentials": credEntries})
	if primary.Raw != holderRaw {
		t.Fatal("the holder copy is not the primary")
	}
}

// storeTestResponse stores a credential response as an issuance does and
// returns the primary credential.
func storeTestResponse(t *testing.T, w *Wallet, keys []*ecdsa.PrivateKey, credResp map[string]any) *StoredCredential {
	t.Helper()
	primary, _, err := w.storeIssuedCredential(credResp, credentialDelivery{proofKeys: keys, report: ignoreFindings})
	if err != nil {
		t.Fatalf("storing the credential response: %v", err)
	}
	return primary
}

// renewTestCredential stores a credential response as the renewal of id.
func renewTestCredential(t *testing.T, w *Wallet, id string, keys []*ecdsa.PrivateKey, raws ...string) *StoredCredential {
	t.Helper()
	entries := make([]any, 0, len(raws))
	for _, raw := range raws {
		entries = append(entries, map[string]any{"credential": raw})
	}
	renewed, _, err := w.storeIssuedCredential(map[string]any{"credentials": entries}, credentialDelivery{proofKeys: keys, replaceID: id, report: ignoreFindings})
	if err != nil {
		t.Fatalf("renewing %s: %v", id, err)
	}
	return renewed
}

func batchTestQuery() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{testBatchVCT}},
		"claims": []any{map[string]any{"path": []any{"family_name"}}},
	}}}
}

func TestBatchSigningKeyPrefersCopyKey(t *testing.T) {
	w := generateTestWallet(t)

	holderSigned, err := w.batchSigningKey(StoredCredential{})
	if err != nil {
		t.Fatalf("batchSigningKey for a plain credential: %v", err)
	}
	if holderSigned != w.HolderKey {
		t.Fatal("a credential with no binding key must present with the wallet holder key")
	}

	copyKey := testKey(t)
	pem, err := encodeECPrivateKeyPEM(copyKey)
	if err != nil {
		t.Fatalf("encoding the copy key: %v", err)
	}
	got, err := w.batchSigningKey(StoredCredential{BindingKeyPEM: pem})
	if err != nil {
		t.Fatalf("batchSigningKey for a batch copy: %v", err)
	}
	if !got.PublicKey.Equal(&copyKey.PublicKey) {
		t.Fatal("a batch copy must present with its own binding key")
	}
}

func TestStoreBatchSiblingsStoresEveryCopy(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	creds := w.GetCredentials()
	if len(creds) != len(keys) {
		t.Fatalf("expected %d stored copies, got %d", len(keys), len(creds))
	}
	group := creds[0].BatchGroup
	if group == "" {
		t.Fatal("the batch copies must carry a batch group")
	}
	holderCopies, keyedCopies := 0, 0
	for i := range creds {
		c := creds[i]
		if c.BatchGroup != group {
			t.Fatalf("copy %s carries a different batch group", c.ID)
		}
		if c.BindingKeyPEM == "" {
			holderCopies++
		} else {
			keyedCopies++
		}
		if w.keyBindingNotHeld(&c) {
			t.Fatalf("batch copy %s reads as not presentable, but its key is held", c.ID)
		}
	}
	if holderCopies != 1 {
		t.Fatalf("expected exactly one holder-key copy, got %d", holderCopies)
	}
	if keyedCopies != len(keys)-1 {
		t.Fatalf("expected %d copies bound to their own key, got %d", len(keys)-1, keyedCopies)
	}
}

func TestListedCredentialsCollapsesBatch(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	if got := len(w.GetCredentials()); got != len(keys) {
		t.Fatalf("the store should hold every copy: got %d, want %d", got, len(keys))
	}
	listed := w.ListedCredentials()
	if len(listed) != 1 {
		t.Fatalf("a batch should list as one credential, got %d", len(listed))
	}
	if listed[0].BindingKeyPEM != "" {
		t.Fatal("a batch should be listed by its holder-key copy")
	}
	if summary := CredentialSummary(listed[0]); summary["batch"] != true {
		t.Fatalf("the listed batch should carry the batch flag, got %v", summary["batch"])
	}
}

func TestRemoveCredentialRemovesWholeBatch(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	rep := w.ListedCredentials()[0]
	if !w.RemoveCredential(rep.ID) {
		t.Fatal("removing the batch reported nothing removed")
	}
	for _, c := range w.GetCredentials() {
		if c.VCT == testBatchVCT {
			t.Fatalf("copy %s survived deleting the batch", c.ID)
		}
	}
}

func TestIssueCredentialBatchMintsEveryCopy(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	res, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           testBatchVCT,
		BatchSize:     3,
		StatusListURI: &noStatus,
	})
	if err != nil {
		t.Fatalf("issuing a batch: %v", err)
	}
	group := res.Credential.BatchGroup
	if group == "" {
		t.Fatal("the issued batch carries no group")
	}

	holderCopies, keyedCopies := 0, 0
	seenKeys := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		if c.BatchGroup != group {
			continue
		}
		if c.BindingKeyPEM == "" {
			holderCopies++
		} else {
			keyedCopies++
		}
		binding := credentialHolderBinding(c.Raw)
		if binding.Key == nil {
			t.Fatalf("copy %s is not holder bound", c.ID)
		}
		kid := mock.KeyIDForPublicKey(binding.Key)
		if seenKeys[kid] {
			t.Fatalf("two copies share holder key %s, which would link them", kid)
		}
		seenKeys[kid] = true
		if w.keyBindingNotHeld(&c) {
			t.Fatalf("issued batch copy %s is not presentable", c.ID)
		}
	}
	if holderCopies != 1 {
		t.Fatalf("a batch has exactly one holder-key copy, got %d", holderCopies)
	}
	if keyedCopies != 2 {
		t.Fatalf("a batch of 3 has two copies on their own key, got %d", keyedCopies)
	}
}

func TestIssueCredentialBatchGivesEachCopyAnOwnStatusIndex(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	statusURL := w.StatusListURL()
	// Batch copies get distinct status indices even with an explicit starting
	// index. A shared index would correlate them.
	explicit := 0
	if _, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           testBatchVCT,
		BatchSize:     3,
		StatusListURI: &statusURL,
		StatusListIdx: &explicit,
	}); err != nil {
		t.Fatalf("issuing a batch with status: %v", err)
	}

	seen := make(map[int]bool)
	count := 0
	for _, c := range w.GetCredentials() {
		if c.VCT != testBatchVCT {
			continue
		}
		count++
		entry, ok := w.StatusEntryFor(c.ID)
		if !ok {
			t.Fatalf("copy %s has no status entry", c.ID)
		}
		if seen[entry.Index] {
			t.Fatalf("two copies share status index %d, which would link them", entry.Index)
		}
		seen[entry.Index] = true
	}
	if count != 3 {
		t.Fatalf("want 3 copies, got %d", count)
	}
}

func TestIssueCredentialBatchRejectsPlainJWT(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	if _, err := w.IssueCredential(IssueOptions{
		Format:        "jwt",
		VCT:           testBatchVCT,
		BatchSize:     2,
		StatusListURI: &noStatus,
	}); err == nil {
		t.Fatal("a batch of a plain JWT VC has no holder binding and must be rejected")
	}
}

func TestRenewalKeepsBatchMembership(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)
	rep := w.ListedCredentials()[0]
	group := rep.BatchGroup
	if group == "" {
		t.Fatal("the batch has no group to keep")
	}

	// The renewed holder credential stays in its batch. Otherwise it would show
	// and rotate on its own.
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	freshRaw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       testBatchVCT,
		Claims:    map[string]any{"family_name": "Doe", "given_name": "Jane"},
		Key:       issuerKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("signing the renewed copy: %v", err)
	}
	freshCopies := []string{freshRaw}
	for _, k := range keys[1:] {
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:    "https://issuer.example",
			VCT:       testBatchVCT,
			Claims:    map[string]any{"family_name": "Doe", "given_name": "Jane"},
			Key:       issuerKey,
			HolderKey: &k.PublicKey,
		})
		if err != nil {
			t.Fatalf("signing a renewed copy: %v", err)
		}
		freshCopies = append(freshCopies, raw)
	}
	renewed := renewTestCredential(t, w, rep.ID, keys, freshCopies...)
	if renewed.BatchGroup != group {
		t.Fatalf("renewal dropped the batch group: got %q, want %q", renewed.BatchGroup, group)
	}
	if listed := w.ListedCredentials(); len(listed) != 1 {
		t.Fatalf("after renewal the batch lists as %d credentials, want 1", len(listed))
	}
	if n := w.BatchGroupSize(group); n != len(keys) {
		t.Fatalf("after renewal the batch holds %d copies, want %d", n, len(keys))
	}
}

func TestBatchCopyHolderBindingReadsAsHeld(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	// Every batch copy shows as bound to this wallet, including copies with
	// separate keys.
	for _, c := range w.GetCredentials() {
		if c.VCT != testBatchVCT {
			continue
		}
		if got := w.credentialHolderBindingState(c); got != holderBindingThisWallet {
			t.Fatalf("copy %s (own key: %v) reads as %q, want %q", c.ID, c.BindingKeyPEM != "", got, holderBindingThisWallet)
		}
	}
}

func TestSetCredentialStatusRevokesWholeBatch(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	// Each copy carries its own status index. A shared index would let a
	// verifier link two presentations.
	idx := 0
	for _, c := range w.GetCredentials() {
		if c.VCT == testBatchVCT {
			w.RegisterStatusEntry(c.ID, idx)
			idx++
		}
	}

	rep := w.ListedCredentials()[0]
	if _, ok := w.SetCredentialStatus(rep.ID, 1); !ok {
		t.Fatal("revoking the batch reported failure")
	}
	for _, c := range w.GetCredentials() {
		if c.VCT != testBatchVCT {
			continue
		}
		entry, ok := w.StatusEntryFor(c.ID)
		if !ok || entry.Status != 1 {
			t.Fatalf("copy %s was not revoked with the batch (entry %+v ok=%v)", c.ID, entry, ok)
		}
	}
}

func TestBatchPresentsEachCopyOnceThenReuses(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	pubByID := make(map[string]*ecdsa.PublicKey)
	for _, c := range w.GetCredentials() {
		sk, err := w.batchSigningKey(c)
		if err != nil {
			t.Fatalf("resolving the signing key of %s: %v", c.ID, err)
		}
		pubByID[c.ID] = &sk.PublicKey
	}

	query := batchTestQuery()
	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "https://verifier.example"}}

	presentedOnce := make(map[string]int)
	for round := 0; round < len(keys); round++ {
		matches := evaluateDCQL(t, w, query)
		if len(matches) != 1 {
			t.Fatalf("round %d: a batch must read as one match, got %d", round, len(matches))
		}
		id := matches[0].CredentialID
		presentedOnce[id]++

		result, err := w.createVPTokenMap(matches, params)
		if err != nil {
			t.Fatalf("round %d: creating the presentation: %v", round, err)
		}
		token := result.TokenMap["pid"][0]
		kbJWT := token[strings.LastIndex(token, "~")+1:]
		if _, err := jws.Verify(kbJWT, pubByID[id]); err != nil {
			t.Fatalf("round %d: the KB-JWT is not signed by the presented copy's key: %v", round, err)
		}
	}

	if len(presentedOnce) != len(keys) {
		t.Fatalf("a full cycle must present each of %d copies once, saw %d distinct", len(keys), len(presentedOnce))
	}
	for id, n := range presentedOnce {
		if n != 1 {
			t.Fatalf("copy %s was presented %d times before the batch cycled", id, n)
		}
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("after exhaustion a batch still presents one copy, got %d", len(matches))
	}
	if _, err := w.createVPTokenMap(matches, params); err != nil {
		t.Fatalf("presenting an exhausted batch must reuse a copy, not fail: %v", err)
	}
	highest := 0
	for _, c := range w.GetCredentials() {
		if c.Uses > highest {
			highest = c.Uses
		}
	}
	if highest != 2 {
		t.Fatalf("the reused copy should be on its second use, got a highest use count of %d", highest)
	}
}

// A request that fails after the first copies were stored leaves no copy and
// no status entry behind.
func TestIssueCredentialFailureLeavesNoPartialBatch(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	statusURL := w.StatusListURL()
	before := len(w.GetCredentials())
	entriesBefore := len(w.StatusEntries)
	_, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           testBatchVCT,
		BatchSize:     3,
		StatusListURI: &statusURL,
		// The template is saved last, and this name is invalid.
		SaveTemplate: ".invalid",
	})
	if err == nil {
		t.Fatal("issuing with an invalid template name succeeded")
	}
	if got := len(w.GetCredentials()); got != before {
		t.Errorf("wallet holds %d credentials after the failed request, want %d", got, before)
	}
	if got := len(w.StatusEntries); got != entriesBefore {
		t.Errorf("wallet holds %d status entries after the failed request, want %d", got, entriesBefore)
	}
}

// One request issues at most MaxBatchSize copies, so a caller can't make the
// wallet sign without bound.
func TestIssueAPICapsTheBatch(t *testing.T) {
	srv := newTestServer(t, false)
	before := len(srv.wallet.GetCredentials())
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", fmt.Sprintf(`{"format": "sdjwt", "batch": %d}`, MaxBatchSize+1))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("a batch of %d answers %d, want 400", MaxBatchSize+1, resp.Code)
	}
	if after := len(srv.wallet.GetCredentials()); after != before {
		t.Errorf("the wallet holds %d credentials after the refused batch, want %d", after, before)
	}
	if resp := serverRequest(t, srv, http.MethodPost, "/api/issue", fmt.Sprintf(`{"format": "sdjwt", "batch": %d}`, MaxBatchSize)); resp.Code != http.StatusCreated {
		t.Errorf("a batch of %d answers %d: %s", MaxBatchSize, resp.Code, resp.Body.String())
	}
}

// A renewal sends a proof per key, and the issuer may bind the renewed
// credential to any of them (OID4VCI 1.0 §8.3). The credential keeps the key
// it is bound to, so its presentations stay signed with that key.
func TestRenewalKeepsTheBindingKeyOfTheRenewedCredential(t *testing.T) {
	w := generateTestWallet(t)
	cred, err := w.ImportCredential(sdJWTBoundTo(t, w, &w.HolderKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	ephemeral := testKey(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, ephemeral}
	renewTestCredential(t, w, cred.ID, keys, sdJWTBoundTo(t, w, &ephemeral.PublicKey))

	stored, _ := w.GetCredential(cred.ID)
	signer, err := w.batchSigningKey(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.PublicKey.Equal(&ephemeral.PublicKey) {
		t.Error("the renewed credential signs its key binding with a key it is not bound to")
	}
	if w.keyBindingNotHeld(&stored) {
		t.Error("the renewed credential reads as bound to a key the wallet does not hold")
	}
}
