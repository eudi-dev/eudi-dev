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
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// MaxBatchSize caps the copies of one batch. It applies to the proof keys
// sent to an issuer, to copies issued by the wallet itself and to copies
// signed by the demo issuer in one request.
const MaxBatchSize = 8

func advertisedBatchSize(metadata map[string]any) int {
	batch, ok := metadata["batch_credential_issuance"].(map[string]any)
	if !ok {
		return 0
	}
	size, ok := batch["batch_size"].(float64)
	if !ok || size < 1 {
		return 0
	}
	return int(size)
}

// issuanceProofKeys returns the proof keys of a credential request, holder
// key first. buildCredentialProofs turns them into proofs. When the issuer
// advertises batch_size >= 2, each copy of the batch is bound to its own fresh
// key. RFC 9901 §10.1 requires this for SD-JWT batches. It is recommended for
// mdoc.
func issuanceProofKeys(holderKey *ecdsa.PrivateKey, metadata map[string]any) ([]*ecdsa.PrivateKey, error) {
	return batchProofKeys(holderKey, metadata, MaxBatchSize)
}

// batchProofKeys returns the holder key and fresh keys for up to wanted
// copies, as many as the issuer's batch_size allows.
func batchProofKeys(holderKey *ecdsa.PrivateKey, metadata map[string]any, wanted int) ([]*ecdsa.PrivateKey, error) {
	keys := []*ecdsa.PrivateKey{holderKey}
	batchSize := advertisedBatchSize(metadata)
	count := min(batchSize, wanted, MaxBatchSize)
	if count < 2 {
		return keys, nil
	}
	for len(keys) < count {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating batch proof key: %w", err)
		}
		keys = append(keys, key)
	}
	log.Printf("[VCI] Issuer advertises batch_credential_issuance (batch_size=%d), requesting %d copies", batchSize, len(keys))
	return keys, nil
}

func createProofJWTs(keys []*ecdsa.PrivateKey, audience, clientID, cNonce string, extraHeader map[string]any) ([]string, error) {
	proofs := make([]string, 0, len(keys))
	for _, key := range keys {
		proof, err := createProofJWT(key, audience, clientID, cNonce, extraHeader)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

// sortedBatch is a credential response matched to the proof keys of its
// request.
type sortedBatch struct {
	primary string
	copies  []batchCopy
}

type batchCopy struct {
	raw    string
	parsed StoredCredential
}

// sortBatch picks the primary credential of a response and the batch copies
// stored beside it. OID4VCI 1.0 §8.3: "The number of elements in the
// credentials array matches the number of keys that the Wallet has provided
// via the proofs parameter of the Credential Request, unless the Issuer
// decides to issue fewer Credentials. Each key provided by the Wallet is used
// to bind to, at most, one Credential." The array is not ordered like the
// proofs, so the binding key is read from each credential.
//
// A single credential is taken with whatever key it is bound to. Among
// several, a copy that breaks the rule above or cannot be read is a server
// deviation. Strict mode refuses the response. Debug mode warns and leaves the
// copy out. The copy bound to the holder key is the primary, or else the
// first one.
func (w *Wallet) sortBatch(credResp map[string]any, keys []*ecdsa.PrivateKey, report func(...string)) (sortedBatch, error) {
	creds := credentialStringsFromResponse(credResp)
	if len(creds) == 0 {
		return sortedBatch{}, fmt.Errorf("no credential in response")
	}
	if len(creds) == 1 {
		return sortedBatch{primary: creds[0]}, nil
	}

	var deviations []string
	type boundCopy struct {
		position int
		raw      string
		key      int
	}
	var bound []boundCopy
	usedBy := make(map[int]int, len(keys))
	for i, raw := range creds {
		position := i + 1
		key := proofKeyIndex(raw, keys)
		if key < 0 {
			deviations = append(deviations, fmt.Sprintf("OID4VCI 1.0 §8.3: credential %d of the response is bound to none of the proof keys of the request", position))
			continue
		}
		if other, used := usedBy[key]; used {
			deviations = append(deviations, fmt.Sprintf("OID4VCI 1.0 §8.3: credentials %d and %d of the response are bound to the same proof key, and each key binds at most one credential", other, position))
			continue
		}
		usedBy[key] = position
		bound = append(bound, boundCopy{position: position, raw: raw, key: key})
	}

	primary := -1
	for i, c := range bound {
		if c.key == 0 {
			primary = i
		}
	}
	if primary < 0 && len(bound) > 0 {
		primary = 0
	}
	batch := sortedBatch{}
	for i, c := range bound {
		if i == primary {
			batch.primary = c.raw
			continue
		}
		pem, err := encodeECPrivateKeyPEM(keys[c.key])
		if err != nil {
			return sortedBatch{}, fmt.Errorf("encoding the binding key of credential %d: %w", c.position, err)
		}
		parsed, err := w.parseDetectedFormat(strings.TrimSpace(c.raw), "", pem)
		if err != nil {
			deviations = append(deviations, fmt.Sprintf("credential %d of the response cannot be read: %v", c.position, err))
			continue
		}
		batch.copies = append(batch.copies, batchCopy{raw: c.raw, parsed: parsed})
	}

	for _, deviation := range deviations {
		if err := w.reportServerDeviation(deviation); err != nil {
			return sortedBatch{}, err
		}
	}
	report(deviations...)
	if batch.primary == "" {
		return sortedBatch{}, fmt.Errorf("none of the %d credentials of the response is bound to a proof key of the request", len(creds))
	}
	if len(batch.copies) > 0 {
		log.Printf("[VCI] Matched %d batch credential(s) to distinct proof keys", len(batch.copies)+1)
	}
	return batch, nil
}

func proofKeyIndex(raw string, keys []*ecdsa.PrivateKey) int {
	for i := range keys {
		if credentialBindsToKey(raw, &keys[i].PublicKey) {
			return i
		}
	}
	return -1
}

// primaryBindingKeyPEM returns the PEM of the credential's binding key when it
// is not the holder key (index 0), and "" otherwise. The holder key needs no
// per-copy record because batchSigningKey falls back to it.
func primaryBindingKeyPEM(raw string, keys []*ecdsa.PrivateKey) string {
	if idx := proofKeyIndex(raw, keys); idx > 0 {
		if pem, err := encodeECPrivateKeyPEM(keys[idx]); err == nil {
			return pem
		}
	}
	return ""
}

// storeIssuedBatch stores a received credential with its batch copies under
// one group, each copy with its own binding key, for EUDI ARF method C (Annex
// 2 Topic 10, ISSU_51-54). The caller holds the store lock.
func (w *Wallet) storeIssuedBatch(primary StoredCredential, copies []batchCopy, display *oid4vc.CredentialDisplay, renewal CredentialRenewal) []StoredCredential {
	if len(copies) > 0 {
		primary.BatchGroup = newCredentialID()
	}
	if renewal.renewable() {
		primary.Renewal = &renewal
	}
	primary.Display = display
	stored := []StoredCredential{primary}
	for _, c := range copies {
		copyCred := c.parsed
		copyCred.BatchGroup = primary.BatchGroup
		copyCred.Display = display
		stored = append(stored, copyCred)
	}
	w.mu.Lock()
	for _, c := range stored {
		w.makeCredentialRoomLocked()
		w.Credentials = append(w.Credentials, c)
	}
	w.mu.Unlock()
	for i := range stored {
		w.adoptOwnStatusEntry(&stored[i])
	}
	if len(copies) > 0 {
		log.Printf("[VCI] Stored a batch of %d copies (group %s) for one-time-use presentation", len(stored), primary.BatchGroup)
	}
	return stored
}

// storeRenewedBatch puts a renewed credential in place of the one with id
// and its copies in place of the other copies of that batch. The wallet's
// bookkeeping of the credential (protection, display, batch, use count) and
// its place stay. A renewal that returns fewer copies drops the rest, since
// they keep the old validity. The caller holds the store lock.
func (w *Wallet) storeRenewedBatch(id string, fresh StoredCredential, copies []batchCopy, renewal CredentialRenewal) ([]StoredCredential, error) {
	w.mu.Lock()
	i := slices.IndexFunc(w.Credentials, func(c StoredCredential) bool { return c.ID == id })
	if i < 0 {
		w.mu.Unlock()
		return nil, fmt.Errorf("credential %s not found", id)
	}
	old := w.Credentials[i]
	fresh.ID = id
	fresh.Protected = old.Protected
	fresh.Renewal = &renewal
	fresh.Display = old.Display
	fresh.BatchGroup = old.BatchGroup
	fresh.Uses = old.Uses
	fresh.LastPresentedAt = old.LastPresentedAt
	if fresh.BatchGroup == "" && len(copies) > 0 {
		fresh.BatchGroup = newCredentialID()
	}
	w.Credentials[i] = fresh
	if old.BatchGroup != "" {
		w.deleteCredentialsLocked(func(c StoredCredential) bool { return c.BatchGroup == old.BatchGroup && c.ID != id })
	}
	stored := []StoredCredential{fresh}
	for _, c := range copies {
		copyCred := c.parsed
		copyCred.BatchGroup = fresh.BatchGroup
		copyCred.Display = fresh.Display
		w.makeCredentialRoomLocked()
		w.Credentials = append(w.Credentials, copyCred)
		stored = append(stored, copyCred)
	}
	w.mu.Unlock()

	// The renewed credential's entry on the wallet's own list replaces the
	// old one and starts valid.
	if ref := w.ownStatusRef(fresh); ref != nil {
		w.registerStatusEntry(id, ref.Idx)
	}
	for i := 1; i < len(stored); i++ {
		w.adoptOwnStatusEntry(&stored[i])
	}
	return stored, nil
}

// batchSize counts the copies of the credential's batch. A credential outside
// a batch counts as one.
func (w *Wallet) batchSize(cred StoredCredential) int {
	if cred.BatchGroup == "" {
		return 1
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	n := 0
	for _, c := range w.Credentials {
		if c.BatchGroup == cred.BatchGroup {
			n++
		}
	}
	return n
}

// collapseBatchMatches keeps one copy per batch so consent does not show
// identical copies as alternatives.
func (w *Wallet) collapseBatchMatches(matches []consent.Match, credentials []StoredCredential) []consent.Match {
	byID := make(map[string]StoredCredential, len(credentials))
	for _, c := range credentials {
		byID[c.ID] = c
	}
	groups := make(map[string][]int)
	for i, m := range matches {
		group := byID[m.CredentialID].BatchGroup
		if group == "" {
			continue
		}
		key := m.QueryID + "\x00" + group
		groups[key] = append(groups[key], i)
	}
	if len(groups) == 0 {
		return matches
	}
	keep := make(map[int]bool, len(groups))
	for _, idxs := range groups {
		keep[chooseBatchCopy(idxs, matches, byID)] = true
	}
	out := matches[:0]
	for i, m := range matches {
		if byID[m.CredentialID].BatchGroup != "" && !keep[i] {
			log.Printf("[DCQL]   query=%s: batch copy %s held back, another copy of the batch is presented", m.QueryID, m.CredentialID)
			continue
		}
		out = append(out, m)
	}
	return out
}

// chooseBatchCopy returns the index into matches of the batch copy to present.
// It picks a random copy among those presented the fewest times. Each copy is
// used once in random order before any copy is reused (EUDI ARF method C,
// ISSU_52).
func chooseBatchCopy(idxs []int, matches []consent.Match, byID map[string]StoredCredential) int {
	fewest := -1
	for _, i := range idxs {
		uses := byID[matches[i].CredentialID].Uses
		if fewest < 0 || uses < fewest {
			fewest = uses
		}
	}
	var least []int
	for _, i := range idxs {
		if byID[matches[i].CredentialID].Uses == fewest {
			least = append(least, i)
		}
	}
	return least[secureIntn(len(least))]
}

func secureIntn(n int) int {
	if n <= 1 {
		return 0
	}
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(r.Int64())
}

// recordBatchPresentation marks a batch copy as presented, so the next
// presentation of the batch prefers a copy used fewer times. It does nothing
// for a credential outside a batch.
func (w *Wallet) recordBatchPresentation(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == id {
			if w.Credentials[i].BatchGroup != "" {
				w.Credentials[i].Uses++
				w.Credentials[i].LastPresentedAt = time.Now()
				w.batchDirty = true
			}
			return
		}
	}
}

func (w *Wallet) setBatchFields(id, group, bindingKeyPEM string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == id {
			w.Credentials[i].BatchGroup = group
			w.Credentials[i].BindingKeyPEM = bindingKeyPEM
			return
		}
	}
}

// credentialStringsFromResponse extracts the credentials from a credential
// response. §8.3 defines a credentials array whose "elements of the array MUST
// be objects", each with a credential member.
func credentialStringsFromResponse(resp map[string]any) []string {
	rawCreds, ok := resp["credentials"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, entry := range rawCreds {
		object, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := object["credential"].(string); ok && c != "" {
			out = append(out, c)
		}
	}
	return out
}
