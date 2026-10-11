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
)

// maxBatchProofKeys caps the proof keys so an advertised batch_size cannot make
// requests arbitrarily large. Separate keys support EUDI ARF method C.
const maxBatchProofKeys = 8

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
	return batchProofKeys(holderKey, metadata, maxBatchProofKeys)
}

// batchProofKeys returns the holder key and fresh keys for up to wanted
// copies, as many as the issuer's batch_size allows.
func batchProofKeys(holderKey *ecdsa.PrivateKey, metadata map[string]any, wanted int) ([]*ecdsa.PrivateKey, error) {
	keys := []*ecdsa.PrivateKey{holderKey}
	batchSize := advertisedBatchSize(metadata)
	count := min(batchSize, wanted, maxBatchProofKeys)
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
	raw           string
	bindingKeyPEM string
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
		if _, err := w.parseDetectedFormat(strings.TrimSpace(c.raw), "", pem); err != nil {
			deviations = append(deviations, fmt.Sprintf("credential %d of the response cannot be read: %v", c.position, err))
			continue
		}
		batch.copies = append(batch.copies, batchCopy{raw: c.raw, bindingKeyPEM: pem})
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

// storeBatchCopies stores batch copies under one group with the primary,
// each with its own binding key, for EUDI ARF method C (Annex 2 Topic 10,
// ISSU_51-54).
//
// A presentation clone keeps only the primary copy. The credential sink has
// already forwarded it to the real wallet without the batch group, so copies
// stored there would be disconnected from it.
func (w *Wallet) storeBatchCopies(primary *StoredCredential, copies []batchCopy, display *CredentialDisplay) ([]*StoredCredential, error) {
	stored := []*StoredCredential{primary}
	if len(copies) == 0 {
		return stored, nil
	}
	if w.credentialSink != nil {
		log.Printf("[VCI] Batch issued during a presentation is kept as its primary copy only")
		return stored, nil
	}
	group := newCredentialID()
	w.setBatchFields(primary.ID, group, primary.BindingKeyPEM)
	primary.BatchGroup = group

	for _, c := range copies {
		copyCred, err := w.importBatchCopy(c.raw, group, c.bindingKeyPEM)
		if err != nil {
			return stored, fmt.Errorf("storing a batch copy: %w", err)
		}
		w.rememberDisplay(copyCred, display)
		stored = append(stored, copyCred)
	}
	log.Printf("[VCI] Stored a batch of %d copies (group %s) for one-time-use presentation", len(stored), group)
	return stored, nil
}

// replaceBatchCopies puts copies in place of the other copies of the renewed
// primary's batch. A renewal that returns fewer copies drops the rest, since
// they keep the old validity.
func (w *Wallet) replaceBatchCopies(primary *StoredCredential, copies []batchCopy) ([]*StoredCredential, error) {
	if primary.BatchGroup == "" {
		return w.storeBatchCopies(primary, copies, primary.Display)
	}
	w.mu.Lock()
	w.Credentials = slices.DeleteFunc(w.Credentials, func(c StoredCredential) bool {
		if c.BatchGroup != primary.BatchGroup || c.ID == primary.ID {
			return false
		}
		delete(w.StatusEntries, c.ID)
		return true
	})
	w.mu.Unlock()

	stored := []*StoredCredential{primary}
	for _, c := range copies {
		copyCred, err := w.importBatchCopy(c.raw, primary.BatchGroup, c.bindingKeyPEM)
		if err != nil {
			return stored, fmt.Errorf("storing a renewed batch copy: %w", err)
		}
		w.rememberDisplay(copyCred, primary.Display)
		stored = append(stored, copyCred)
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
func (w *Wallet) collapseBatchMatches(matches []CredentialMatch, credentials []StoredCredential) []CredentialMatch {
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
func chooseBatchCopy(idxs []int, matches []CredentialMatch, byID map[string]StoredCredential) int {
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
	sink := w.batchPresentedSink
	bumped := false
	for i := range w.Credentials {
		if w.Credentials[i].ID == id {
			if w.Credentials[i].BatchGroup != "" {
				w.Credentials[i].Uses++
				w.Credentials[i].LastPresentedAt = time.Now()
				w.batchDirty = true
				bumped = true
			}
			break
		}
	}
	w.mu.Unlock()
	// Auto-accept and ISO-transcript presentations run on a clone. The use is
	// recorded on the source wallet so the rotation still advances.
	if bumped && sink != nil {
		sink(id)
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
