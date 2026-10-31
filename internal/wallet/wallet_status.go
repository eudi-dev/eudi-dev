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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

// SetCredentialStatus accepts values from 0 through 255 as draft-ietf-oauth-status-list §7
// requires. Reject values that cannot be encoded.
func (w *Wallet) SetCredentialStatus(credID string, status int) (StatusEntry, bool) {
	if status < 0 || status > 255 {
		return StatusEntry{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	// Each batch copy has a distinct status index. Revoke every copy to revoke the
	// logical credential.
	group := ""
	for _, c := range w.Credentials {
		if c.ID == credID {
			if c.Protected {
				// Revoking the shared baseline would break the demo for everyone.
				return StatusEntry{}, false
			}
			group = c.BatchGroup
			break
		}
	}

	ids := []string{credID}
	if group != "" {
		ids = ids[:0]
		for _, c := range w.Credentials {
			if c.BatchGroup != group {
				continue
			}
			if c.Protected {
				return StatusEntry{}, false
			}
			ids = append(ids, c.ID)
		}
	}

	entry, ok := w.StatusEntries[credID]
	if !ok {
		return StatusEntry{}, false
	}
	for _, id := range ids {
		e, ok := w.StatusEntries[id]
		if !ok {
			continue
		}
		e.Status = status
		w.StatusEntries[id] = e
		if id == credID {
			entry = e
		}
	}
	return entry, true
}

// BuildStatusList allocates enough bits for every stored status value, as §7 requires. A
// fixed one-bit list cannot represent SUSPENDED correctly.
func (w *Wallet) BuildStatusList() (int, []byte) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	maxStatus := 0
	for _, entry := range w.StatusEntries {
		if entry.Index >= 0 && entry.Status > maxStatus {
			maxStatus = entry.Status
		}
	}
	bits, err := statuslist.BitsForStatus(maxStatus)
	if err != nil {
		// The API rejects values outside 0..255. If stored state contains one anyway,
		// use the widest permitted entry width.
		bits = 8
	}

	entries := statusListSize(w.StatusListCounter)
	numBytes := (entries*bits + 7) / 8
	// The 16-byte minimum is a wallet choice. The specification sets no minimum, but a
	// list with only one entry would identify the credential being checked.
	if numBytes < 16 {
		numBytes = 16
	}
	bitstring := make([]byte, numBytes)
	capacity := len(bitstring) * 8 / bits

	for _, entry := range w.StatusEntries {
		if entry.Status == 0 {
			continue
		}
		// Imported indices are untrusted. A negative index can pass an upper-bound
		// check and panic during a bit shift.
		if entry.Index < 0 || entry.Index >= capacity {
			continue
		}
		bitPos := entry.Index * bits
		mask := (1 << bits) - 1
		bitstring[bitPos/8] |= byte((entry.Status & mask) << (bitPos % 8))
	}

	return bits, bitstring
}

// NextStatusIndex allocates an index on the wallet's own status list. HAIP
// 1.0 §6.1: "Each Credential MUST have its own unique, unpredictable status
// list index". The wallet counts allocations, with the shared backend counter
// when there is one, and maps each count to an index with a keyed
// permutation. Distinct counts give distinct indices, also across servers on
// one database.
func (w *Wallet) NextStatusIndex() (int, error) {
	for {
		n, err := w.nextStatusAllocation()
		if err != nil {
			return 0, err
		}
		idx := w.statusIndexFor(n)
		// An entry assigned in counting order can hold the index already.
		if !w.statusIndexHeld(idx) {
			return idx, nil
		}
	}
}

func (w *Wallet) nextStatusAllocation() (int, error) {
	w.mu.RLock()
	allocate := w.allocateStatusIndex
	w.mu.RUnlock()
	if allocate != nil {
		return allocate(w)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.StatusListCounter
	w.StatusListCounter++
	return n, nil
}

func (w *Wallet) statusIndexHeld(idx int) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, entry := range w.StatusEntries {
		if entry.Index == idx {
			return true
		}
	}
	return false
}

// minStatusListBits sizes the smallest list at 128 entries. BuildStatusList
// writes at least 16 bytes.
const minStatusListBits = 7

// statusRange returns the power of two range that holds allocation or index
// n: its start and its width in bits. The permutation keeps every index in
// the range of its allocation, so the list grows with the allocations.
func statusRange(n int) (start, width int) {
	if n < 1<<minStatusListBits {
		return 0, minStatusListBits
	}
	width = bits.Len(uint(n)) - 1
	return 1 << width, width
}

// statusListSize is the number of entries that covers the first count
// allocations.
func statusListSize(count int) int {
	if count <= 1<<minStatusListBits {
		return 1 << minStatusListBits
	}
	start, width := statusRange(count - 1)
	return start + 1<<width
}

func (w *Wallet) statusIndexFor(n int) int {
	start, width := statusRange(n)
	return start + int(w.statusIndexKey().permute(width, uint64(n-start), false))
}

// statusAllocation is the inverse of statusIndexFor.
func (w *Wallet) statusAllocation(idx int) int {
	start, width := statusRange(idx)
	return start + int(w.statusIndexKey().permute(width, uint64(idx-start), true))
}

// statusIndexKey keys the permutation with a secret shared by every server
// of the wallet. Without the issuer key the order stays unique.
func (w *Wallet) statusIndexKey() statusPermutation {
	w.mu.RLock()
	defer w.mu.RUnlock()
	mac := hmac.New(sha256.New, []byte("eudi-dev status list index"))
	if w.IssuerKey != nil {
		if secret, err := w.IssuerKey.Bytes(); err == nil {
			mac.Write(secret)
		}
	}
	return mac.Sum(nil)
}

// statusPermutation is a Feistel network with cycle walking over the
// numbers of a given bit width.
type statusPermutation []byte

const statusPermutationRounds = 4

func (k statusPermutation) permute(width int, x uint64, inverse bool) uint64 {
	half := uint((width + 1) / 2)
	mask := uint64(1)<<half - 1
	for {
		l, r := x>>half, x&mask
		if inverse {
			for round := statusPermutationRounds - 1; round >= 0; round-- {
				l, r = r^k.round(width, round, l)&mask, l
			}
		} else {
			for round := range statusPermutationRounds {
				l, r = r, l^k.round(width, round, r)&mask
			}
		}
		x = l<<half | r
		if x < 1<<uint(width) {
			return x
		}
	}
}

func (k statusPermutation) round(width, round int, half uint64) uint64 {
	mac := hmac.New(sha256.New, k)
	var input [10]byte
	input[0], input[1] = byte(width), byte(round)
	binary.BigEndian.PutUint64(input[2:], half)
	mac.Write(input[:])
	return binary.BigEndian.Uint64(mac.Sum(nil))
}

// ownStatusIndex picks the index of a new credential on the wallet's own
// status list. The wallet assigns the indices. A request can only take an
// assigned index if no other credential holds it, because a status change
// applies to every credential on the index. Batch copies each take a fresh
// index, because a shared index would link their presentations.
func (w *Wallet) ownStatusIndex(requested *int, batch bool) (int, error) {
	if requested == nil || batch {
		return w.NextStatusIndex()
	}
	if err := w.statusIndexFree(*requested, ""); err != nil {
		return 0, err
	}
	return *requested, nil
}

// statusIndexFree reports why credID cannot hold idx on the wallet's own
// status list. Copies of one batch may share an index. The list covers only
// the indices assigned by the wallet.
func (w *Wallet) statusIndexFree(idx int, credID string) error {
	allocation := -1
	if idx >= 0 {
		allocation = w.statusAllocation(idx)
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if allocation < 0 || allocation >= w.StatusListCounter {
		return fmt.Errorf("status index %d was not assigned by the wallet. Leave out the index to let the wallet assign one", idx)
	}
	group := ""
	for _, c := range w.Credentials {
		if c.ID == credID {
			group = c.BatchGroup
		}
	}
	for id, entry := range w.StatusEntries {
		if entry.Index != idx || id == credID {
			continue
		}
		if group != "" && slices.ContainsFunc(w.Credentials, func(c StoredCredential) bool { return c.ID == id && c.BatchGroup == group }) {
			continue
		}
		return fmt.Errorf("status index %d belongs to another credential", idx)
	}
	return nil
}

// Reject negative indices because imported credentials supply them.
func (w *Wallet) registerStatusEntry(credID string, idx int) {
	if idx < 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.StatusEntries == nil {
		w.StatusEntries = make(map[string]StatusEntry)
	}
	w.StatusEntries[credID] = StatusEntry{Index: idx, Status: 0}
}

func (w *Wallet) RegisterStatusEntry(credID string, idx int) {
	w.registerStatusEntry(credID, idx)
}

func (w *Wallet) StatusEntryFor(credID string) (StatusEntry, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry, ok := w.StatusEntries[credID]
	return entry, ok
}

// CredentialStatusRef reads the status claim of a JWT credential or the MSO status
// of an mdoc.
func CredentialStatusRef(c StoredCredential) *statuslist.StatusRef {
	switch c.Format {
	case credtype.FormatMDOC:
		doc, err := mdoc.Parse(c.Raw)
		if err != nil || doc.StatusClaims() == nil {
			return nil
		}
		return statuslist.ExtractStatusRef(doc.StatusClaims())
	default:
		return statuslist.ExtractStatusRef(c.Claims)
	}
}

// CredentialStatusInfo returns nil without a status reference or managed entry.
func (w *Wallet) CredentialStatusInfo(c StoredCredential) map[string]any {
	ref := CredentialStatusRef(c)
	entry, managed := w.StatusEntryFor(c.ID)
	if ref == nil && !managed {
		return nil
	}
	info := map[string]any{"managed": managed}
	if ref != nil {
		if ref.Invalid != "" {
			// Report malformed status_list objects as invalid. Partially parsed fields
			// could look like a usable reference.
			info["error"] = ref.Invalid
		} else {
			info["uri"] = ref.URI
			info["idx"] = ref.Idx
		}
	}
	if managed {
		info["status"] = entry.Status
		info["statusName"] = statuslist.StatusName(entry.Status)
	}
	return info
}

func (w *Wallet) CredentialSummaryWithStatus(c StoredCredential) map[string]any {
	summary := CredentialSummary(c)
	if info := w.CredentialStatusInfo(c); info != nil {
		summary["status"] = info
	}
	summary["certificate_status"] = w.certificateStatus(c)
	// Report missing signing capability only when the wallet cannot present the
	// credential.
	if w.keyBindingNotHeld(&c) {
		summary["key_binding_not_held"] = true
	}
	summary["holder_binding"] = w.credentialHolderBindingState(c)
	return summary
}

// CredentialSummaryWithBatch adds batch counts for list and detail responses. Issue and
// import responses use the plain status summary.
func (w *Wallet) CredentialSummaryWithBatch(c StoredCredential) map[string]any {
	summary := w.CredentialSummaryWithStatus(c)
	if c.BatchGroup != "" {
		summary["batch_size"] = w.BatchGroupSize(c.BatchGroup)
	}
	return summary
}

// checkRemoteStatus fetches the status list of a credential from another
// issuer. The revocation service of the trusted list that anchors the
// credential anchors its status list. A valid signature alone does not
// establish trust.
func (w *Wallet) checkRemoteStatus(cred StoredCredential, ref *statuslist.StatusRef) (*statuslist.StatusResult, error) {
	return w.checkStatusWithAnchors(cred, ref, w.StatusListAnchors(cred.Raw))
}

func (w *Wallet) checkStatusWithAnchors(cred StoredCredential, ref *statuslist.StatusRef, anchors []*x509.Certificate) (*statuslist.StatusResult, error) {
	opts := statuslist.CheckOptions{HTTPClient: w.HTTPClient(), Prefer: statuslist.FormatForCredential(cred.Format)}
	for _, anchor := range anchors {
		opts.CandidateAnchors = append(opts.CandidateAnchors, statuslist.TrustCert{Raw: anchor.Raw})
	}
	return statuslist.CheckWithOptions(ref, opts)
}

// ownStatusAt is the status at an index of the wallet's own status list.
// An index without an entry is valid, as BuildStatusList publishes it.
func (w *Wallet) ownStatusAt(idx int) int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, entry := range w.StatusEntries {
		if entry.Index == idx {
			return entry.Status
		}
	}
	return 0
}
