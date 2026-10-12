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
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
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

	entries := w.StatusListCounter
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

// NextStatusIndex uses the shared backend counter when there is one.
func (w *Wallet) NextStatusIndex() (int, error) {
	w.mu.RLock()
	allocate := w.allocateStatusIndex
	w.mu.RUnlock()
	if allocate != nil {
		return allocate(w)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.StatusListCounter
	w.StatusListCounter++
	return idx, nil
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
	case "mso_mdoc":
		doc, err := mdoc.Parse(c.Raw)
		if err != nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.Status == nil {
			return nil
		}
		return statuslist.ExtractStatusRef(map[string]any{"status": doc.IssuerAuth.MSO.Status})
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
