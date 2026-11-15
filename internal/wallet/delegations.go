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
	"cmp"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

// maxDelegationRecords bounds the records of one credential, and of all
// copies of a batch together. A shared credential of the public demo collects
// a record from every visitor.
const maxDelegationRecords = 50

// DelegationRecord describes one Delegate SD-JWT signed by the wallet with
// the key of a credential (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.4). The
// draft has no way to take a delegation back. A record stays until its
// credential is deleted. Beyond 50 records the wallet drops the oldest expired
// record first.
type DelegationRecord struct {
	ID string `json:"id"`
	// Name is the name of the requester when the wallet signed: its
	// registered name, the client_name of its metadata or its client_id.
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
	Audience string `json:"aud"`
	// Format is the presentation format for the Delegate Holder, dSD-JWT or
	// dSD-JWT+KB.
	Format   string    `json:"format"`
	SignedAt time.Time `json:"signed_at"`
	// Disclosed lists the claim paths of the credential in the chain.
	Disclosed []string `json:"disclosed,omitempty"`
	// Delegates has one entry for each Delegate Payload of the KB-SD-JWT.
	Delegates []DelegationDelegate `json:"delegates"`
	// Chain is the Delegate SD-JWT sent by the wallet.
	Chain string `json:"chain"`
}

// DelegationDelegate is one Delegate Payload of a record.
type DelegationDelegate struct {
	KeyThumbprint string         `json:"key_thumbprint,omitempty"`
	Key           map[string]any `json:"jwk,omitempty"`
	Payload       map[string]any `json:"payload"`
	// ExpiresAt is the exp of the payload. A delegation without exp does not
	// expire.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// expiry is the latest exp of the delegates. unlimited is true when a
// delegate has no exp.
func (r DelegationRecord) expiry() (latest time.Time, unlimited bool) {
	for _, d := range r.Delegates {
		if d.ExpiresAt == nil {
			return time.Time{}, true
		}
		if d.ExpiresAt.After(latest) {
			latest = *d.ExpiresAt
		}
	}
	return latest, false
}

func (r DelegationRecord) activeAt(now time.Time) bool {
	latest, unlimited := r.expiry()
	return unlimited || now.Before(latest)
}

// newDelegationRecord describes the Delegate SD-JWT that answers the delegate
// entries of request.
func newDelegationRecord(chain string, kbType string, entries []oid4vp.TransactionData, request *oid4vp.Request, disclosed []string) (DelegationRecord, error) {
	parsed, err := delegate.Parse(chain)
	if err != nil {
		return DelegationRecord{}, err
	}
	signed := parsed.Links[len(parsed.Links)-1].Token.Payload
	record := DelegationRecord{
		ID:        newCredentialID(),
		Name:      requesterName(request),
		ClientID:  request.ClientID,
		Audience:  jsonutil.GetString(signed, "aud"),
		Format:    delegate.FormatDSDJWT,
		Disclosed: slices.Clone(disclosed),
		Chain:     chain,
	}
	if kbType == delegate.TypeKBSDJWTKB {
		record.Format = delegate.FormatDSDJWTKB
	}
	if iat, ok := jsonutil.GetFloat64(signed, "iat"); ok {
		record.SignedAt = time.Unix(int64(iat), 0).UTC()
	}
	for _, entry := range entries {
		if _, ok := entry.Delegation(); !ok {
			continue
		}
		payload := entry.DelegatePayload()
		delegated := DelegationDelegate{
			KeyThumbprint: delegatepayload.KeyThumbprint(payload),
			Key:           jsonutil.GetMap(jsonutil.GetMap(payload, "cnf"), "jwk"),
			Payload:       payload,
		}
		if expires, ok := delegatepayload.Expiry(payload); ok {
			delegated.ExpiresAt = &expires
		}
		record.Delegates = append(record.Delegates, delegated)
	}
	return record, nil
}

// requesterName is the sender's name, as shown in the consent dialog. An
// unsigned request over the Digital Credentials API has no client_id. Its
// origin is used instead.
func requesterName(request *oid4vp.Request) string {
	return cmp.Or(oid4vp.RegisteredName(request), oid4vp.ClientMetadataName(request), request.ClientID, request.RequestOrigin)
}

// recordDelegation gathers the records of a batch on the copy that signed,
// so that the cap covers the whole batch.
func (w *Wallet) recordDelegation(credentialID string, record DelegationRecord) {
	w.mu.Lock()
	defer w.mu.Unlock()
	i := slices.IndexFunc(w.Credentials, func(c StoredCredential) bool { return c.ID == credentialID })
	if i < 0 {
		return
	}
	records := append(slices.Clone(w.Credentials[i].Delegations), record)
	if group := w.Credentials[i].BatchGroup; group != "" {
		for j := range w.Credentials {
			if c := &w.Credentials[j]; j != i && c.BatchGroup == group && len(c.Delegations) > 0 {
				records = append(records, c.Delegations...)
				c.Delegations = nil
			}
		}
	}
	w.Credentials[i].Delegations = trimDelegationRecords(records, time.Now())
	w.presentationDirty = true
}

// trimDelegationRecords sorts records by SignedAt, the oldest first. Beyond
// maxDelegationRecords it drops the oldest expired record. Without an expired
// record it drops the oldest one.
func trimDelegationRecords(records []DelegationRecord, now time.Time) []DelegationRecord {
	slices.SortStableFunc(records, func(a, b DelegationRecord) int { return a.SignedAt.Compare(b.SignedAt) })
	for len(records) > maxDelegationRecords {
		drop := max(slices.IndexFunc(records, func(r DelegationRecord) bool { return !r.activeAt(now) }), 0)
		records = slices.Delete(records, drop, drop+1)
	}
	return records
}

// moveDelegationsLocked gives the records of a batch copy that is about to
// be removed to another copy of its batch.
func (w *Wallet) moveDelegationsLocked(removed StoredCredential) {
	if removed.BatchGroup == "" || len(removed.Delegations) == 0 {
		return
	}
	for i := range w.Credentials {
		if c := &w.Credentials[i]; c.ID != removed.ID && c.BatchGroup == removed.BatchGroup {
			c.Delegations = trimDelegationRecords(slices.Concat(c.Delegations, removed.Delegations), time.Now())
			return
		}
	}
}

// delegationRecords returns the records of a credential, the newest first.
// A batch is one credential to the user, so its copies share their records.
func (w *Wallet) delegationRecords(cred StoredCredential) []DelegationRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.delegationRecordsLocked(cred)
}

func (w *Wallet) delegationRecordsLocked(cred StoredCredential) []DelegationRecord {
	var records []DelegationRecord
	add := func(c StoredCredential) {
		records = append(records, c.Delegations...)
	}
	// A credential outside a batch holds its own records. Only a batch needs
	// the scan over the copies.
	if cred.BatchGroup == "" {
		add(cred)
	} else {
		for _, c := range w.Credentials {
			if c.BatchGroup == cred.BatchGroup {
				add(c)
			}
		}
	}
	slices.SortStableFunc(records, func(a, b DelegationRecord) int { return b.SignedAt.Compare(a.SignedAt) })
	return records
}

// delegationView is a record in the API. It adds the time-dependent fields
// (expired, expires_at) and the readable form of each Delegate Payload.
type delegationView struct {
	DelegationRecord
	Expired bool `json:"expired"`
	// Revoked is true when the credential is revoked on the wallet's own
	// status list. That ends every delegation of the credential.
	Revoked bool `json:"revoked,omitempty"`
	// ExpiresAt is the latest exp of the delegates. It is absent when a
	// delegate has no exp.
	ExpiresAt *time.Time               `json:"expires_at,omitempty"`
	Delegates []delegationDelegateView `json:"delegates"`
}

type delegationDelegateView struct {
	DelegationDelegate
	Limits []delegatepayload.Limit `json:"limits,omitempty"`
}

// delegationSummary is the delegations member of a credential in the API. It
// is nil for a credential without records. withRecords adds the records, the
// active ones first.
func (w *Wallet) delegationSummary(cred StoredCredential, withRecords bool) map[string]any {
	records := w.delegationRecords(cred)
	if len(records) == 0 {
		return nil
	}
	now := time.Now()
	revoked := w.ownStatusRevoked(cred)
	views := make([]delegationView, 0, len(records))
	active := 0
	for _, record := range records {
		view := delegationView{DelegationRecord: record, Expired: !record.activeAt(now), Revoked: revoked}
		if latest, unlimited := record.expiry(); !unlimited {
			view.ExpiresAt = &latest
		}
		for _, delegated := range record.Delegates {
			view.Delegates = append(view.Delegates, delegationDelegateView{DelegationDelegate: delegated, Limits: delegatepayload.Limits(delegated.Payload)})
		}
		if !view.ended() {
			active++
		}
		views = append(views, view)
	}
	summary := map[string]any{"active": active, "total": len(records)}
	if withRecords {
		slices.SortStableFunc(views, func(a, b delegationView) int {
			if a.ended() == b.ended() {
				return 0
			}
			if a.ended() {
				return 1
			}
			return -1
		})
		summary["records"] = views
	}
	return summary
}

func (v delegationView) ended() bool { return v.Expired || v.Revoked }

// ownStatusRevoked reports a credential that is INVALID (0x01,
// draft-ietf-oauth-status-list-21 §7.1) on the wallet's own status list.
func (w *Wallet) ownStatusRevoked(cred StoredCredential) bool {
	entry, managed := w.StatusEntryFor(cred.ID)
	return managed && entry.Status == 1
}
