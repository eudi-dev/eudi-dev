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

// Deferred issuance (OpenID4VCI 1.0 §9). The credential endpoint accepts the
// request and returns a transaction id. The deferred credential endpoint
// returns the credential once it is ready.

package demorp

import (
	"crypto/ecdsa"
	"net/http"
	"time"
)

const (
	// deferredReadyDelay is long enough to show the pending state in the UI and
	// short enough to keep the demo quick.
	deferredReadyDelay  = 5 * time.Second
	deferredPollSeconds = 2
)

// deferredTicket keeps the proof keys and the grant of an accepted issuance.
// The batch is signed from them once it is ready.
type deferredTicket struct {
	holderKeys []*ecdsa.PublicKey
	granted    ticketGrant
	token      string
	readyAt    time.Time
	expires    time.Time
}

// writeIssuancePending answers a credential request or a deferred credential
// request whose credentials are not ready. OpenID4VCI 1.0 §8.3 and §9.2 require
// HTTP 202 with transaction_id and interval, which is "REQUIRED if
// transaction_id is present".
func writeIssuancePending(w http.ResponseWriter, transactionID string) {
	writeJSON(w, http.StatusAccepted, map[string]any{
		"transaction_id": transactionID,
		"interval":       deferredPollSeconds,
	})
}

func (d *DemoRP) deferIssuance(holderKeys []*ecdsa.PublicKey, granted ticketGrant, token string) string {
	txID := randToken()
	now := time.Now()
	d.mu.Lock()
	d.pruneLocked()
	makeRoom(d.deferred, func(t *deferredTicket) time.Time { return t.expires })
	d.deferred[txID] = &deferredTicket{
		holderKeys: holderKeys,
		granted:    granted,
		token:      token,
		readyAt:    now.Add(d.deferredDelay),
		expires:    now.Add(entryTTL),
	}
	d.mu.Unlock()
	return txID
}

// handleDeferredCredential is the Deferred Credential Endpoint of §9.2. It
// returns a transaction_id and an interval until the credential is ready.
// Then it returns the credentials array.
func (d *DemoRP) handleDeferredCredential(w http.ResponseWriter, r *http.Request) {

	token, _, refused := d.authorizeAccessToken(r, "/deferred_credential")
	if refused != nil {
		d.writeAccessTokenError(w, refused)
		return
	}
	var req struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_credential_request", err.Error()))
		return
	}

	d.mu.Lock()
	pending, known := d.deferred[req.TransactionID]
	if known && time.Now().After(pending.expires) {
		delete(d.deferred, req.TransactionID)
		known = false
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_transaction_id", "unknown or expired transaction id"))
		return
	}
	// Only the access token that started the issuance can collect the credential.
	if pending.token != token {
		_, scheme, _ := accessToken(r)
		d.writeAccessTokenError(w, &accessTokenError{scheme: scheme, code: "invalid_token", description: "the access token does not match this transaction"})
		return
	}

	if time.Now().Before(pending.readyAt) {
		writeIssuancePending(w, req.TransactionID)
		return
	}

	// Claim the transaction before signing. Two polls that arrive at the same
	// time then issue the batch only once.
	d.mu.Lock()
	_, stillPending := d.deferred[req.TransactionID]
	delete(d.deferred, req.TransactionID)
	d.mu.Unlock()
	if !stillPending {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_transaction_id", "the credential was already collected"))
		return
	}
	credentials, err := d.signBatch(pending.holderKeys, pending.granted)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": credentials})
}
