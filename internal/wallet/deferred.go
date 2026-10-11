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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// DeferredIssuance is stored on its own because issuance may take hours. It
// holds everything the poller needs after the original flow ends.
type DeferredIssuance struct {
	ID               string `json:"id"`
	TransactionID    string `json:"transaction_id"`
	DeferredEndpoint string `json:"deferred_endpoint"`
	// CredentialRenewal names the issuer, its endpoints, the configuration and
	// the client of the issuance. Collection refreshes the access token with
	// it, and the collected credential keeps it for renewal.
	CredentialRenewal
	Format string `json:"format,omitempty"`
	// VCT and DocType identify what is being issued. They come from the
	// issuer metadata, since an offer carries only configuration ids.
	VCT     string `json:"vct,omitempty"`
	DocType string `json:"doctype,omitempty"`
	// Display keeps the display metadata from the original flow until
	// collection completes.
	Display     *oid4vc.CredentialDisplay `json:"display,omitempty"`
	AccessToken string                    `json:"access_token"`
	AuthScheme  string                    `json:"auth_scheme,omitempty"`
	// AccessTokenExpiresAt tells when a long deferral needs a new access
	// token. The original token is short lived, and an issuer may ask the
	// wallet to come back in an hour.
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
	IntervalSeconds      int       `json:"interval_seconds,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	NextAttemptAt        time.Time `json:"next_attempt_at"`
	Attempts             int       `json:"attempts,omitempty"`
	LastError            string    `json:"last_error,omitempty"`
	// ProofKeyPEMs holds the binding keys from the credential request, holder
	// key first. A batch request adds ephemeral keys that exist only here, and
	// each credential is matched back to one of them.
	ProofKeyPEMs []string `json:"proof_keys,omitempty"`
}

// Interval is how long to wait between attempts, as the issuer asked.
func (p *DeferredIssuance) Interval() time.Duration {
	if p == nil || p.IntervalSeconds < 1 {
		return deferredPollInterval
	}
	return time.Duration(p.IntervalSeconds) * time.Second
}

func (p *DeferredIssuance) Expired(now time.Time) bool {
	return p != nil && now.Sub(p.CreatedAt) > deferredIssuanceMaxAge
}

const deferredIssuanceMaxAge = 24 * time.Hour

// deferredTransaction is a Credential Response that carries a transaction_id
// (OID4VCI 1.0 §8.3) together with the issuance it answers.
type deferredTransaction struct {
	transactionID string
	interval      time.Duration
	renewal       CredentialRenewal
	metadata      map[string]any
	format        string
	display       *oid4vc.CredentialDisplay
	grant         *accessGrant
	proofKeys     []*ecdsa.PrivateKey
}

// deferredInterval reads the interval of a deferred answer (OID4VCI 1.0 §8.3
// and §9.2).
func deferredInterval(resp map[string]any) time.Duration {
	if seconds, ok := numericValue(resp["interval"]); ok && seconds >= 1 {
		return time.Duration(seconds) * time.Second
	}
	return deferredPollInterval
}

func newDeferredIssuance(t deferredTransaction) (*DeferredIssuance, error) {
	endpoint, _ := t.metadata["deferred_credential_endpoint"].(string)
	if endpoint == "" {
		return nil, fmt.Errorf("issuer deferred the credential but published no deferred_credential_endpoint")
	}
	pems := make([]string, 0, len(t.proofKeys))
	for _, key := range t.proofKeys {
		encoded, err := encodeECPrivateKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("encoding proof key for the deferred credential: %w", err)
		}
		pems = append(pems, encoded)
	}
	seconds := max(int(t.interval/time.Second), 1)
	vct, docType := credentialTypeForConfiguration(t.metadata, t.renewal.ConfigurationID)
	now := time.Now()
	return &DeferredIssuance{
		ID:                   newCredentialID(),
		TransactionID:        t.transactionID,
		DeferredEndpoint:     endpoint,
		CredentialRenewal:    t.renewal,
		Format:               t.format,
		VCT:                  vct,
		DocType:              docType,
		Display:              t.display,
		AccessToken:          t.grant.accessToken,
		AuthScheme:           t.grant.authScheme,
		AccessTokenExpiresAt: t.grant.expiresAt(now),
		IntervalSeconds:      seconds,
		CreatedAt:            now,
		NextAttemptAt:        now.Add(t.interval),
		ProofKeyPEMs:         pems,
	}, nil
}

func (p *DeferredIssuance) ProofKeys() ([]*ecdsa.PrivateKey, error) {
	keys := make([]*ecdsa.PrivateKey, 0, len(p.ProofKeyPEMs))
	for _, encoded := range p.ProofKeyPEMs {
		key, err := decodeECPrivateKeyPEM(encoded)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func encodeECPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func decodeECPrivateKeyPEM(encoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, fmt.Errorf("proof key is not valid PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func (w *Wallet) AddDeferredIssuance(pending *DeferredIssuance) {
	if w == nil || pending == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.capacity.Deferred > 0 && len(w.DeferredIssuances) >= w.capacity.Deferred {
		w.DeferredIssuances = slices.Delete(w.DeferredIssuances, 0, len(w.DeferredIssuances)-w.capacity.Deferred+1)
	}
	w.DeferredIssuances = append(w.DeferredIssuances, *pending)
}

func (w *Wallet) DeferredIssuanceList() []DeferredIssuance {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]DeferredIssuance(nil), w.DeferredIssuances...)
}

func (w *Wallet) DeferredIssuanceByID(id string) (DeferredIssuance, bool) {
	if w == nil {
		return DeferredIssuance{}, false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, pending := range w.DeferredIssuances {
		if pending.ID == id {
			return pending, true
		}
	}
	return DeferredIssuance{}, false
}

func (w *Wallet) RemoveDeferredIssuance(id string) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, pending := range w.DeferredIssuances {
		if pending.ID == id {
			w.DeferredIssuances = append(w.DeferredIssuances[:i], w.DeferredIssuances[i+1:]...)
			return true
		}
	}
	return false
}

func (w *Wallet) UpdateDeferredIssuance(id string, apply func(*DeferredIssuance)) {
	if w == nil || apply == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.DeferredIssuances {
		if w.DeferredIssuances[i].ID == id {
			apply(&w.DeferredIssuances[i])
			return
		}
	}
}

// recordDeferredIssuance hands a deferred response to background collection
// and reports the issuance as successful.
func (w *Wallet) recordDeferredIssuance(pending *DeferredIssuance) *IssuanceResult {
	w.saveChange(func() bool {
		w.AddDeferredIssuance(pending)
		w.addProtocolLog("issuance", "issuance_deferred",
			fmt.Sprintf("Issuer deferred the credential, collecting it every %s", pending.Interval()), true, map[string]any{
				"issuer":         pending.Issuer,
				"transaction_id": pending.TransactionID,
				"interval":       pending.Interval().String(),
				"next_attempt":   pending.NextAttemptAt,
			})
		return true
	})
	return &IssuanceResult{
		Pending:       true,
		TransactionID: pending.TransactionID,
		RetryInterval: pending.Interval().String(),
		Issuer:        pending.Issuer,
		Format:        pending.Format,
	}
}

// credentialTypeForConfiguration reads the credential type from metadata to
// label deferred records. Offers carry only configuration IDs.
func credentialTypeForConfiguration(metadata map[string]any, configID string) (vct, docType string) {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return "", ""
	}
	config, ok := configs[configID].(map[string]any)
	if !ok {
		return "", ""
	}
	vct, _ = config["vct"].(string)
	docType, _ = config["doctype"].(string)
	return vct, docType
}

// AccessTokenExpired includes a small margin so the token does not expire
// during the request.
func (p *DeferredIssuance) AccessTokenExpired(now time.Time) bool {
	if p == nil || p.AccessTokenExpiresAt.IsZero() {
		return false
	}
	return now.Add(15 * time.Second).After(p.AccessTokenExpiresAt)
}

func (p *DeferredIssuance) CanRefresh() bool {
	return p != nil && p.RefreshToken != "" && p.TokenEndpoint != ""
}

func DeferredIssuanceSummary(p DeferredIssuance) map[string]any {
	return map[string]any{
		"id":                          p.ID,
		"transaction_id":              p.TransactionID,
		"issuer":                      p.Issuer,
		"credential_configuration_id": p.ConfigurationID,
		"format":                      p.Format,
		"vct":                         p.VCT,
		"doctype":                     p.DocType,
		"display":                     p.Display,
		"can_refresh":                 p.CanRefresh(),
		"interval":                    p.Interval().String(),
		"created_at":                  p.CreatedAt,
		"next_attempt_at":             p.NextAttemptAt,
		"attempts":                    p.Attempts,
		"last_error":                  p.LastError,
	}
}
