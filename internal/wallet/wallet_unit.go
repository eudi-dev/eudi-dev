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
	"log"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// The wallet acts as its own wallet provider. Its wallet instance attestations
// (WIA) and key attestations (KA) carry the claims of CIR (EU) 2024/2979 Annex
// Ib, added by CIR (EU) 2026/1731, section 2(c).

// solutionVersion is the wallet_version of C_WIA-1. The cmd package sets it
// to the release of this binary.
var solutionVersion = "dev"

// SetSolutionVersion sets the wallet_version of the wallet instance
// attestation.
func SetSolutionVersion(v string) {
	if v = strings.TrimSpace(v); v != "" {
		solutionVersion = v
	}
}

// walletLink is the wallet_link of C_WIA-2: "a URI where further information
// about the wallet solution can be obtained".
const walletLink = "https://github.com/eudi-dev/eudi-dev"

// testCertificationURI explains that the wallet solution and its key storage
// are certified by nobody. C_KA-1 requires the KA certification claim to
// contain "a URL where information can be obtained about the certification".
const testCertificationURI = "https://github.com/eudi-dev/eudi-dev/blob/main/SECURITY.md"

// walletSolutionCertification is the wallet_solution_certification_information
// of C_WIA-1, "a JSON object containing information about the conformity
// assessment body that certified the wallet solution, the certification
// number, as applicable, and other relevant details". EC TS3 v1.5.2 §2.3.1
// leaves the content undefined. The values say that this is an uncertified
// test wallet.
type walletSolutionCertification struct {
	ConformityAssessmentBody string `json:"conformity_assessment_body"`
	CertificationNumber      string `json:"certification_number"`
	Details                  string `json:"details"`
}

var testWalletCertification = walletSolutionCertification{
	ConformityAssessmentBody: "none (test wallet)",
	CertificationNumber:      "TEST-UNCERTIFIED",
	Details:                  testCertificationURI,
}

// maintainedStatus is the client_status of a WIA and the key_storage_status
// of a KA: a Token Status List reference and the time until which the wallet
// provider maintains it (C_WIA-1, C_KA-1).
type maintainedStatus struct {
	Status statusReference `json:"status"`
	Exp    int64           `json:"exp"`
}

type statusReference struct {
	StatusList statusListEntry `json:"status_list"`
}

type statusListEntry struct {
	Idx int    `json:"idx"`
	URI string `json:"uri"`
}

// minStatusMaintenance covers LC_GEN-1: the wallet unit "can always present"
// attestations whose status is maintained "at least 31 days in the future at
// the time of presentation". The extra day covers the way to the issuer.
const minStatusMaintenance = 32 * 24 * time.Hour

// statusMaintenanceExp is the exp of a maintained status. With a preferred
// period of the issuer, LC_GEN_2.1 and LC_GEN_2.2 ask for an exp whose
// remaining period exceeds it by as little as possible. The wallet keeps its
// status entries for good, so it can promise any period.
func statusMaintenanceExp(now time.Time, preferredSeconds int64) int64 {
	if preferredSeconds > 0 {
		return now.Unix() + preferredSeconds
	}
	return now.Add(minStatusMaintenance).Unix()
}

// keyStorageStatusID is the status entry of the wallet's key storage. Every KA
// of the wallet shares it: R_KA_1 option 1, the "type-shared index".
const keyStorageStatusID = "key-storage"

// walletInstanceStatusID is the status entry of the wallet instance in the WIAs
// sent to one authorization server. R_WIA-1 calls this the "per-issuer reuse"
// option. R_WIA-1.3: "The wallet unit shall not reuse the same index value for
// interactions with different authorization servers".
func walletInstanceStatusID(server string) string {
	return "wallet-instance-" + shortHash(server)
}

// ownMaintainedStatus returns the maintained status of the entry id on the
// wallet's own status list. It allocates the entry on first use. Without a
// status list URL the wallet publishes no list, and ok is false.
func (w *Wallet) ownMaintainedStatus(id string, preferredSeconds int64) (status maintainedStatus, ok bool, err error) {
	uri := strings.TrimSpace(w.StatusListURL())
	if uri == "" {
		return maintainedStatus{}, false, nil
	}
	idx := 0
	w.saveChange(func() bool {
		if entry, held := w.StatusEntryFor(id); held {
			idx = entry.Index
			return false
		}
		if idx, err = w.NextStatusIndex(); err != nil {
			return false
		}
		w.registerStatusEntry(id, idx)
		return true
	})
	if err != nil {
		return maintainedStatus{}, false, fmt.Errorf("allocating the status entry %s: %w", id, err)
	}
	return maintainedStatus{
		Status: statusReference{StatusList: statusListEntry{Idx: idx, URI: uri}},
		Exp:    statusMaintenanceExp(time.Now(), preferredSeconds),
	}, true, nil
}

// clientKey is the wallet instance key proven to the authorization server of
// r: the cnf key of its WIAs and its DPoP key. ARF ISSU_35a b) asks for a
// different WIA public key per provider, so the wallet derives one key per
// authorization server from its holder key. A renewal without an
// authorization server keeps the holder key, because its tokens are bound to
// it.
func (w *Wallet) clientKey(r CredentialRenewal) *ecdsa.PrivateKey {
	if r.AuthorizationServer == "" {
		return w.HolderKeyPair()
	}
	return w.walletInstanceKey(r.AuthorizationServer)
}

func (w *Wallet) walletInstanceKey(server string) *ecdsa.PrivateKey {
	holder := w.HolderKeyPair()
	if holder == nil {
		return nil
	}
	secret, err := holder.Bytes()
	if err == nil {
		var key *ecdsa.PrivateKey
		if key, err = mock.Seed(secret).Key("wallet instance " + server); err == nil {
			return key
		}
	}
	log.Printf("[VCI] Deriving the wallet instance key for %s failed, using the holder key: %v", server, err)
	return holder
}

// walletInstanceClaims are the claims of C_WIA-1 and C_WIA-2 in a WIA sent to
// server.
func (w *Wallet) walletInstanceClaims(server string, preferredStatusSeconds int64) (map[string]any, error) {
	claims := map[string]any{
		"wallet_name":    config.WalletName,
		"wallet_version": solutionVersion,
		"wallet_link":    walletLink,
		"wallet_solution_certification_information": testWalletCertification,
	}
	status, ok, err := w.ownMaintainedStatus(walletInstanceStatusID(server), preferredStatusSeconds)
	if err != nil {
		return nil, err
	}
	if ok {
		claims["client_status"] = status
	}
	return claims, nil
}

// keyStorageClaims are the claims of C_KA-1 that describe the key storage.
// requirement is the issuer's key_attestations_required object.
func (w *Wallet) keyStorageClaims(requirement map[string]any) (map[string]any, error) {
	claims := map[string]any{"certification": testCertificationURI}
	preferred := int64(0)
	if seconds, ok := requirement["preferred_key_storage_status_period"].(float64); ok && seconds > 0 {
		preferred = int64(seconds)
	}
	status, ok, err := w.ownMaintainedStatus(keyStorageStatusID, preferred)
	if err != nil {
		return nil, err
	}
	if ok {
		claims["key_storage_status"] = status
	}
	return claims, nil
}
