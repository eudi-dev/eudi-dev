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

package registrar

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"time"
)

// AccessCertificateStatus records an access certificate issued for a CSR, so
// that the relying party access CA can revoke it. CIR (EU) 2025/848 Article
// 9(6) requires the provider of access certificates to revoke those of a
// relying party with a cancelled registration. Annex IV point 3(e) also revokes them "when
// the content of the certificate is no longer accurate and consistent with the
// information registered".
type AccessCertificateStatus struct {
	// Serial is the hexadecimal serial number of the certificate.
	Serial     string `json:"serial"`
	Identifier string `json:"identifier"`
	Service    string `json:"service"`
	// Content identifies the registered data certified by the certificate.
	Content string `json:"content"`
	// Expires is when the certificate expires (Unix time).
	Expires int64 `json:"expires"`
	// Revoked is when the CA revoked the certificate (Unix time).
	Revoked int64 `json:"revoked,omitempty"`
	// Reason is the CRL reason code of RFC 5280 §5.3.1.
	Reason int `json:"reason,omitempty"`
}

// The CRL reason codes of RFC 5280 §5.3.1 for a changed registration and a
// deleted one.
const (
	reasonSuperseded           = 4
	reasonCessationOfOperation = 5
)

// maxTrackedAccessCertificates bounds the number of tracked valid access
// certificates per relying party.
const maxTrackedAccessCertificates = 100

// accessCertificateContent identifies the registration data copied into an
// access certificate of the service (ETSI TS 119 411-8 V1.1.1
// GEN-6.6.1-10). It is empty when the service is gone.
func accessCertificateContent(rp WalletRelyingParty, serviceIdentifier string) string {
	service, ok := serviceByIdentifier(rp, serviceIdentifier)
	if !ok {
		return ""
	}
	data, _ := json.Marshal([]any{rp.Identifier[0].Identifier, rp.LegalPerson.LegalName, rp.Country, service.ServiceIdentifier, service.ServiceTradeName, service.SupportURI})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// pruneAccessCertificatesLocked drops the records of expired certificates. A
// CRL may leave out an expired certificate (RFC 5280 §3.3). The caller holds
// r.mu.
func (r *Registrar) pruneAccessCertificatesLocked(now int64) {
	r.state.AccessCertificates = slices.DeleteFunc(r.state.AccessCertificates, func(s AccessCertificateStatus) bool { return s.Expires < now })
}

// recordAccessCertificate tracks a new access certificate. Beyond
// maxTrackedAccessCertificates valid ones of the relying party it stops
// tracking the oldest. That certificate stays valid and never goes on the
// CRL, so a client that requests many certificates is never refused.
func (r *Registrar) recordAccessCertificate(rp WalletRelyingParty, serviceIdentifier string, cert *x509.Certificate) {
	identifier := rp.Identifier[0].Identifier
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneAccessCertificatesLocked(time.Now().Unix())
	tracked := 0
	for _, s := range r.state.AccessCertificates {
		if s.Identifier == identifier && s.Revoked == 0 {
			tracked++
		}
	}
	if tracked >= maxTrackedAccessCertificates {
		// The certificates share one validity period, so the one that
		// expires first is the oldest. The stored order is lost on DB
		// backends, which sort the records by serial.
		oldest := -1
		for i, s := range r.state.AccessCertificates {
			if s.Identifier == identifier && s.Revoked == 0 && (oldest < 0 || s.Expires < r.state.AccessCertificates[oldest].Expires) {
				oldest = i
			}
		}
		r.state.AccessCertificates = slices.Delete(r.state.AccessCertificates, oldest, oldest+1)
	}
	r.state.AccessCertificates = append(r.state.AccessCertificates, AccessCertificateStatus{
		Serial:     cert.SerialNumber.Text(16),
		Identifier: identifier,
		Service:    serviceIdentifier,
		Content:    accessCertificateContent(rp, serviceIdentifier),
		Expires:    cert.NotAfter.Unix(),
	})
}

// revokeAccessCertificatesLocked revokes the valid access certificates of
// identifier whose content differs from the registration rp. A nil rp
// revokes all of them. The caller holds r.mu.
func (r *Registrar) revokeAccessCertificatesLocked(identifier string, rp *WalletRelyingParty) {
	now := time.Now().Unix()
	for i := range r.state.AccessCertificates {
		s := &r.state.AccessCertificates[i]
		if s.Identifier != identifier || s.Revoked != 0 {
			continue
		}
		switch {
		case rp == nil:
			s.Revoked, s.Reason = now, reasonCessationOfOperation
		case accessCertificateContent(*rp, s.Service) != s.Content:
			s.Revoked, s.Reason = now, reasonSuperseded
		}
	}
}

// RevokedAccessCertificates are the CRL entries of the revoked access
// certificates that have not expired.
func (r *Registrar) RevokedAccessCertificates() []x509.RevocationListEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := time.Now().Unix()
	var out []x509.RevocationListEntry
	for _, s := range r.state.AccessCertificates {
		serial, ok := new(big.Int).SetString(s.Serial, 16)
		if s.Revoked == 0 || s.Expires < now || !ok {
			continue
		}
		out = append(out, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: time.Unix(s.Revoked, 0).UTC(), ReasonCode: s.Reason})
	}
	return out
}

// accessCertificateRecords copies the access certificate records of
// identifier.
func (r *Registrar) accessCertificateRecords(identifier string) []AccessCertificateStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []AccessCertificateStatus
	for _, s := range r.state.AccessCertificates {
		if s.Identifier == identifier {
			out = append(out, s)
		}
	}
	return out
}
