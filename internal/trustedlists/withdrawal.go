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

package trustedlists

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
)

// WithdrawnCertificate is a certificate removed from the wallet's own trusted
// lists. ID is the SHA-256 of the certificate. Certificate is base64 DER.
type WithdrawnCertificate struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Certificate string `json:"certificate"`
	Withdrawn   int64  `json:"withdrawn"`
}

// WithdrawnList returns the withdrawn certificates.
func (t *Set) WithdrawnList() []WithdrawnCertificate {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return slices.Clone(t.additions.WithdrawnCertificates)
}

// Withdraw takes a certificate off the wallet's own trusted lists. A trust
// anchor has no issuer to revoke it, so a list operator removes it.
func (t *Set) Withdraw(cert *x509.Certificate) (WithdrawnCertificate, error) {
	if !t.Listed(cert) {
		return WithdrawnCertificate{}, errors.New("the certificate is not on a trusted list of this wallet")
	}
	sum := sha256.Sum256(cert.Raw)
	entry := WithdrawnCertificate{
		ID: hex.EncodeToString(sum[:]), Subject: cert.Subject.String(),
		Certificate: base64.StdEncoding.EncodeToString(cert.Raw), Withdrawn: time.Now().Unix(),
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.additions.WithdrawnCertificates = append(t.additions.WithdrawnCertificates, entry)
	return entry, nil
}

// Restore puts a withdrawn certificate back on the lists.
func (t *Set) Restore(id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	before := len(t.additions.WithdrawnCertificates)
	t.additions.WithdrawnCertificates = slices.DeleteFunc(t.additions.WithdrawnCertificates, func(w WithdrawnCertificate) bool { return w.ID == id })
	if len(t.additions.WithdrawnCertificates) == before {
		return fmt.Errorf("no withdrawn certificate has this ID: %w", ErrNotFound)
	}
	return nil
}

// Listed reports whether a certificate is an issuance anchor of an own list.
func (t *Set) Listed(cert *x509.Certificate) bool {
	for _, group := range t.Groups() {
		list, err := t.ReadList(t.OwnListURL(group.ID))
		if err != nil {
			continue
		}
		anchors, err := lote.Anchors(list, lote.IssuanceServices, time.Now())
		if err != nil {
			continue
		}
		if slices.ContainsFunc(anchors, cert.Equal) {
			return true
		}
	}
	return false
}

// withoutWithdrawn filters base64 DER certificates. It drops each withdrawn
// certificate and each certificate issued by one.
func (t *Set) withoutWithdrawn(certificates []string) []string {
	withdrawn := t.WithdrawnList()
	if len(withdrawn) == 0 {
		return certificates
	}
	return slices.DeleteFunc(slices.Clone(certificates), func(encoded string) bool {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return false
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		return slices.ContainsFunc(withdrawn, func(w WithdrawnCertificate) bool { return w.covers(cert) })
	})
}

// covers reports whether cert is this certificate or was issued by it.
func (w WithdrawnCertificate) covers(cert *x509.Certificate) bool {
	der, err := base64.StdEncoding.DecodeString(w.Certificate)
	if err != nil {
		return false
	}
	parent, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	return parent.Equal(cert) || cert.CheckSignatureFrom(parent) == nil
}
