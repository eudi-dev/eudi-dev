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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"testing"
	"time"
)

func issueTestAccessCertificate(t *testing.T, w *testWallet, identifier string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.IssueAccessCertificate(AccessCertificateRequest{Identifier: identifier, CSR: testAccessCSR(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func revokedSerials(w *testWallet) map[string]int {
	out := map[string]int{}
	for _, entry := range w.RevokedAccessCertificates() {
		out[entry.SerialNumber.Text(16)] = entry.ReasonCode
	}
	return out
}

// CIR (EU) 2025/848 Annex IV point 3(e): the provider revokes an access
// certificate "when the content of the certificate is no longer accurate and
// consistent with the information registered, or when the registration of
// the wallet-relying party is suspended or cancelled" (Article 9(6)).
func TestTheAccessCAWithdrawsCertificatesOfChangedOrDeletedRegistrations(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	identifier := rp.Identifier[0].Identifier
	first := issueTestAccessCertificate(t, w, identifier)
	if len(w.RevokedAccessCertificates()) != 0 {
		t.Fatal("a new access certificate is on the CRL")
	}

	rp.Services[0].IntendedUses[0].Purpose[0].Content = "Age check at the door"
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if len(w.RevokedAccessCertificates()) != 0 {
		t.Error("a change outside the access certificate revoked it")
	}

	rp.Services[0].ServiceTradeName = "Example Shop Online"
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if reason := revokedSerials(w)[first.SerialNumber.Text(16)]; reason != reasonSuperseded {
		t.Errorf("after a new trade name the first certificate has reason %d, want superseded", reason)
	}

	second := issueTestAccessCertificate(t, w, identifier)
	if err := w.DeleteRelyingParty(identifier); err != nil {
		t.Fatal(err)
	}
	if reason := revokedSerials(w)[second.SerialNumber.Text(16)]; reason != reasonCessationOfOperation {
		t.Errorf("after the deletion the second certificate has reason %d, want cessation of operation", reason)
	}
}

// A test tool never refuses another access certificate. Past the tracking
// limit the registrar forgets the oldest one, so the state stays bounded.
func TestTheRegistrarKeepsIssuingAccessCertificatesPastTheTrackingLimit(t *testing.T) {
	w := generateTestWallet(t)
	identifier := registerTestRelyingParty(t, w).Identifier[0].Identifier
	first := issueTestAccessCertificate(t, w, identifier)
	for range maxTrackedAccessCertificates {
		issueTestAccessCertificate(t, w, identifier)
	}
	if n := len(w.State.AccessCertificates); n != maxTrackedAccessCertificates {
		t.Errorf("%d tracked access certificates, want %d", n, maxTrackedAccessCertificates)
	}
	if err := w.DeleteRelyingParty(identifier); err != nil {
		t.Fatal(err)
	}
	revoked := revokedSerials(w)
	if _, ok := revoked[first.SerialNumber.Text(16)]; ok || len(revoked) != maxTrackedAccessCertificates {
		t.Errorf("%d revoked, first untracked certificate revoked %t", len(revoked), ok)
	}
}

// DB backends load the records sorted by serial, so the oldest record is the
// one that expires first, not the first one stored.
func TestTheRegistrarForgetsTheAccessCertificateThatExpiresFirst(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	identifier := rp.Identifier[0].Identifier
	expires := time.Now().Add(time.Hour).Unix()
	for i := range maxTrackedAccessCertificates {
		w.State.AccessCertificates = append(w.State.AccessCertificates, AccessCertificateStatus{
			Serial: fmt.Sprintf("%x", i+1), Identifier: identifier, Expires: expires + int64(maxTrackedAccessCertificates-i),
		})
	}
	oldest := w.State.AccessCertificates[maxTrackedAccessCertificates-1].Serial
	issueTestAccessCertificate(t, w, identifier)
	if slices.ContainsFunc(w.State.AccessCertificates, func(s AccessCertificateStatus) bool { return s.Serial == oldest }) {
		t.Errorf("the record %s that expires first is still tracked", oldest)
	}
	if n := len(w.State.AccessCertificates); n != maxTrackedAccessCertificates {
		t.Errorf("%d tracked access certificates, want %d", n, maxTrackedAccessCertificates)
	}
}
