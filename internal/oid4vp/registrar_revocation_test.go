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

package oid4vp

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
)

// CIR (EU) 2024/2982 Annex II WRP-VALIDATION-02, as added by CIR (EU)
// 2026/1731: the wallet warns where the validation of the registration
// certificate fails, "including where the certificate is expired, revoked".
// Article 3(4) applies it from 11 August 2028, so a revoked registrar
// certificate is an advisory.
func TestARevokedRegistrarCertificateIsAnAdvisory(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateNamedCACert(caKey, "Test Registrar CA")
	if err != nil {
		t.Fatal(err)
	}
	var crl []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(crl) }))
	defer srv.Close()
	signerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mock.GenerateLeafCertWithOptions(caKey, ca, &signerKey.PublicKey, mock.LeafCertOptions{Role: mock.RegistrarCertificate, CRLDistributionPoints: []string{srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	crl, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: signer.SerialNumber, RevocationTime: time.Now()}},
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	registrations := []regcert.Registration{{Claims: map[string]any{"name": "Example Shop"}, Chain: []*x509.Certificate{signer}}}
	advisories := RegistrarRevocationAdvisories(registrations, []*x509.Certificate{ca}, srv.Client(), findings.ARF.Registration("RPRC_17"))
	if len(advisories) != 1 || !strings.Contains(advisories[0].String(), "is revoked") || !strings.Contains(advisories[0].String(), RegistrationDeadline) {
		t.Errorf("advisories %v, want the revoked registrar certificate with the deadline", advisories)
	}
}
