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
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
)

// writeCRL signs a CRL of the CA with the revoked certificates. Each request
// gets a fresh CRL, which ETSI EN 319 411-1 V1.5.1 CSS-6.3.9-07 permits
// before the next scheduled issue.
func writeCRL(w http.ResponseWriter, key *ecdsa.PrivateKey, ca *x509.Certificate, revoked []x509.RevocationListEntry) {
	now := time.Now().UTC().Truncate(time.Second)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlUpdateInterval),
		RevokedCertificateEntries: revoked,
	}, ca, key)
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "signing the CRL: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(der)
}

// handleCRL serves the CRL of the wallet CA. Credential revocation uses the
// status list, and the wallet revokes none of the certificates of this CA.
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	caKey, chain := s.wallet.certificateAuthority()
	if caKey == nil || len(chain) == 0 {
		apierror.WriteStatus(w, http.StatusInternalServerError, "wallet has no CA certificate")
		return
	}
	writeCRL(w, caKey, chain[len(chain)-1], nil)
}

func (s *Server) handleProviderCRL(w http.ResponseWriter, r *http.Request) {
	key, cert, err := s.providerCAForRequest(r)
	if err != nil {
		writeProviderCAError(w, r, err)
		return
	}
	writeCRL(w, key, cert, nil)
}

func (s *Server) handleAccessCACRL(w http.ResponseWriter, r *http.Request) {
	key, ca, err := s.wallet.Signer().RelyingPartyAccessCA()
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "loading the relying party access CA: "+err.Error())
		return
	}
	writeCRL(w, key, ca, s.wallet.Registrar().RevokedAccessCertificates())
}

// handleRegistrarCACRL serves the CRL of the registrar CA. Nothing revokes
// the registrar's signing certificate.
func (s *Server) handleRegistrarCACRL(w http.ResponseWriter, r *http.Request) {
	key, ca, err := s.wallet.Signer().RegistrarCA()
	if err != nil {
		apierror.WriteStatus(w, http.StatusInternalServerError, "loading the registrar CA: "+err.Error())
		return
	}
	writeCRL(w, key, ca, nil)
}
