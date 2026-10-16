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
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

const providerCRLPrefix = "/api/crl/providers/"

// CRL signs the CRL served at path. Each call signs a fresh
// CRL, which ETSI EN 319 411-1 V1.5.1 CSS-6.3.9-07 permits before the next
// scheduled issue. An unknown path wraps fs.ErrNotExist.
//
// The wallet CA, the provider CAs and the registrar CA revoke nothing.
// Credentials are revoked on the status list. The relying party access CA
// lists the access certificates revoked by the registrar.
func (w *Wallet) CRL(path string) ([]byte, error) {
	var key *ecdsa.PrivateKey
	var ca *x509.Certificate
	var revoked []x509.RevocationListEntry
	var err error
	switch {
	case path == provider.RootCRLPath:
		var chain []*x509.Certificate
		key, chain = w.certificateAuthority()
		if key == nil || len(chain) == 0 {
			return nil, errors.New("wallet has no CA certificate")
		}
		ca = chain[len(chain)-1]
	case path == provider.AccessCACRLPath:
		key, ca, err = w.Signer().RelyingPartyAccessCA()
		revoked = w.Registrar().RevokedAccessCertificates()
	case path == provider.RegistrarCACRLPath:
		key, ca, err = w.Signer().RegistrarCA()
	case strings.HasPrefix(path, providerCRLPrefix):
		role, country, ok := strings.Cut(strings.TrimPrefix(path, providerCRLPrefix), "/")
		if !ok || !validCountry(country) {
			return nil, fmt.Errorf("invalid provider CRL path: %w", fs.ErrNotExist)
		}
		key, ca, err = w.Signer().ProviderCA(role, country)
	default:
		return nil, fmt.Errorf("no CRL at %s: %w", path, fs.ErrNotExist)
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlUpdateInterval),
		RevokedCertificateEntries: revoked,
	}, ca, key)
}

func validCountry(country string) bool {
	return len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z'
}

// ownCRLPath returns the CRL path of a URL on one of the wallet's own
// origins.
func (w *Wallet) ownCRLPath(u *url.URL) (string, bool) {
	for _, origin := range w.Signer().CRLDistributionPoints("") {
		base, err := url.Parse(origin)
		if err != nil || !format.SameOrigin(u, base) {
			continue
		}
		if path, ok := strings.CutPrefix(u.Path, base.Path); ok && strings.HasPrefix(path, provider.RootCRLPath) {
			return path, true
		}
	}
	return "", false
}

func (s *Server) serveCRL(w http.ResponseWriter, r *http.Request, path string) {
	der, err := s.wallet.CRL(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		http.NotFound(w, r)
	case err != nil:
		apierror.WriteStatus(w, http.StatusInternalServerError, "signing the CRL: "+err.Error())
	default:
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(der)
	}
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	s.serveCRL(w, r, provider.RootCRLPath)
}

func (s *Server) handleProviderCRL(w http.ResponseWriter, r *http.Request) {
	s.serveCRL(w, r, provider.ProviderCRLPath(r.PathValue("role"), r.PathValue("country")))
}

func (s *Server) handleAccessCACRL(w http.ResponseWriter, r *http.Request) {
	s.serveCRL(w, r, provider.AccessCACRLPath)
}

func (s *Server) handleRegistrarCACRL(w http.ResponseWriter, r *http.Request) {
	s.serveCRL(w, r, provider.RegistrarCACRLPath)
}
