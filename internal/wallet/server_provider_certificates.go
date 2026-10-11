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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"path"
	"strings"
	"time"
)

func (s *Server) handleSigningCertificate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("certificate")
	ext := path.Ext(name)
	fingerprint := strings.TrimSuffix(name, ext)
	digest, err := hex.DecodeString(fingerprint)
	if err != nil || len(digest) != 32 || (ext != ".der" && ext != ".pem") {
		http.NotFound(w, r)
		return
	}
	store := s.wallet.signingStore()
	der, err := store.backend.Read(path.Join(store.prefix, "certificate-der", fingerprint+".der"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "reading signing certificate: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	if ext == ".pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		der = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Write(der)
}

func (s *Server) providerCAForRequest(r *http.Request) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	role := r.PathValue("role")
	if !isProviderRole(role) {
		return nil, nil, fmt.Errorf("unknown provider role: %w", fs.ErrNotExist)
	}
	country := strings.TrimSuffix(r.PathValue("country"), ".der")
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return nil, nil, fmt.Errorf("invalid provider country: %w", fs.ErrNotExist)
	}
	store := s.wallet.signingStore()
	if _, err := store.backend.Stat(path.Join(store.prefix, "signing-keys", role+"-ca-"+country+".pem")); err != nil {
		return nil, nil, err
	}
	s.wallet.mu.RLock()
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		s.wallet.mu.RUnlock()
		return nil, nil, fmt.Errorf("wallet has no CA certificate chain")
	}
	rootKey, root, issuer := s.wallet.CAKey, s.wallet.CertChain[len(s.wallet.CertChain)-1], s.wallet.IssuerURL
	s.wallet.mu.RUnlock()
	return store.providerCA(rootKey, root, issuer, role, country)
}

func writeProviderCAError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, "loading provider CA: "+err.Error(), http.StatusInternalServerError)
}

func (s *Server) handleProviderCertificateDER(w http.ResponseWriter, r *http.Request) {
	_, cert, err := s.providerCAForRequest(r)
	if err != nil {
		writeProviderCAError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Write(cert.Raw)
}

func (s *Server) handleProviderCRL(w http.ResponseWriter, r *http.Request) {
	key, cert, err := s.providerCAForRequest(r)
	if err != nil {
		writeProviderCAError(w, r, err)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(now.Unix()), ThisUpdate: now, NextUpdate: now.Add(crlUpdateInterval),
	}, cert, key)
	if err != nil {
		http.Error(w, "signing CRL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(der)
}
