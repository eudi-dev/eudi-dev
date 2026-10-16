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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
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
	der, err := s.wallet.providerKeys().RetainedCertificate(fingerprint)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			apierror.WriteStatus(w, http.StatusInternalServerError, "reading signing certificate: "+err.Error())
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
	country := strings.TrimSuffix(r.PathValue("country"), ".der")
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return nil, nil, fmt.Errorf("invalid provider country: %w", fs.ErrNotExist)
	}
	return s.wallet.Signer().ProviderCA(r.PathValue("role"), country)
}

func writeProviderCAError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	apierror.WriteStatus(w, http.StatusInternalServerError, "loading provider CA: "+err.Error())
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
