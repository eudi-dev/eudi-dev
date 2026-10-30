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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

const (
	providerCRLPrefix          = "/api/crl/providers/"
	certificateRevocationsPath = "/api/certificates/revocations"
)

// CRL signs the CRL served at path. Each call signs a fresh
// CRL, which ETSI EN 319 411-1 V1.5.1 CSS-6.3.9-07 permits before the next
// scheduled issue. An unknown path wraps fs.ErrNotExist.
//
// A CRL lists the certificates revoked through the API. The relying party
// access CA also lists the access certificates revoked by the registrar.
func (w *Wallet) CRL(path string) ([]byte, error) {
	fault := w.crlFaultState()
	if fault.unavailable() {
		return nil, errCRLUnavailable
	}
	key, ca, err := w.crlSigner(path)
	if err != nil {
		return nil, err
	}
	revoked := w.revokedEntries(path)
	if path == provider.AccessCACRLPath {
		revoked = append(revoked, w.Registrar().RevokedAccessCertificates()...)
	}
	now := time.Now().UTC().Truncate(time.Second)
	thisUpdate, nextUpdate := now, now.Add(crlUpdateInterval)
	if fault.NextUpdateSeconds > 0 {
		nextUpdate = now.Add(time.Duration(fault.NextUpdateSeconds) * time.Second)
	}
	if fault.Fault == crlFaultExpired {
		thisUpdate, nextUpdate = now.Add(-2*crlUpdateInterval), now.Add(-crlUpdateInterval)
	}
	if fault.Fault == crlFaultBadSignature {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revoked,
	}, ca, key)
}

// crlSigner returns the CA that signs the CRL at path.
func (w *Wallet) crlSigner(path string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	switch {
	case path == provider.RootCRLPath:
		key, chain := w.certificateAuthority()
		if key == nil || len(chain) == 0 {
			return nil, nil, errors.New("wallet has no CA certificate")
		}
		return key, chain[len(chain)-1], nil
	case path == provider.AccessCACRLPath:
		return w.Signer().RelyingPartyAccessCA()
	case path == provider.RegistrarCACRLPath:
		return w.Signer().RegistrarCA()
	case strings.HasPrefix(path, providerCRLPrefix):
		role, country, ok := strings.Cut(strings.TrimPrefix(path, providerCRLPrefix), "/")
		if !ok || !validCountry(country) {
			return nil, nil, fmt.Errorf("invalid provider CRL path: %w", fs.ErrNotExist)
		}
		return w.Signer().ProviderCA(role, country)
	}
	return nil, nil, fmt.Errorf("no CRL at %s: %w", path, fs.ErrNotExist)
}

// RevokedCertificate is a certificate on the CRL of its issuer. Serial is
// hexadecimal, and CRLPath is the path of that CRL.
type RevokedCertificate struct {
	Serial  string `json:"serial"`
	Subject string `json:"subject"`
	CRLPath string `json:"crl_path"`
	Revoked int64  `json:"revoked"`
	Expires int64  `json:"expires"`
	Reason  int    `json:"reason,omitempty"`
}

// revokedEntries are the entries of the CRL at path. RFC 5280 §3.3: "An entry
// MUST NOT be removed from the CRL until it appears on one regularly scheduled
// CRL issued beyond the revoked certificate's validity period."
func (w *Wallet) revokedEntries(path string) []x509.RevocationListEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	oldest := time.Now().Add(-crlUpdateInterval).Unix()
	var entries []x509.RevocationListEntry
	for _, r := range w.RevokedCertificates {
		serial, ok := new(big.Int).SetString(r.Serial, 16)
		if r.CRLPath != path || r.Expires < oldest || !ok {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: time.Unix(r.Revoked, 0).UTC(), ReasonCode: r.Reason})
	}
	return entries
}

// issuerCRLPath returns the CRL path for a certificate issued by this wallet.
// The path comes from the CRL distribution points of the certificate.
func (w *Wallet) issuerCRLPath(cert *x509.Certificate) (string, error) {
	if cert.CheckSignatureFrom(cert) == nil {
		return "", errors.New("you can't revoke a self-signed certificate. If it is on a trusted list, withdraw it instead")
	}
	for _, point := range cert.CRLDistributionPoints {
		u, err := url.Parse(point)
		if err != nil {
			continue
		}
		path, ok := w.ownCRLPath(u)
		if !ok {
			continue
		}
		if _, ca, err := w.crlSigner(path); err == nil && cert.CheckSignatureFrom(ca) == nil {
			return path, nil
		}
	}
	return "", errors.New("this wallet did not issue the certificate")
}

// revokeCertificate adds a certificate to the CRL of its issuer.
func (w *Wallet) revokeCertificate(cert *x509.Certificate, reason int) (RevokedCertificate, error) {
	path, err := w.issuerCRLPath(cert)
	if err != nil {
		return RevokedCertificate{}, err
	}
	entry := RevokedCertificate{
		Serial: cert.SerialNumber.Text(16), Subject: cert.Subject.String(), CRLPath: path,
		Revoked: time.Now().Unix(), Expires: cert.NotAfter.Unix(), Reason: reason,
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.RevokedCertificates = slices.DeleteFunc(w.RevokedCertificates, func(r RevokedCertificate) bool { return r.Serial == entry.Serial && r.CRLPath == path })
	w.RevokedCertificates = append(w.RevokedCertificates, entry)
	return entry, nil
}

// undoCertificateRevocation takes a certificate off its CRL. It reports whether
// the certificate was on one.
func (w *Wallet) undoCertificateRevocation(serial string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.RevokedCertificates)
	w.RevokedCertificates = slices.DeleteFunc(w.RevokedCertificates, func(r RevokedCertificate) bool { return r.Serial == serial })
	return len(w.RevokedCertificates) != before
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
	if s.wallet.crlFaultState().Fault == crlFaultHang {
		s.allowSlowResponse(w, crlHangLimit)
		select {
		case <-r.Context().Done():
			return
		case <-time.After(crlHangLimit):
		}
	}
	der, err := s.wallet.CRL(path)
	switch {
	case errors.Is(err, errCRLUnavailable):
		apierror.WriteStatus(w, http.StatusServiceUnavailable, err.Error())
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

func (s *Server) handleListCertificateRevocations(w http.ResponseWriter, _ *http.Request) {
	s.wallet.mu.RLock()
	revoked := slices.Clone(s.wallet.RevokedCertificates)
	s.wallet.mu.RUnlock()
	if revoked == nil {
		revoked = []RevokedCertificate{}
	}
	writeJSON(w, http.StatusOK, revoked)
}

// validCRLReason accepts the reason codes of RFC 5280 §5.3.1 for a full CRL.
// Code 7 is unused, and code 8 "may only appear in delta CRLs".
func validCRLReason(reason int) bool {
	return reason >= 0 && reason <= 10 && reason != 7 && reason != 8
}

func (s *Server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	if !validCRLReason(body.Reason) {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("reason %d is not a CRL reason code (RFC 5280 §5.3.1)", body.Reason))
		return
	}
	cert, err := keys.ParseCertificatePEM([]byte(body.Certificate), "certificate")
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusBadRequest, err)
		return
	}
	var entry RevokedCertificate
	s.saveMutation(func() bool {
		entry, err = s.wallet.revokeCertificate(cert, body.Reason)
		return err == nil
	})
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleUndoCertificateRevocation(w http.ResponseWriter, r *http.Request) {
	var found bool
	s.saveMutation(func() bool {
		serial, ok := new(big.Int).SetString(r.PathValue("serial"), 16)
		found = ok && s.wallet.undoCertificateRevocation(serial.Text(16))
		return found
	})
	if !found {
		apierror.WriteStatus(w, http.StatusNotFound, "no revoked certificate has this serial")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CRL faults for tests of a CRL client.
const (
	crlFaultUnavailable  = "unavailable"
	crlFaultHang         = "hang"
	crlFaultExpired      = "expired"
	crlFaultBadSignature = "bad-signature"
)

// crlHangLimit ends a hanging CRL response for a client without a timeout.
const crlHangLimit = 2 * time.Minute

// maxCRLNextUpdateSeconds is 10 years. It keeps nextUpdate within time.Duration.
const maxCRLNextUpdateSeconds = 10 * 365 * 24 * 60 * 60

var errCRLUnavailable = errors.New("the CRL is unavailable")

// CRLFault changes how this server answers CRL requests until it is cleared.
// It stays in memory, so other instances of the wallet are not affected.
type CRLFault struct {
	Fault             string `json:"fault,omitempty"`
	NextUpdateSeconds int64  `json:"next_update_seconds,omitempty"`
}

func (f CRLFault) unavailable() bool {
	return f.Fault == crlFaultUnavailable || f.Fault == crlFaultHang
}

func (w *Wallet) crlFaultState() CRLFault {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.crlFault
}

func (w *Wallet) setCRLFault(fault CRLFault) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.crlFault = fault
}

func (s *Server) handleGetCRLFault(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.wallet.crlFaultState())
}

func (s *Server) handleSetCRLFault(w http.ResponseWriter, r *http.Request) {
	var body CRLFault
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	switch body.Fault {
	case "", crlFaultUnavailable, crlFaultHang, crlFaultExpired, crlFaultBadSignature:
	default:
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("unknown CRL fault %q", body.Fault))
		return
	}
	if body.NextUpdateSeconds < 0 || body.NextUpdateSeconds > maxCRLNextUpdateSeconds || (body.Fault == "" && body.NextUpdateSeconds == 0) {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("set a fault, or a next_update_seconds between 1 and %d", maxCRLNextUpdateSeconds))
		return
	}
	s.wallet.setCRLFault(body)
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleClearCRLFault(w http.ResponseWriter, _ *http.Request) {
	s.wallet.setCRLFault(CRLFault{})
	w.WriteHeader(http.StatusNoContent)
}
