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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// Roles of a certificate in a chain.
const (
	certificateRoleSigner       = "signer"
	certificateRoleIntermediate = "intermediate"
	certificateRoleRoot         = "root"
)

// CredentialCertificate is one certificate of a credential's chain, leaf
// first. Revocable and Withdrawable say which actions this wallet offers for
// it. Only a CA is withdrawable: a verifier still accepts a signing certificate
// without its own list entry while the list contains its CA.
// Credentials names the other credentials with this certificate in their chain.
type CredentialCertificate struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Subject      string   `json:"subject"`
	Serial       string   `json:"serial"`
	Certificate  string   `json:"certificate"`
	Revocable    bool     `json:"revocable"`
	Revoked      bool     `json:"revoked"`
	Withdrawable bool     `json:"withdrawable"`
	WithdrawnID  string   `json:"withdrawn_id,omitempty"`
	Credentials  []string `json:"credentials"`
}

// credentialChain returns the certificates of a credential. A chain usually
// ends below the trust anchor. The certificates of the wallet's own CAs complete
// it.
func (w *Wallet) credentialChain(cred StoredCredential) []*x509.Certificate {
	return w.completedChain(embeddedCertificates(cred))
}

func (w *Wallet) completedChain(chain []*x509.Certificate) []*x509.Certificate {
	chain = slices.Clone(chain)
	for len(chain) > 0 {
		path, err := w.issuerCRLPath(chain[len(chain)-1])
		if err != nil {
			break
		}
		_, ca, err := w.crlSigner(path)
		if err != nil || slices.ContainsFunc(chain, ca.Equal) {
			break
		}
		chain = append(chain, ca)
	}
	return chain
}

// CertificateProblems reads the CRLs of a chain. The CRLs of this wallet are
// answered in process.
func (w *Wallet) CertificateProblems(chain []*x509.Certificate) []certchain.RevocationProblem {
	return certchain.CheckRevocation(w.completedChain(chain), w.RegistrationStatusClient(), time.Now())
}

// flagRevokedCertificates marks the matches and candidates of a consent
// request with revoked certificates in their chain. It reads the revocations of
// this wallet and no CRL. A slow CRL endpoint must not delay the consent dialog.
func (w *Wallet) flagRevokedCertificates(matches []consent.Match, options *consent.CredentialOptions) {
	revoked := w.revokedSerials()
	if len(revoked) == 0 {
		return
	}
	names := map[string][]string{}
	flag := func(list []consent.Match) {
		for i := range list {
			id := list[i].CredentialID
			if _, known := names[id]; !known {
				names[id] = w.revokedCertificateNames(id, revoked)
			}
			list[i].RevokedCertificates = names[id]
		}
	}
	flag(matches)
	if options != nil {
		for _, query := range options.Queries {
			flag(query.Candidates)
		}
	}
}

func (w *Wallet) revokedCertificateNames(id string, revoked map[string]string) []string {
	cred, ok := w.GetCredential(id)
	if !ok {
		return nil
	}
	return w.revokedNames(w.credentialChain(cred), revoked)
}

func (w *Wallet) revokedNames(chain []*x509.Certificate, revoked map[string]string) []string {
	if len(revoked) == 0 {
		return nil
	}
	var names []string
	for _, cert := range chain {
		path, err := w.issuerCRLPath(cert)
		if err == nil && revoked[cert.SerialNumber.Text(16)] == path {
			names = append(names, cert.Subject.CommonName)
		}
	}
	return names
}

func (w *Wallet) revokedSerials() map[string]string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	revoked := make(map[string]string, len(w.RevokedCertificates))
	for _, r := range w.RevokedCertificates {
		revoked[r.Serial] = r.CRLPath
	}
	return revoked
}

// Certificate status of a credential.
const (
	certificateStatusValid     = "valid"
	certificateStatusRevoked   = "revoked"
	certificateStatusExpired   = "expired"
	certificateStatusUnchecked = "unchecked"
	certificateStatusUnknown   = "unknown"
	certificateStatusNone      = "none"
)

// CertificateStatus sums up the certificates of a credential. Problems names
// the certificates behind the status.
type CertificateStatus struct {
	Status   string   `json:"status"`
	Problems []string `json:"problems,omitempty"`
}

// certificateStatus reads the revocations of this wallet and no CRL. Reading the
// credential list must not wait for an external CRL, so the CRLs of another issuer
// stay unchecked until handleCertificateStatus reads them.
func (w *Wallet) certificateStatus(cred StoredCredential) CertificateStatus {
	return w.chainStatus(w.credentialChain(cred))
}

func (w *Wallet) chainStatus(chain []*x509.Certificate) CertificateStatus {
	if names := w.revokedNames(chain, w.revokedSerials()); len(names) > 0 {
		return CertificateStatus{Status: certificateStatusRevoked, Problems: names}
	}
	status := CertificateStatus{Status: certificateStatusNone}
	for _, cert := range chain {
		if time.Now().After(cert.NotAfter) {
			return CertificateStatus{Status: certificateStatusExpired, Problems: []string{cert.Subject.CommonName}}
		}
		if len(cert.CRLDistributionPoints) == 0 {
			continue
		}
		if _, err := w.issuerCRLPath(cert); err != nil {
			status.Status = certificateStatusUnchecked
		} else if status.Status == certificateStatusNone {
			status.Status = certificateStatusValid
		}
	}
	return status
}

// handleCertificateStatus reads the CRLs of a credential's certificates.
func (s *Server) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	cred, ok := s.wallet.GetCredential(r.PathValue("id"))
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "credential not found")
		return
	}
	status := s.wallet.certificateStatus(cred)
	if status.Status != certificateStatusUnchecked {
		writeJSON(w, http.StatusOK, status)
		return
	}
	chain := embeddedCertificates(cred)
	if len(chain) > validate.MaxRevocationChain {
		apierror.WriteStatus(w, http.StatusUnprocessableEntity, fmt.Sprintf("the chain has %d certificates, so the wallet reads no CRLs", len(chain)))
		return
	}
	writeJSON(w, http.StatusOK, s.wallet.readCertificateStatus(chain))
}

func (w *Wallet) readCertificateStatus(chain []*x509.Certificate) CertificateStatus {
	status := CertificateStatus{Status: certificateStatusValid}
	for _, problem := range w.CertificateProblems(chain) {
		status.Problems = append(status.Problems, problem.Error())
		if problem.Revoked {
			status.Status = certificateStatusRevoked
		} else if status.Status != certificateStatusRevoked {
			status.Status = certificateStatusUnknown
		}
	}
	// A CRL check needs the issuer of the certificate, and an x5c often ends below
	// the trust anchor.
	completed := w.completedChain(chain)
	if last := completed[len(completed)-1]; len(last.CRLDistributionPoints) > 0 && last.CheckSignatureFrom(last) != nil && status.Status != certificateStatusRevoked {
		status.Status = certificateStatusUnknown
		status.Problems = append(status.Problems, fmt.Sprintf("the chain has no issuer of %q, so its CRL can't be checked", last.Subject.CommonName))
	}
	return status
}

func certificateRole(cert *x509.Certificate) string {
	switch {
	case !cert.IsCA:
		return certificateRoleSigner
	case cert.CheckSignatureFrom(cert) == nil:
		return certificateRoleRoot
	}
	return certificateRoleIntermediate
}

func embeddedCertificates(cred StoredCredential) []*x509.Certificate {
	if cred.Format == credtype.FormatMDOC {
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return nil
		}
		certs, _ := validate.ExtractMDOCX5ChainCertificates(doc)
		return certs
	}
	token, err := sdjwt.ParseLenient(cred.Raw)
	if err != nil || token == nil {
		return nil
	}
	certs, _ := validate.X5CCertificates(token.Header)
	return certs
}

func (w *Wallet) credentialCertificates(cred StoredCredential) []CredentialCertificate {
	others := map[string][]*x509.Certificate{}
	for _, other := range w.ListedCredentials() {
		if other.ID != cred.ID {
			others[credentialLabel(other)] = append(others[credentialLabel(other)], w.credentialChain(other)...)
		}
	}
	withdrawn := w.TrustedLists().WithdrawnList()
	w.mu.RLock()
	revoked := slices.Clone(w.RevokedCertificates)
	w.mu.RUnlock()

	certificates := []CredentialCertificate{}
	for _, cert := range w.credentialChain(cred) {
		path, err := w.issuerCRLPath(cert)
		serial := cert.SerialNumber.Text(16)
		sum := sha256.Sum256(cert.Raw)
		id := hex.EncodeToString(sum[:])
		entry := CredentialCertificate{
			Name: cert.Subject.CommonName, Role: certificateRole(cert), Subject: cert.Subject.String(), Serial: serial,
			Certificate:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
			Revocable:    err == nil,
			Revoked:      err == nil && slices.ContainsFunc(revoked, func(r RevokedCertificate) bool { return r.Serial == serial && r.CRLPath == path }),
			Withdrawable: cert.IsCA && w.TrustedLists().Listed(cert),
			Credentials:  []string{},
		}
		if slices.ContainsFunc(withdrawn, func(c trustedlists.WithdrawnCertificate) bool { return c.ID == id }) {
			entry.WithdrawnID = id
		}
		for label, chain := range others {
			if slices.ContainsFunc(chain, cert.Equal) {
				entry.Credentials = append(entry.Credentials, label)
			}
		}
		slices.Sort(entry.Credentials)
		certificates = append(certificates, entry)
	}
	return certificates
}

func (s *Server) handleCredentialCertificates(w http.ResponseWriter, r *http.Request) {
	cred, ok := s.wallet.GetCredential(r.PathValue("id"))
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "credential not found")
		return
	}
	writeJSON(w, http.StatusOK, s.wallet.credentialCertificates(cred))
}
