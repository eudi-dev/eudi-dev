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
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
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
// first. Issued says that this wallet issued it. Revocable and Withdrawable say which actions this wallet offers for
// it. Only a CA is withdrawable: a verifier still accepts a signing certificate
// without its own list entry while the list contains its CA.
// Credentials names the other credentials with this certificate in their chain.
type CredentialCertificate struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Subject      string   `json:"subject"`
	Serial       string   `json:"serial"`
	Certificate  string   `json:"certificate"`
	Issued       bool     `json:"issued"`
	Revocable    bool     `json:"revocable"`
	Revoked      bool     `json:"revoked"`
	Withdrawable bool     `json:"withdrawable"`
	WithdrawnID  string   `json:"withdrawn_id,omitempty"`
	Credentials  []string `json:"credentials"`
	// AnchoredBy is the trusted list that holds this certificate, for a trust
	// anchor that the credential's chain does not contain.
	AnchoredBy string `json:"anchored_by,omitempty"`
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

// revocableHere keeps the shared certificates of a public demo working. There a
// visitor can revoke only the signing certificate of an attestation provider,
// and not one of a protected credential. PID and wallet providers, access
// certificates and CAs stay out of reach. An x5c in a credential proves nothing,
// because import skips the checks.
func (w *Wallet) revocableHere(cert *x509.Certificate) bool {
	if !w.publicDemo {
		return true
	}
	path, err := w.issuerCRLPath(cert)
	if err != nil || cert.IsCA {
		return false
	}
	role, _, _ := strings.Cut(strings.TrimPrefix(path, providerCRLPrefix), "/")
	if !strings.HasPrefix(path, providerCRLPrefix) || !slices.Contains([]string{credtemplate.CategoryEAA, credtemplate.CategoryQEAA, credtemplate.CategoryPubEAA}, role) {
		return false
	}
	return !slices.ContainsFunc(w.GetCredentials(), func(cred StoredCredential) bool {
		return cred.Protected && slices.ContainsFunc(w.credentialChain(cred), cert.Equal)
	})
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

// maxDemoCRLPoints keeps a check on a public demo within the server's write
// timeout, because each address can take as long as the fetch timeout.
const maxDemoCRLPoints = 4

// maxListedChain limits the work of a certificate list on a public demo. A real
// chain has a few certificates.
const maxListedChain = 16

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
	if w.publicDemo && len(chain) > maxListedChain {
		return CertificateStatus{Status: certificateStatusUnchecked}
	}
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
	chain := embeddedCertificates(cred)
	if len(chain) > validate.MaxRevocationChain {
		apierror.WriteStatus(w, http.StatusUnprocessableEntity, fmt.Sprintf("the chain has %d certificates, so the wallet reads no CRLs", len(chain)))
		return
	}
	status := s.wallet.certificateStatus(cred)
	if status.Status != certificateStatusUnchecked {
		writeJSON(w, http.StatusOK, status)
		return
	}
	if s.wallet.publicDemo {
		var points int
		for _, cert := range chain {
			points += len(cert.CRLDistributionPoints)
		}
		if points > maxDemoCRLPoints {
			apierror.WriteStatus(w, http.StatusUnprocessableEntity, fmt.Sprintf("the chain lists %d CRL addresses. The public demo reads at most %d", points, maxDemoCRLPoints))
			return
		}
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
			if chain := w.credentialChain(other); !w.publicDemo || len(chain) <= maxListedChain {
				if anchor, _ := w.catalogueAnchor(other, chain); anchor != nil {
					chain = append(chain, anchor)
				}
				others[credentialLabel(other)] = append(others[credentialLabel(other)], chain...)
			}
		}
	}
	withdrawn := w.TrustedLists().WithdrawnList()
	w.mu.RLock()
	revoked := slices.Clone(w.RevokedCertificates)
	w.mu.RUnlock()

	certificates := []CredentialCertificate{}
	chain := w.credentialChain(cred)
	anchor, anchorList := w.catalogueAnchor(cred, chain)
	if anchor != nil {
		chain = append(chain, anchor)
	}
	for i, cert := range chain {
		path, err := w.issuerCRLPath(cert)
		serial := cert.SerialNumber.Text(16)
		sum := sha256.Sum256(cert.Raw)
		id := hex.EncodeToString(sum[:])
		entry := CredentialCertificate{
			Name: cert.Subject.CommonName, Role: certificateRole(cert), Subject: cert.Subject.String(), Serial: serial,
			Certificate:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
			Issued:       err == nil,
			Revocable:    err == nil && w.revocableHere(cert),
			Revoked:      err == nil && slices.ContainsFunc(revoked, func(r RevokedCertificate) bool { return r.Serial == serial && r.CRLPath == path }),
			Withdrawable: !w.publicDemo && cert.IsCA && w.TrustedLists().Listed(cert),
			Credentials:  []string{},
		}
		if anchorList != "" && i == len(chain)-1 {
			entry.AnchoredBy = anchorList
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

// catalogueAnchor finds the trust anchor of a chain on the lists of the
// credential's catalogue entries. It reads only what the wallet already holds,
// because a slow list must not delay the certificates dialog.
func (w *Wallet) catalogueAnchor(cred StoredCredential, chain []*x509.Certificate) (*x509.Certificate, string) {
	if len(chain) == 0 || chain[len(chain)-1].CheckSignatureFrom(chain[len(chain)-1]) == nil {
		return nil, ""
	}
	for _, entry := range catalogueEntriesIn(w.Registrar().CatalogAttestations(), cred.Format, []string{cred.VCT, cred.DocType}) {
		for _, authority := range entry.Schema.TrustedAuthorities {
			if authority.FrameworkType != "etsi_tl" || authority.IsLOTE == nil || !*authority.IsLOTE {
				continue
			}
			if anchor := chainAnchor(chain, w.TrustedLists().CachedAnchors(authority.Value)); anchor != nil {
				return anchor, authority.Value
			}
		}
	}
	return nil, ""
}

// chainAnchor returns the list's certificate that issued the end of the chain.
// A chain leaves its trust anchor out, so the list is the only place to find it.
func chainAnchor(chain, anchors []*x509.Certificate) *x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	last := chain[len(chain)-1]
	for _, anchor := range anchors {
		if !anchor.Equal(last) && last.CheckSignatureFrom(anchor) == nil {
			return anchor
		}
	}
	return nil
}

func (s *Server) handleCredentialCertificates(w http.ResponseWriter, r *http.Request) {
	cred, ok := s.wallet.GetCredential(r.PathValue("id"))
	if !ok {
		apierror.WriteStatus(w, http.StatusNotFound, "credential not found")
		return
	}
	if chain := embeddedCertificates(cred); s.wallet.publicDemo && len(chain) > maxListedChain {
		apierror.WriteStatus(w, http.StatusUnprocessableEntity, fmt.Sprintf("the chain has %d certificates. The wallet lists at most %d", len(chain), maxListedChain))
		return
	}
	writeJSON(w, http.StatusOK, s.wallet.credentialCertificates(cred))
}
