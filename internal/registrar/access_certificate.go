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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// AccessCACertificatePath serves the DER certificate of the relying party
// access CA. Access certificates link it as their issuer certificate.
const AccessCACertificatePath = "/api/certificates/relying-party-access-ca.der"

// AccessCertificateRequest asks the wallet's access certificate authority for
// an access certificate of a registered relying party (ETSI TS 119 411-8). The
// relying party keeps its private key and sends only a PKCS#10 CSR. The
// certificate takes the public key from the CSR and the subject from the
// registration (TS 119 411-8 GEN-6.6.1-10).
type AccessCertificateRequest struct {
	Identifier        string `json:"identifier"`
	ServiceIdentifier string `json:"serviceIdentifier,omitempty"`
	// CSR is the PEM certificate signing request. Its subject may be empty.
	CSR string `json:"csr"`
	// DNSNames are extra subject alternative names, for a verifier that uses
	// the x509_san_dns client identifier prefix.
	DNSNames []string `json:"dnsNames,omitempty"`
	// Validity is a Go duration of at most one year.
	Validity string `json:"validity,omitempty"`
}

// AccessCertificateResult carries the issued certificate and the client
// identifiers that work with it (OpenID4VP 1.0 §5.9.3).
type AccessCertificateResult struct {
	// Certificate is the PEM leaf. A request object's x5c carries it without
	// the trust anchor (HAIP 1.0).
	Certificate string `json:"certificate"`
	// Chain is the PEM leaf followed by the issuing CA (ARF Reg_10b).
	Chain     string   `json:"chain"`
	ClientIDs []string `json:"clientIds"`
}

const MaxAccessCertificateValidity = 365 * 24 * time.Hour

// x509_san_dns identifies one host, so a DNS name may not contain a wildcard
// (OpenID4VP 1.0 §5.9.3).
var dnsNamePattern = regexp.MustCompile(`^(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))*$`)

// IssueAccessCertificate signs an access certificate for the public key of a
// CSR.
func (r *Registrar) IssueAccessCertificate(req AccessCertificateRequest) (*AccessCertificateResult, error) {
	rp, ok := r.RelyingParty(req.Identifier)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errRelyingPartyNotFound, req.Identifier)
	}
	publicKey, validity, err := req.parse()
	if err != nil {
		return nil, err
	}
	service, err := findService(rp, req.ServiceIdentifier)
	if err != nil {
		return nil, err
	}
	chain, err := r.AccessCertificateFor(rp, service.ServiceIdentifier, publicKey, req.DNSNames, validity)
	if err != nil {
		return nil, err
	}
	r.recordAccessCertificate(rp, service.ServiceIdentifier, chain[0])
	return accessCertificateResult(chain), nil
}

// parse reads the key of the CSR and the validity.
func (req AccessCertificateRequest) parse() (*ecdsa.PublicKey, time.Duration, error) {
	publicKey, err := csrPublicKey(req.CSR)
	if err != nil {
		return nil, 0, err
	}
	validity := MaxAccessCertificateValidity
	if strings.TrimSpace(req.Validity) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(req.Validity))
		if err != nil || parsed <= 0 || parsed > MaxAccessCertificateValidity {
			return nil, 0, fmt.Errorf("validity %q is not a Go duration of at most %s", req.Validity, MaxAccessCertificateValidity)
		}
		validity = parsed
	}
	return publicKey, validity, nil
}

func accessCertificateResult(chain []*x509.Certificate) *AccessCertificateResult {
	leaf, ca := chain[0], chain[1]
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	hash := sha256.Sum256(leaf.Raw)
	clientIDs := []string{"x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])}
	for _, dnsName := range leaf.DNSNames {
		clientIDs = append(clientIDs, "x509_san_dns:"+dnsName)
	}
	return &AccessCertificateResult{
		Certificate: certificate,
		Chain:       certificate + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		ClientIDs:   clientIDs,
	}
}

// AccessCertificateFor signs an access certificate for a service of rp with
// the relying party access CA. It returns the certificate and the CA.
func (r *Registrar) AccessCertificateFor(rp WalletRelyingParty, serviceIdentifier string, publicKey *ecdsa.PublicKey, dnsNames []string, validity time.Duration) ([]*x509.Certificate, error) {
	service, err := findService(rp, serviceIdentifier)
	if err != nil {
		return nil, err
	}
	subject, err := SemanticIdentifier(rp.Identifier[0], rp.Country)
	if err != nil {
		return nil, err
	}
	dnsNames, err = accessCertificateDNSNames(dnsNames)
	if err != nil {
		return nil, err
	}
	uris, emails, err := supportContact(service.SupportURI)
	if err != nil {
		return nil, err
	}
	caKey, ca, err := r.env.RelyingPartyAccessCA()
	if err != nil {
		return nil, fmt.Errorf("%w: loading the relying party access CA: %w", errRegistrarSigning, err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, publicKey, mock.LeafCertOptions{
		CommonName:             service.ServiceTradeName,
		Organization:           rp.LegalPerson.LegalName[0],
		OrganizationalUnit:     service.ServiceIdentifier,
		Country:                rp.Country,
		OrganizationIdentifier: subject,
		Role:                   mock.AccessCertificate,
		URIs:                   uris,
		EmailAddresses:         emails,
		DNSNames:               dnsNames,
		Validity:               validity,
		// CIR (EU) 2025/848 Annex IV point 3(k) asks for the location of the
		// issuer certificate (authorityInformationAccess caIssuers).
		IssuingCertificateURL: []string{strings.TrimRight(r.env.RegistrarBase(), "/") + AccessCACertificatePath},
		CRLDistributionPoints: r.env.AccessCACRLDistributionPoints(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: signing the access certificate: %w", errRegistrarSigning, err)
	}
	return []*x509.Certificate{leaf, ca}, nil
}

// supportContact maps the support contact of a service to the subject
// alternative names of ETSI TS 119 411-8 V1.1.1 GEN-6.6.1-07: a website is a
// uniformResourceIdentifier and an email address an rfc822Name.
func supportContact(supportURI string) (uris []*url.URL, emails []string, err error) {
	u, err := url.Parse(supportURI)
	switch {
	case err != nil:
	case u.Scheme == "mailto":
		if address, err := mail.ParseAddress(u.Opaque); err == nil && address.Address == u.Opaque {
			return nil, []string{u.Opaque}, nil
		}
	case u.Scheme == "https" || u.Scheme == "http":
		if u.Host != "" {
			return []*url.URL{u}, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("the support contact %q is not a web address or a mailto: address", supportURI)
}

// accessCertificateDNSNames checks the DNS names for the subject alternative
// names of an access certificate.
func accessCertificateDNSNames(dnsNames []string) ([]string, error) {
	dnsNames = trimmedNonEmpty(dnsNames)
	if len(dnsNames) > maxRegistrationItems {
		return nil, fmt.Errorf("an access certificate may name at most %d DNS names", maxRegistrationItems)
	}
	for _, name := range dnsNames {
		if !dnsNamePattern.MatchString(name) {
			return nil, fmt.Errorf("%q is not a DNS name", name)
		}
	}
	return dnsNames, nil
}

// csrPublicKey returns the P-256 key of a CSR after checking that its signature
// proves possession of the private key. HAIP 1.0 §7 has every wallet support
// ES256 for signed presentation requests.
func csrPublicKey(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemData)))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("the CSR is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the CSR signature does not verify: %w", err)
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the CSR key is not a P-256 key")
	}
	return key, nil
}

func trimmedNonEmpty(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
