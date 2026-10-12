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

package provider

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// Root is the wallet's own signing material: the issuer key, the CA key and
// the chain [leaf, CA] the CA issued for the issuer key.
type Root struct {
	IssuerKey *ecdsa.PrivateKey
	CAKey     *ecdsa.PrivateKey
	Chain     []*x509.Certificate
	IssuerURL string
}

// Env gives the signer the root material of the wallet. Root reads it under
// one lock, so a concurrent reset can't pair a new key with an old chain.
type Env interface {
	Root() Root
}

// Signer issues the signing material of the providers from the keys and the
// wallet's root.
type Signer struct {
	keys *Keys
	env  Env
}

func NewSigner(keys *Keys, env Env) *Signer {
	return &Signer{keys: keys, env: env}
}

// Keys are the keys and certificates the signer stores.
func (s *Signer) Keys() *Keys {
	return s.keys
}

// HasCA reports whether the wallet holds a CA key and a signing chain under
// it.
func (s *Signer) HasCA() bool {
	root := s.env.Root()
	return root.CAKey != nil && len(root.Chain) >= 2
}

// ForCredential returns the signing key and chain of the type's trusted
// list. The signer's countryName matches issuing_country, as ISO/IEC
// 18013-5 Table B.3 requires.
func (s *Signer) ForCredential(spec IssuedAttestationSpec, claims map[string]any) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return s.ForList(spec.List(), IssuingCountry(claims))
}

// IssuingCountry is the issuing_country claim when it is a two-letter
// upper-case country code.
func IssuingCountry(claims map[string]any) string {
	country, _ := claims["issuing_country"].(string)
	if len(country) == 2 && country == strings.ToUpper(country) {
		return country
	}
	return ""
}

// ForList returns the signing key of the list and its chain under the
// provider CA of the country.
func (s *Signer) ForList(list List, country string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if country == "" {
		country = mock.DefaultCertificateCountry
	}
	root := s.env.Root()
	issuerKey, caKey, chain := root.IssuerKey, root.CAKey, root.Chain
	if issuerKey == nil || caKey == nil || len(chain) < 2 {
		return nil, nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	caCert := chain[len(chain)-1]
	opts := mock.LeafCertOptions{
		CommonName:            signingLeafCommonName(list),
		Country:               country,
		CRLDistributionPoints: CRLDistributionPoints(root.IssuerURL),
	}
	role := Role(list)
	switch {
	case list.Category == credtemplate.CategoryPID:
		opts.Role = mock.PIDProviderCertificate
	case role == string(mock.WalletProviderCertificate):
		opts.Role = mock.WalletProviderCertificate
	}
	if role != credtemplate.CategoryPID {
		var err error
		if issuerKey, err = s.keys.Key(signingKeyName(role)); err != nil {
			return nil, nil, err
		}
	}
	opts.IssuingCertificateURL = issuingCertificateURLs(root.IssuerURL)
	parentKey, parent, err := s.keys.ProviderCA(caKey, caCert, root.IssuerURL, role, country)
	if err != nil {
		return nil, nil, fmt.Errorf("generating provider CA: %w", err)
	}
	if !parent.Equal(caCert) {
		base := strings.TrimRight(root.IssuerURL, "/")
		if base != "" {
			opts.IssuingCertificateURL = []string{base + "/api/certificates/providers/" + role + "/" + country + ".der"}
			opts.CRLDistributionPoints = []string{base + "/api/crl/providers/" + role + "/" + country}
		}
	}
	opts.DNSNames, opts.IPAddresses, opts.URIs = IssuerSubjectAltNames(root.IssuerURL)
	leafCert, err := s.keys.Certificate(parentKey, parent, &issuerKey.PublicKey, opts, false)
	if err != nil {
		return nil, nil, fmt.Errorf("generating signing leaf certificate: %w", err)
	}
	certs := []*x509.Certificate{leafCert, parent}
	if !parent.Equal(caCert) {
		certs = append(certs, caCert)
	}
	return issuerKey, certs, nil
}

// Role returns the name of the provider CA and signing key for a trusted
// list. Each category list, custom list and the wallet provider list has its
// own, so a list anchors only the credentials signed for it. The pid category
// signs with the wallet's issuer key.
func Role(list List) string {
	switch {
	case list.LoTEType == lote.WalletProvidersListType:
		return string(mock.WalletProviderCertificate)
	case list.LoTEType == "":
		return unlistedRole
	}
	return ListID(list)
}

const unlistedRole = "unlisted"

var customRolePattern = regexp.MustCompile(`^tl-[0-9a-f]{8}$`)

// isRole accepts the roles that Role returns.
func isRole(role string) bool {
	return slices.Contains(credtemplate.Categories, role) || role == unlistedRole || role == legacyEAARole ||
		role == string(mock.WalletProviderCertificate) || customRolePattern.MatchString(role)
}

func signingKeyName(role string) string {
	if role == string(mock.WalletProviderCertificate) {
		return "wallet-provider"
	}
	return "issuer-" + role
}

// CRLDistributionPoints is the CRL of the issuer. ISO/IEC 18013-5 Table B.3
// requires a CRL distribution point URI in document signer certificates.
func CRLDistributionPoints(issuerURL string) []string {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil
	}
	return []string{issuer + "/api/crl"}
}

// issuingCertificateURLs is where the issuer publishes the wallet CA.
func issuingCertificateURLs(issuerURL string) []string {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil
	}
	return []string{issuer + "/api/certificates/ca.der"}
}

// WalletProvider signs wallet and key attestations.
func (s *Signer) WalletProvider() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return s.ForList(WalletProviderList(), "")
}

// ProviderCA returns an existing provider CA of the role and country. An
// unknown role or a CA that was never created wraps fs.ErrNotExist.
func (s *Signer) ProviderCA(role, country string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if !isRole(role) {
		return nil, nil, fmt.Errorf("unknown provider role: %w", fs.ErrNotExist)
	}
	if err := s.keys.hasProviderCA(role, country); err != nil {
		return nil, nil, err
	}
	root := s.env.Root()
	if root.CAKey == nil || len(root.Chain) == 0 {
		return nil, nil, fmt.Errorf("wallet has no CA certificate chain")
	}
	return s.keys.ProviderCA(root.CAKey, root.Chain[len(root.Chain)-1], root.IssuerURL, role, country)
}

// RelyingPartyAccessCA issues the access certificates of registered relying
// parties. It is a separate root, because the wallet CA is the trust anchor for
// credential issuers and a visitor's CSR must never produce a certificate under
// it.
func (s *Signer) RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return s.keys.selfSignedCA("relying-party-access-ca", "EUDI Dev Test Relying Party Access CA")
}

// RegistrarCA is the root of the registrar's signing certificate. It is a
// separate root like the relying party access CA, so the list of registration
// certificate providers names only the registrar (ETSI TS 119 602 V1.1.1
// Annex G).
func (s *Signer) RegistrarCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return s.keys.selfSignedCA("registrar-ca", "EUDI Dev Test Registrar CA")
}

// Registrar signs registration certificates, registrar responses and the
// status list of registration certificates.
func (s *Signer) Registrar() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	key, err := s.keys.Key("registrar")
	if err != nil {
		return nil, nil, err
	}
	caKey, ca, err := s.RegistrarCA()
	if err != nil {
		return nil, nil, err
	}
	leaf, err := s.keys.Certificate(caKey, ca, &key.PublicKey, mock.LeafCertOptions{CommonName: "EUDI Dev Test Registrar", Role: mock.RegistrarCertificate}, false)
	if err != nil {
		return nil, nil, err
	}
	return key, []*x509.Certificate{leaf, ca}, nil
}

// TrustList signs the wallet's trusted lists.
func (s *Signer) TrustList(operator, country string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return s.auxiliary("trustlist", mock.LeafCertOptions{CommonName: "EUDI Dev Test List Operator", Role: mock.TrustListCertificate, Organization: operator, Country: country})
}

func (s *Signer) auxiliary(keyRole string, opts mock.LeafCertOptions) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	root := s.env.Root()
	caKey, chain, issuer := root.CAKey, root.Chain, root.IssuerURL
	if caKey == nil || len(chain) < 2 {
		return nil, nil, fmt.Errorf("wallet has no access certificate authority")
	}
	key, err := s.keys.Key(keyRole)
	if err != nil {
		return nil, nil, err
	}
	opts.IssuingCertificateURL = issuingCertificateURLs(issuer)
	opts.CRLDistributionPoints = CRLDistributionPoints(issuer)
	opts.DNSNames, opts.IPAddresses, opts.URIs = IssuerSubjectAltNames(issuer)
	ca := chain[len(chain)-1]
	leaf, err := s.keys.Certificate(caKey, ca, &key.PublicKey, opts, false)
	if err != nil {
		return nil, nil, err
	}
	return key, []*x509.Certificate{leaf, ca}, nil
}

// TrustAnchor is the wallet CA, the last certificate of the root chain.
func (s *Signer) TrustAnchor() *x509.Certificate {
	chain := s.env.Root().Chain
	if len(chain) == 0 {
		return nil
	}
	return chain[len(chain)-1]
}

// StatusList signs the status lists of issued credentials.
func (s *Signer) StatusList() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	root := s.env.Root()
	issuerKey, caKey, chain := root.IssuerKey, root.CAKey, root.Chain
	if issuerKey == nil || len(chain) == 0 {
		return nil, nil, fmt.Errorf("wallet has no status list signing material")
	}
	if caKey == nil || len(chain) < 2 {
		return issuerKey, chain, nil
	}
	caCert := chain[len(chain)-1]
	var err error
	issuerKey, err = s.keys.Key("status")
	if err != nil {
		return nil, nil, err
	}
	leaf, err := s.keys.Certificate(caKey, caCert, &issuerKey.PublicKey, mock.LeafCertOptions{
		CommonName:            "EUDI Dev Status List Signer",
		StatusListSigner:      true,
		CRLDistributionPoints: CRLDistributionPoints(root.IssuerURL),
	}, false)
	if err != nil {
		return nil, nil, fmt.Errorf("generating status list signer certificate: %w", err)
	}
	return issuerKey, []*x509.Certificate{leaf, caCert}, nil
}

// Default is the signing material of the PID list, the first credential
// category.
func (s *Signer) Default() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return s.ForList(CategoryList(credtemplate.Categories[0]), "")
}

// IssuerSubjectAltNames are the SANs of a signing leaf. SD-JWT VC draft-08
// and earlier require the issuer identifier in them. Verifiers check either
// the DNS or the URI form, so both are included. IP hosts get an IP SAN.
func IssuerSubjectAltNames(issuerURL string) (dnsNames []string, ips []net.IP, uris []*url.URL) {
	raw := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if raw == "" {
		return nil, nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, nil, nil
	}
	dnsNames, ips = HostSubjectAltNames(parsed.Hostname())
	return dnsNames, ips, []*url.URL{parsed}
}

// HostSubjectAltNames puts an IP address in the iPAddress SAN and a name in
// the dNSName SAN (RFC 5280 §4.2.1.6). TLS clients match an IP host only
// against iPAddress entries.
func HostSubjectAltNames(host string) (dnsNames []string, ips []net.IP) {
	if host == "" {
		return nil, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, []net.IP{ip}
	}
	return []string{host}, nil
}

func signingLeafCommonName(list List) string {
	if list.LoTEType == "" {
		return config.WalletIssuerName
	}
	return jsonutil.FirstNonEmpty(list.EntityName, config.WalletIssuerName) + " (" + ListID(list) + ")"
}
