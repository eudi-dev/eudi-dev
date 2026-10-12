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
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

// SigningCertChainForIssuedAttestation uses a distinct leaf per profile under the shared
// CA.
func (w *Wallet) SigningCertChainForIssuedAttestation(spec IssuedAttestationSpec) ([]*x509.Certificate, error) {
	return w.SigningCertChainForProfile(trustListProfileFromSpec(spec))
}

// SigningCertChainForIssuedCredential matches the signer's countryName to issuing_country
// as ISO/IEC 18013-5 Table B.3 requires.
func (w *Wallet) SigningCertChainForIssuedCredential(spec IssuedAttestationSpec, claims map[string]any) ([]*x509.Certificate, error) {
	_, chain, err := w.signingMaterialForProfile(trustListProfileFromSpec(spec), IssuingCountryFromClaims(claims))
	return chain, err
}

// SigningMaterialForIssuedAttestation reads the key and chain together so a reset
// cannot pair values from before and after it.
func (w *Wallet) SigningMaterialForIssuedAttestation(spec IssuedAttestationSpec) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(trustListProfileFromSpec(spec), "")
}

func (w *Wallet) SigningCertChainForGroup(group TrustListGroup) ([]*x509.Certificate, error) {
	return w.SigningCertChainForProfile(group.Profile)
}

func (w *Wallet) SigningCertChainForProfile(profile trustListProfile) ([]*x509.Certificate, error) {
	_, chain, err := w.signingMaterialForProfile(profile, "")
	return chain, err
}

func IssuingCountryFromClaims(claims map[string]any) string {
	country, _ := claims["issuing_country"].(string)
	if len(country) == 2 && country == strings.ToUpper(country) {
		return country
	}
	return ""
}

// Hold one lock while reading the key and chain. A concurrent reset could
// otherwise pair a new key with an old chain.
func (w *Wallet) signingMaterialForProfile(profile trustListProfile, country string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if w == nil {
		return nil, nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	if country == "" {
		country = mock.DefaultCertificateCountry
	}
	w.mu.RLock()
	issuerKey, caKey := w.IssuerKey, w.CAKey
	chain := append([]*x509.Certificate(nil), w.CertChain...)
	w.mu.RUnlock()

	if issuerKey == nil || caKey == nil || len(chain) < 2 {
		return nil, nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	caCert := chain[len(chain)-1]
	opts := mock.LeafCertOptions{
		CommonName:            signingLeafCommonName(profile),
		Country:               country,
		CRLDistributionPoints: crlDistributionPoints(w.IssuerURL),
	}
	switch profile.LoTEType {
	case pidTrustListType:
		opts.Role = mock.PIDProviderCertificate
	case walletProviderTrustListType:
		opts.Role = mock.WalletProviderCertificate
		var err error
		issuerKey, err = w.signingStore().key("wallet-provider")
		if err != nil {
			return nil, nil, err
		}
	}
	opts.IssuingCertificateURL = issuingCertificateURLs(w.IssuerURL)
	role := string(opts.Role)
	if role == "" {
		role = "local"
	}
	parentKey, parent, err := w.signingStore().providerCA(caKey, caCert, w.IssuerURL, role, country)
	if err != nil {
		return nil, nil, fmt.Errorf("generating provider CA: %w", err)
	}
	if !parent.Equal(caCert) {
		certificateCountry := country
		if certificateCountry == "" {
			certificateCountry = mock.DefaultCertificateCountry
		}
		base := strings.TrimRight(w.IssuerURL, "/")
		if base != "" {
			opts.IssuingCertificateURL = []string{base + "/api/certificates/providers/" + role + "/" + certificateCountry + ".der"}
			opts.CRLDistributionPoints = []string{base + "/api/crl/providers/" + role + "/" + certificateCountry}
		}
	}
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(w.IssuerURL)
	leafCert, err := w.signingStore().certificate(parentKey, parent, &issuerKey.PublicKey, opts, false)
	if err != nil {
		return nil, nil, fmt.Errorf("generating signing leaf certificate: %w", err)
	}
	certs := []*x509.Certificate{leafCert, parent}
	if !parent.Equal(caCert) {
		certs = append(certs, caCert)
	}
	return issuerKey, certs, nil
}

// ISO/IEC 18013-5 Table B.3 requires a CRL distribution point URI in document signer
// certificates.
func crlDistributionPoints(issuerURL string) []string {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil
	}
	return []string{issuer + "/api/crl"}
}

func issuingCertificateURLs(issuerURL string) []string {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil
	}
	return []string{issuer + "/api/certificates/ca.der"}
}

func (w *Wallet) WalletProviderSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(walletProviderTrustListProfile(), "")
}

func (w *Wallet) AccessSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("access", mock.LeafCertOptions{CommonName: "EUDI Dev Test Access", Role: mock.AccessCertificate})
}

func (w *Wallet) RegistrarSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("registrar", mock.LeafCertOptions{CommonName: "EUDI Dev Test Registrar", Role: mock.RegistrarCertificate})
}

func (w *Wallet) TrustListSigningMaterial(operator, country string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("trustlist", mock.LeafCertOptions{CommonName: "EUDI Dev Test List Operator", Role: mock.TrustListCertificate, Organization: operator, Country: country})
}

func (w *Wallet) auxiliarySigningMaterial(keyRole string, opts mock.LeafCertOptions) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if w == nil {
		return nil, nil, fmt.Errorf("wallet has no signing material")
	}
	w.mu.RLock()
	caKey, chain, issuer := w.CAKey, append([]*x509.Certificate(nil), w.CertChain...), w.IssuerURL
	w.mu.RUnlock()
	if caKey == nil || len(chain) < 2 {
		return nil, nil, fmt.Errorf("wallet has no access certificate authority")
	}
	key, err := w.signingStore().key(keyRole)
	if err != nil {
		return nil, nil, err
	}
	opts.IssuingCertificateURL = issuingCertificateURLs(issuer)
	opts.CRLDistributionPoints = crlDistributionPoints(issuer)
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(issuer)
	ca := chain[len(chain)-1]
	leaf, err := w.signingStore().certificate(caKey, ca, &key.PublicKey, opts, false)
	if err != nil {
		return nil, nil, err
	}
	return key, []*x509.Certificate{leaf, ca}, nil
}

// TrustAnchorCertificate holds the read lock because a reset can replace the
// chain concurrently.
func (w *Wallet) TrustAnchorCertificate() *x509.Certificate {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.CertChain) == 0 {
		return nil
	}
	return w.CertChain[len(w.CertChain)-1]
}

func (w *Wallet) DefaultSigningCertChain() ([]*x509.Certificate, error) {
	_, chain, err := w.DefaultSigningMaterial()
	return chain, err
}

func (w *Wallet) StatusListSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	w.mu.RLock()
	issuerKey, caKey := w.IssuerKey, w.CAKey
	chain := append([]*x509.Certificate(nil), w.CertChain...)
	w.mu.RUnlock()
	if issuerKey == nil || len(chain) == 0 {
		return nil, nil, fmt.Errorf("wallet has no status list signing material")
	}
	if caKey == nil || len(chain) < 2 {
		return issuerKey, chain, nil
	}
	caCert := chain[len(chain)-1]
	var err error
	issuerKey, err = w.signingStore().key("status")
	if err != nil {
		return nil, nil, err
	}
	leaf, err := w.signingStore().certificate(caKey, caCert, &issuerKey.PublicKey, mock.LeafCertOptions{
		CommonName:            "EUDI Dev Status List Signer",
		StatusListSigner:      true,
		CRLDistributionPoints: crlDistributionPoints(w.IssuerURL),
	}, false)
	if err != nil {
		return nil, nil, fmt.Errorf("generating status list signer certificate: %w", err)
	}
	return issuerKey, []*x509.Certificate{leaf, caCert}, nil
}

// DefaultSigningMaterial reads the key and chain together. A reload or reset between
// two separate reads could return a key that does not match the chain.
func (w *Wallet) DefaultSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	group, ok := DefaultTrustListGroupForWallet(w)
	if !ok {
		if w == nil {
			return nil, nil, fmt.Errorf("wallet has no signing certificate chain")
		}
		w.mu.RLock()
		issuerKey := w.IssuerKey
		chain := append([]*x509.Certificate(nil), w.CertChain...)
		w.mu.RUnlock()
		if len(chain) == 0 {
			return nil, nil, fmt.Errorf("wallet has no signing certificate chain")
		}
		return issuerKey, chain, nil
	}
	return w.signingMaterialForProfile(group.Profile, "")
}

// SD-JWT VC draft-08 and earlier require the issuer identifier in the signing
// leaf's SANs. Verifiers check either the DNS or the URI form, so both are
// included. IP hosts get an IP SAN.
func issuerSubjectAltNames(issuerURL string) (dnsNames []string, ips []net.IP, uris []*url.URL) {
	raw := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if raw == "" {
		return nil, nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, nil, nil
	}
	if host := parsed.Hostname(); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	return dnsNames, ips, []*url.URL{parsed}
}

func signingLeafCommonName(profile trustListProfile) string {
	label := strings.TrimSpace(profile.EntityName)
	if label == "" {
		label = "EUDI Dev Wallet Issuer"
	}
	id := trustListGroupID(profile)
	if id == "" {
		return label
	}
	return label + " (" + id + ")"
}
