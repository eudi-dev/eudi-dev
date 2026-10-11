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

package mock

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // ISO/IEC 18013-5 Annex B mandates SHA-1 for the subject key identifier, a name, not a security primitive
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
)

func SigningCertificateURL(issuer string, cert *x509.Certificate, extension string) string {
	issuer = strings.TrimRight(issuer, "/")
	if cert == nil || (!strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://")) {
		return ""
	}
	digest := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%s/api/certificates/signers/%x.%s", issuer, digest, extension)
}

// DefaultCertificateCountry is the subject countryName of a generated certificate
// when the credential has no issuing country. ISO/IEC 18013-5 Table B.3 requires
// the document signer certificate's countryName to equal the credential's
// issuing_country element, so it matches the default PID claim sets.
const DefaultCertificateCountry = "NL"

// issuerContactURI is the contact of the operator of a generated CA. ISO/IEC
// 18013-5 Annex B requires an issuer alternative name extension with issuer
// contact information on IACA and document signer certificates.
const issuerContactURI = "https://github.com/dominikschlosser/eudi-dev"

var (
	oidExtensionIssuerAltName    = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	// mdlDS is the document signing key purpose of ISO/IEC 18013-5 Annex B.
	oidMdlDocumentSigner = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
)

type CertificateRole string

const (
	PIDProviderCertificate    CertificateRole = "pid"
	WalletProviderCertificate CertificateRole = "wallet"
	AccessCertificate         CertificateRole = "access"
	RegistrarCertificate      CertificateRole = "registrar"
	TrustListCertificate      CertificateRole = "trustlist"
)

// randomSerialNumber returns a positive certificate serial of at most 20
// octets (RFC 5280 §4.1.2.2 and ISO/IEC 18013-5 Annex B).
func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating certificate serial: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

// issuerAltNameExtension builds the issuer alternative name extension with the
// issuer contact URI, non-critical as ISO/IEC 18013-5 Annex B requires.
func issuerAltNameExtension() (pkix.Extension, error) {
	generalNames, err := asn1.Marshal([]asn1.RawValue{{
		Class: asn1.ClassContextSpecific,
		Tag:   6, // uniformResourceIdentifier
		Bytes: []byte(issuerContactURI),
	}})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding issuer alternative name: %w", err)
	}
	return pkix.Extension{Id: oidExtensionIssuerAltName, Value: generalNames}, nil
}

// subjectKeyIdentifier computes the SHA-1 hash of the subject public key BIT
// STRING value. Every ISO/IEC 18013-5 Annex B profile requires this derivation.
func subjectKeyIdentifier(pub *ecdsa.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encoding subject public key: %w", err)
	}
	var wrapper struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing subject public key info: %w", err)
	}
	sum := sha1.Sum(wrapper.PublicKey.Bytes) //nolint:gosec // the RFC 5280 §4.2.1.2 method 1 key identifier every Annex B profile requires
	return sum[:], nil
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func PublicKeyJWKMap(key *ecdsa.PublicKey) map[string]string {
	jwk, err := keys.PublicJWK(key)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(jwk))
	for name, value := range jwk {
		out[name], _ = value.(string)
	}
	return out
}

// KeyIDForPublicKey computes the RFC 7638 JWK thumbprint of a public key.
func KeyIDForPublicKey(key *ecdsa.PublicKey) string {
	sum, err := keys.PublicKeyThumbprint(key)
	if err != nil {
		return ""
	}
	return format.EncodeBase64URL(sum)
}

func SigningJWKMap(key *ecdsa.PublicKey) map[string]any {
	jwk := PublicKeyJWKMap(key)
	return map[string]any{
		"kty": jwk["kty"],
		"crv": jwk["crv"],
		"x":   jwk["x"],
		"y":   jwk["y"],
		"kid": KeyIDForPublicKey(key),
		"use": "sig",
		"alg": "ES256",
	}
}

func PublicKeyJWK(key *ecdsa.PublicKey) string {
	jwk, err := keys.PublicJWK(key)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}

	b, _ := json.MarshalIndent(jwk, "", "  ")
	return string(b)
}

// GenerateCACert creates a self-signed CA certificate for the given key. It
// follows the IACA root certificate profile of ISO/IEC 18013-5 Table B.1.
func GenerateCACert(caKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	return generateCACert(caKey, 0)
}

func GenerateRootCACert(caKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	return generateCACert(caKey, 1)
}

// GenerateNamedCACert creates a self-signed CA certificate that issues end
// entity certificates only.
func GenerateNamedCACert(caKey *ecdsa.PrivateKey, commonName string) (*x509.Certificate, error) {
	return generateNamedCACert(caKey, 0, pkix.Name{
		CommonName:   commonName,
		Country:      []string{DefaultCertificateCountry},
		Organization: []string{"EUDI Dev Test CA"},
	})
}

func generateCACert(caKey *ecdsa.PrivateKey, maxPathLen int) (*x509.Certificate, error) {
	return generateNamedCACert(caKey, maxPathLen, pkix.Name{
		CommonName:   "OID4VC Dev Wallet CA",
		Country:      []string{DefaultCertificateCountry},
		Organization: []string{"EUDI Dev Test CA"},
	})
}

func generateNamedCACert(caKey *ecdsa.PrivateKey, maxPathLen int, subject pkix.Name) (*x509.Certificate, error) {
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	issuerAltName, err := issuerAltNameExtension()
	if err != nil {
		return nil, err
	}
	// Go generates an RFC 7093 identifier (truncated SHA-256). Annex B requires
	// the RFC 5280 method 1 SHA-1 derivation.
	subjectKeyID, err := subjectKeyIdentifier(&caKey.PublicKey)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		SubjectKeyId:          subjectKeyID,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
		ExtraExtensions:       []pkix.Extension{issuerAltName},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

func GenerateLeafCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafPubKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	return GenerateLeafCertWithOptions(caKey, caCert, leafPubKey, LeafCertOptions{})
}

type certificatePolicy struct {
	ID         asn1.ObjectIdentifier
	Qualifiers []policyQualifier
}

type policyQualifier struct {
	ID  asn1.ObjectIdentifier
	URI string `asn1:"ia5"`
}

type LeafCertOptions struct {
	CommonName            string
	Organization          string
	SerialNumber          *big.Int
	Role                  CertificateRole
	IssuingCertificateURL []string
	CertificateAuthority  bool
	// EU 2026/1731, EAA-6.2.10.1-08 permits status signing without an EKU.
	StatusListSigner bool
	// Country becomes the subject countryName. ISO/IEC 18013-5 Table B.3
	// requires it to equal the signed credential's issuing_country element.
	// Empty uses DefaultCertificateCountry.
	Country string
	// CRLDistributionPoints are the URIs of the revocation information for this
	// certificate. Table B.3 requires at least one.
	CRLDistributionPoints []string
	// DNSNames, URIs and IPAddresses become the subject alternative names.
	// A verifier that resolves an issuer key from the x5c header checks the
	// credential's iss against them (HAIP 1.0).
	DNSNames       []string
	URIs           []*url.URL
	IPAddresses    []net.IP
	EmailAddresses []string
	// OrganizationalUnit names one service of the organization (ARF Reg_33,
	// ETSI TS 119 411-8 GEN-6.6.1-08). Empty leaves it out.
	OrganizationalUnit string
	// OrganizationIdentifier is the subject organizationIdentifier (OID
	// 2.5.4.97). Empty uses a placeholder for the country.
	OrganizationIdentifier string
	// Validity is the leaf's lifetime. Zero is one year.
	Validity time.Duration
}

// GenerateLeafCertWithOptions creates a leaf certificate signed by the CA. By default
// it follows the document signer certificate profile of ISO/IEC 18013-5:2021 Table B.3.
func GenerateLeafCertWithOptions(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafPubKey *ecdsa.PublicKey, opts LeafCertOptions) (*x509.Certificate, error) {
	commonName := opts.CommonName
	if commonName == "" {
		commonName = "OID4VC Dev Wallet Issuer"
	}
	country := opts.Country
	if country == "" {
		country = DefaultCertificateCountry
	}
	organization := opts.Organization
	if organization == "" {
		organization = "EUDI Dev Test Provider"
	}
	organizationIdentifier := opts.OrganizationIdentifier
	if organizationIdentifier == "" {
		// The legal person semantics identifier of the EUID <country>TEST.00000000
		// (ETSI EN 319 412-1 V1.6.1 LEG-5.1.4-07 b).
		organizationIdentifier = "NTR" + country + "-" + country + "TEST.00000000"
	}
	validity := opts.Validity
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}
	serialNumber := opts.SerialNumber
	if serialNumber == nil || serialNumber.Sign() <= 0 {
		var err error
		serialNumber, err = randomSerialNumber()
		if err != nil {
			return nil, err
		}
	}
	subjectKeyID, err := subjectKeyIdentifier(leafPubKey)
	if err != nil {
		return nil, err
	}
	issuerAltName, err := issuerAltNameExtension()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Country:      []string{country},
			Organization: []string{organization},
			ExtraNames:   []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: organizationIdentifier}},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID,
		CRLDistributionPoints: opts.CRLDistributionPoints,
		DNSNames:              opts.DNSNames,
		URIs:                  opts.URIs,
		IPAddresses:           opts.IPAddresses,
		EmailAddresses:        opts.EmailAddresses,
		IssuingCertificateURL: opts.IssuingCertificateURL,
		ExtraExtensions: []pkix.Extension{
			issuerAltName,
		},
	}
	if opts.OrganizationalUnit != "" {
		template.Subject.OrganizationalUnit = []string{opts.OrganizationalUnit}
	}
	if opts.CertificateAuthority {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.MaxPathLen = 0
		template.MaxPathLenZero = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.NotAfter = time.Now().Add(5 * 365 * 24 * time.Hour)
	}
	if template.NotAfter.After(caCert.NotAfter) {
		template.NotAfter = caCert.NotAfter
	}
	if !opts.CertificateAuthority && !opts.StatusListSigner && (opts.Role == "" || opts.Role == PIDProviderCertificate) {
		extendedKeyUsage, err := asn1.Marshal([]asn1.ObjectIdentifier{oidMdlDocumentSigner})
		if err != nil {
			return nil, fmt.Errorf("encoding extended key usage: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id: oidExtensionExtendedKeyUsage, Critical: true, Value: extendedKeyUsage,
		})
	}
	if opts.Role == PIDProviderCertificate || opts.Role == WalletProviderCertificate {
		role := asn1.ObjectIdentifier{0, 4, 0, 194126, 1, 1}
		if opts.Role == WalletProviderCertificate {
			role[len(role)-1] = 2
		}
		// EN 319 412-5 V2.5.1 §4.2.3 encodes QcType as a sequence of purpose OIDs.
		statements, err := asn1.Marshal([]struct {
			ID    asn1.ObjectIdentifier
			Types []asn1.ObjectIdentifier
		}{{asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}, []asn1.ObjectIdentifier{role}}})
		if err != nil {
			return nil, fmt.Errorf("encoding QCStatements: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}, Value: statements})
	}
	if opts.Role == AccessCertificate {
		template.BasicConstraintsValid = true
		// TS 119 411-8 V1.1.1 §5.3 defines the legal person access policy.
		policies, err := asn1.Marshal([]certificatePolicy{{
			ID: asn1.ObjectIdentifier{0, 4, 0, 194118, 1, 2},
			Qualifiers: []policyQualifier{{
				ID:  asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
				URI: "https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md",
			}},
		}})
		if err != nil {
			return nil, fmt.Errorf("encoding access certificate policy: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: policies})
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, leafPubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating leaf certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

// WithoutSelfSignedTrustAnchor removes a terminal self-signed root certificate from
// a chain for JOSE headers or JWK metadata.
func WithoutSelfSignedTrustAnchor(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	out := make([]*x509.Certificate, len(chain))
	copy(out, chain)
	last := out[len(out)-1]
	if bytes.Equal(last.RawSubject, last.RawIssuer) && last.CheckSignatureFrom(last) == nil {
		return out[:len(out)-1]
	}
	return out
}

func PrivateKeyJWK(key *ecdsa.PrivateKey) string {
	jwk, err := keys.PublicJWK(&key.PublicKey)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	dBytes, err := key.Bytes()
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	jwk["d"] = format.EncodeBase64URL(dBytes)

	b, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	return string(b)
}

// Seed keeps generated keys stable across restarts with memory storage. An empty seed
// generates random keys.
type Seed []byte

// Key derives an independent P-256 key for each label. It runs HKDF-SHA256
// over the seed and reduces the result into the curve order (FIPS 186-5 A.2.1).
func (s Seed) Key(label string) (*ecdsa.PrivateKey, error) {
	if len(s) == 0 {
		return GenerateKey()
	}
	material, err := hkdf.Key(sha256.New, s, []byte("eudi-dev/key"), label, 48)
	if err != nil {
		return nil, fmt.Errorf("deriving the %s key: %w", label, err)
	}
	order := elliptic.P256().Params().N
	scalar := new(big.Int).SetBytes(material)
	scalar.Mod(scalar, new(big.Int).Sub(order, big.NewInt(1)))
	scalar.Add(scalar, big.NewInt(1))
	raw := make([]byte, 32)
	scalar.FillBytes(raw)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("deriving the %s key: %w", label, err)
	}
	return key, nil
}
