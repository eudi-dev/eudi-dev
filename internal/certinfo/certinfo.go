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

// Package certinfo describes X.509 certificates for people to read.
package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Certificate is the readable content of one certificate.
type Certificate struct {
	Subject            string      `json:"subject"`
	Issuer             string      `json:"issuer"`
	SerialNumber       string      `json:"serialNumber"`
	NotBefore          time.Time   `json:"notBefore"`
	NotAfter           time.Time   `json:"notAfter"`
	SelfSigned         bool        `json:"selfSigned"`
	CA                 bool        `json:"ca"`
	MaxPathLength      *int        `json:"maxPathLength,omitempty"`
	PublicKey          string      `json:"publicKey"`
	SignatureAlgorithm string      `json:"signatureAlgorithm"`
	KeyUsage           []string    `json:"keyUsage,omitempty"`
	ExtendedKeyUsage   []string    `json:"extendedKeyUsage,omitempty"`
	SubjectAltNames    []string    `json:"subjectAltNames,omitempty"`
	Policies           []string    `json:"policies,omitempty"`
	CRLDistribution    []string    `json:"crlDistributionPoints,omitempty"`
	OCSPServers        []string    `json:"ocspServers,omitempty"`
	IssuerURLs         []string    `json:"issuingCertificateURLs,omitempty"`
	SubjectKeyID       string      `json:"subjectKeyId,omitempty"`
	AuthorityKeyID     string      `json:"authorityKeyId,omitempty"`
	Extensions         []Extension `json:"extensions"`
	SHA256Fingerprint  string      `json:"sha256Fingerprint"`
	PEM                string      `json:"pem"`
}

type Extension struct {
	OID      string `json:"oid"`
	Name     string `json:"name,omitempty"`
	Critical bool   `json:"critical"`
}

func Describe(cert *x509.Certificate) Certificate {
	fingerprint := sha256.Sum256(cert.Raw)
	c := Certificate{
		Subject:            distinguishedName(cert.RawSubject, cert.Subject),
		Issuer:             distinguishedName(cert.RawIssuer, cert.Issuer),
		SerialNumber:       cert.SerialNumber.Text(16),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		SelfSigned:         SelfSigned(cert),
		CA:                 cert.BasicConstraintsValid && cert.IsCA,
		PublicKey:          publicKey(cert.PublicKey),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyUsage:           keyUsage(cert.KeyUsage),
		ExtendedKeyUsage:   extendedKeyUsage(cert),
		SubjectAltNames:    subjectAltNames(cert),
		CRLDistribution:    cert.CRLDistributionPoints,
		OCSPServers:        cert.OCSPServer,
		IssuerURLs:         cert.IssuingCertificateURL,
		Extensions:         extensions(cert.Extensions),
		SHA256Fingerprint:  hex.EncodeToString(fingerprint[:]),
		PEM:                string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	if c.CA && (cert.MaxPathLen > 0 || cert.MaxPathLenZero) {
		pathLength := cert.MaxPathLen
		c.MaxPathLength = &pathLength
	}
	for _, policy := range cert.Policies {
		c.Policies = append(c.Policies, policy.String())
	}
	if len(cert.SubjectKeyId) > 0 {
		c.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		c.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}
	return c
}

// SelfSigned reports whether cert names itself as issuer and its own key
// verifies its signature. CheckSignatureFrom would refuse an end-entity
// certificate as its own parent, because it has no keyCertSign usage.
func SelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// DescribeAll describes a chain in its order.
func DescribeAll(certs []*x509.Certificate) []Certificate {
	out := make([]Certificate, 0, len(certs))
	for _, cert := range certs {
		out = append(out, Describe(cert))
	}
	return out
}

// attributeNames are the names of RFC 4514 §3 and, for attributes it doesn't
// name, those of X.520 and of PKCS #9 (RFC 2985) for emailAddress.
var attributeNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "surname",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "givenName",
	"2.5.4.97":                   "organizationIdentifier",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
}

// distinguishedName lists the attributes in the order of the certificate,
// so country and organization come before the common name. Values are
// escaped and multi-valued RDNs joined with "+" as in RFC 4514 §2.
func distinguishedName(raw []byte, parsed pkix.Name) string {
	var sequence pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &sequence); err != nil || len(rest) > 0 {
		return parsed.String()
	}
	rdns := make([]string, 0, len(sequence))
	for _, rdn := range sequence {
		attributes := make([]string, 0, len(rdn))
		for _, attribute := range rdn {
			name, ok := attributeNames[attribute.Type.String()]
			if !ok {
				name = attribute.Type.String()
			}
			attributes = append(attributes, name+"="+attributeValue(attribute.Value))
		}
		rdns = append(rdns, strings.Join(attributes, "+"))
	}
	return strings.Join(rdns, ", ")
}

// attributeValue gives a value without a string form as "#" and the hex of
// its BER encoding (RFC 4514 §2.4).
func attributeValue(value any) string {
	if text, ok := value.(string); ok {
		return escapeAttributeValue(text)
	}
	if ber, err := asn1.Marshal(value); err == nil {
		return "#" + hex.EncodeToString(ber)
	}
	return escapeAttributeValue(fmt.Sprint(value))
}

// escapeAttributeValue escapes the characters of RFC 4514 §2.4.
func escapeAttributeValue(value string) string {
	var b strings.Builder
	for i, r := range value {
		switch {
		case strings.ContainsRune(`"+,;<>\`, r),
			i == 0 && (r == ' ' || r == '#'),
			i == len(value)-1 && r == ' ':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == 0:
			b.WriteString(`\00`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func publicKey(key any) string {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return "EC " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", key)
}

// keyUsageNames are the bit names of RFC 5280 §4.2.1.3.
var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyUsage(usage x509.KeyUsage) []string {
	var names []string
	for _, u := range keyUsageNames {
		if usage&u.bit != 0 {
			names = append(names, u.name)
		}
	}
	return names
}

// extendedKeyUsageNames are the purposes of RFC 5280 §4.2.1.12 and the
// document signer purpose of ISO/IEC 18013-5 Table B.3.
var extendedKeyUsageNames = map[string]string{
	"2.5.29.37.0":       "anyExtendedKeyUsage",
	"1.3.6.1.5.5.7.3.1": "serverAuth",
	"1.3.6.1.5.5.7.3.2": "clientAuth",
	"1.3.6.1.5.5.7.3.3": "codeSigning",
	"1.3.6.1.5.5.7.3.4": "emailProtection",
	"1.3.6.1.5.5.7.3.8": "timeStamping",
	"1.3.6.1.5.5.7.3.9": "OCSPSigning",
	"1.0.18013.5.1.2":   "mdlDS",
}

// extendedKeyUsage reads the purposes from the extension, because Go maps
// only some of them to its own constants.
func extendedKeyUsage(cert *x509.Certificate) []string {
	var names []string
	for _, e := range cert.Extensions {
		if !e.Id.Equal(oidExtendedKeyUsage) {
			continue
		}
		var purposes []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(e.Value, &purposes); err != nil {
			return nil
		}
		for _, purpose := range purposes {
			name, ok := extendedKeyUsageNames[purpose.String()]
			if !ok {
				name = purpose.String()
			}
			names = append(names, name)
		}
	}
	return names
}

var oidExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

func subjectAltNames(cert *x509.Certificate) []string {
	var names []string
	for _, name := range cert.DNSNames {
		names = append(names, "DNS:"+name)
	}
	for _, uri := range cert.URIs {
		names = append(names, "URI:"+uri.String())
	}
	for _, email := range cert.EmailAddresses {
		names = append(names, "email:"+email)
	}
	for _, ip := range cert.IPAddresses {
		names = append(names, "IP:"+ip.String())
	}
	return names
}

// extensionNames are the extensions of RFC 5280 §4.2 and the qualified
// certificate statements of RFC 3739 §3.2.6.
var extensionNames = map[string]string{
	"2.5.29.14":         "subjectKeyIdentifier",
	"2.5.29.15":         "keyUsage",
	"2.5.29.17":         "subjectAltName",
	"2.5.29.18":         "issuerAltName",
	"2.5.29.19":         "basicConstraints",
	"2.5.29.30":         "nameConstraints",
	"2.5.29.31":         "cRLDistributionPoints",
	"2.5.29.32":         "certificatePolicies",
	"2.5.29.35":         "authorityKeyIdentifier",
	"2.5.29.37":         "extKeyUsage",
	"1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
	"1.3.6.1.5.5.7.1.3": "qcStatements",
}

func extensions(list []pkix.Extension) []Extension {
	out := make([]Extension, 0, len(list))
	for _, e := range list {
		oid := e.Id.String()
		out = append(out, Extension{OID: oid, Name: extensionNames[oid], Critical: e.Critical})
	}
	return out
}
