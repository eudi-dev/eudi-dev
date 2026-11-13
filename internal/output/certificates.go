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

package output

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/certinfo"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func BuildCertificatesJSON(certs []*x509.Certificate) map[string]any {
	return map[string]any{
		"format":       string(format.FormatX509),
		"certificates": certinfo.DescribeAll(certs),
	}
}

func PrintCertificates(certs []*x509.Certificate, opts Options) {
	if opts.JSON {
		PrintJSON(BuildCertificatesJSON(certs))
		return
	}
	headerColor.Println("X.509 Certificates")
	headerColor.Println(strings.Repeat("─", 50))
	for i, c := range certinfo.DescribeAll(certs) {
		printSection(fmt.Sprintf("Certificate %d", i+1))
		printCertificate(c, opts.Verbose)
	}
	fmt.Println()
}

// tokenCertificates are the x5c certificates of a JWT header. A header
// without x5c, or with one that does not parse, has none.
func tokenCertificates(token *sdjwt.Token) []*x509.Certificate {
	certs, err := certchain.FromX5C(token.Header["x5c"])
	if err != nil {
		return nil
	}
	return certs
}

// mdocCertificates are the x5chain certificates of the issuerAuth.
func mdocCertificates(doc *mdoc.Document) []*x509.Certificate {
	if doc.IssuerAuth == nil {
		return nil
	}
	certs, err := certchain.FromCOSE(doc.IssuerAuth.ProtectedHeader, doc.IssuerAuth.UnprotectedHeader)
	if err != nil {
		return nil
	}
	return certs
}

func addCertificates(out map[string]any, certs []*x509.Certificate) {
	if len(certs) > 0 {
		out["certificates"] = certinfo.DescribeAll(certs)
	}
}

// printCertificateChain prints the signer's certificates of a credential.
func printCertificateChain(title string, certs []*x509.Certificate, verbose bool) {
	for i, c := range certinfo.DescribeAll(certs) {
		printSection(fmt.Sprintf("%s certificate %d", title, i+1))
		printCertificate(c, verbose)
	}
}

func printCertificate(c certinfo.Certificate, verbose bool) {
	printKV("Subject", c.Subject, 1)
	printKV("Issuer", c.Issuer, 1)
	printKV("Valid", c.NotBefore.Format(time.RFC3339)+" → "+c.NotAfter.Format(time.RFC3339)+dimColor.Sprintf(" (%s)", relativeTime(c.NotAfter)), 1)
	printKV("Public key", c.PublicKey, 1)
	if c.CA {
		printKV("CA", "yes", 1)
	}
	if c.SelfSigned {
		printKV("Self-signed", "yes", 1)
	}
	printList("Key usage", c.KeyUsage)
	printList("Extended key usage", c.ExtendedKeyUsage)
	printList("Subject alt names", c.SubjectAltNames)
	printList("Policies", c.Policies)
	printList("CRL", c.CRLDistribution)
	if !verbose {
		return
	}
	printKV("Serial number", c.SerialNumber, 1)
	printKV("Signature", c.SignatureAlgorithm, 1)
	if c.SubjectKeyID != "" {
		printKV("Subject key id", c.SubjectKeyID, 1)
	}
	if c.AuthorityKeyID != "" {
		printKV("Authority key id", c.AuthorityKeyID, 1)
	}
	printKV("SHA-256", c.SHA256Fingerprint, 1)
	fmt.Print(c.PEM)
}

func printList(label string, values []string) {
	if len(values) > 0 {
		printKV(label, strings.Join(values, ", "), 1)
	}
}
