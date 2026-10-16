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

package certchain

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxCRLSize bounds a fetched CRL. The URL comes from a certificate that any
// verifier or issuer can present.
const maxCRLSize = 4 << 20

// RevocationProblem is a revoked certificate of a chain, or one with an
// unreadable CRL.
type RevocationProblem struct {
	Certificate *x509.Certificate
	// Revoked is false when the CRL can't be read.
	Revoked bool
	Err     error
}

func (p RevocationProblem) Error() string {
	subject := p.Certificate.Subject.String()
	if p.Revoked {
		return fmt.Sprintf("the certificate %q is revoked: %v", subject, p.Err)
	}
	return fmt.Sprintf("the revocation status of the certificate %q cannot be checked: %v", subject, p.Err)
}

// CheckRevocation checks each certificate of a verified chain. A certificate
// with a CRL distribution point must not be on its issuer's CRL. RFC 5280
// §6.1.3 (a)(3): "At the current time, the certificate is not revoked." The
// chain runs from the leaf to the trust anchor, so the next certificate is
// always the issuer. The trust anchor itself is not checked.
func CheckRevocation(chain []*x509.Certificate, client *http.Client, now time.Time) []RevocationProblem {
	var problems []RevocationProblem
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		if len(cert.CRLDistributionPoints) == 0 {
			continue
		}
		crl, err := fetchCRL(cert.CRLDistributionPoints, issuer, client, now)
		if err != nil {
			problems = append(problems, RevocationProblem{Certificate: cert, Err: err})
			continue
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				problems = append(problems, RevocationProblem{Certificate: cert, Revoked: true,
					Err: fmt.Errorf("its issuer revoked it on %s (reason code %d)", entry.RevocationTime.UTC().Format(time.RFC3339), entry.ReasonCode)})
				break
			}
		}
	}
	return problems
}

// RevocationFindings states each problem of CheckRevocation together with the
// broken rule. Without a client the wallet doesn't check revocation.
func RevocationFindings(path []*x509.Certificate, client *http.Client, rule string) []string {
	if client == nil {
		return nil
	}
	var findings []string
	for _, problem := range CheckRevocation(path, client, time.Now()) {
		findings = append(findings, rule+": "+problem.Error())
	}
	return findings
}

// fetchCRL returns the first current CRL from the distribution points that is
// signed by the certificate's issuer. It skips other URI schemes, such as ldap.
func fetchCRL(points []string, issuer *x509.Certificate, client *http.Client, now time.Time) (*x509.RevocationList, error) {
	var errs []error
	for _, point := range points {
		if !strings.HasPrefix(point, "http://") && !strings.HasPrefix(point, "https://") {
			continue
		}
		crl, err := readCRL(point, client)
		if err == nil {
			err = checkCRL(crl, issuer, now)
		}
		if err == nil {
			return crl, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", point, err))
	}
	if len(errs) == 0 {
		return nil, errors.New("no CRL distribution point uses http or https")
	}
	return nil, errors.Join(errs...)
}

func readCRL(url string, client *http.Client) (*x509.RevocationList, error) {
	if client == nil {
		return nil, errors.New("no HTTP client")
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCRLSize {
		return nil, fmt.Errorf("the CRL is larger than %d bytes", maxCRLSize)
	}
	// RFC 5280 §4.2.1.13 asks for a DER CRL. Some CAs serve PEM.
	if block, _ := pem.Decode(data); block != nil && block.Type == "X509 CRL" {
		data = block.Bytes
	}
	return x509.ParseRevocationList(data)
}

// checkCRL applies RFC 5280 §6.3.3: the CRL issuer is the certificate's
// issuer, the signature verifies, and the CRL is not past its nextUpdate.
func checkCRL(crl *x509.RevocationList, issuer *x509.Certificate, now time.Time) error {
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("the CRL is issued by %q, not by the certificate's issuer", crl.Issuer.String())
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("the CRL signature does not verify: %w", err)
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return fmt.Errorf("the CRL expired at its nextUpdate %s", crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	return nil
}
