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

package validate

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certinfo"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// Certificates checks pasted certificates, leaf first as in x5c. It needs at
// least one certificate. The checks are the validity period of each
// certificate, the signature of each one by the next, and revocation. Nothing
// anchors the chain.
func Certificates(certs []*x509.Certificate, trust Trust, opts Options) *Result {
	v := newRun(trust, opts)
	r := &Result{Format: FormatX509, Certificates: certs}
	r.add(certificatesValidity(certs, v.now), chainSignatures(certs))
	r.add(v.certificateRevocation(certs, r)...)
	return r
}

func certificatesValidity(certs []*x509.Certificate, now time.Time) Check {
	first := certs[0].NotAfter
	for i, cert := range certs {
		switch {
		case now.Before(cert.NotBefore):
			return Check{Name: CheckExpiry, Status: Fail, Detail: fmt.Sprintf("Certificate %d is not valid before %s", i+1, cert.NotBefore.UTC().Format(time.RFC3339))}
		case now.After(cert.NotAfter):
			return Check{Name: CheckExpiry, Status: Fail, Detail: fmt.Sprintf("Certificate %d expired %s", i+1, validity.Relative(cert.NotAfter, now))}
		}
		if cert.NotAfter.Before(first) {
			first = cert.NotAfter
		}
	}
	if len(certs) == 1 {
		return Check{Name: CheckExpiry, Status: Pass, Detail: "Valid until " + first.UTC().Format(time.RFC3339)}
	}
	return Check{Name: CheckExpiry, Status: Pass, Detail: "Valid until " + first.UTC().Format(time.RFC3339) + ". The chain expires with its earliest certificate."}
}

// chainSignatures checks the order of RFC 7515 §4.1.6: "Each subsequent
// certificate in the array MUST be the one used to certify the previous one."
func chainSignatures(certs []*x509.Certificate) Check {
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			detail := fmt.Sprintf("Certificate %d is not signed by certificate %d: %v", i+1, i+2, err)
			if certs[i+1].CheckSignatureFrom(certs[i]) == nil {
				detail = fmt.Sprintf("Certificate %d is signed by certificate %d. A chain lists the leaf first", i+2, i+1)
			}
			return Check{Name: CheckSignature, Status: Fail, Detail: detail}
		}
	}
	switch {
	case len(certs) == 1 && certinfo.SelfSigned(certs[0]):
		return Check{Name: CheckSignature, Status: Pass, Detail: "The certificate is self-signed and its signature verifies"}
	case len(certs) == 1:
		return Check{Name: CheckSignature, Status: Skipped, Detail: "Needs the issuer certificate"}
	}
	return Check{Name: CheckSignature, Status: Pass, Detail: "Each certificate is signed by the next one"}
}
