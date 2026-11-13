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
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
)

func TestCertificateRevocationCheck(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "signer"}, CRLDistributionPoints: []string{"https://ca.example/crl"}}
	chain := []*x509.Certificate{cert, {Subject: pkix.Name{CommonName: "ca"}}}
	signed := &Result{Checks: []Check{{Name: CheckSignature, Status: Pass}}}
	for name, tc := range map[string]struct {
		problems []certchain.RevocationProblem
		want     string
	}{
		"no problem":     {nil, Pass},
		"revoked":        {[]certchain.RevocationProblem{{Certificate: cert, Revoked: true, Err: errors.New("key compromise")}}, Fail},
		"unreadable CRL": {[]certchain.RevocationProblem{{Certificate: cert, Err: errors.New("503")}}, Warning},
		"revoked wins":   {[]certchain.RevocationProblem{{Certificate: cert, Err: errors.New("503")}, {Certificate: cert, Revoked: true, Err: errors.New("revoked")}}, Fail},
	} {
		trust := Trust{CertificateProblems: func([]*x509.Certificate) []certchain.RevocationProblem { return tc.problems }}
		if got := newRun(trust, Options{}).certificateRevocation(chain, signed); len(got) != 1 || got[0].Status != tc.want {
			t.Errorf("%s: checks = %+v, want status %v", name, got, tc.want)
		}
	}
	none := Trust{CertificateProblems: func([]*x509.Certificate) []certchain.RevocationProblem {
		t.Error("the check read CRLs although no certificate names one")
		return nil
	}}
	withoutCRL := []*x509.Certificate{{Subject: pkix.Name{CommonName: "signer"}}, chain[1]}
	if got := newRun(none, Options{}).certificateRevocation(withoutCRL, signed); len(got) != 1 || got[0].Status != Skipped {
		t.Errorf("without a CRL: checks = %+v, want skipped", got)
	}
	if got := newRun(Trust{}, Options{}).certificateRevocation(chain, signed); got != nil {
		t.Errorf("without a CRL reader: checks = %+v", got)
	}
	unsigned := &Result{Checks: []Check{{Name: CheckSignature, Status: Fail}}}
	read := Trust{CertificateProblems: func([]*x509.Certificate) []certchain.RevocationProblem {
		t.Error("the check read CRLs for an invalid signature")
		return nil
	}}
	if got := newRun(read, Options{}).certificateRevocation(chain, unsigned); got != nil {
		t.Errorf("with an invalid signature: checks = %+v", got)
	}
}

func TestCertificateRevocationReadsTheCompletedChain(t *testing.T) {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "signer"}, CRLDistributionPoints: []string{"https://ca.example/crl"}}
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "ca"}}
	signed := &Result{Checks: []Check{{Name: CheckSignature, Status: Pass}}}
	trust := Trust{
		CertificateProblems: func([]*x509.Certificate) []certchain.RevocationProblem {
			return []certchain.RevocationProblem{{Certificate: leaf, Revoked: true, Err: errors.New("key compromise")}}
		},
		CompleteChain: func(chain []*x509.Certificate) []*x509.Certificate { return append(chain, ca) },
	}

	if got := newRun(trust, Options{}).certificateRevocation([]*x509.Certificate{leaf}, signed); len(got) != 1 || got[0].Status != Fail {
		t.Errorf("checks = %+v, want the revoked leaf whose issuer the wallet adds", got)
	}
}

func TestCertificateRevocationSkipsCRLsItCannotRead(t *testing.T) {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "signer"}, CRLDistributionPoints: []string{"ldap://ca.example/cn=crl"}}
	chain := []*x509.Certificate{leaf, {Subject: pkix.Name{CommonName: "ca"}}}
	signed := &Result{Checks: []Check{{Name: CheckSignature, Status: Pass}}}
	trust := Trust{CertificateProblems: func([]*x509.Certificate) []certchain.RevocationProblem {
		t.Error("the check read CRLs although none uses http or https")
		return nil
	}}

	if got := newRun(trust, Options{}).certificateRevocation(chain, signed); len(got) != 1 || got[0].Status != Skipped {
		t.Errorf("checks = %+v, want skipped", got)
	}
}

func TestCertificateRevocationWithoutTheLastIssuer(t *testing.T) {
	crl := []string{"https://ca.example/crl"}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "signer"}, CRLDistributionPoints: crl}
	intermediate := &x509.Certificate{Subject: pkix.Name{CommonName: "intermediate"}, CRLDistributionPoints: crl}
	signed := &Result{Checks: []Check{{Name: CheckSignature, Status: Pass}}}
	trust := Trust{CertificateProblems: func([]*x509.Certificate) []certchain.RevocationProblem { return nil }}
	chain := []*x509.Certificate{leaf, intermediate}

	if got := newRun(trust, Options{}).certificateRevocation(chain, signed); len(got) != 1 || got[0].Status != Warning {
		t.Errorf("online: checks = %+v, want a warning for the unread CRL of the intermediate", got)
	}
	if got := newRun(trust, Options{Offline: true}).certificateRevocation([]*x509.Certificate{leaf}, signed); len(got) != 1 || !got[0].NeedsNetwork {
		t.Errorf("offline: checks = %+v, want a check that needs the network", got)
	}
}
