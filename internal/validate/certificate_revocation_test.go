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
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "signer"}}
	chain := []*x509.Certificate{cert}
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
