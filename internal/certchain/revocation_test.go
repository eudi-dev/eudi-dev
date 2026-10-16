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

package certchain_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mock.GenerateNamedCACert(key, "Test Access CA")
	if err != nil {
		t.Fatal(err)
	}
	return testCA{key: key, cert: cert}
}

func (ca testCA) crl(t *testing.T, nextUpdate time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, cert := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: nextUpdate, RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (ca testCA) leaf(t *testing.T, crlURLs ...string) *x509.Certificate {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mock.GenerateLeafCertWithOptions(ca.key, ca.cert, &key.PublicKey, mock.LeafCertOptions{Role: mock.AccessCertificate, CRLDistributionPoints: crlURLs})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// RFC 5280 §6.1.3 (a)(3): "At the current time, the certificate is not
// revoked." §6.3.3 checks that the CRL's issuer signed it and that it is
// current.
func TestCheckRevocationReadsTheCRLOfEachCertificate(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	var served []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(served)
	}))
	defer srv.Close()
	leaf := ca.leaf(t, srv.URL+"/crl")
	path := []*x509.Certificate{leaf, ca.cert}
	future := time.Now().Add(time.Hour)

	for _, tc := range []struct {
		name    string
		crl     []byte
		revoked bool
		want    string
	}{
		{"a valid certificate", ca.crl(t, future), false, ""},
		{"a revoked certificate", ca.crl(t, future, leaf), true, "is revoked"},
		{"an unreachable CRL", nil, false, "HTTP 404"},
		{"a CRL under the same name with another key", other.crl(t, future, leaf), false, "signature does not verify"},
		{"an expired CRL", ca.crl(t, time.Now().Add(-time.Minute)), false, "expired at its nextUpdate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served = tc.crl
			problems := certchain.CheckRevocation(path, srv.Client(), time.Now())
			if tc.want == "" {
				if len(problems) != 0 {
					t.Fatalf("problems %v", problems)
				}
				return
			}
			if len(problems) != 1 || problems[0].Revoked != tc.revoked || !strings.Contains(problems[0].Error(), tc.want) {
				t.Fatalf("problems %v, want one with %q (revoked %t)", problems, tc.want, tc.revoked)
			}
		})
	}
}

// A certificate without a CRL distribution point and the trust anchor are not
// checked. When one distribution point fails, the next one is used.
func TestCheckRevocationFallsBackToTheNextDistributionPoint(t *testing.T) {
	ca := newTestCA(t)
	crl := ca.crl(t, time.Now().Add(time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/good" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(crl)
	}))
	defer srv.Close()
	for name, leaf := range map[string]*x509.Certificate{
		"two points":    ca.leaf(t, "ldap://ldap.example/crl", srv.URL+"/missing", srv.URL+"/good"),
		"no CRL at all": ca.leaf(t),
	} {
		if problems := certchain.CheckRevocation([]*x509.Certificate{leaf, ca.cert}, srv.Client(), time.Now()); len(problems) != 0 {
			t.Errorf("%s: problems %v", name, problems)
		}
	}
}
