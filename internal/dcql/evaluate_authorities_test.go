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

package dcql

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// authorityChain returns a CA and a leaf it signed. The leaf carries an
// authority key identifier. An "aki" trusted authority matches on it.
func authorityChain(t *testing.T) (ca, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, aki []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeyID := []byte{0x01, 0x02, 0x03, 0x04}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Authority CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          subjectKeyID,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return ca, leaf, leafKey, subjectKeyID
}

func mdocWithChain(t *testing.T, chain ...*x509.Certificate) Credential {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{"given_name": "Erika", "family_name": "Mustermann"},
		Key:       key,
		CertChain: chain,
	})
	if err != nil {
		t.Fatal(err)
	}
	return Credential{Format: "mso_mdoc", Raw: raw}
}

func TestExtractCredentialCertificatesIgnoresOtherFormats(t *testing.T) {
	certs, err := extractCredentialCertificates(Credential{Format: "jwt_vc", Raw: "whatever"})
	if err != nil || certs != nil {
		t.Errorf("certs = %v, err = %v, want both empty for a format with no chain", certs, err)
	}
}

func TestExtractCredentialCertificatesReportsUnparseableCredentials(t *testing.T) {
	if _, err := extractCredentialCertificates(Credential{Format: "dc+sd-jwt", Raw: "not a token"}); err == nil {
		t.Error("an unparseable SD-JWT was accepted")
	}
	if _, err := extractCredentialCertificates(Credential{Format: "mso_mdoc", Raw: "not an mdoc"}); err == nil {
		t.Error("an unparseable mdoc was accepted")
	}
}

func TestCheckAuthorityKeyIdentifiers(t *testing.T) {
	caCert, leafCert, _, aki := authorityChain(t)
	wanted := format.EncodeBase64URL(aki)

	withChain := mdocWithChain(t, leafCert, caCert)

	t.Run("a matching authority key identifier", func(t *testing.T) {
		if !checkAuthorityKeyIdentifiers(withChain, []string{wanted}) {
			t.Error("the credential's own authority was not recognised")
		}
	})

	t.Run("an authority that is not asked for", func(t *testing.T) {
		if checkAuthorityKeyIdentifiers(withChain, []string{"c29tZXRoaW5nLWVsc2U"}) {
			t.Error("a credential from another authority was accepted")
		}
	})

	t.Run("a credential with no chain", func(t *testing.T) {
		if checkAuthorityKeyIdentifiers(Credential{Format: "jwt_vc"}, []string{wanted}) {
			t.Error("a credential without a certificate chain was accepted")
		}
	})

	t.Run("a credential that does not parse", func(t *testing.T) {
		if checkAuthorityKeyIdentifiers(Credential{Format: "mso_mdoc", Raw: "nope"}, []string{wanted}) {
			t.Error("an unparseable credential was accepted")
		}
	})
}

func TestCheckTrustedAuthorities(t *testing.T) {
	caCert, leafCert, _, aki := authorityChain(t)
	cred := mdocWithChain(t, leafCert, caCert)
	wanted := format.EncodeBase64URL(aki)

	tests := []struct {
		name string
		list []any
		want bool
	}{
		{
			name: "an aki entry naming the credential's authority",
			list: []any{map[string]any{"type": "aki", "values": []any{wanted}}},
			want: true,
		},
		{
			name: "an aki entry naming somebody else",
			list: []any{map[string]any{"type": "aki", "values": []any{"b3RoZXI"}}},
			want: false,
		},
		{
			name: "several entries where the last one matches",
			list: []any{
				map[string]any{"type": "aki", "values": []any{"b3RoZXI"}},
				map[string]any{"type": "aki", "values": []any{wanted}},
			},
			want: true,
		},
		{
			name: "an aki entry with no values",
			list: []any{map[string]any{"type": "aki", "values": []any{}}},
			want: false,
		},
		{
			name: "values that are not strings are ignored",
			list: []any{map[string]any{"type": "aki", "values": []any{42, ""}}},
			want: false,
		},
		{
			name: "an etsi_tl entry with no values",
			list: []any{map[string]any{"type": "etsi_tl", "values": []any{}}},
			want: false,
		},
		{
			name: "a type nothing supports",
			list: []any{map[string]any{"type": "openid_federation", "values": []any{"https://example"}}},
			want: false,
		},
		{name: "an entry that is not an object", list: []any{"nonsense"}, want: false},
		{name: "an empty list", list: []any{}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkTrustedAuthorities(cred, tt.list, nil); got != tt.want {
				t.Errorf("checkTrustedAuthorities = %v, want %v", got, tt.want)
			}
		})
	}
}

// mdoc uses a separate chain validation path from SD-JWT. Check that it accepts a
// listed CA and rejects an unrelated one.
func TestCheckETSITrustListMDOC(t *testing.T) {
	caCert, leafCert, _, _ := authorityChain(t)
	const listURL = "https://lists.example/pid"
	anchors := map[string][]*x509.Certificate{listURL: {caCert}}

	otherCA, otherLeaf, _, _ := authorityChain(t)

	t.Run("an mdoc chaining to the trusted list", func(t *testing.T) {
		if !checkETSITrustList(mdocWithChain(t, leafCert, caCert), listURL, anchors[listURL]) {
			t.Error("an mdoc whose issuer is in the trusted list was refused")
		}
	})

	t.Run("an mdoc from another authority", func(t *testing.T) {
		if checkETSITrustList(mdocWithChain(t, otherLeaf, otherCA), listURL, anchors[listURL]) {
			t.Error("an mdoc from an authority not in the trusted list was accepted")
		}
	})
}
