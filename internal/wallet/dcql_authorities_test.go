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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
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

func mdocWithChain(t *testing.T, chain ...*x509.Certificate) StoredCredential {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    mock.MDOCPIDClaims,
		Key:       key,
		CertChain: chain,
	})
	if err != nil {
		t.Fatal(err)
	}
	return StoredCredential{Format: "mso_mdoc", Raw: raw}
}

func TestExtractX5CCertificates(t *testing.T) {
	caCert, leafCert, _, _ := authorityChain(t)
	b64 := base64.StdEncoding.EncodeToString

	t.Run("a chain", func(t *testing.T) {
		certs, err := extractX5CCertificates(map[string]any{"x5c": []any{b64(leafCert.Raw), b64(caCert.Raw)}})
		if err != nil {
			t.Fatalf("extractX5CCertificates: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("certificates = %d, want 2", len(certs))
		}
		if certs[0].Subject.CommonName != "Document Signer" {
			t.Errorf("first certificate = %q, want the leaf first", certs[0].Subject.CommonName)
		}
	})

	t.Run("no x5c", func(t *testing.T) {
		certs, err := extractX5CCertificates(map[string]any{"alg": "ES256"})
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("an empty x5c", func(t *testing.T) {
		certs, err := extractX5CCertificates(map[string]any{"x5c": []any{}})
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("an entry that is not a string", func(t *testing.T) {
		certs, err := extractX5CCertificates(map[string]any{"x5c": []any{42}})
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("an entry that is not base64", func(t *testing.T) {
		if _, err := extractX5CCertificates(map[string]any{"x5c": []any{"!!!"}}); err == nil {
			t.Error("an unreadable x5c entry was accepted")
		}
	})

	t.Run("an entry that is not a certificate", func(t *testing.T) {
		if _, err := extractX5CCertificates(map[string]any{"x5c": []any{b64([]byte("nope"))}}); err == nil {
			t.Error("bytes that are not a certificate were accepted")
		}
	})
}

// COSE decoders return the x5chain label as int64 or uint64, depending on the
// encoder. A single certificate is a bare byte string.
func TestExtractMDOCX5Chain(t *testing.T) {
	caCert, leafCert, _, _ := authorityChain(t)
	withHeader := func(h map[any]any) *mdoc.Document {
		return &mdoc.Document{IssuerAuth: &mdoc.IssuerAuth{UnprotectedHeader: h}}
	}

	t.Run("one certificate under int64", func(t *testing.T) {
		certs, err := extractMDOCX5Chain(withHeader(map[any]any{int64(33): leafCert.Raw}))
		if err != nil || len(certs) != 1 {
			t.Fatalf("certs = %d, err = %v, want 1", len(certs), err)
		}
	})

	t.Run("a chain under uint64", func(t *testing.T) {
		certs, err := extractMDOCX5Chain(withHeader(map[any]any{uint64(33): []any{leafCert.Raw, caCert.Raw}}))
		if err != nil || len(certs) != 2 {
			t.Fatalf("certs = %d, err = %v, want 2", len(certs), err)
		}
	})

	t.Run("no issuer authentication", func(t *testing.T) {
		certs, err := extractMDOCX5Chain(&mdoc.Document{})
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("no x5chain", func(t *testing.T) {
		certs, err := extractMDOCX5Chain(withHeader(map[any]any{int64(1): int64(-7)}))
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("an x5chain of an unexpected shape", func(t *testing.T) {
		certs, err := extractMDOCX5Chain(withHeader(map[any]any{int64(33): "a string"}))
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("an entry that is not bytes", func(t *testing.T) {
		certs, err := extractMDOCX5Chain(withHeader(map[any]any{int64(33): []any{"a string"}}))
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("bytes that are not a certificate", func(t *testing.T) {
		if _, err := extractMDOCX5Chain(withHeader(map[any]any{int64(33): []byte("nope")})); err == nil {
			t.Error("unparseable DER was accepted")
		}
	})
}

func TestExtractCredentialCertificatesIgnoresOtherFormats(t *testing.T) {
	certs, err := extractCredentialCertificates(StoredCredential{Format: "jwt_vc", Raw: "whatever"})
	if err != nil || certs != nil {
		t.Errorf("certs = %v, err = %v, want both empty for a format with no chain", certs, err)
	}
}

func TestExtractCredentialCertificatesReportsUnparseableCredentials(t *testing.T) {
	if _, err := extractCredentialCertificates(StoredCredential{Format: "dc+sd-jwt", Raw: "not a token"}); err == nil {
		t.Error("an unparseable SD-JWT was accepted")
	}
	if _, err := extractCredentialCertificates(StoredCredential{Format: "mso_mdoc", Raw: "not an mdoc"}); err == nil {
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
		if checkAuthorityKeyIdentifiers(StoredCredential{Format: "jwt_vc"}, []string{wanted}) {
			t.Error("a credential without a certificate chain was accepted")
		}
	})

	t.Run("a credential that does not parse", func(t *testing.T) {
		if checkAuthorityKeyIdentifiers(StoredCredential{Format: "mso_mdoc", Raw: "nope"}, []string{wanted}) {
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
			if got := checkTrustedAuthorities(cred, tt.list); got != tt.want {
				t.Errorf("checkTrustedAuthorities = %v, want %v", got, tt.want)
			}
		})
	}
}

// mdoc uses a separate chain validation path from SD-JWT. Check that it accepts a
// listed CA and rejects an unrelated one.
func TestCheckETSITrustListMDOC(t *testing.T) {
	caCert, leafCert, _, _ := authorityChain(t)
	tlJWT, err := GenerateTrustListJWT(mustGenerateKey(t), caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}
	ts := serveTrustList(t, tlJWT)

	otherCA, otherLeaf, _, _ := authorityChain(t)

	t.Run("an mdoc chaining to the trust list", func(t *testing.T) {
		if !checkETSITrustList(mdocWithChain(t, leafCert, caCert), ts.URL) {
			t.Error("an mdoc whose issuer is in the trust list was refused")
		}
	})

	t.Run("an mdoc from another authority", func(t *testing.T) {
		if checkETSITrustList(mdocWithChain(t, otherLeaf, otherCA), ts.URL) {
			t.Error("an mdoc from an authority not in the trust list was accepted")
		}
	})
}

func mustGenerateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// An etsi_tl entry with an unreachable trust list refuses the credential.
func TestCheckETSITrustListWithAnUnreachableList(t *testing.T) {
	caCert, leafCert, _, _ := authorityChain(t)
	cred := mdocWithChain(t, leafCert, caCert)

	if checkETSITrustList(cred, "http://127.0.0.1:1/trustlist") {
		t.Error("an unreachable trust list was treated as satisfied")
	}
}
