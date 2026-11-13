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

package format

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCertificatesReadsTheCopiedForms(t *testing.T) {
	leaf, ca := testCertificate(t, "leaf"), testCertificate(t, "ca")
	pemOf := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	x5c, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(ca.Raw)})
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}))

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"PEM bundle", pemOf(leaf) + pemOf(ca), []string{"leaf", "ca"}},
		{"key and certificate", key + pemOf(leaf), []string{"leaf"}},
		{"x5c array", string(x5c), []string{"leaf", "ca"}},
		{"x5c entry", base64.StdEncoding.EncodeToString(leaf.Raw), []string{"leaf"}},
		{"base64url", base64.RawURLEncoding.EncodeToString(leaf.Raw), []string{"leaf"}},
		{"wrapped base64", wrap(base64.StdEncoding.EncodeToString(leaf.Raw), 64), []string{"leaf"}},
		{"hex", hex.EncodeToString(leaf.Raw), []string{"leaf"}},
		{"text before the PEM", "subject=CN=leaf\n" + pemOf(leaf), []string{"leaf"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := Certificates(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, c := range certs {
				got = append(got, c.Subject.CommonName)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("certificates %v, want %v", got, tt.want)
			}
			if Detect(tt.input) != FormatX509 {
				t.Errorf("detected %s, want %s", Detect(tt.input), FormatX509)
			}
		})
	}
}

func TestCertificatesNeedsEveryCertificateToParse(t *testing.T) {
	leaf := base64.StdEncoding.EncodeToString(testCertificate(t, "leaf").Raw)
	for name, input := range map[string]string{
		"x5c with a broken entry": `["` + leaf + `", "AAAA"]`,
		"empty x5c":               `[]`,
		"key only":                string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})),
		"JWT":                     "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln",
		"other base64":            base64.StdEncoding.EncodeToString([]byte("not a certificate")),
	} {
		if _, err := Certificates(input); err == nil {
			t.Errorf("%s: read as certificates", name)
		}
	}
}

func wrap(s string, width int) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width] + "\n")
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}

func TestCertificatesNamesTheParseError(t *testing.T) {
	der := testCertificate(t, "leaf").Raw
	_, err := Certificates(base64.StdEncoding.EncodeToString(der[:len(der)-8]))
	if err == nil || errors.Is(err, errNoCertificate) {
		t.Errorf("error %v, want the parse error of the certificate", err)
	}
}

func TestCertificatesNamesTheBrokenCertificate(t *testing.T) {
	leaf := testCertificate(t, "leaf").Raw
	broken := leaf[:len(leaf)-8]
	pemOf := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	tests := []struct {
		name, input, want string
	}{
		{"PEM bundle", pemOf(leaf) + pemOf(broken), "certificate 2 of 2: "},
		{"x5c array", `["` + base64.StdEncoding.EncodeToString(leaf) + `", "` + base64.StdEncoding.EncodeToString(broken) + `"]`, "certificate 2 of 2: "},
		{"cut off PEM", pemOf(leaf) + "-----BEGIN CERTIFICATE-----\nMIIB\n", "certificate 2 of 2: the PEM block doesn't decode"},
		{"broken base64 before a good block", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n" + pemOf(leaf), "certificate 1 of 2: the PEM block doesn't decode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Certificates(tt.input)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("error %v, want it to start with %q", err, tt.want)
			}
			if Detect(tt.input) != FormatX509 {
				t.Errorf("detected %s, want %s", Detect(tt.input), FormatX509)
			}
		})
	}
}

// A bare base64 value that doesn't parse as a certificate can be an mdoc,
// and a JSON array can be a vp_token, so both are left to the other formats.
func TestOtherInputIsNotDetectedAsCertificate(t *testing.T) {
	der := testCertificate(t, "leaf").Raw
	for name, input := range map[string]string{
		"broken bare DER":     base64.StdEncoding.EncodeToString(der[:len(der)-8]),
		"vp_token of SD-JWTs": `["eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln~"]`,
	} {
		if got := Detect(input); got == FormatX509 {
			t.Errorf("%s: detected %s", name, got)
		}
	}
}
