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
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func TestIssueWithSigningOverride(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := New(holderKey, issuerKey, false)
	w.Templates = credtemplate.FileLocation(t.TempDir())

	ca, leaf, leafKey, _ := authorityChain(t)
	opts := IssueOptions{
		Format:           "sdjwt",
		Claims:           map[string]any{"given_name": "Erika"},
		SigningKey:       leafKey,
		SigningCertChain: []*x509.Certificate{leaf, ca},
		Trust:            provider.IssuedAttestationSpec{Entitlements: []string{"https://entitlement.example/custom"}},
	}
	result, err := w.IssueCredential(opts)
	if err != nil {
		t.Fatal(err)
	}

	// The override chain is embedded as given, including the self-signed
	// root. This lets a user test how a verifier handles it. Debug mode
	// records the HAIP finding.
	token, err := sdjwt.ParseLenient(result.Raw)
	if err != nil {
		t.Fatal(err)
	}
	x5c, _ := token.Header["x5c"].([]any)
	if len(x5c) != 2 || x5c[0] != base64.StdEncoding.EncodeToString(leaf.Raw) || x5c[1] != base64.StdEncoding.EncodeToString(ca.Raw) {
		t.Errorf("x5c = %d entries, want the provided chain as given", len(x5c))
	}
	warned := false
	for _, e := range w.GetLog() {
		if e.Severity == severityWarning && strings.Contains(e.Detail, "self-signed root") {
			warned = true
		}
	}
	if !warned {
		t.Error("expected a warning about the self-signed root in the chain")
	}

	// The wallet's lists contain the wallet CA, so the request's trust metadata
	// does not apply to the foreign chain.
	for _, spec := range w.IssuedAttestations {
		for _, e := range spec.Entitlements {
			if e == "https://entitlement.example/custom" {
				t.Errorf("override issuance must not apply the request's trust metadata, got %+v", spec)
			}
		}
	}

	w.ValidationMode = ValidationModeStrict
	if _, err := w.IssueCredential(opts); err == nil || !strings.Contains(err.Error(), "self-signed root") {
		t.Errorf("strict mode must refuse a chain carrying its root, got %v", err)
	}

	opts.SigningCertChain = []*x509.Certificate{leaf}
	if _, err := w.IssueCredential(opts); err != nil {
		t.Errorf("a rootless chain must issue in strict mode: %v", err)
	}
}

func TestParseSigningOverride(t *testing.T) {
	ca, leaf, leafKey, _ := authorityChain(t)
	keyPEM, err := encodeECPrivateKeyPEM(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))

	key, chain, err := ParseSigningOverride(keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(leafKey) || len(chain) != 2 {
		t.Errorf("parsed key/chain do not match the input (chain length %d)", len(chain))
	}

	if _, _, err := ParseSigningOverride(keyPEM, ""); err == nil {
		t.Error("a key without a certificate must be refused")
	}
	if _, _, err := ParseSigningOverride("", certPEM); err == nil {
		t.Error("a certificate without a key must be refused")
	}

	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := encodeECPrivateKeyPEM(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseSigningOverride(otherPEM, certPEM); err == nil || !strings.Contains(err.Error(), "certify") {
		t.Errorf("a leaf that does not certify the key must be refused, got %v", err)
	}
}

func TestDemoRefusesSigningOverride(t *testing.T) {
	srv := newTestServer(t, true)
	if err := srv.SetDemo(DemoOptions{ResetInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}

	rec := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt","signing_key":"key","signing_cert":"cert"}`)
	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// authorityChain returns a CA and a leaf signed by it. The leaf carries an
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

// A credential for another holder registers its attestation type, takes the
// next status index, carries the given issuer and rounds iat to the hour (RFC
// 9901 §10.1). The wallet stores no copy of it.
func TestSignForHolderDoesTheIssuersBookkeeping(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := New(holderKey, issuerKey, false)
	w.Templates = credtemplate.FileLocation(t.TempDir())
	resolved, err := credtemplate.Resolve(&credtemplate.Template{Format: "sdjwt", VCT: "urn:test:holder:1", Claims: map[string]any{"given_name": "Erika"}}, credtemplate.Request{})
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	before := w.StatusListCounter
	raw, err := w.SignForHolder(resolved, provider.IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:test:holder:1"}, &visitor.PublicKey,
		HolderSigning{Issuer: "https://issuer.example/demo", StatusListURI: "https://issuer.example/status"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := sdjwt.ParseLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if token.Payload["iss"] != "https://issuer.example/demo" {
		t.Errorf("iss = %v", token.Payload["iss"])
	}
	if iat, _ := token.Payload["iat"].(float64); int64(iat)%3600 != 0 {
		t.Errorf("iat = %v, want a full hour", iat)
	}
	if w.StatusListCounter != before+1 {
		t.Errorf("status counter %d, want %d", w.StatusListCounter, before+1)
	}
	registered := false
	for _, spec := range w.IssuedAttestations {
		registered = registered || spec.VCT == "urn:test:holder:1"
	}
	if !registered {
		t.Error("the attestation type is not registered")
	}
	if n := len(w.GetCredentials()); n != 0 {
		t.Errorf("the wallet stored %d credentials", n)
	}
}

// The category of the attestation type decides whether a credential is a PID.
// A PID discloses iat (CIR (EU) 2024/2977 Annex section 4.2, as replaced by
// CIR (EU) 2026/1731).
func TestTheCategoryDecidesWhetherACredentialIsAPID(t *testing.T) {
	w := generateTestWallet(t)
	for _, tc := range []struct {
		vct, category string
		disclosed     bool
	}{
		{"urn:example:national-id:1", credtemplate.CategoryPID, true},
		{"urn:eudi:pid:xx:1", credtemplate.CategoryEAA, false},
	} {
		t.Run(tc.category, func(t *testing.T) {
			result, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: tc.vct, Claims: map[string]any{"given_name": "Erika"}, Category: tc.category})
			if err != nil {
				t.Fatal(err)
			}
			token, err := sdjwt.Parse(result.Raw)
			if err != nil {
				t.Fatal(err)
			}
			_, plain := token.Payload["iat"]
			if _, resolved := token.ResolvedClaims["iat"]; !resolved || plain == tc.disclosed {
				t.Errorf("iat plain = %v, want disclosed = %v", plain, tc.disclosed)
			}
		})
	}
}
