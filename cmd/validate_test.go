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

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

func generateCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, caKey, caDER
}

func generateLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return leafCert, leafKey, leafDER
}

func TestExtractAndValidateX5C_TrustedChain(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	// x5c uses standard base64.
	leafB64 := encodeBase64Std(leafDER)

	header := map[string]any{
		"alg": "ES256",
		"x5c": []any{leafB64},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := validate.ExtractAndValidateX5C(header, tlCerts)
	if err != nil {
		t.Fatalf("validate.ExtractAndValidateX5C() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestExtractAndValidateX5C_UntrustedChain(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	otherCACert, _, otherCADER := generateCACert(t)

	header := map[string]any{
		"x5c": []any{encodeBase64Std(leafDER)},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: otherCACert.PublicKey, Raw: otherCADER},
	}

	_, err := validate.ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for untrusted chain")
	}
}

func TestExtractAndValidateX5C_NoX5CHeader(t *testing.T) {
	header := map[string]any{
		"alg": "ES256",
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: nil, Raw: []byte("dummy")},
	}

	key, err := validate.ExtractAndValidateX5C(header, tlCerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no x5c header")
	}
}

func TestExtractAndValidateX5C_NoTrustListCerts(t *testing.T) {
	header := map[string]any{
		"x5c": []any{"some-cert"},
	}

	key, err := validate.ExtractAndValidateX5C(header, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no trusted list certs")
	}
}

func TestExtractAndValidateX5C_WithIntermediate(t *testing.T) {
	rootCert, rootKey, rootDER := generateCACert(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	_, _, leafDER := generateLeafCert(t, intCert, intKey)

	header := map[string]any{
		"x5c": []any{
			encodeBase64Std(leafDER),
			encodeBase64Std(intDER),
		},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: rootCert.PublicKey, Raw: rootDER},
	}

	key, err := validate.ExtractAndValidateX5C(header, tlCerts)
	if err != nil {
		t.Fatalf("validate.ExtractAndValidateX5C() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateMDOCX5Chain_TrustedSingleCert(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): leafDER,
			},
		},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("validate.ExtractAndValidateMDOCX5Chain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateMDOCX5Chain_TrustedCertArray(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): []any{leafDER},
			},
		},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("validate.ExtractAndValidateMDOCX5Chain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateMDOCX5Chain_UntrustedChain(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	otherCACert, _, otherCADER := generateCACert(t)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): leafDER,
			},
		},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: otherCACert.PublicKey, Raw: otherCADER},
	}

	_, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err == nil {
		t.Error("expected error for untrusted chain")
	}
}

func TestExtractAndValidateMDOCX5Chain_NoX5Chain(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{},
		},
	}

	tlCerts := []trustlist.CertInfo{
		{Raw: []byte("dummy")},
	}

	key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no x5chain")
	}
}

func TestExtractAndValidateMDOCX5Chain_NoIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{}

	key, err := validate.ExtractAndValidateMDOCX5Chain(doc, []trustlist.CertInfo{{Raw: []byte("x")}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no issuerAuth")
	}
}

func TestExtractAndValidateMDOCX5Chain_Uint64Label(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	// Some CBOR decoders use uint64 for the label.
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				uint64(33): leafDER,
			},
		},
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("validate.ExtractAndValidateMDOCX5Chain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateX5C_InvalidCertData(t *testing.T) {
	header := map[string]any{
		"x5c": []any{"not-valid-base64-cert-data!!!"},
	}

	tlCerts := []trustlist.CertInfo{
		{Raw: []byte("dummy")},
	}

	_, err := validate.ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for invalid certificate data")
	}
}

func TestExtractAndValidateX5C_ValidBase64ButInvalidDER(t *testing.T) {
	header := map[string]any{
		"x5c": []any{encodeBase64Std([]byte("not a certificate"))},
	}

	tlCerts := []trustlist.CertInfo{
		{Raw: []byte("dummy")},
	}

	_, err := validate.ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for invalid DER data")
	}
}

// A revoked credential fails validate with the name of its status type.
func TestValidateFailsForRevokedCredential(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	bitstring := make([]byte, 16)
	bitstring[0] = 1

	var statusSrv *httptest.Server
	statusSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The token's sub must equal the status list URI in the credential, so
		// the token uses this server's URL.
		jwt, err := statuslist.GenerateStatusListJWT(bitstring, key, statuslist.StatusListConfig{
			URI: statusSrv.URL,
		})
		if err != nil {
			t.Errorf("GenerateStatusListJWT: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(jwt))
	}))
	defer statusSrv.Close()

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        "https://localhost:1",
		VCT:           "urn:test:revoked",
		ExpiresIn:     time.Hour,
		Claims:        map[string]any{"given_name": "Erika"},
		Key:           key,
		StatusListURI: statusSrv.URL,
		StatusListIdx: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = runValidateArgs(t, raw)
	if err == nil || !strings.Contains(err.Error(), "INVALID") {
		t.Fatalf("validate = %v, want the INVALID status", err)
	}
}

// runValidateArgs runs validate on a credential file and resets the flags.
func runValidateArgs(t *testing.T, raw string, flags ...string) error {
	t.Helper()
	resetRemoteTestState(t)
	credFile := filepath.Join(t.TempDir(), "cred.txt")
	if err := os.WriteFile(credFile, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		keyFile, trustListFile, statusListFlag, allowExpired, validateHAIP, jsonOutput = "", "", true, false, false, false
	})
	rootCmd.SetArgs(append(append([]string{"validate"}, flags...), credFile))
	return rootCmd.Execute()
}

func encodeBase64Std(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func TestValidateCommand_OfflineViaEmbeddedX5C(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	leafCert, leafKey, _ := generateLeafCert(t, caCert, caKey)

	// The issuer URL is unreachable: validation must succeed offline via the
	// embedded certificate chain, without fetching issuer metadata.
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test:offline",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       leafKey,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	credFile := filepath.Join(t.TempDir(), "cred.txt")
	if err := os.WriteFile(credFile, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"validate", credFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("offline validate must pass via the embedded x5c leaf: %v", err)
	}

	mdocRaw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.example.test.1",
		Namespace: "eu.example.test.1",
		Claims:    map[string]any{"family_name": "Mustermann"},
		Key:       leafKey,
		ExpiresIn: time.Hour,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}
	mdocFile := filepath.Join(t.TempDir(), "cred.mdoc")
	if err := os.WriteFile(mdocFile, []byte(mdocRaw), 0o644); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"validate", mdocFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("offline mdoc validate must pass via the embedded x5chain leaf: %v", err)
	}
}

// --haip reports what the profile adds without failing the command.
func TestValidateHAIPFindings(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	credential := func(t *testing.T, leaf *x509.Certificate) *sdjwt.Token {
		t.Helper()
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:    "https://issuer.example",
			VCT:       mock.DefaultPIDVCT,
			ExpiresIn: time.Hour,
			Claims:    map[string]any{"given_name": "ERIKA"},
			Key:       issuerKey,
			CertChain: []*x509.Certificate{leaf, caCert},
		})
		if err != nil {
			t.Fatalf("generating a credential: %v", err)
		}
		token, err := sdjwt.Parse(raw)
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		return token
	}

	leaf, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &issuerKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if findings := validate.HAIPCredentialFindings(credential(t, leaf).Header, credential(t, leaf).Payload); len(findings) != 0 {
		t.Errorf("a credential carrying its issuer chain produced %v", findings)
	}

	// §6.1.1: "The SD-JWT VC MUST contain the credential issuer's signing
	// certificate along with a trust chain in the x5c JOSE header parameter".
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA"},
		Key:       issuerKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if findings := validate.HAIPCredentialFindings(token.Header, token.Payload); len(findings) != 1 {
		t.Errorf("a credential with no x5c produced %v, want the missing-chain finding", findings)
	}

	// §6.1.1: "The X.509 certificate of the trust anchor MUST NOT be included
	// in the x5c JOSE header of the SD-JWT VC."
	withAnchor, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA"},
		Key:       issuerKey,
		CertChain: []*x509.Certificate{leaf, caCert, caCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	anchorToken, err := sdjwt.Parse(withAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if findings := validate.HAIPCredentialFindings(anchorToken.Header, anchorToken.Payload); len(findings) != 1 {
		t.Errorf("a chain carrying the trust anchor produced %v, want the anchor finding", findings)
	}
}

func TestValidateHAIPFindingsInJSON(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &issuerKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}

	previousHAIP, previousJSON := validateHAIP, jsonOutput
	t.Cleanup(func() { validateHAIP, jsonOutput = previousHAIP, previousJSON })

	for _, tc := range []struct {
		name         string
		chain        []*x509.Certificate
		wantFindings int
	}{
		{name: "issuer chain", chain: []*x509.Certificate{leaf, caCert}, wantFindings: 0},
		{name: "chain with the trust anchor", chain: []*x509.Certificate{leaf, caCert, caCert}, wantFindings: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
				Issuer:    "https://localhost:1",
				VCT:       mock.DefaultPIDVCT,
				ExpiresIn: time.Hour,
				Claims:    map[string]any{"given_name": "ERIKA"},
				Key:       issuerKey,
				CertChain: tc.chain,
			})
			if err != nil {
				t.Fatal(err)
			}
			credFile := filepath.Join(t.TempDir(), "cred.txt")
			if err := os.WriteFile(credFile, []byte(raw), 0o644); err != nil {
				t.Fatal(err)
			}

			var runErr error
			out := captureStdout(t, func() {
				rootCmd.SetArgs([]string{"validate", "--haip", "--json", credFile})
				runErr = rootCmd.Execute()
			})
			if runErr != nil {
				t.Fatalf("validate --haip --json: %v", runErr)
			}

			var doc struct {
				Format       string          `json:"format"`
				Verification json.RawMessage `json:"verification"`
				HAIPFindings []string        `json:"haipFindings"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("the output is not one JSON document: %v\n%s", err, out)
			}
			if doc.Format != "dc+sd-jwt" || doc.Verification == nil {
				t.Errorf("the document lacks the credential or its verification:\n%s", out)
			}
			if findings := doc.HAIPFindings; findings == nil || len(findings) != tc.wantFindings {
				t.Errorf("haipFindings = %#v, want %d findings", findings, tc.wantFindings)
			}
		})
	}
}

// validate reads the catalogue of an existing wallet and creates none.
func TestValidateCreatesNoWallet(t *testing.T) {
	resetRemoteTestState(t)
	useLocalTestWallet(t)
	if _, err := validateTrust(); err != nil {
		t.Fatal(err)
	}
	store, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := store.Exists(); err != nil || exists {
		t.Errorf("Exists = %v, %v after validate, want no wallet", exists, err)
	}
}
