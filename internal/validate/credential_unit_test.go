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
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

func mustFind(t *testing.T, r *Result, name string) Check {
	t.Helper()
	c, ok := r.Find(name)
	if !ok {
		t.Fatalf("no %s check in %+v", name, r.Checks)
	}
	return c
}

func TestCredential_MDOCStatusWrapping(t *testing.T) {
	// MSO.Status is the inner {"status_list": ...} object.
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				Status: map[string]any{
					"status_list": map[string]any{
						"idx": float64(42),
						"uri": "https://example.com/statuslist",
					},
				},
			},
		},
	}

	result := mustFind(t, MDOC(doc, Trust{}, Options{Status: false}), CheckStatus)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when CheckStatus=false, got %s", result.Status)
	}
	if result.Detail != "Not requested" {
		t.Errorf("expected 'Not requested', got %q", result.Detail)
	}
}

func TestCredential_MDOCStatusNoStatus(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{},
		},
	}

	result := mustFind(t, MDOC(doc, Trust{}, Options{Status: true}), CheckStatus)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no status in MSO, got %s", result.Status)
	}
	if result.Detail != "No status list reference in credential" {
		t.Errorf("expected 'No status list reference in credential', got %q", result.Detail)
	}
}

func TestCredential_SDJWTExpiryNotYetValid(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{
			"nbf": float64(4102444800), // 2100-01-01
			"exp": float64(4102444900),
		},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{Offline: true}), CheckExpiry)
	if result.Status != "fail" {
		t.Errorf("expected fail for not-yet-valid token, got %s: %s", result.Status, result.Detail)
	}
}

func TestCredential_SDJWTExpiryNoExp(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{"sub": "user"},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{Offline: true}), CheckExpiry)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no exp, got %s", result.Status)
	}
}

func TestCredential_MDOCExpiryNoValidityInfo(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{},
		},
	}

	result := mustFind(t, MDOC(doc, Trust{}, Options{Offline: true}), CheckExpiry)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no validity info, got %s", result.Status)
	}
}

func TestCredential_SignatureSkippedNoKey(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{"sub": "user"},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{}), CheckSignature)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no key, got %s", result.Status)
	}
	if result.Detail != "No key provided" {
		t.Errorf("expected 'No key provided', got %q", result.Detail)
	}
}

// Supplied trust is the only trust source. Without a key or an issuance
// service, the certificate a credential carries cannot verify it.
func TestCredential_SuppliedTrustWithoutAnchorsFailsTheSignature(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(key, caCert, &key.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: "https://issuer.example", VCT: "urn:example:vc", ExpiresIn: time.Hour,
		Claims: map[string]any{"name": "x"}, Key: key, CertChain: []*x509.Certificate{leaf},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mdoc.Parse(mustMDOC(t, key, leaf))
	if err != nil {
		t.Fatal(err)
	}

	for name, result := range map[string]*Result{
		"SD-JWT VC": SDJWT(token, Trust{Supplied: true}, Options{Offline: true}),
		"mdoc":      MDOC(doc, Trust{Supplied: true}, Options{Offline: true}),
	} {
		if check := mustFind(t, result, CheckSignature); check.Status != Fail {
			t.Errorf("%s: signature %s (%s), want fail", name, check.Status, check.Detail)
		}
	}
}

func mustMDOC(t *testing.T, key *ecdsa.PrivateKey, leaf *x509.Certificate) string {
	t.Helper()
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType: "org.example.doc", Namespace: "org.example.doc",
		Claims: map[string]any{"name": "x"}, Key: key, CertChain: []*x509.Certificate{leaf},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCredential_SignatureSkippedWhenIssuerMetadataLookupFails(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{}), CheckSignature)
	if result.Status != "skipped" {
		t.Fatalf("expected skipped when issuer metadata lookup fails, got %s (%s)", result.Status, result.Detail)
	}
	if result.Detail == "" || result.Detail == "No key provided" {
		t.Fatalf("expected issuer metadata lookup detail, got %q", result.Detail)
	}
}

func TestCredential_MDOCStatusNilIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{}

	result := mustFind(t, MDOC(doc, Trust{}, Options{Status: true}), CheckStatus)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no issuerAuth, got %s", result.Status)
	}
}

func TestCredential_MDOCExpiryNilIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{}

	result := mustFind(t, MDOC(doc, Trust{}, Options{Offline: true}), CheckExpiry)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no issuerAuth, got %s", result.Status)
	}
}

func TestCredential_MDOCSignatureSkippedNoKey(t *testing.T) {
	doc := &mdoc.Document{}

	result := mustFind(t, MDOC(doc, Trust{}, Options{}), CheckSignature)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no key, got %s", result.Status)
	}
	if result.Detail != "No key provided" {
		t.Errorf("expected 'No key provided', got %q", result.Detail)
	}
}

func TestCredential_SDJWTExpiryPass(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{
			"exp": float64(4102444800), // far future
		},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{Offline: true}), CheckExpiry)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCredential_SDJWTExpiryExpired(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{
			"exp": float64(1000000000), // way in the past
		},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{Offline: true}), CheckExpiry)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCredential_SDJWTStatusSkippedNotRequested(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"sub": "user",
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": float64(7),
					"uri": "https://issuer.example/status-list/1",
				},
			},
		},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{Status: false}), CheckStatus)
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
	if result.Detail != "Not requested" {
		t.Errorf("expected 'Not requested', got %q", result.Detail)
	}
}

func TestCredential_SDJWTStatusNoRef(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{"sub": "user"},
	}

	result := mustFind(t, SDJWT(token, Trust{}, Options{Status: true}), CheckStatus)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no status ref, got %s", result.Status)
	}
	if result.Detail != "No status list reference in credential" {
		t.Errorf("expected 'No status list reference in credential', got %q", result.Detail)
	}
}
