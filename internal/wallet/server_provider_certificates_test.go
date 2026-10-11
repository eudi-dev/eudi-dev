package wallet

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
)

func TestProviderCertificateRetrievalAndCRL(t *testing.T) {
	srv := newTestServer(t, false)
	w := srv.wallet
	w.IssuerURL = "https://issuer.example"
	spec := provider.ApplyCategoryDefaults(provider.IssuedAttestationSpec{Format: "mso_mdoc", DocType: mock.PIDNamespace, Category: credtemplate.CategoryPID})
	_, chain, err := w.Signer().ForCredential(spec, map[string]any{"issuing_country": "DE"})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("provider chain has %d certificates, want leaf, intermediate and root", len(chain))
	}
	parentURL, err := url.Parse(chain[0].IssuingCertificateURL[0])
	if err != nil {
		t.Fatal(err)
	}
	response := serverRequest(t, srv, http.MethodGet, parentURL.Path, "")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/pkix-cert" {
		t.Fatalf("AIA retrieval: %d %s", response.Code, response.Body.String())
	}
	parent, err := x509.ParseCertificate(response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parent.Raw, chain[1].Raw) {
		t.Error("AIA returned a different issuer certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(parent)
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatal(err)
	}
	crlURL, err := url.Parse(chain[0].CRLDistributionPoints[0])
	if err != nil {
		t.Fatal(err)
	}
	response = serverRequest(t, srv, http.MethodGet, crlURL.Path, "")
	if response.Code != http.StatusOK {
		t.Fatalf("CRL retrieval: %d", response.Code)
	}
	crl, err := x509.ParseRevocationList(response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(parent); err != nil {
		t.Fatal(err)
	}
}

func TestPublishedSigningCertificateSurvivesRenewal(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	old := w.CertChain[0]
	reference, err := url.Parse(mock.SigningCertificateURL(w.IssuerURL, old, "der"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.RefreshSigningCertificate(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(old.Raw, w.CertChain[0].Raw) {
		t.Fatal("renewal retained the old certificate")
	}
	srv := NewServer(w, 0, nil)
	response := serverRequest(t, srv, http.MethodGet, reference.Path, "")
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), old.Raw) {
		t.Fatal("renewal changed the published signing certificate")
	}
}
