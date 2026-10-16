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
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// ETSI EN 319 412-2 V2.5.1 GEN-4.3.11-3: the CRL distribution point "shall
// include at least one reference to a publicly available CRL", and
// GEN-4.3.11-4: "At least one of the present references shall use either http
// (http://) [...] or ldap (ldap://) scheme." Every certificate issued by
// the wallet points to a CRL served by the wallet and signed by the
// certificate's issuer.
func TestEveryIssuedCertificateNamesAServedCRL(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL, w.IssuerURL = "http://localhost:8085", "https://localhost:8086"
	srv := NewServer(w, 0, nil)
	chains := map[string]func() ([]*x509.Certificate, error){
		"PID signer": func() ([]*x509.Certificate, error) {
			_, chain, err := w.Signer().ForList(provider.CategoryList(credtemplate.CategoryPID), "", credtype.FormatMDOC)
			return chain, err
		},
		"wallet provider signer": func() ([]*x509.Certificate, error) { _, chain, err := w.Signer().WalletProvider(); return chain, err },
		"status signer":          func() ([]*x509.Certificate, error) { _, chain, err := w.Signer().StatusList(); return chain, err },
		"list signer": func() ([]*x509.Certificate, error) {
			_, chain, err := w.Signer().TrustList(config.WalletName, "EU")
			return chain, err
		},
		"registrar signer": func() ([]*x509.Certificate, error) { _, chain, err := w.Signer().Registrar(); return chain, err },
		"verifier access": func() ([]*x509.Certificate, error) {
			_, chain, err := w.DemoVerifierAccessSigningMaterial()
			return chain, err
		},
		"PID provider CA": func() ([]*x509.Certificate, error) {
			_, chain, err := w.Signer().ForList(provider.CategoryList(credtemplate.CategoryPID), "", credtype.FormatMDOC)
			return chain[1:], err
		},
	}
	for name, chainOf := range chains {
		t.Run(name, func(t *testing.T) {
			chain, err := chainOf()
			if err != nil {
				t.Fatal(err)
			}
			cert, issuer := chain[0], chain[1]
			if len(cert.CRLDistributionPoints) == 0 || !strings.HasPrefix(cert.CRLDistributionPoints[0], "http://") {
				t.Fatalf("CRL distribution points %v, want an http one first", cert.CRLDistributionPoints)
			}
			for _, point := range cert.CRLDistributionPoints {
				u, err := url.Parse(point)
				if err != nil {
					t.Fatal(err)
				}
				resp := serverRequest(t, srv, http.MethodGet, u.Path, "")
				if resp.Code != http.StatusOK {
					t.Fatalf("%s: status %d", point, resp.Code)
				}
				crl, err := x509.ParseRevocationList(resp.Body.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if err := crl.CheckSignatureFrom(issuer); err != nil {
					t.Errorf("%s is not signed by the issuer of the certificate: %v", point, err)
				}
			}
		})
	}
}

// The http reference comes first. An https base URL on the default port is a
// public origin, so a TLS terminator answers plain http on the issuer's host.
// Without such an origin only the https reference is given.
func TestCRLDistributionPointsUseHTTPFirst(t *testing.T) {
	for _, tc := range []struct {
		base, issuer string
		want         []string
	}{
		{"http://localhost:8085", "https://localhost:8086", []string{"http://localhost:8085/api/crl", "https://localhost:8086/api/crl"}},
		{"https://eudi-test.dev/prefix", "https://eudi-test.dev/prefix", []string{"http://eudi-test.dev/prefix/api/crl", "https://eudi-test.dev/prefix/api/crl"}},
		{"", "https://[::1]:8443", []string{"https://[::1]:8443/api/crl"}},
		{"https://localhost:8086", "https://localhost:8086", []string{"https://localhost:8086/api/crl"}},
		{"https://[2001:db8::1]", "https://[2001:db8::1]", []string{"http://[2001:db8::1]/api/crl", "https://[2001:db8::1]/api/crl"}},
		{"http://192.168.1.5:8085", "", []string{"http://192.168.1.5:8085/api/crl"}},
		{"", "", nil},
	} {
		if got := provider.CRLDistributionPoints(tc.base, tc.issuer, provider.RootCRLPath); strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("base %q issuer %q: %v, want %v", tc.base, tc.issuer, got, tc.want)
		}
	}
}

func TestCRLEndpointServesSignedEmptyList(t *testing.T) {
	srv := newTestServerWithStatusList(t)

	resp := serverRequest(t, srv, http.MethodGet, "/api/crl", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != "application/pkix-crl" {
		t.Errorf("Content-Type = %q, want application/pkix-crl", got)
	}
	crl, err := x509.ParseRevocationList(resp.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	caCert := srv.wallet.Signer().TrustAnchor()
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("CRL signature does not verify against the wallet CA: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("expected an empty CRL, got %d entries", len(crl.RevokedCertificateEntries))
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Error("nextUpdate must be after thisUpdate")
	}
}

// ISO/IEC 18013-5 Table B.3 defines countryName in the document signer subject.
func TestSigningChainCountryFollowsIssuingCountry(t *testing.T) {
	w := generateTestWallet(t)

	spec := provider.IssuedAttestationSpec{Format: "mso_mdoc", DocType: DefaultMDOCDocType}
	_, chain, err := w.Signer().ForCredential(spec, map[string]any{"issuing_country": "DE"})
	if err != nil {
		t.Fatalf("ForCredential: %v", err)
	}
	if got := chain[0].Subject.Country; len(got) != 1 || got[0] != "DE" {
		t.Errorf("leaf subject country = %v, want [DE]", got)
	}

	_, chain, err = w.Signer().ForCredential(spec, map[string]any{})
	if err != nil {
		t.Fatalf("ForCredential: %v", err)
	}
	if got := chain[0].Subject.Country; len(got) != 1 || got[0] != "NL" {
		t.Errorf("leaf subject country without a claim = %v, want the default [NL]", got)
	}
}

// CIR (EU) 2025/848 Article 9(6): the provider of access certificates revokes
// those of a relying party whose registration is cancelled. The relying party
// access CA publishes the revocation in its CRL.
func TestTheAccessCACRLListsTheCertificatesOfADeletedRelyingParty(t *testing.T) {
	srv := newTestServer(t, true)
	created := registrarJSON(t, srv, "POST", "/api/registrar/wrp", `{"tradeName":"Example Shop","services":[{"serviceIdentifier":"web","intendedUses":[{"purpose":[{"lang":"en","content":"Age check"}],"credentials":[{"format":"dc+sd-jwt","meta":{"vct_values":["`+mock.DefaultPIDVCT+`"]},"claims":[{"path":["given_name"]}]}]}]}]}`)
	var rp registrar.WalletRelyingParty
	if err := json.Unmarshal(created.Body.Bytes(), &rp); err != nil {
		t.Fatal(err)
	}
	id := rp.Identifier[0].Identifier
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := json.Marshal(testAccessCSR(t, key))
	issued := registrarJSON(t, srv, "POST", "/api/registrar/access-certificates", `{"identifier":"`+id+`","csr":`+string(csr)+`}`)
	var result registrar.AccessCertificateResult
	if err := json.Unmarshal(issued.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	crlOf := func() *x509.RevocationList {
		resp := serverRequest(t, srv, http.MethodGet, provider.AccessCACRLPath, "")
		crl, err := x509.ParseRevocationList(resp.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		_, ca, _ := srv.wallet.Signer().RelyingPartyAccessCA()
		if err := crl.CheckSignatureFrom(ca); err != nil {
			t.Fatal(err)
		}
		return crl
	}
	if len(crlOf().RevokedCertificateEntries) != 0 {
		t.Fatal("the access certificate is revoked right after its issue")
	}
	if rec := registrarJSON(t, srv, "DELETE", "/api/registrar/wrp/"+id, ""); rec.Code >= 300 {
		t.Fatalf("DELETE: %d %s", rec.Code, rec.Body.String())
	}
	entries := crlOf().RevokedCertificateEntries
	if len(entries) != 1 || entries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("CRL entries %+v, want the access certificate of the deleted relying party", entries)
	}
}
