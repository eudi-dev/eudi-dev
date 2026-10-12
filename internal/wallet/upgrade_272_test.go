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
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// openV272Wallet opens a copy of the state directory that eudi-dev 2.7.2
// wrote (testdata/v2.7.2-wallet/README.md).
func openV272Wallet(t *testing.T) *Wallet {
	t.Helper()
	home := t.TempDir()
	if err := os.CopyFS(home, os.DirFS(filepath.Join("testdata", "v2.7.2-wallet"))); err != nil {
		t.Fatal(err)
	}
	store, err := OpenWalletStore(filepath.Join(home, "wallet"), storage.KindFile)
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// A wallet of eudi-dev 2.7.2 keeps its credentials and templates.
func TestAnEudiDev272WalletKeepsItsCredentialsAndTemplates(t *testing.T) {
	w := openV272Wallet(t)
	types := map[string]bool{}
	for _, cred := range w.GetCredentials() {
		types[cred.Format+" "+cred.VCT+cred.DocType] = true
	}
	for _, want := range []string{"dc+sd-jwt urn:eudi:pid:1", "dc+sd-jwt urn:test:membership:1", "mso_mdoc org.test.membership.1"} {
		if !types[want] {
			t.Errorf("credential %s is missing, got %v", want, types)
		}
	}
	tmpl, err := credtemplate.Load("membership", w.Templates)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.VCT != "urn:test:membership:1" || tmpl.Claims["member_id"] != "M-1001" {
		t.Errorf("template membership = %+v", tmpl)
	}
}

// eudi-dev 2 put its EAAs on a list of type LoTEType/local. Those
// credentials belong to the EAA list, so the wallet publishes no list of
// their own.
func TestTheEAAsOfAnEudiDev272WalletAreOnTheEAAList(t *testing.T) {
	w := openV272Wallet(t)
	for _, group := range w.TrustedLists().Groups() {
		if strings.HasPrefix(group.ID, "tl-") {
			t.Errorf("the wallet publishes the custom list %s for %+v", group.ID, group.Specs)
		}
	}
	group, ok := w.TrustedLists().FindGroup(credtemplate.CategoryEAA, "", "")
	if !ok {
		t.Fatal("the wallet has no EAA list")
	}
	var specs []string
	for _, spec := range group.Specs {
		specs = append(specs, spec.VCT+spec.DocType)
	}
	if strings.Join(specs, " ") != "urn:test:membership:1 org.test.membership.1" {
		t.Errorf("the EAA list carries %v", specs)
	}
}

// eudi-dev 2 signed its EAAs under the provider CA local-ca-NL. The EAA list
// anchors them, so `validate --trusted-list` with that list accepts them.
func TestTheEAAListAnchorsTheEAAsOfAnEudiDev272Wallet(t *testing.T) {
	w := openV272Wallet(t)
	group, _ := w.TrustedLists().FindGroup(credtemplate.CategoryEAA, "", "")
	raw, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, "/api/trustlists/eaa")
	if err != nil {
		t.Fatal(err)
	}
	list, err := lote.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := lote.Anchors(list, lote.IssuanceServices, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}
	checked := 0
	for _, cred := range w.GetCredentials() {
		if cred.VCT == "urn:eudi:pid:1" {
			continue
		}
		var chain []*x509.Certificate
		switch cred.Format {
		case "dc+sd-jwt":
			token, err := sdjwt.Parse(cred.Raw)
			if err != nil {
				t.Fatal(err)
			}
			chain, err = validate.X5CCertificates(token.Header)
			if err != nil {
				t.Fatal(err)
			}
		case "mso_mdoc":
			doc, err := mdoc.Parse(cred.Raw)
			if err != nil {
				t.Fatal(err)
			}
			chain, err = validate.ExtractMDOCX5ChainCertificates(doc)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !slices.ContainsFunc(anchors, chain[1].Equal) {
			t.Errorf("%s %s%s: the EAA list does not name the CA %s", cred.Format, cred.VCT, cred.DocType, chain[1].Subject)
		}
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		// The fixture's signing certificates expire a year after it was
		// made, so the check runs at the time they were issued.
		if _, err := chain[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			CurrentTime:   chain[0].NotBefore.Add(time.Hour),
		}); err != nil {
			t.Errorf("%s %s%s: %v", cred.Format, cred.VCT, cred.DocType, err)
		}
		checked++
	}
	if checked != 2 {
		t.Errorf("checked %d EAAs, want 2", checked)
	}
}

// The signing certificates of eudi-dev 2 EAAs point at the provider CA of
// the role local. The wallet serves that CA and its CRL under the old URLs,
// and under the URLs of the EAA role.
func TestTheProviderCAOfEudiDev272EAAsIsServed(t *testing.T) {
	w := openV272Wallet(t)
	srv := NewServer(w, 0, nil)
	var old *x509.Certificate
	for _, cred := range w.GetCredentials() {
		if cred.VCT != "urn:test:membership:1" {
			continue
		}
		token, err := sdjwt.Parse(cred.Raw)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := validate.X5CCertificates(token.Header)
		if err != nil {
			t.Fatal(err)
		}
		old = chain[0]
		if got := fetchProviderCA(t, srv, old.IssuingCertificateURL[0]); !got.Equal(chain[1]) {
			t.Errorf("the AIA URL %s serves %s", old.IssuingCertificateURL[0], got.Subject)
		}
	}
	if old == nil {
		t.Fatal("the fixture has no SD-JWT EAA")
	}
	_, chain, err := w.Signer().ForList(provider.CategoryList(credtemplate.CategoryEAA), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := old.CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("the EAA provider CA did not sign the eudi-dev 2 EAA: %v", err)
	}
	if got := fetchProviderCA(t, srv, chain[0].IssuingCertificateURL[0]); !got.Equal(chain[1]) {
		t.Errorf("the AIA URL %s serves %s", chain[0].IssuingCertificateURL[0], got.Subject)
	}
	for _, crl := range []string{old.CRLDistributionPoints[0], chain[0].CRLDistributionPoints[0]} {
		reference, err := url.Parse(crl)
		if err != nil {
			t.Fatal(err)
		}
		if response := serverRequest(t, srv, http.MethodGet, reference.Path, ""); response.Code != http.StatusOK {
			t.Errorf("CRL %s: %d", reference.Path, response.Code)
		}
	}
}

func fetchProviderCA(t *testing.T, srv *Server, aia string) *x509.Certificate {
	t.Helper()
	reference, err := url.Parse(aia)
	if err != nil {
		t.Fatal(err)
	}
	response := serverRequest(t, srv, http.MethodGet, reference.Path, "")
	if response.Code != http.StatusOK {
		t.Fatalf("AIA %s: %d", reference.Path, response.Code)
	}
	cert, err := x509.ParseCertificate(response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
