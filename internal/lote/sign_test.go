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

package lote

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// Parse reads back what Sign builds: the scheme, the operator's provider
// first, the further entities and the certificates of each service.
func TestParseReadsWhatSignBuilds(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mock.GenerateCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	other := base64.StdEncoding.EncodeToString(signer.Raw)
	raw, err := Sign(key, signer, Options{
		OperatorName: "Operator",
		Issuer:       "https://issuer.example",
		Path:         "/api/trustlists/pid",
		Profile:      Profile{LoTEType: PIDProvidersListType, SchemeTerritory: "NL", IssuanceServiceType: "issuance", RevocationServiceType: "revocation"},
		Sequence:     7,
		Entities:     []Entity{{Name: "Other", Issuance: []string{other}}},
		ProviderName: "Provider",
		Country:      "NL",
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Current(time.Now()); err != nil {
		t.Fatal(err)
	}
	scheme := list.SchemeInfo
	if scheme.LoTEType != PIDProvidersListType || scheme.SchemeOperatorName != "Operator" || scheme.SchemeTerritory != "NL" {
		t.Errorf("scheme %+v", scheme)
	}
	if len(scheme.Pointers) != 1 || scheme.Pointers[0].Location != "https://issuer.example/api/trustlists/pid" {
		t.Errorf("pointers %+v, want one to the list itself", scheme.Pointers)
	}
	if len(list.Entities) != 2 || list.Entities[0].Name != "Provider" || list.Entities[1].Name != "Other" {
		t.Fatalf("entities %+v", list.Entities)
	}
	provider := list.Entities[0].Services
	if len(provider) != 2 || provider[0].ServiceType != "issuance" || provider[1].ServiceType != "revocation" {
		t.Fatalf("services %+v, want issuance and revocation", provider)
	}
	if !signer.Equal(mustCertificate(t, provider[0].Certificates[0])) {
		t.Error("the provider's issuance service does not list the signer's certificate")
	}
}

func mustCertificate(t *testing.T, info CertInfo) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(info.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The categories with a list type of ETSI TS 119 602 use the constants Sign
// switches on.
func TestCategoryListTypesAreTheETSITypes(t *testing.T) {
	if got := registrar.CategoryOf(credtemplate.CategoryPID).TrustedList.Type; got != PIDProvidersListType {
		t.Errorf("PID list type %q, want %q", got, PIDProvidersListType)
	}
	if got := registrar.CategoryOf(credtemplate.CategoryPubEAA).TrustedList.Type; got != PubEAAProvidersListType {
		t.Errorf("PuB-EAA list type %q, want %q", got, PubEAAProvidersListType)
	}
}

// An entity's trade name is the registration identifier its own certificates
// carry, and an entity without one has none (ETSI TS 119 602 V1.1.1 §6.5.2).
func TestAListedEntityTakesTheTradeNameOfItsCertificates(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &leafKey.PublicKey, mock.LeafCertOptions{OrganizationIdentifier: "NTRBE-BETEST.42"})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(c *x509.Certificate) []string { return []string{base64.StdEncoding.EncodeToString(c.Raw)} }
	own := trustedEntityInformation(Options{}, Entity{Name: "Own", Issuance: encode(leaf)})
	if got := own["TETradeName"].([]map[string]string)[0]["value"]; got != "NTRBE-BETEST.42" {
		t.Errorf("trade name %q, want the certificate's identifier", got)
	}
	if certchain.OrganizationIdentifier(ca) != "" {
		t.Fatal("the test CA carries an organizationIdentifier")
	}
	if none := trustedEntityInformation(Options{}, Entity{Name: "None", Issuance: encode(ca)}); none["TETradeName"] != nil {
		t.Errorf("trade name %v for a certificate without an identifier", none["TETradeName"])
	}
}
