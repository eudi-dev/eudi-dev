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
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
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
		Scheme:       Scheme{LoTEType: PIDProvidersListType, SchemeTerritory: "NL", IssuanceServiceType: "issuance", RevocationServiceType: "revocation"},
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

// ETSI TS 119 602 V1.1.1 §6.3.6 writes the scheme name as CC:name, and
// §6.3.5.2 asks for the operator's email address and website.
func TestTheSchemeNameAndOperatorAddressFollowTheirForms(t *testing.T) {
	scheme := signedPayload(t, Options{OperatorName: "Operator", Scheme: Scheme{LoTEType: PIDProvidersListType, SchemeTerritory: "NL"}})["ListAndSchemeInformation"].(map[string]any)
	if got := firstMultiLangValue(scheme["SchemeName"]); got != "NL:EUDI Dev Test Providers" {
		t.Errorf("scheme name %q", got)
	}
	var mail, web bool
	for _, entry := range objects(scheme["SchemeOperatorAddress"].(map[string]any)["SchemeOperatorElectronicAddress"]) {
		uri, _ := entry["uriValue"].(string)
		mail = mail || strings.HasPrefix(uri, "mailto:")
		web = web || strings.HasPrefix(uri, "https://")
	}
	if !mail || !web {
		t.Errorf("electronic address %v, want a mailto and a web URI", scheme["SchemeOperatorAddress"])
	}
}

// ETSI TS 119 602 V1.1.1 Table H.1 keeps the history of a Pub-EAA providers
// list forever. A service the next list no longer names stays with the status
// withdrawn (Table H.3) and its earlier status in ServiceHistory (§6.4.4),
// whose digital identity is an X509SKI only. Every service holds one public
// key.
func TestAPubEAAListKeepsTheServicesItWithdraws(t *testing.T) {
	certificate := func() string {
		key, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := mock.GenerateCACert(key)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(cert.Raw)
	}
	kept, removed, revocationA, revocationB := certificate(), certificate(), certificate(), certificate()
	scheme := Scheme{LoTEType: PubEAAProvidersListType, SchemeTerritory: "EU", IssuanceServiceType: "issuance", RevocationServiceType: "revocation"}
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mock.GenerateCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Sign(key, signer, Options{Scheme: scheme, ProviderName: "Provider", IssuedAt: time.Now().Add(-time.Hour),
		IssuanceCertificates: []string{kept, removed}, RevocationCertificates: []string{revocationA, revocationB}})
	if err != nil {
		t.Fatal(err)
	}
	firstServices := serviceInformation(listPayload(t, first)["TrustedEntitiesList"].([]any)[0].(map[string]any))
	if len(firstServices) != 4 {
		t.Fatalf("services %v, want one per certificate", firstServices)
	}
	second, err := Sign(key, signer, Options{Scheme: scheme, ProviderName: "Provider", Previous: first,
		IssuanceCertificates: []string{kept}, RevocationCertificates: []string{revocationA, revocationB}})
	if err != nil {
		t.Fatal(err)
	}
	entities := listPayload(t, second)["TrustedEntitiesList"].([]any)
	if len(entities) != 1 {
		t.Fatalf("entities %v, want the provider once", entities)
	}
	services := objects(entities[0].(map[string]any)["TrustedEntityServices"])
	statuses := map[string]string{}
	for _, svc := range services {
		info := svc["ServiceInformation"].(map[string]any)
		statuses[firstCertificate(info)] = info["ServiceStatus"].(string)
		if firstCertificate(info) == kept && info["StatusStartingTime"] != firstServices[0]["StatusStartingTime"] {
			t.Errorf("the kept service starts at %v, want %v from the first list", info["StatusStartingTime"], firstServices[0]["StatusStartingTime"])
		}
		if firstCertificate(info) != removed {
			continue
		}
		history := objects(svc["ServiceHistory"])
		if len(history) != 1 || history[0]["ServiceStatus"] != PubEAANotifiedStatus || history[0]["ServiceDigitalIdentity"].(map[string]any)["X509SKIs"] == nil {
			t.Errorf("history %v, want the notified status with an X509SKI", history)
		}
	}
	if statuses[kept] != PubEAANotifiedStatus || statuses[removed] != PubEAAWithdrawnStatus || len(services) != 4 {
		t.Errorf("statuses %v, want the removed service withdrawn and the others notified", statuses)
	}
	list, err := Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range ServiceCertificates(list, IssuanceServices) {
		if base64.StdEncoding.EncodeToString(info.Raw) == removed {
			t.Error("the withdrawn service still anchors credentials")
		}
	}
}

func signedPayload(t *testing.T, opts Options) map[string]any {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mock.GenerateCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(key, signer, opts)
	if err != nil {
		t.Fatal(err)
	}
	return listPayload(t, raw)
}

func listPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	list, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, _, err := format.ParseJWTParts(list.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return payload["LoTE"].(map[string]any)
}
