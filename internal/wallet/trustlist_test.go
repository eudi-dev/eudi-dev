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
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

// generateEAATrustListJWT signs an EAA list with the CA as its
// trust anchor.
func signingChain(w *Wallet, spec provider.IssuedAttestationSpec) ([]*x509.Certificate, error) {
	_, chain, err := w.Signer().ForList(spec.List(), "")
	return chain, err
}

func generateEAATrustListJWT(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate) (string, error) {
	return provider.SignTrustList(signingKey, caCert, lote.Options{
		OperatorName: "EUDI Dev Wallet",
		Scheme: lote.Scheme{
			LoTEType:              provider.CategoryList(credtemplate.CategoryEAA).LoTEType,
			IssuanceServiceType:   provider.CategoryList(credtemplate.CategoryEAA).IssuanceServiceType,
			RevocationServiceType: provider.CategoryList(credtemplate.CategoryEAA).RevocationServiceType,
			IssuanceServiceName:   "Issuance Service",
			RevocationServiceName: "Revocation Service",
			EntityName:            "EUDI Dev Wallet Issuer",
		},
	})
}

func TestGenerateTrustListJWT_ValidSignature(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}

	jwt, err := generateEAATrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("generateEAATrustListJWT: %v", err)
	}

	token, err := sdjwt.Parse(jwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	result := sdjwt.Verify(token, &caKey.PublicKey)
	if !result.SignatureValid {
		t.Errorf("expected valid signature, got errors: %v", result.Errors)
	}
}

func TestGenerateTrustListJWT_Header(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := generateEAATrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("generateEAATrustListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}

	if alg, _ := header["alg"].(string); alg != "ES256" {
		t.Errorf("expected alg ES256, got %q", alg)
	}
	if typ, _ := header["typ"].(string); typ != "JWT" {
		t.Errorf("expected typ JWT, got %q", typ)
	}
}

func TestGenerateTrustListJWT_PayloadStructure(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := generateEAATrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("generateEAATrustListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	loteBody, ok := payload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", payload["LoTE"])
	}
	if _, ok := loteBody["ListAndSchemeInformation"]; !ok {
		t.Error("expected ListAndSchemeInformation in LoTE payload")
	}
	if _, ok := loteBody["TrustedEntitiesList"]; !ok {
		t.Error("expected TrustedEntitiesList in LoTE payload")
	}
	schemeInfo, ok := loteBody["ListAndSchemeInformation"].(map[string]any)
	if !ok {
		t.Fatal("expected ListAndSchemeInformation object")
	}
	if schemeInfo["LoTEVersionIdentifier"] != float64(1) {
		t.Errorf("expected LoTEVersionIdentifier 1, got %v", schemeInfo["LoTEVersionIdentifier"])
	}
	if schemeInfo["LoTESequenceNumber"] != float64(1) {
		t.Errorf("expected LoTESequenceNumber 1, got %v", schemeInfo["LoTESequenceNumber"])
	}
	if schemeInfo["LoTEType"] != provider.CategoryList(credtemplate.CategoryEAA).LoTEType {
		t.Errorf("expected the EAA list type %s, got %v", provider.CategoryList(credtemplate.CategoryEAA).LoTEType, schemeInfo["LoTEType"])
	}
	if _, ok := schemeInfo["ListIssueDateTime"].(string); !ok {
		t.Errorf("expected ListIssueDateTime string, got %T", schemeInfo["ListIssueDateTime"])
	}
	if _, ok := schemeInfo["NextUpdate"].(string); !ok {
		t.Errorf("expected NextUpdate string, got %T", schemeInfo["NextUpdate"])
	}

	entities, ok := loteBody["TrustedEntitiesList"].([]any)
	if !ok || len(entities) == 0 {
		t.Fatal("expected non-empty TrustedEntitiesList")
	}
}

func TestTheSignedPIDListMatchesTheETSIShape(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.IssuerURL = "https://wallet.example:8443"

	jwt, err := w.TrustedLists().SignedGroupList(w.IssuerURL, w.TrustedLists().DefaultGroup(), provider.TrustedListPath(credtemplate.CategoryPID))
	if err != nil {
		t.Fatalf("SignedList: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	loteBody, ok := payload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", payload["LoTE"])
	}
	schemeInfo, ok := loteBody["ListAndSchemeInformation"].(map[string]any)
	if !ok {
		t.Fatalf("expected ListAndSchemeInformation object, got %T", loteBody["ListAndSchemeInformation"])
	}
	if schemeInfo["LoTEType"] != lote.PIDProvidersListType {
		t.Fatalf("expected PID LoTEType %s, got %v", lote.PIDProvidersListType, schemeInfo["LoTEType"])
	}
	if schemeInfo["StatusDeterminationApproach"] != provider.CategoryList(credtemplate.CategoryPID).StatusDeterminationApproach {
		t.Fatalf("expected PID status determination %s, got %v", provider.CategoryList(credtemplate.CategoryPID).StatusDeterminationApproach, schemeInfo["StatusDeterminationApproach"])
	}
	if schemeInfo["SchemeTerritory"] != "EU" {
		t.Fatalf("expected EU scheme territory, got %v", schemeInfo["SchemeTerritory"])
	}
	rules, ok := schemeInfo["SchemeTypeCommunityRules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected one SchemeTypeCommunityRules entry, got %v", schemeInfo["SchemeTypeCommunityRules"])
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || rule["uriValue"] != provider.CategoryList(credtemplate.CategoryPID).SchemeTypeCommunityRules {
		t.Fatalf("expected PID scheme rule %s, got %v", provider.CategoryList(credtemplate.CategoryPID).SchemeTypeCommunityRules, rules)
	}
}

func TestTrustedListGroupsWithMixedProfiles(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.RegisterIssuedAttestation(categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryPID,
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	})); err != nil {
		t.Fatalf("registering PID attestation: %v", err)
	}
	if err := w.RegisterIssuedAttestation(categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryEAA,
		Format:  "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
		Entitlements: []string{
			registrar.NonQEAAProviderEntitlement,
		},
	})); err != nil {
		t.Fatalf("registering local attestation: %v", err)
	}

	groups := w.TrustedLists().Groups()
	var ids []string
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	if want := []string{"pid", "qeaa", "pub-eaa", "eaa", "wallet-provider", "access-ca", "registrar"}; !slices.Equal(ids, want) {
		t.Fatalf("groups %v, want %v", ids, want)
	}
	if len(groups[3].Specs) != 1 || groups[3].Specs[0].DocType != "org.iso.23220.photoid.1" {
		t.Fatalf("eaa group lists %+v, want the photo ID", groups[3].Specs)
	}

	defaultGroup := w.TrustedLists().DefaultGroup()
	if defaultGroup.ID != "pid" {
		t.Fatalf("expected default group pid, got %s", defaultGroup.ID)
	}
}

func TestWalletProviderTrustList_UsesDistinctSignerAndIsNeverDefault(t *testing.T) {
	// Wallet attestations exist before the wallet issues credentials.
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example:8443"

	group, ok := w.TrustedLists().FindGroup("wallet-provider", "", "")
	if !ok {
		t.Fatal("expected a wallet-provider trust-list group")
	}
	if group.List.LoTEType != lote.WalletProvidersListType {
		t.Fatalf("expected EUWalletProvidersList type, got %s", group.List.LoTEType)
	}
	if group.List.IssuanceServiceType != provider.WalletProviderList().IssuanceServiceType {
		t.Fatalf("expected wallet solution issuance service type, got %s", group.List.IssuanceServiceType)
	}

	defaultGroup := w.TrustedLists().DefaultGroup()
	if defaultGroup.ID == "wallet-provider" {
		t.Fatal("wallet-provider list must never be the default trusted list")
	}

	// TS 119 412-6 V1.1.1 §5 distinguishes the wallet provider signing role.
	walletJWT, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, "/api/trustlists/wallet-provider")
	if err != nil {
		t.Fatalf("SignedGroupList(wallet-provider): %v", err)
	}
	credentialJWT, err := w.TrustedLists().SignedGroupList(w.IssuerURL, defaultGroup, "/api/trustlists/"+defaultGroup.ID)
	if err != nil {
		t.Fatalf("SignedGroupList(%s): %v", defaultGroup.ID, err)
	}
	if got, want := trustListAnchorCert(t, walletJWT), trustListAnchorCert(t, credentialJWT); got == want {
		t.Fatal("wallet and credential lists share a service signing certificate")
	}
}

func trustListAnchorCert(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}
	loteBody, _ := payload["LoTE"].(map[string]any)
	entities, _ := loteBody["TrustedEntitiesList"].([]any)
	if len(entities) == 0 {
		t.Fatal("expected a trusted entity in the trusted list")
	}
	entity, _ := entities[0].(map[string]any)
	services, _ := entity["TrustedEntityServices"].([]any)
	if len(services) == 0 {
		t.Fatal("expected a service entry in the trusted list")
	}
	service, _ := services[0].(map[string]any)
	info, _ := service["ServiceInformation"].(map[string]any)
	identity, _ := info["ServiceDigitalIdentity"].(map[string]any)
	certs, _ := identity["X509Certificates"].([]any)
	if len(certs) == 0 {
		t.Fatal("expected a certificate in the service digital identity")
	}
	cert, _ := certs[0].(map[string]any)
	val, _ := cert["val"].(string)
	if val == "" {
		t.Fatal("expected a base64 certificate value")
	}
	return val
}

func TestBuildTrustListIndexEntries_UsesRelativePathAndOptionalAdvertisedURL(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.RegisterIssuedAttestation(categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryPID,
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	})); err != nil {
		t.Fatalf("registering PID attestation: %v", err)
	}

	entries := w.TrustedLists().IndexEntries("")
	if len(entries) != 7 {
		t.Fatalf("expected seven trust-list entries, got %d", len(entries))
	}
	if entries[0].Path != "/api/trustlists/pid" {
		t.Fatalf("expected pid path, got %s", entries[0].Path)
	}
	if entries[0].AdvertisedURL != "" {
		t.Fatalf("expected empty advertised_url without issuer, got %s", entries[0].AdvertisedURL)
	}
	if entries[0].URL != "" {
		t.Fatalf("expected empty legacy url without issuer, got %s", entries[0].URL)
	}

	entries = w.TrustedLists().IndexEntries("https://wallet.example:8443")
	if len(entries) != 7 {
		t.Fatalf("expected seven trust-list entries, got %d", len(entries))
	}
	if entries[0].AdvertisedURL != "https://wallet.example:8443/api/trustlists/pid" {
		t.Fatalf("expected advertised_url, got %s", entries[0].AdvertisedURL)
	}
	if entries[0].URL != entries[0].AdvertisedURL {
		t.Fatalf("expected legacy url alias to match advertised_url, got %s vs %s", entries[0].URL, entries[0].AdvertisedURL)
	}
}

// Each category signs with its own key under its own provider CA. The PID
// signer keeps the wallet's issuer key.
func TestEachCategorySignsWithItsOwnKey(t *testing.T) {
	w := generateTestWallet(t)
	pid, err := signingChain(w, categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryPID, Format: "dc+sd-jwt", VCT: mock.DefaultPIDVCT}))
	if err != nil {
		t.Fatal(err)
	}
	eaa, err := signingChain(w, categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryEAA, Format: "mso_mdoc", DocType: "org.iso.23220.photoid.1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pid) != 3 || len(eaa) != 3 || !bytes.Equal(pid[2].Raw, eaa[2].Raw) {
		t.Fatalf("chains of %d and %d certificates, want leaf, provider CA and the shared root", len(pid), len(eaa))
	}
	if pid[1].Subject.CommonName == eaa[1].Subject.CommonName {
		t.Errorf("both categories use the provider CA %s", pid[1].Subject.CommonName)
	}
	pidKey, eaaKey := pid[0].PublicKey.(*ecdsa.PublicKey), eaa[0].PublicKey.(*ecdsa.PublicKey)
	if !pidKey.Equal(&w.IssuerKey.PublicKey) || eaaKey.Equal(pidKey) {
		t.Error("want the issuer key for PIDs and another key for EAAs")
	}
}

func TestGenerateTrustListJWT_WrongKeyVerification(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	otherKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := generateEAATrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("generateEAATrustListJWT: %v", err)
	}

	token, _ := sdjwt.Parse(jwt)
	result := sdjwt.Verify(token, &otherKey.PublicKey)
	if result.SignatureValid {
		t.Error("expected invalid signature with wrong key")
	}
}

// A credential is on the list of its category. The category comes from the
// template or the catalogue entry. A credential without either is an EAA, and
// an unlisted credential is on no list.
func TestACredentialIsOnTheListOfItsCategory(t *testing.T) {
	t.Run("generated root", func(t *testing.T) { checkCategoryLists(t, generateTestWallet(t)) })
	// A root with path length zero signs the leaves directly.
	t.Run("root with path length zero", func(t *testing.T) {
		w := generateTestWallet(t)
		caKey, _ := mock.GenerateKey()
		ca, err := mock.GenerateCACert(caKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.SetCertificateAuthority(caKey, ca); err != nil {
			t.Fatal(err)
		}
		checkCategoryLists(t, w)
	})
}

func checkCategoryLists(t *testing.T, w *Wallet) {
	w.IssuerURL = "https://wallet.example"
	entry := diplomaCatalogEntry()
	entry.Category = credtemplate.CategoryQEAA
	if _, err := w.Registrar().AddCatalogAttestation(entry); err != nil {
		t.Fatal(err)
	}
	listed := func(raw string) []string {
		t.Helper()
		token, err := sdjwt.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		var lists []string
		for _, category := range credtemplate.Categories {
			group, _ := w.TrustedLists().FindGroup(category, "", "")
			jwt, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, "/api/trustlists/"+category)
			if err != nil {
				t.Fatal(err)
			}
			list, err := lote.Parse(jwt)
			if err != nil {
				t.Fatal(err)
			}
			certificates := list.Entities[0].Services[0].Certificates
			_, chainErr := validate.ExtractAndValidateX5C(token.Header, certificates)
			signedByListedKey := slices.ContainsFunc(certificates, func(c lote.CertInfo) bool {
				return sdjwt.Verify(token, c.PublicKey).SignatureValid
			})
			if chainErr == nil || signedByListedKey {
				lists = append(lists, category)
			}
		}
		return lists
	}
	for _, tc := range []struct {
		name string
		opts IssueOptions
		want []string
	}{
		{"a PID template", IssueOptions{Format: "sdjwt", Template: "pid-sdjwt"}, []string{"pid"}},
		{"a catalogue entry", IssueOptions{Format: "sdjwt", VCT: testDiplomaVCT, Claims: map[string]any{"degree": "MSc"}}, []string{"qeaa"}},
		{"neither", IssueOptions{Format: "sdjwt", VCT: "urn:example:badge:1", Claims: map[string]any{"level": "gold"}}, []string{"eaa"}},
		{"unlisted", IssueOptions{Format: "sdjwt", VCT: "urn:example:badge:2", Claims: map[string]any{"level": "gold"}, Category: provider.UnlistedCategory}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := w.IssueCredential(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := listed(result.Raw); !slices.Equal(got, tc.want) {
				t.Errorf("on the lists %v, want %v", got, tc.want)
			}
		})
	}
}

// An imported PID leaves the wallet's own PID types on the PID list, because
// the wallet lists only what it issues.
func TestAnImportedPIDLeavesTheWalletsPIDList(t *testing.T) {
	w := generateTestWalletWithPID(t)
	for _, c := range generateTestWalletWithPID(t).GetCredentials() {
		if _, err := w.ImportCredential(c.Raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range w.issuedAttestationSpecs() {
		if spec.Category != credtemplate.CategoryPID {
			t.Errorf("%s %s%s has category %q, want pid", spec.Format, spec.VCT, spec.DocType, spec.Category)
		}
	}
}
