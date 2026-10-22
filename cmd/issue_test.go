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
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// The German PID types come from the predefined templates.
const (
	germanPIDVCT       = "urn:eudi:pid:de:1"
	germanPIDNamespace = "eu.europa.ec.eudi.pid.de.1"
)

// A bare credential has no wallet to store a display, a batch or trust
// metadata, so issue without --wallet refuses those flags.
func TestStandaloneIssueRefusesWalletOnlyFlags(t *testing.T) {
	for _, name := range issueWalletOnlyFlags {
		if issueSDJWTCmd.Flags().Lookup(name) == nil && issueCmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("--%s is no issue flag", name)
		}
	}
	resetTemplateTestState(t)
	t.Cleanup(func() { resetFlags(rootCmd) })
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--display-name", "Diploma", "--batch", "3"})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--batch, --display-name apply only with --wallet") {
		t.Fatalf("standalone issue: %v, want a refusal", err)
	}
	resetFlags(rootCmd)
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--display-name", "Diploma"})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--display-name applies only with --wallet") {
		t.Fatalf("standalone issue with one wallet flag: %v, want a refusal", err)
	}
}

func TestOmitClaims_RemovesSpecifiedClaims(t *testing.T) {
	result := credtemplate.OmitClaims(predefinedClaims("pid-sdjwt"), []string{"place_of_birth", "address", "nationalities"})

	for _, name := range []string{"place_of_birth", "address", "nationalities"} {
		if _, ok := result[name]; ok {
			t.Errorf("%s should have been omitted", name)
		}
	}

	for _, name := range []string{"family_name", "given_name", "birthdate"} {
		if _, ok := result[name]; !ok {
			t.Errorf("%s should still be present", name)
		}
	}

	expectedCount := len(predefinedClaims("pid-sdjwt")) - 3
	if len(result) != expectedCount {
		t.Errorf("expected %d claims, got %d", expectedCount, len(result))
	}
}

func TestOmitClaims_EmptyOmitReturnsOriginal(t *testing.T) {
	result := credtemplate.OmitClaims(predefinedClaims("pid-sdjwt"), nil)
	if len(result) != len(predefinedClaims("pid-sdjwt")) {
		t.Errorf("expected %d claims, got %d", len(predefinedClaims("pid-sdjwt")), len(result))
	}
}

func TestOmitClaims_OmitNonexistentClaimIsNoOp(t *testing.T) {
	result := credtemplate.OmitClaims(credtemplate.DefaultClaims, []string{"nonexistent_claim"})
	if len(result) != len(credtemplate.DefaultClaims) {
		t.Errorf("expected %d claims, got %d", len(credtemplate.DefaultClaims), len(result))
	}
}

func TestOmitClaims_TrimsWhitespace(t *testing.T) {
	result := credtemplate.OmitClaims(predefinedClaims("pid-sdjwt"), []string{" place_of_birth ", " address"})

	if _, ok := result["place_of_birth"]; ok {
		t.Error("place_of_birth should have been omitted (with whitespace trimming)")
	}
	if _, ok := result["address"]; ok {
		t.Error("address should have been omitted (with whitespace trimming)")
	}
}

func TestOmitClaims_DoesNotMutateOriginal(t *testing.T) {
	original := map[string]any{"a": 1, "b": 2, "c": 3}
	result := credtemplate.OmitClaims(original, []string{"b"})

	if len(result) != 2 {
		t.Errorf("expected 2 claims in result, got %d", len(result))
	}
	if len(original) != 3 {
		t.Errorf("original should not be mutated, expected 3 claims, got %d", len(original))
	}
}

func TestOmitClaims_OmitAllClaims(t *testing.T) {
	claims := map[string]any{"a": 1, "b": 2}
	result := credtemplate.OmitClaims(claims, []string{"a", "b"})
	if len(result) != 0 {
		t.Errorf("expected 0 claims, got %d", len(result))
	}
}

func TestResolveIssueClaims_DefaultWhenEmpty(t *testing.T) {
	issuePID = false
	issueClaims = ""
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(credtemplate.DefaultClaims) {
		t.Errorf("expected %d default claims, got %d", len(credtemplate.DefaultClaims), len(claims))
	}
}

func TestResolveIssueClaims_PIDWhenFlagged_SDJWT(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	tpl, err := credtemplate.Load("pid-sdjwt", credtemplate.FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(predefinedClaims("pid-sdjwt")) {
		t.Errorf("expected %d SD-JWT PID claims, got %d", len(predefinedClaims("pid-sdjwt")), len(claims))
	}
	if _, ok := claims["birth_family_name"]; !ok {
		t.Error("the country-independent PID claim set is missing birth_family_name")
	}
}

func TestResolveIssueClaims_PIDWhenFlagged_GermanSDJWT(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	tpl, err := credtemplate.Load("german-pid-sdjwt", credtemplate.FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading German PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(predefinedClaims("german-pid-sdjwt")) {
		t.Errorf("expected %d German SD-JWT PID claims, got %d", len(predefinedClaims("german-pid-sdjwt")), len(claims))
	}
	for _, name := range []string{"birth_name", "source_document_type"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("the German PID claim set is missing %q", name)
		}
	}
}

func TestResolveIssueClaims_PIDWhenFlagged_MDOC(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	tpl, err := credtemplate.Load("pid-mdoc", credtemplate.FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("mdoc", tpl)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(predefinedClaims("pid-mdoc")) {
		t.Errorf("expected %d mdoc PID claims, got %d", len(predefinedClaims("pid-mdoc")), len(claims))
	}
	for name := range claims {
		if strings.Contains(name, ":") {
			t.Errorf("the country-independent mdoc PID has an element outside its own namespace: %q", name)
		}
	}
}

func TestResolveIssueClaims_PIDWhenFlagged_GermanMDOC(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	tpl, err := credtemplate.Load("german-pid-mdoc", credtemplate.FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading German PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("mdoc", tpl)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(predefinedClaims("german-pid-mdoc")) {
		t.Errorf("expected %d German mdoc PID claims, got %d", len(predefinedClaims("german-pid-mdoc")), len(claims))
	}
	if _, ok := claims[germanPIDNamespace+":birth_name"]; !ok {
		t.Errorf("the German mdoc PID claim set is missing %s:birth_name", germanPIDNamespace)
	}
}

func TestResolveIssueClaims_PIDWithOmit(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = []string{"place_of_birth", "address"}

	tpl, err := credtemplate.Load("german-pid-sdjwt", credtemplate.FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}

	expected := len(predefinedClaims("german-pid-sdjwt")) - 2
	if len(claims) != expected {
		t.Errorf("expected %d claims, got %d", expected, len(claims))
	}
	if _, ok := claims["place_of_birth"]; ok {
		t.Error("place_of_birth should be omitted")
	}
	if _, ok := claims["address"]; ok {
		t.Error("address should be omitted")
	}
}

func TestResolveIssueClaims_JSONString(t *testing.T) {
	issuePID = false
	issueClaims = `{"name":"Test","active":true}`
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if claims["name"] != "Test" {
		t.Errorf("expected name=Test, got %v", claims["name"])
	}
	if claims["active"] != true {
		t.Errorf("expected active=true, got %v", claims["active"])
	}
}

func TestResolveIssueClaims_JSONStringWithOmit(t *testing.T) {
	issuePID = false
	issueClaims = `{"a":1,"b":2,"c":3}`
	issueOmit = []string{"b"}

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != 2 {
		t.Errorf("expected 2 claims, got %d", len(claims))
	}
	if _, ok := claims["b"]; ok {
		t.Error("b should be omitted")
	}
}

func TestResolveIssueClaims_FileReference(t *testing.T) {
	tmpDir := t.TempDir()
	claimsFile := filepath.Join(tmpDir, "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"file_claim":"works"}`), 0644); err != nil {
		t.Fatalf("writing claims file: %v", err)
	}

	issuePID = false
	issueClaims = "@" + claimsFile
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if claims["file_claim"] != "works" {
		t.Errorf("expected file_claim=works, got %v", claims["file_claim"])
	}
}

func TestResolveIssueClaims_InvalidJSON(t *testing.T) {
	issuePID = false
	issueClaims = `{not json}`
	issueOmit = nil

	_, err := resolveIssueClaimsForFormat("sdjwt", nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildIssueAttestationSpec_CategoryDefaults(t *testing.T) {
	issueCategory = "eaa"
	issueEntitlements = nil
	issueTrustListType = ""
	issueStatusDetermination = ""
	issueSchemeCommunityRule = ""
	issueSchemeTerritory = ""
	issueTrustEntityName = ""
	issueIssuanceServiceType = ""
	issueRevocationServiceType = ""
	issueIssuanceServiceName = ""
	issueRevocationServiceName = ""

	spec := issueTrustSpecFromFlags()
	spec.Format, spec.VCT = "dc+sd-jwt", "urn:test:employee:1"
	spec, err := provider.NormalizeIssuedAttestationSpec(spec, issueCategory)
	if err != nil {
		t.Fatalf("NormalizeIssuedAttestationSpec: %v", err)
	}
	if spec.Category != "eaa" || spec.LoTEType != "https://eudi-test.dev/LoTEType/EAAProvidersList" {
		t.Fatalf("category %q and trust-list type %q, want eaa and the EAA list type", spec.Category, spec.LoTEType)
	}
	if len(spec.Entitlements) != 1 || spec.Entitlements[0] != "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider" {
		t.Fatalf("expected Non_Q_EAA entitlement, got %v", spec.Entitlements)
	}
}

func TestBuildIssueAttestationSpec_RespectsExplicitOverrides(t *testing.T) {
	issueCategory = "eaa"
	issueEntitlements = []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"}
	issueTrustListType = "http://example.com/LoTEType/Custom"
	issueStatusDetermination = "http://example.com/status"
	issueSchemeCommunityRule = "http://example.com/rules"
	issueSchemeTerritory = "DE"
	issueTrustEntityName = "Custom Entity"
	issueIssuanceServiceType = "http://example.com/SvcType/Custom/Issuance"
	issueRevocationServiceType = "http://example.com/SvcType/Custom/Revocation"
	issueIssuanceServiceName = "Custom Issuance"
	issueRevocationServiceName = "Custom Revocation"

	spec := issueTrustSpecFromFlags()
	spec.Format, spec.DocType = "mso_mdoc", "org.iso.23220.photoid.1"
	spec, err := provider.NormalizeIssuedAttestationSpec(spec, issueCategory)
	if err != nil {
		t.Fatalf("NormalizeIssuedAttestationSpec: %v", err)
	}
	if spec.LoTEType != "http://example.com/LoTEType/Custom" {
		t.Fatalf("expected custom trust-list type, got %s", spec.LoTEType)
	}
	if spec.IssuanceServiceType != "http://example.com/SvcType/Custom/Issuance" {
		t.Fatalf("expected custom issuance service type, got %s", spec.IssuanceServiceType)
	}
	if spec.RevocationServiceType != "http://example.com/SvcType/Custom/Revocation" {
		t.Fatalf("expected custom revocation service type, got %s", spec.RevocationServiceType)
	}
	if spec.EntityName != "Custom Entity" {
		t.Fatalf("expected custom entity name, got %s", spec.EntityName)
	}
}

func TestResolveIssueClaims_MissingFile(t *testing.T) {
	issuePID = false
	issueClaims = "@/nonexistent/path/claims.json"
	issueOmit = nil

	_, err := resolveIssueClaimsForFormat("sdjwt", nil)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestIssueSDJWT_EndToEnd(t *testing.T) {
	token := issuedSDJWT(t, "issue", "sdjwt")
	if token.Payload["iss"] != mock.DefaultIssuer || token.Payload["vct"] != mock.DefaultPIDVCT {
		t.Errorf("iss %v, vct %v, want the defaults", token.Payload["iss"], token.Payload["vct"])
	}
	requireExpiresIn(t, token.Payload["exp"], credtemplate.DefaultExp)
}

func TestIssueSDJWT_WithPID(t *testing.T) {
	token := issuedSDJWT(t, "issue", "sdjwt", "--pid")
	requireClaims(t, token.ResolvedClaims, "given_name", "family_name", "birthdate")
}

// A JWT VC carries the PID claim set plainly, so --pid applies to `issue jwt`
// too.
func TestIssueJWT_WithPID(t *testing.T) {
	_, payload, _, err := format.ParseJWTParts(issuedCredential(t, "issue", "jwt", "--pid"))
	if err != nil {
		t.Fatalf("parsing the issued JWT: %v", err)
	}
	requireClaims(t, payload, "given_name", "family_name", "birthdate")
}

func TestIssueSDJWT_WithPIDAndOmit(t *testing.T) {
	token := issuedSDJWT(t, "issue", "sdjwt", "--pid", "--omit", "place_of_birth,sex")
	requireClaims(t, token.ResolvedClaims, "given_name", "family_name")
	for _, name := range []string{"place_of_birth", "sex"} {
		if _, ok := token.ResolvedClaims[name]; ok {
			t.Errorf("the credential has the omitted claim %s", name)
		}
	}
}

func TestIssueSDJWT_WithCustomClaims(t *testing.T) {
	token := issuedSDJWT(t, "issue", "sdjwt", "--claims", `{"custom":"claim"}`)
	if token.ResolvedClaims["custom"] != "claim" {
		t.Errorf("custom = %v, want claim", token.ResolvedClaims["custom"])
	}
}

func TestIssueSDJWTToWallet_UsesWalletIssuerContext(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:test:employee:1"
	issueExpires = "24h"
	issueNBF = ""
	issuePID = false
	issueOmit = nil
	issueToWallet = false
	issueStatusListURI = ""
	issueStatusListIdx = 0
	issueCategory = ""
	issueEntitlements = nil
	issueTrustListType = ""
	issueStatusDetermination = ""
	issueSchemeCommunityRule = ""
	issueSchemeTerritory = ""
	issueTrustEntityName = ""
	issueIssuanceServiceType = ""
	issueRevocationServiceType = ""
	issueIssuanceServiceName = ""
	issueRevocationServiceName = ""
	walletDir = ""

	rootCmd.SetArgs([]string{"issue", "--wallet-dir", wDir, "sdjwt", "--wallet", "--vct", "urn:test:employee:1", "--category", "eaa"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --wallet: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("loading wallet: %v", err)
	}
	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if len(w.StatusEntries) != 1 {
		t.Fatalf("expected 1 wallet-managed status entry, got %d", len(w.StatusEntries))
	}
	token, err := sdjwt.Parse(creds[0].Raw)
	if err != nil {
		t.Fatalf("parsing wallet-issued SD-JWT: %v", err)
	}
	wantIssuer := wallet.LocalIssuerURL(config.DefaultWalletPort+1, false)
	if token.Payload["iss"] != wantIssuer {
		t.Fatalf("expected iss %s, got %v", wantIssuer, token.Payload["iss"])
	}
	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected status claim on wallet-issued SD-JWT")
	}
	statusList, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected status_list claim on wallet-issued SD-JWT")
	}
	if got := statusList["uri"]; got != wantIssuer+"/api/statuslist" {
		t.Fatalf("expected status list uri %s/api/statuslist, got %v", wantIssuer, got)
	}

	group, ok := w.TrustedLists().FindGroup("eaa", "", "")
	if !ok {
		t.Fatal("no eaa trusted list")
	}
	tlJWT, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, "/api/trustlists/eaa")
	if err != nil {
		t.Fatalf("SignedGroupList: %v", err)
	}
	tl, err := lote.Parse(tlJWT)
	if err != nil {
		t.Fatalf("lote.Parse: %v", err)
	}
	if len(tl.Entities) == 0 || len(tl.Entities[0].Services) == 0 {
		t.Fatal("expected trusted list services")
	}
	key, err := validate.ExtractAndValidateX5C(token.Header, tl.Entities[0].Services[0].Certificates)
	if err != nil {
		t.Fatalf("validating wallet-issued SD-JWT x5c against trusted list: %v", err)
	}
	if key == nil {
		t.Fatal("expected trust-list-validated x5c key")
	}
}

func TestIssueSDJWTToWallet_PersistsTrustMetadataFlags(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:test:employee:1"
	issueExpires = "24h"
	issueNBF = ""
	issuePID = false
	issueOmit = nil
	issueToWallet = false
	issueStatusListURI = ""
	issueStatusListIdx = 0
	issueCategory = ""
	issueEntitlements = nil
	issueTrustListType = ""
	issueStatusDetermination = ""
	issueSchemeCommunityRule = ""
	issueSchemeTerritory = ""
	issueTrustEntityName = ""
	issueIssuanceServiceType = ""
	issueRevocationServiceType = ""
	issueIssuanceServiceName = ""
	issueRevocationServiceName = ""
	walletDir = ""

	const wantEntitlement = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
	const wantEntity = "Acme Test Issuer"
	rootCmd.SetArgs([]string{
		"issue", "--wallet-dir", wDir, "sdjwt", "--wallet",
		"--vct", "urn:test:employee:1",
		"--entitlement", wantEntitlement,
		"--trusted-entity-name", wantEntity,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --wallet: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("loading wallet: %v", err)
	}
	if len(w.IssuedAttestations) != 1 {
		t.Fatalf("expected 1 registered attestation, got %d", len(w.IssuedAttestations))
	}
	spec := w.IssuedAttestations[0]
	if spec.EntityName != wantEntity {
		t.Fatalf("expected entity name %q, got %q", wantEntity, spec.EntityName)
	}
	found := false
	for _, e := range spec.Entitlements {
		if e == wantEntitlement {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected entitlement %q to be persisted, got %v", wantEntitlement, spec.Entitlements)
	}
}

func TestIssueSDJWT_WithCustomIssuerVCTExp(t *testing.T) {
	token := issuedSDJWT(t, "issue", "sdjwt", "--iss", "https://custom.example", "--vct", "custom:type", "--exp", "1h")
	if token.Payload["iss"] != "https://custom.example" || token.Payload["vct"] != "custom:type" {
		t.Errorf("iss %v, vct %v", token.Payload["iss"], token.Payload["vct"])
	}
	requireExpiresIn(t, token.Payload["exp"], time.Hour)
}

func TestIssueSDJWT_WithKeyFile(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpDir := t.TempDir()
	jwk, err := keys.PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk["d"] = format.EncodeBase64URL(d)
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(tmpDir, "key.jwk")
	if err := os.WriteFile(keyFile, jwkJSON, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	token := issuedSDJWT(t, "issue", "sdjwt", "--key", keyFile)
	if result := sdjwt.Verify(token, &key.PublicKey); !result.SignatureValid {
		t.Errorf("the credential does not verify with the key from --key: %v", result.Errors)
	}
}

func TestIssueSDJWT_InvalidExpDuration(t *testing.T) {
	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--exp", "not-a-duration"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid --exp duration")
	}
}

func TestIssueMDOC_EndToEnd(t *testing.T) {
	doc := issuedMDOC(t, "issue", "mdoc")
	if doc.DocType != credtemplate.DefaultDocType {
		t.Errorf("docType %s, want the default", doc.DocType)
	}
	validity := doc.IssuerAuth.MSO.ValidityInfo
	if validity == nil || validity.ValidUntil == nil {
		t.Fatal("the MSO has no validUntil")
	}
	requireExpiresIn(t, float64(validity.ValidUntil.Unix()), credtemplate.DefaultExp)
}

func TestIssueMDOC_WithPID(t *testing.T) {
	doc := issuedMDOC(t, "issue", "mdoc", "--pid")
	requireClaims(t, mdocElements(doc, "eu.europa.ec.eudi.pid.1"), "given_name", "family_name", "birth_date")
}

func TestIssueMDOC_WithCustomDocType(t *testing.T) {
	doc := issuedMDOC(t, "issue", "mdoc", "--doc-type", "com.example.test", "--namespace", "com.example.test")
	if doc.DocType != "com.example.test" || len(doc.NameSpaces["com.example.test"]) == 0 {
		t.Errorf("docType %s with namespaces %v, want com.example.test for both", doc.DocType, slices.Collect(maps.Keys(doc.NameSpaces)))
	}
}

func TestIssueMDOC_WithClaimsFile(t *testing.T) {
	tmpDir := t.TempDir()
	claimsFile := filepath.Join(tmpDir, "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"test":"value"}`), 0644); err != nil {
		t.Fatalf("writing claims file: %v", err)
	}

	doc := issuedMDOC(t, "issue", "mdoc", "--claims", "@"+claimsFile)
	if got := mdocElements(doc, "eu.europa.ec.eudi.pid.1")["test"]; got != "value" {
		t.Errorf("test = %v, want the value from the claims file", got)
	}
}

func TestIssueMDOC_InvalidKeyFile(t *testing.T) {
	issueClaims = ""
	issueOmit = nil
	issuePID = false
	issueExpires = "720h"
	issueNBF = ""
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc", "--key", "/nonexistent/key.pem"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent key file")
	}
}

func TestDefaultClaims_HasExpectedFields(t *testing.T) {
	required := []string{"given_name", "family_name", "birthdate"}
	for _, name := range required {
		if _, ok := credtemplate.DefaultClaims[name]; !ok {
			t.Errorf("DefaultClaims missing %q", name)
		}
	}
}

// The country-independent PID claims follow the EUDI PID Rulebook (ARF
// Annex 3.01). The German ones follow the German PID Rulebook (see
// internal/mock/claims.go). Every default PID, template and demo credential
// is built from these sets.
func TestSDJWTPIDClaims_HasExpectedFields(t *testing.T) {
	want := map[string]bool{
		"family_name": true, "given_name": true, "birthdate": true,
		"birth_family_name": true, "sex": true, "place_of_birth": true,
		"address": true, "nationalities": true, "picture": true,
		"personal_administrative_number": true, "document_number": true,
		"date_of_issuance": true, "date_of_expiry": true,
		"issuing_authority": true, "issuing_country": true,
	}
	assertClaimSet(t, "SDJWTPIDClaims", predefinedClaims("pid-sdjwt"), want)

	// National additions belong to the German PID only. This includes the age
	// attributes. EUDI PID Rulebook 1.1 defines none (CIR 2024/2977).
	for _, name := range []string{
		"birth_name", "title", "also_known_as", "source_document_type",
		"age_equal_or_over", "age_in_years", "age_birth_year",
	} {
		if _, ok := predefinedClaims("pid-sdjwt")[name]; ok {
			t.Errorf("%q is a German addition and must not be in the country-independent PID", name)
		}
	}

	addr, ok := predefinedClaims("pid-sdjwt")["address"].(map[string]any)
	if !ok {
		t.Fatal("address should be a map")
	}
	// CIR (EU) 2024/2977 Annex, as replaced by CIR (EU) 2026/1731, has no
	// resident_house_number. resident_street includes the house number.
	assertClaimSet(t, "address", addr, map[string]bool{
		"street_address": true, "postal_code": true,
		"locality": true, "region": true, "country": true,
	})

	pob, ok := predefinedClaims("pid-sdjwt")["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("place_of_birth should be a map")
	}
	assertClaimSet(t, "place_of_birth", pob, map[string]bool{
		"locality": true, "country": true,
	})

	nats, ok := predefinedClaims("pid-sdjwt")["nationalities"].([]any)
	if !ok || len(nats) != 1 || nats[0] != "NL" {
		t.Errorf("nationalities should be [\"NL\"], got %v", predefinedClaims("pid-sdjwt")["nationalities"])
	}
}

func TestSDJWTGermanPIDClaims_HasExpectedFields(t *testing.T) {
	want := map[string]bool{
		"family_name": true, "given_name": true, "birth_name": true,
		"academic_title": true, "birthdate": true, "raw_eid_birth_date": true,
		"age_equal_or_over": true,
		"place_of_birth":    true, "address": true, "nationalities": true,
		"issuing_authority": true, "issuing_country": true,
		"source_document_type": true,
	}
	assertClaimSet(t, "SDJWTGermanPIDClaims", predefinedClaims("german-pid-sdjwt"), want)

	// The rulebook lists these, but the German eID does not supply them. A
	// realistic PID does not carry them.
	for _, name := range []string{
		"sex", "picture", "email", "phone_number", "document_number",
		"personal_administrative_number", "issuing_jurisdiction", "trust_anchor",
		"age_in_years", "age_birth_year", "birth_family_name", "birth_given_name",
		"administrative_number", "date_of_issuance",
	} {
		if _, ok := predefinedClaims("german-pid-sdjwt")[name]; ok {
			t.Errorf("%q is not part of the German PID and must not be present", name)
		}
	}

	addr, ok := predefinedClaims("german-pid-sdjwt")["address"].(map[string]any)
	if !ok {
		t.Fatal("address should be a map")
	}
	assertClaimSet(t, "address", addr, map[string]bool{
		"street_address": true, "postal_code": true, "locality": true,
		"region": true, "country": true,
	})

	ages, ok := predefinedClaims("german-pid-sdjwt")["age_equal_or_over"].(map[string]any)
	if !ok {
		t.Fatal("age_equal_or_over should be a map")
	}
	assertClaimSet(t, "age_equal_or_over", ages, map[string]bool{
		"12": true, "14": true, "16": true, "18": true, "21": true, "65": true,
	})
	for _, over := range []string{"12", "14", "16", "18", "21"} {
		if v, ok := ages[over].(bool); !ok || !v {
			t.Errorf("age_equal_or_over.%s should be true, got %v", over, ages[over])
		}
	}
	if v, ok := ages["65"].(bool); !ok || v {
		t.Errorf("age_equal_or_over.65 should be false for a 1964 birthdate, got %v", ages["65"])
	}

	pob, ok := predefinedClaims("german-pid-sdjwt")["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("place_of_birth should be a map")
	}
	assertClaimSet(t, "place_of_birth", pob, map[string]bool{
		"locality": true,
	})

	nats, ok := predefinedClaims("german-pid-sdjwt")["nationalities"].([]any)
	if !ok || len(nats) != 1 || nats[0] != "DE" {
		t.Errorf("nationalities should be [\"DE\"], got %v", predefinedClaims("german-pid-sdjwt")["nationalities"])
	}
}

func TestMDOCPIDClaims_HasExpectedFields(t *testing.T) {
	// The country-independent PID keeps every element in eu.europa.ec.eudi.pid.1.
	want := map[string]bool{
		"family_name": true, "given_name": true, "birth_date": true,
		"family_name_birth": true, "sex": true, "place_of_birth": true,
		"portrait": true, "nationality": true, "resident_street": true,
		"resident_postal_code": true, "resident_city": true,
		"resident_state": true, "resident_country": true,
		"personal_administrative_number": true, "document_number": true,
		"issuance_date": true, "expiry_date": true,
		"issuing_authority": true, "issuing_country": true,
	}
	assertClaimSet(t, "MDOCPIDClaims", predefinedClaims("pid-mdoc"), want)

	for name := range predefinedClaims("pid-mdoc") {
		if strings.Contains(name, ":") {
			t.Errorf("%q sits in another namespace than the PID's own", name)
		}
	}

	birthPlace, ok := predefinedClaims("pid-mdoc")["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("place_of_birth should be a map")
	}
	if birthPlace["locality"] != "Amsterdam" {
		t.Errorf("expected place_of_birth.locality Amsterdam, got %v", birthPlace["locality"])
	}
}

func TestMDOCGermanPIDClaims_HasExpectedFields(t *testing.T) {
	// ISO/IEC 18013-5 has no inheritance between document types, so the
	// German PID keeps the doctype of the country-independent one and puts
	// its national elements in a second namespace.
	de := germanPIDNamespace + ":"
	want := map[string]bool{
		"family_name": true, "given_name": true, "birth_date": true,
		"expiry_date": true, "place_of_birth": true, "nationality": true,
		"resident_street": true, "resident_postal_code": true,
		"resident_city": true, "resident_state": true, "resident_country": true,
		"issuing_authority": true, "issuing_country": true,
		de + "birth_name": true, de + "academic_title": true,
		de + "raw_eid_birth_date":   true,
		de + "source_document_type": true,
		de + "age_over_12":          true, de + "age_over_14": true,
		de + "age_over_16": true, de + "age_over_18": true,
		de + "age_over_21": true, de + "age_over_65": true,
	}
	assertClaimSet(t, "MDOCGermanPIDClaims", predefinedClaims("german-pid-mdoc"), want)

	for _, name := range []string{
		"sex", "portrait", "email_address", "mobile_phone_number", "document_number",
		"personal_administrative_number", "issuing_jurisdiction", "trust_anchor",
		"age_in_years", "age_birth_year", "family_name_birth", "given_name_birth",
		"resident_address", "resident_house_number", "administrative_number",
		// The German PID Rulebook says the German PID carries no issuance date.
		// Only the technical validFrom of the credential is set.
		"issuance_date",
	} {
		if _, ok := predefinedClaims("german-pid-mdoc")[name]; ok {
			t.Errorf("%q is not part of the German PID and must not be present", name)
		}
	}

	// The national elements must stay out of the PID namespace. A verifier
	// reading the country-independent rulebook would find them there.
	for _, name := range []string{"birth_name", "academic_title", "also_known_as", "age_over_18"} {
		if _, ok := predefinedClaims("german-pid-mdoc")[name]; ok {
			t.Errorf("%q must sit in %s, not in the PID namespace", name, germanPIDNamespace)
		}
	}

	birthPlace, ok := predefinedClaims("german-pid-mdoc")["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("place_of_birth should be a map")
	}
	if birthPlace["locality"] != "BERLIN" {
		t.Errorf("expected place_of_birth.locality BERLIN, got %v", birthPlace["locality"])
	}
}

// The SD-JWT and mdoc versions of each PID must describe the same person. The EU and
// German templates use different rulebook specimens.
func TestPIDClaims_TypesAreCorrect(t *testing.T) {
	pairs := []struct {
		label             string
		sdjwt, mdoc       map[string]any
		sdjwtKey, mdocKey string
	}{
		{"family_name", predefinedClaims("pid-sdjwt"), predefinedClaims("pid-mdoc"), "family_name", "family_name"},
		{"given_name", predefinedClaims("pid-sdjwt"), predefinedClaims("pid-mdoc"), "given_name", "given_name"},
		{"birthdate", predefinedClaims("pid-sdjwt"), predefinedClaims("pid-mdoc"), "birthdate", "birth_date"},
		{"expiry", predefinedClaims("pid-sdjwt"), predefinedClaims("pid-mdoc"), "date_of_expiry", "expiry_date"},
		{"German family_name", predefinedClaims("german-pid-sdjwt"), predefinedClaims("german-pid-mdoc"), "family_name", "family_name"},
		{"German given_name", predefinedClaims("german-pid-sdjwt"), predefinedClaims("german-pid-mdoc"), "given_name", "given_name"},
		{"German birthdate", predefinedClaims("german-pid-sdjwt"), predefinedClaims("german-pid-mdoc"), "birthdate", "birth_date"},
	}
	for _, p := range pairs {
		if p.sdjwt[p.sdjwtKey] != p.mdoc[p.mdocKey] {
			t.Errorf("%s differs between the SD-JWT and mdoc PID: %v vs %v", p.label, p.sdjwt[p.sdjwtKey], p.mdoc[p.mdocKey])
		}
	}

	if predefinedClaims("pid-sdjwt")["family_name"] == predefinedClaims("german-pid-sdjwt")["family_name"] &&
		predefinedClaims("pid-sdjwt")["given_name"] == predefinedClaims("german-pid-sdjwt")["given_name"] {
		t.Error("the country-independent and the German PID should describe different people")
	}
	if v, ok := predefinedClaims("pid-sdjwt")["family_name"].(string); !ok || v != "'t Hart" {
		t.Errorf("country-independent family_name should be \"'t Hart\", got %v", v)
	}
	if v, ok := predefinedClaims("german-pid-sdjwt")["family_name"].(string); !ok || !strings.Contains(v, "MUSTERMANN") {
		t.Errorf("German family_name should contain MUSTERMANN, got %v", v)
	}

	// The expiry is a calendar day with no time component, and the rulebook
	// puts it five years out.
	v, ok := predefinedClaims("pid-mdoc")["expiry_date"].(string)
	if !ok {
		t.Fatalf("expiry_date should be a string, got %T", predefinedClaims("pid-mdoc")["expiry_date"])
	}
	expiry, err := time.Parse(time.DateOnly, v)
	if err != nil {
		t.Fatalf("expiry_date = %q is not a calendar date: %v", v, err)
	}
	if years := expiry.Year() - time.Now().UTC().Year(); years != 5 {
		t.Errorf("expiry_date is %d years out, want 5", years)
	}

	issued, ok := predefinedClaims("pid-mdoc")["issuance_date"].(string)
	if !ok {
		t.Fatalf("issuance_date should be a string, got %T", predefinedClaims("pid-mdoc")["issuance_date"])
	}
	if issued != time.Now().UTC().Format(time.DateOnly) {
		t.Errorf("issuance_date = %q, want today", issued)
	}
}

func assertClaimSet(t *testing.T, label string, claims map[string]any, want map[string]bool) {
	t.Helper()
	for name := range want {
		if _, ok := claims[name]; !ok {
			t.Errorf("%s is missing %q", label, name)
		}
	}
	for name := range claims {
		if !want[name] {
			t.Errorf("%s has unexpected claim %q", label, name)
		}
	}
	if len(claims) != len(want) {
		t.Errorf("%s has %d claims, want %d", label, len(claims), len(want))
	}
}

// resolveIssueClaimsForFormat resolves the claims of the --claims, --omit and
// --pid flags against tpl.
func resolveIssueClaimsForFormat(format string, tpl *credtemplate.Template) (map[string]any, error) {
	overrides, err := parseClaimsArg(issueClaims)
	if err != nil {
		return nil, err
	}
	resolved, err := credtemplate.Resolve(tpl, credtemplate.Request{Format: format, Claims: overrides, Omit: issueOmit, ClaimSet: true})
	return resolved.Claims, err
}

// A standalone credential from a template gives each unique claim a fresh
// value, as the wallet and the demo issuer do.
func TestIssueSDJWT_TemplateUniqueClaims(t *testing.T) {
	dir := t.TempDir()
	tpl := `{"name":"uniq","format":"sdjwt","claims":{"subject_id":"fixed"},"unique_claims":["subject_id"]}`
	if err := os.WriteFile(filepath.Join(dir, "uniq.json"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	templatesDir = dir
	t.Cleanup(func() { templatesDir = "" })
	issueClaims, issueKeyPath, issueOmit, issuePID = "", "", nil, false

	issueOnce := func() any {
		out := captureStdout(t, func() {
			rootCmd.SetArgs([]string{"issue", "sdjwt", "--template", "uniq"})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("issue sdjwt --template: %v", err)
			}
		})
		token, err := sdjwt.Parse(strings.TrimSpace(out))
		if err != nil {
			t.Fatalf("parsing the issued credential: %v", err)
		}
		return token.ResolvedClaims["subject_id"]
	}
	first, second := issueOnce(), issueOnce()
	if first == "fixed" || first == second {
		t.Errorf("subject_id = %v then %v, want a fresh value per credential", first, second)
	}
}

// --iss sets the issuer of one credential. The stored issuer URL belongs to
// wallet serve (ADR-0019).
func TestIssueToWalletKeepsTheStoredIssuerURL(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:test:employee:1"
	issueExpires = "24h"
	issueNBF = ""
	issuePID = false
	issueOmit = nil
	issueToWallet = false
	issueStatusListURI = ""
	issueStatusListIdx = 0
	issueCategory = ""
	issueEntitlements = nil
	issueTrustListType = ""
	issueStatusDetermination = ""
	issueSchemeCommunityRule = ""
	issueSchemeTerritory = ""
	issueTrustEntityName = ""
	issueIssuanceServiceType = ""
	issueRevocationServiceType = ""
	issueIssuanceServiceName = ""
	issueRevocationServiceName = ""
	walletDir = ""

	issueTemplate = ""
	rootCmd.SetArgs([]string{"issue", "--wallet-dir", wDir, "sdjwt", "--wallet", "--iss", "https://custom.example", "--vct", "urn:test:employee:1"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --wallet --iss: %v", err)
	}
	w, err := wallet.NewWalletStore(wDir).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if w.IssuerURL != "" {
		t.Fatalf("issue stored the issuer URL %q", w.IssuerURL)
	}
	token, err := sdjwt.Parse(w.GetCredentials()[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if token.Payload["iss"] != "https://custom.example" {
		t.Fatalf("iss = %v, want the --iss value", token.Payload["iss"])
	}
}

// predefinedClaims returns the claims of a predefined template.
func predefinedClaims(name string) map[string]any {
	t, ok := credtemplate.Predefined(name)
	if !ok {
		panic("no predefined template " + name)
	}
	return t.Claims
}

// issuedCredential runs an issue command from the flag defaults and returns
// the credential it prints.
func issuedCredential(t *testing.T, args ...string) string {
	t.Helper()
	resetFlags(rootCmd)
	t.Cleanup(func() { resetFlags(rootCmd) })
	out := captureStdout(t, func() {
		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("%s: %v", strings.Join(args, " "), err)
		}
	})
	return strings.TrimSpace(out)
}

func issuedSDJWT(t *testing.T, args ...string) *sdjwt.Token {
	t.Helper()
	token, err := sdjwt.Parse(issuedCredential(t, args...))
	if err != nil {
		t.Fatalf("parsing the issued SD-JWT: %v", err)
	}
	return token
}

func issuedMDOC(t *testing.T, args ...string) *mdoc.Document {
	t.Helper()
	doc, err := mdoc.Parse(issuedCredential(t, args...))
	if err != nil {
		t.Fatalf("parsing the issued mdoc: %v", err)
	}
	return doc
}

func mdocElements(doc *mdoc.Document, namespace string) map[string]any {
	elements := map[string]any{}
	for _, item := range doc.NameSpaces[namespace] {
		elements[item.ElementIdentifier] = item.ElementValue
	}
	return elements
}

func requireClaims(t *testing.T, claims map[string]any, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, ok := claims[name]; !ok {
			t.Errorf("the credential lacks %s", name)
		}
	}
}

// requireExpiresIn checks an expiry in seconds since the epoch against now
// plus validity.
func requireExpiresIn(t *testing.T, exp any, validity time.Duration) {
	t.Helper()
	seconds, ok := exp.(float64)
	if !ok {
		t.Fatalf("expiry %v is no number", exp)
	}
	want := time.Now().Add(validity)
	if got := time.Unix(int64(seconds), 0); got.Sub(want).Abs() > time.Minute {
		t.Errorf("expires %s, want about %s", got, want)
	}
}
