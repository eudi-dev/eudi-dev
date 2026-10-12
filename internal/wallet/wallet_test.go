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
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// The German PID types come from the predefined templates.
const (
	germanPIDVCT       = "urn:eudi:pid:de:1"
	germanPIDNamespace = "eu.europa.ec.eudi.pid.de.1"
)

func generateTestWallet(t testing.TB) *Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := New(holderKey, issuerKey, false)
	// Use an isolated store so tests cannot load the developer's templates.
	w.Templates = NewWalletStore(t.TempDir()).Templates()
	return w
}

func generateTestWalletWithPID(t *testing.T) *Wallet {
	t.Helper()
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID credentials: %v", err)
	}
	return w
}

func TestNew(t *testing.T) {
	w := generateTestWallet(t)

	if w.HolderKey == nil {
		t.Fatal("expected non-nil holder key")
	}
	if w.IssuerKey == nil {
		t.Fatal("expected non-nil issuer key")
	}
	if w.AutoAccept {
		t.Error("expected AutoAccept to be false")
	}
	if len(w.Credentials) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(w.Credentials))
	}
}

// Generating the PIDs again keeps the other issued credential types and their
// trusted lists.
func TestGeneratingPIDsKeepsOtherIssuedTypes(t *testing.T) {
	w := generateTestWalletWithPID(t)
	if _, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:badge:1", Claims: map[string]any{"level": "gold"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(w.issuedAttestationSpecs(), func(s provider.IssuedAttestationSpec) bool { return s.VCT == "urn:example:badge:1" }) {
		t.Errorf("issued types %+v, want the badge kept", w.issuedAttestationSpecs())
	}
}

func TestGenerateDefaultCredentials(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	if creds[0].Format != "dc+sd-jwt" {
		t.Errorf("expected first credential to be dc+sd-jwt, got %s", creds[0].Format)
	}
	if creds[0].VCT != mock.DefaultPIDVCT {
		t.Errorf("expected VCT %s, got %s", mock.DefaultPIDVCT, creds[0].VCT)
	}
	if len(creds[0].Claims) == 0 {
		t.Error("expected SD-JWT to have claims")
	}
	if len(creds[0].Disclosures) == 0 {
		t.Error("expected SD-JWT to have disclosures")
	}

	if creds[1].Format != "mso_mdoc" {
		t.Errorf("expected second credential to be mso_mdoc, got %s", creds[1].Format)
	}
	if creds[1].DocType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("expected DocType eu.europa.ec.eudi.pid.1, got %s", creds[1].DocType)
	}
	if len(creds[1].Claims) == 0 {
		t.Error("expected mdoc to have claims")
	}
	birthPlace, ok := creds[1].Claims["eu.europa.ec.eudi.pid.1:place_of_birth"].(map[string]any)
	if !ok {
		t.Fatalf("expected mdoc place_of_birth map, got %T", creds[1].Claims["eu.europa.ec.eudi.pid.1:place_of_birth"])
	}
	if birthPlace["locality"] != "Amsterdam" {
		t.Errorf("expected mdoc place_of_birth.locality Amsterdam, got %v", birthPlace["locality"])
	}
}

func TestGenerateDefaultCredentials_SDJWTIssuerUsesWalletIssuerURL(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.wallet.example:8443"

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID credentials: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected generated credentials")
	}

	token, err := sdjwt.Parse(creds[0].Raw)
	if err != nil {
		t.Fatalf("parsing generated SD-JWT: %v", err)
	}
	if token.Payload["iss"] != w.IssuerURL {
		t.Fatalf("expected SD-JWT iss %s, got %v", w.IssuerURL, token.Payload["iss"])
	}
	if _, ok := token.ResolvedClaims["trust_anchor"]; ok {
		t.Fatal("did not expect trust_anchor in generated SD-JWT claims")
	}
}

func TestGenerateDefaultCredentials_Overwrite(t *testing.T) {
	w := generateTestWalletWithPID(t)

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID credentials second time: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials after overwrite, got %d", len(creds))
	}
}

func TestGenerateDefaultCredentials_ClaimOverrides(t *testing.T) {
	w := generateTestWallet(t)

	overrides := map[string]any{
		"given_name":  "MAX",
		"family_name": "MUSTERMANN-OVERRIDE",
	}
	if err := w.GenerateDefaultCredentials(overrides, ""); err != nil {
		t.Fatalf("generating PID credentials with overrides: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	sdjwtCred := creds[0]
	if sdjwtCred.Claims["given_name"] != "MAX" {
		t.Errorf("expected given_name MAX, got %v", sdjwtCred.Claims["given_name"])
	}
	if sdjwtCred.Claims["family_name"] != "MUSTERMANN-OVERRIDE" {
		t.Errorf("expected family_name MUSTERMANN-OVERRIDE, got %v", sdjwtCred.Claims["family_name"])
	}
	if sdjwtCred.Claims["birthdate"] != "1978-02-12" {
		t.Errorf("expected birthdate 1978-02-12, got %v", sdjwtCred.Claims["birthdate"])
	}
}

func TestGenerateDefaultCredentials_OverwritePreservesOtherCreds(t *testing.T) {
	w := generateTestWallet(t)

	key, _ := mock.GenerateKey()
	sdjwtRaw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCredential",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating test SD-JWT: %v", err)
	}
	if _, err := w.ImportCredential(sdjwtRaw); err != nil {
		t.Fatalf("importing test credential: %v", err)
	}

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}

	if len(w.GetCredentials()) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(w.GetCredentials()))
	}

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID second time: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials after overwrite, got %d", len(creds))
	}

	found := false
	for _, c := range creds {
		if c.VCT == "TestCredential" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected non-PID credential to be preserved")
	}
}

func TestImportSDJWT(t *testing.T) {
	w := generateTestWallet(t)

	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCredential",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}

	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatalf("importing SD-JWT: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Format != "dc+sd-jwt" {
		t.Errorf("expected dc+sd-jwt, got %s", creds[0].Format)
	}
	if creds[0].VCT != "TestCredential" {
		t.Errorf("expected VCT TestCredential, got %s", creds[0].VCT)
	}
	if creds[0].ID == "" {
		t.Error("expected non-empty credential ID")
	}
}

func TestImportMDoc(t *testing.T) {
	w := generateTestWallet(t)

	key, _ := mock.GenerateKey()
	mdocRaw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "org.test.credential",
		Namespace: "org.test.credential",
		Claims:    map[string]any{"field": "value"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating mdoc: %v", err)
	}

	if _, err := w.ImportCredential(mdocRaw); err != nil {
		t.Fatalf("importing mdoc: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Format != "mso_mdoc" {
		t.Errorf("expected mso_mdoc, got %s", creds[0].Format)
	}
	if creds[0].DocType != "org.test.credential" {
		t.Errorf("expected DocType org.test.credential, got %s", creds[0].DocType)
	}
}

func TestImportPlainJWT(t *testing.T) {
	w := generateTestWallet(t)

	jwt, err := signJWT(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"sub": "user123", "vct": "urn:test:credential", "given_name": "Erika", "family_name": "Mustermann"},
		w.IssuerKey,
	)
	if err != nil {
		t.Fatalf("creating test JWT: %v", err)
	}

	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatalf("importing plain JWT: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	cred := creds[0]
	if cred.Format != "jwt_vc_json" {
		t.Errorf("expected format jwt_vc_json, got %s", cred.Format)
	}
	if cred.VCT != "urn:test:credential" {
		t.Errorf("expected VCT urn:test:credential, got %s", cred.VCT)
	}
	if len(cred.Disclosures) != 0 {
		t.Errorf("expected 0 disclosures, got %d", len(cred.Disclosures))
	}
	if cred.Claims["given_name"] != "Erika" {
		t.Errorf("expected given_name Erika, got %v", cred.Claims["given_name"])
	}
}

func TestImportInvalidCredential(t *testing.T) {
	w := generateTestWallet(t)
	_, err := w.ImportCredential("not-a-credential")
	if err == nil {
		t.Fatal("expected error importing invalid credential")
	}
}

func TestRemoveCredential(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	id := creds[0].ID

	if !w.RemoveCredential(id) {
		t.Fatal("expected RemoveCredential to return true")
	}
	if len(w.GetCredentials()) != 1 {
		t.Errorf("expected 1 credential after removal, got %d", len(w.GetCredentials()))
	}
}

func TestRemoveCredential_NotFound(t *testing.T) {
	w := generateTestWallet(t)
	if w.RemoveCredential("nonexistent") {
		t.Error("expected RemoveCredential to return false for nonexistent ID")
	}
}

func TestGetCredential(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	cred, ok := w.GetCredential(creds[0].ID)
	if !ok {
		t.Fatal("expected to find credential")
	}
	if cred.ID != creds[0].ID {
		t.Errorf("expected ID %s, got %s", creds[0].ID, cred.ID)
	}
}

func TestGetCredential_NotFound(t *testing.T) {
	w := generateTestWallet(t)
	_, ok := w.GetCredential("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent credential")
	}
}

func TestAddLog(t *testing.T) {
	w := generateTestWallet(t)

	w.AddLog("test", "test detail", true)
	w.AddLog("test", "failure detail", false)

	log := w.GetLog()
	if len(log) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(log))
	}
	if log[0].Action != "test" {
		t.Errorf("expected action 'test', got %s", log[0].Action)
	}
	if log[0].Success != true {
		t.Error("expected first log entry to be success")
	}
	if log[1].Success != false {
		t.Error("expected second log entry to be failure")
	}
}

func TestSubscribe(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.Consents().Subscribe()
	defer unsub()

	req := &consent.Request{
		ID:        "test-req",
		Type:      "presentation",
		Status:    "pending",
		ClientID:  "test-client",
		CreatedAt: time.Now(),
		ResultCh:  make(chan consent.Result, 1),
	}

	go w.Consents().Create(req)

	select {
	case received := <-ch:
		if received.ID != "test-req" {
			t.Errorf("expected request ID test-req, got %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscriber notification")
	}
}

func TestPendingRequestDocsListOnlyPendingRequests(t *testing.T) {
	w := generateTestWallet(t)

	req1 := &consent.Request{
		ID:        "req-1",
		Status:    "pending",
		CreatedAt: time.Now(),
		ResultCh:  make(chan consent.Result, 1),
	}
	req2 := &consent.Request{
		ID:        "req-2",
		Status:    "approved",
		CreatedAt: time.Now(),
		ResultCh:  make(chan consent.Result, 1),
	}

	w.Consents().Create(req1)
	w.Consents().Create(req2)

	pending := w.Consents().PendingDocsFor(nil, "")
	if len(pending) != 1 || pending[0]["id"] != "req-1" {
		t.Fatalf("pending requests %v, want req-1 only", pending)
	}
}

func TestCredentialSummary(t *testing.T) {
	cred := StoredCredential{
		ID:     "test-id",
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
		Claims: map[string]any{"given_name": "Test"},
	}

	summary := CredentialSummary(cred)
	if summary["id"] != "test-id" {
		t.Errorf("expected id test-id, got %v", summary["id"])
	}
	if summary["format"] != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %v", summary["format"])
	}
	if summary["vct"] != mock.DefaultPIDVCT {
		t.Errorf("expected vct, got %v", summary["vct"])
	}
	if _, ok := summary["doctype"]; ok {
		t.Error("expected no doctype field for SD-JWT")
	}
}

func TestSubscribeErrors(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.Consents().SubscribeErrors()
	defer unsub()

	go w.Consents().NotifyError(consent.Error{Message: "test error", Detail: "detail"})

	select {
	case err := <-ch:
		if err.Message != "test error" {
			t.Errorf("expected 'test error', got %s", err.Message)
		}
		if err.Detail != "detail" {
			t.Errorf("expected 'detail', got %s", err.Detail)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for error notification")
	}
}

func TestLastErrorKeepsTheLatest(t *testing.T) {
	w := generateTestWallet(t)

	if err := w.Consents().PeekLastError(nil); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	w.Consents().NotifyError(consent.Error{Message: "first"})
	w.Consents().NotifyError(consent.Error{Message: "second"})

	err := w.Consents().PeekLastError(nil)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Message != "second" {
		t.Errorf("expected 'second', got %s", err.Message)
	}

	w.Consents().ClearLastError(nil)
	if err := w.Consents().PeekLastError(nil); err != nil {
		t.Errorf("expected nil once cleared, got %v", err)
	}
}

func TestRehydrate_SDJWT(t *testing.T) {
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}

	cred := StoredCredential{
		ID:     "test-id",
		Format: "dc+sd-jwt",
		Raw:    sdjwt,
	}

	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if len(cred.Disclosures) == 0 {
		t.Error("expected disclosures after rehydrate")
	}
	if len(cred.Claims) == 0 {
		t.Error("expected claims after rehydrate")
	}
}

func TestRehydrate_MDoc(t *testing.T) {
	key, _ := mock.GenerateKey()
	mdocRaw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "org.test.cred",
		Namespace: "org.test.cred",
		Claims:    map[string]any{"field": "value"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating mdoc: %v", err)
	}

	cred := StoredCredential{
		ID:     "test-id",
		Format: "mso_mdoc",
		Raw:    mdocRaw,
	}

	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if len(cred.NameSpaces) == 0 {
		t.Error("expected namespaces after rehydrate")
	}
	if len(cred.Claims) == 0 {
		t.Error("expected claims after rehydrate")
	}
}

func TestRehydrate_EmptyRaw(t *testing.T) {
	stored := StoredCredential{ID: "test-id", Format: "dc+sd-jwt", Claims: map[string]any{"name": "Test"}}
	cred := stored
	if err := cred.Rehydrate(); err != nil {
		t.Errorf("expected no error for empty raw, got %v", err)
	}
	if cred.ID != stored.ID || cred.Format != stored.Format || len(cred.Claims) != 1 || cred.Claims["name"] != "Test" || cred.NameSpaces != nil {
		t.Errorf("rehydrated %+v, want the stored fields kept", cred)
	}
}

func TestRehydrate_PreservesExistingClaims(t *testing.T) {
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}

	existingClaims := map[string]any{"custom": "value"}
	cred := StoredCredential{
		ID:     "test-id",
		Format: "dc+sd-jwt",
		Raw:    sdjwt,
		Claims: existingClaims,
	}

	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if cred.Claims["custom"] != "value" {
		t.Error("expected existing claims to be preserved")
	}
}

func TestMarshalConsentRequest(t *testing.T) {
	now := time.Now()
	req := &consent.Request{
		ID:          "req-1",
		Type:        "presentation",
		Status:      "pending",
		ClientID:    "https://verifier.example",
		Nonce:       "nonce123",
		ResponseURI: "https://verifier.example/callback",
		CreatedAt:   now,
		MatchedCreds: []consent.Match{
			{QueryID: "pid", Format: "dc+sd-jwt"},
		},
		DCQLQuery: map[string]any{"credentials": []any{}},
	}

	m := consent.NewRuntime().DocFor(req, nil)

	if m["id"] != "req-1" {
		t.Errorf("expected id req-1, got %v", m["id"])
	}
	if m["type"] != "presentation" {
		t.Errorf("expected type presentation, got %v", m["type"])
	}
	if m["client_id"] != "https://verifier.example" {
		t.Errorf("expected client_id, got %v", m["client_id"])
	}
	if m["nonce"] != "nonce123" {
		t.Errorf("expected nonce, got %v", m["nonce"])
	}
	if m["response_uri"] != "https://verifier.example/callback" {
		t.Errorf("expected response_uri, got %v", m["response_uri"])
	}
	if m["dcql_query"] == nil {
		t.Error("expected dcql_query")
	}
}

func TestMarshalConsentRequest_MinimalFields(t *testing.T) {
	req := &consent.Request{
		ID:        "req-2",
		Type:      "issuance",
		Status:    "approved",
		ClientID:  "test",
		CreatedAt: time.Now(),
	}

	m := consent.NewRuntime().DocFor(req, nil)

	if _, ok := m["nonce"]; ok {
		t.Error("expected no nonce field when empty")
	}
	if _, ok := m["response_uri"]; ok {
		t.Error("expected no response_uri field when empty")
	}
	if _, ok := m["dcql_query"]; ok {
		t.Error("expected no dcql_query field when nil")
	}
}

// The signing certificate's SAN matches client_id.
func signedRequestParams(t *testing.T, dnsName, clientName string) *oid4vp.Request {
	t.Helper()
	key, certB64, _ := testCertWithKeyDER([]string{dnsName})
	header := map[string]any{
		"alg": "ES256",
		"typ": "oauth-authz-req+jwt",
		"x5c": []any{certB64},
	}
	payload := map[string]any{
		"client_id":     "x509_san_dns:" + dnsName,
		"response_type": "vp_token",
		"nonce":         "nonce-123",
	}
	if clientName != "" {
		payload["client_metadata"] = map[string]any{"client_name": clientName}
	}
	raw, err := signJWT(header, payload, key)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parsedHeader, parsedPayload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		t.Fatalf("ParseJWTParts: %v", err)
	}
	return &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "x509_san_dns:" + dnsName, RequestObject: &oid4vc.RequestObjectJWT{
		Raw:     raw,
		Header:  parsedHeader,
		Payload: parsedPayload,
	}}}
}

func TestMarshalConsentRequest_ClientAuthSigned(t *testing.T) {
	req := &consent.Request{
		ID:        "req-signed",
		Type:      consent.TypePresentation,
		Status:    "pending",
		ClientID:  "x509_san_dns:verifier.example",
		CreatedAt: time.Now(),
	}
	applyClientAuth(req, signedRequestParams(t, "verifier.example", ""))

	m := consent.NewRuntime().DocFor(req, nil)
	auth, ok := m["client_auth"].(map[string]any)
	if !ok {
		t.Fatalf("expected client_auth object, got %v", m["client_auth"])
	}
	if auth["signed"] != true {
		t.Errorf("expected signed true, got %v", auth["signed"])
	}
	if auth["detail"] != "" {
		t.Errorf("expected empty detail for a verified signature, got %q", auth["detail"])
	}
}

func TestMarshalConsentRequest_ClientAuthUnsigned(t *testing.T) {
	req := &consent.Request{
		ID:        "req-unsigned",
		Type:      consent.TypePresentation,
		Status:    "pending",
		ClientID:  "redirect_uri:https://verifier.example/cb",
		CreatedAt: time.Now(),
	}
	applyClientAuth(req, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: req.ClientID}})

	m := consent.NewRuntime().DocFor(req, nil)
	auth, ok := m["client_auth"].(map[string]any)
	if !ok {
		t.Fatalf("expected client_auth object, got %v", m["client_auth"])
	}
	if auth["signed"] != false {
		t.Errorf("expected signed false, got %v", auth["signed"])
	}
	if auth["detail"] == "" {
		t.Error("expected a non-empty detail for an unsigned request")
	}
}

func TestMarshalConsentRequest_ClientAuthInvalidSignature(t *testing.T) {
	params := signedRequestParams(t, "verifier.example", "")
	// Corrupt the signature while retaining the signed Request Object.
	parts := strings.Split(params.RequestObject.Raw, ".")
	params.RequestObject.Raw = parts[0] + "." + parts[1] + ".AAAA"

	req := &consent.Request{
		ID:        "req-badsig",
		Type:      consent.TypePresentation,
		Status:    "pending",
		ClientID:  params.ClientID,
		CreatedAt: time.Now(),
	}
	applyClientAuth(req, params)

	auth := consent.NewRuntime().DocFor(req, nil)["client_auth"].(map[string]any)
	if auth["signed"] != false {
		t.Errorf("expected signed false for a broken signature, got %v", auth["signed"])
	}
	if auth["detail"] == "" {
		t.Error("expected a non-empty detail naming the verification failure")
	}
}

func TestMarshalConsentRequest_ClientName(t *testing.T) {
	req := &consent.Request{
		ID:        "req-name",
		Type:      consent.TypePresentation,
		Status:    "pending",
		ClientID:  "x509_san_dns:verifier.example",
		CreatedAt: time.Now(),
	}
	applyClientAuth(req, signedRequestParams(t, "verifier.example", "Example Verifier"))

	m := consent.NewRuntime().DocFor(req, nil)
	if m["client_name"] != "Example Verifier" {
		t.Errorf("expected client_name from client_metadata, got %v", m["client_name"])
	}
}

func TestMarshalConsentRequest_IssuanceNoClientAuth(t *testing.T) {
	req := &consent.Request{
		ID:        "req-issuance",
		Type:      consent.TypeIssuance,
		Status:    "pending",
		ClientID:  "https://issuer.example",
		CreatedAt: time.Now(),
	}

	m := consent.NewRuntime().DocFor(req, nil)
	if _, ok := m["client_auth"]; ok {
		t.Error("expected no client_auth for a pure issuance request")
	}
}

func hasEncryptionKey(reqObj *oid4vc.RequestObjectJWT) bool {
	_, err := extractEncryptionKey(ValidationModeDebug, reqObj, nil)
	return err == nil
}

func TestExtractEncryptionKey_NoRequestObject(t *testing.T) {
	if hasEncryptionKey(nil) {
		t.Error("expected false for nil request object")
	}
}

func TestExtractEncryptionKey_NoPayload(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{}
	if hasEncryptionKey(reqObj) {
		t.Error("expected false for nil payload")
	}
}

func TestExtractEncryptionKey_NoClientMetadata(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{},
	}
	if hasEncryptionKey(reqObj) {
		t.Error("expected false for missing client_metadata")
	}
}

func TestExtractEncryptionKey_WithKeyInClientMetadata(t *testing.T) {
	key, _ := mock.GenerateKey()
	jwkJSON := mock.PublicKeyJWK(&key.PublicKey)

	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("parsing JWK: %v", err)
	}
	jwk["alg"] = "ECDH-ES"

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}
	if !hasEncryptionKey(reqObj) {
		t.Error("expected true for valid encryption key in client_metadata")
	}
}

func TestExtractEncryptionKey_TopLevelJWKSNotUsed(t *testing.T) {
	key, _ := mock.GenerateKey()
	jwkJSON := mock.PublicKeyJWK(&key.PublicKey)

	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("parsing JWK: %v", err)
	}

	// OID4VP 1.0 reads encryption keys only from client_metadata.jwks.
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"encrypted_response_enc_values_supported": []any{"A128GCM"},
			},
			"jwks": map[string]any{
				"keys": []any{jwk},
			},
		},
	}
	if hasEncryptionKey(reqObj) {
		t.Error("expected false, wallet should only accept JWK in client_metadata.jwks per OID4VP 1.0")
	}
}

// Regeneration must not replace protected baseline credentials with unprotected
// copies.
func TestGenerateDefaultCredentials_KeepsProtected(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("GenerateProtectedDefaults: %v", err)
	}

	before := w.GetCredentials()
	if len(before) != 2*len(predefinedBaselineTypes(t)) {
		t.Fatalf("expected %d baseline credentials, got %d", 2*len(predefinedBaselineTypes(t)), len(before))
	}
	ids := make(map[string]bool)
	for _, c := range before {
		if !c.Protected {
			t.Fatalf("baseline credential %s should be protected", c.ID)
		}
		ids[c.ID] = true
	}

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	after := w.GetCredentials()
	if want := 2 * len(predefinedBaselineTypes(t)); len(after) != want {
		t.Errorf("expected the %d protected PIDs and no duplicates, got %d", want, len(after))
	}
	for _, c := range after {
		if !ids[c.ID] {
			t.Errorf("credential %s (%s) replaced a protected one", c.ID, c.Format)
		}
		if !c.Protected {
			t.Errorf("credential %s lost its protection", c.ID)
		}
	}
}

// The selected PID type determines its required claim set.
func TestGenerateDefaultCredentials_VCTSelectsTheClaimSet(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, germanPIDVCT); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	creds := w.GetCredentials()
	var sdjwt, mdoc *StoredCredential
	for i := range creds {
		switch creds[i].Format {
		case "dc+sd-jwt":
			sdjwt = &creds[i]
		case "mso_mdoc":
			mdoc = &creds[i]
		}
	}
	if sdjwt == nil || mdoc == nil {
		t.Fatal("expected an SD-JWT and an mdoc PID")
	}
	if sdjwt.VCT != germanPIDVCT {
		t.Errorf("vct = %q, want %q", sdjwt.VCT, germanPIDVCT)
	}
	if _, ok := sdjwt.Claims["source_document_type"]; !ok {
		t.Error("the German PID was issued without its national claims")
	}
	// A credential can satisfy requests for a type it extends.
	if !credtype.Answers(sdjwt.VCT, credtype.AkaVCTs(sdjwt.Claims), mock.DefaultPIDVCT) {
		t.Errorf("the German PID does not answer for %q: aka_vcts=%v", mock.DefaultPIDVCT, sdjwt.Claims[credtype.AkaVCTsClaim])
	}
	// National additions use a separate namespace under the shared doctype.
	if mdoc.DocType != mock.PIDNamespace {
		t.Errorf("doctype = %q, want %q", mdoc.DocType, mock.PIDNamespace)
	}
	if _, ok := mdoc.Claims[germanPIDNamespace+":birth_name"]; !ok {
		t.Errorf("the German mdoc PID is missing %s:birth_name", germanPIDNamespace)
	}
}

// EUDI and German PIDs share a doctype. Namespaces distinguish them during
// regeneration.
func TestGenerateDefaultCredentials_KeepsTheOtherPIDTypesMDoc(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, mock.DefaultPIDVCT); err != nil {
		t.Fatalf("generating the country-independent PID: %v", err)
	}
	if err := w.GenerateDefaultCredentials(nil, germanPIDVCT); err != nil {
		t.Fatalf("generating the German PID: %v", err)
	}

	var mdocs int
	var german bool
	for _, c := range w.GetCredentials() {
		if c.Format != "mso_mdoc" {
			continue
		}
		mdocs++
		if _, ok := c.Claims[germanPIDNamespace+":birth_name"]; ok {
			german = true
		}
	}
	if mdocs != 2 {
		t.Errorf("wallet holds %d mdoc PIDs, want both types", mdocs)
	}
	if !german {
		t.Error("the German mdoc PID is missing")
	}

	if err := w.GenerateDefaultCredentials(nil, germanPIDVCT); err != nil {
		t.Fatalf("regenerating the German PID: %v", err)
	}
	mdocs = 0
	for _, c := range w.GetCredentials() {
		if c.Format == "mso_mdoc" {
			mdocs++
		}
	}
	if mdocs != 2 {
		t.Errorf("regenerating one PID type left %d mdoc PIDs, want 2", mdocs)
	}
}

// Older files have unprefixed claim keys. Regeneration must still recognize and
// replace their existing mdoc PIDs.
func TestGenerateDefaultCredentials_ReplacesAMDocStoredWithoutNamespacedClaims(t *testing.T) {
	w := generateTestWalletWithPID(t)

	var raw string
	for i := range w.Credentials {
		c := &w.Credentials[i]
		if c.Format != "mso_mdoc" {
			continue
		}
		raw = c.Raw
		bare := make(map[string]any, len(c.Claims))
		for key, value := range c.Claims {
			_, element, found := strings.Cut(key, ":")
			if !found {
				element = key
			}
			bare[element] = value
		}
		c.Claims = bare
	}
	if raw == "" {
		t.Fatal("no mdoc PID to age")
	}
	// Loading rebuilds namespaces from the raw credential.
	for i := range w.Credentials {
		if err := w.Credentials[i].Rehydrate(); err != nil {
			t.Fatalf("rehydrating: %v", err)
		}
	}

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	var mdocs int
	for _, c := range w.GetCredentials() {
		if c.Format == "mso_mdoc" {
			mdocs++
		}
	}
	if mdocs != 1 {
		t.Errorf("wallet holds %d mdoc PIDs, want the regenerated one alone", mdocs)
	}
}

func TestGenerateDefaultCredentials_ReplacesUnprotected(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}
	first := w.GetCredentials()
	if len(first) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(first))
	}

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("second GenerateDefaultCredentials: %v", err)
	}
	second := w.GetCredentials()
	if len(second) != 2 {
		t.Errorf("expected 2 credentials after regenerating, got %d", len(second))
	}
	for _, c := range second {
		for _, old := range first {
			if c.ID == old.ID {
				t.Errorf("unprotected credential %s should have been replaced", c.ID)
			}
		}
	}
}

// Baseline generation replaces protected defaults so upgrades pick up current template
// claims.
func TestGenerateProtectedDefaults_RefreshesOwnBaseline(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("first GenerateProtectedDefaults: %v", err)
	}
	first := w.GetCredentials()
	if len(first) != 2*len(predefinedBaselineTypes(t)) {
		t.Fatalf("expected %d baseline credentials, got %d", 2*len(predefinedBaselineTypes(t)), len(first))
	}
	oldIDs := map[string]bool{}
	for _, c := range first {
		oldIDs[c.ID] = true
	}

	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("second GenerateProtectedDefaults: %v", err)
	}

	second := w.GetCredentials()
	if want := 2 * len(predefinedBaselineTypes(t)); len(second) != want {
		t.Fatalf("expected the baseline to stay at %d credentials, got %d", want, len(second))
	}
	for _, c := range second {
		if oldIDs[c.ID] {
			t.Errorf("credential %s (%s) was not refreshed", c.ID, c.Format)
		}
		if !c.Protected {
			t.Errorf("refreshed credential %s must stay protected", c.ID)
		}
	}
}

// Baseline refresh must preserve visitor credentials of the same type.
func TestGenerateProtectedDefaults_KeepsVisitorCredentialOfBaselineType(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("first GenerateProtectedDefaults: %v", err)
	}

	// The visitor credential uses the current template type so the types collide.
	var baselineVCT string
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" {
			baselineVCT = c.VCT
		}
	}
	if baselineVCT == "" {
		t.Fatal("no baseline SD-JWT PID to match against")
	}
	w.Credentials = append(w.Credentials, StoredCredential{
		ID:     "visitor-pid",
		Format: "dc+sd-jwt",
		VCT:    baselineVCT,
	})

	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("second GenerateProtectedDefaults: %v", err)
	}

	var foundVisitor bool
	var protectedCount int
	for _, c := range w.GetCredentials() {
		if c.ID == "visitor-pid" {
			foundVisitor = true
			if c.Protected {
				t.Error("the visitor credential was marked protected by the refresh")
			}
		}
		if c.Protected {
			protectedCount++
		}
	}
	if !foundVisitor {
		t.Error("the visitor's PID was dropped by the baseline refresh")
	}
	if want := 2 * len(predefinedBaselineTypes(t)); protectedCount != want {
		t.Errorf("expected %d protected baseline credentials, got %d", want, protectedCount)
	}
}

func TestGenerateDefaultCredentials_APIPathCannotReplaceProtected(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("GenerateProtectedDefaults: %v", err)
	}
	before := w.GetCredentials()

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	after := w.GetCredentials()
	if len(after) != len(before) {
		t.Fatalf("expected %d credentials, got %d", len(before), len(after))
	}
	for i, c := range after {
		if c.ID != before[i].ID {
			t.Errorf("protected credential %s was replaced by %s", before[i].ID, c.ID)
		}
	}
}

func TestUserClaimCountExcludesProtocolClaims(t *testing.T) {
	claims := map[string]any{
		"family_name": "Doe", "given_name": "Jane", "birthdate": "2000-01-01",
		"iss": "x", "cnf": map[string]any{}, "iat": 1, "exp": 2, "vct": "y",
		"status": map[string]any{}, "_sd_alg": "sha-256",
	}
	if got := userClaimCount(claims); got != 3 {
		t.Fatalf("userClaimCount counted %d, want 3 (only the subject attributes)", got)
	}
	if got := userClaimCount(nil); got != 0 {
		t.Fatalf("userClaimCount(nil) = %d, want 0", got)
	}
}

// predefinedBaselineTypes lists the baseline PIDs of the predefined templates.
func predefinedBaselineTypes(t *testing.T) []string {
	t.Helper()
	return (&Wallet{Templates: credtemplate.FileLocation(t.TempDir())}).baselinePIDTypes()
}

func testCertWithKeyDER(dnsNames []string) (*ecdsa.PrivateKey, string, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return key, base64.StdEncoding.EncodeToString(der), der
}
