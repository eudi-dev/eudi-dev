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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

func receiptResponse(raws ...string) map[string]any {
	creds := make([]any, 0, len(raws))
	for _, raw := range raws {
		creds = append(creds, map[string]any{"credential": raw})
	}
	return map[string]any{"credentials": creds}
}

func receiptSDJWT(t *testing.T, w *Wallet, cfg mock.SDJWTConfig) string {
	t.Helper()
	if cfg.VCT == "" {
		cfg.VCT = "urn:example:receipt:1"
	}
	if cfg.Claims == nil {
		cfg.Claims = map[string]any{"given_name": "Erika"}
	}
	if cfg.ExpiresIn == 0 {
		cfg.ExpiresIn = time.Hour
	}
	cfg.Issuer = "https://issuer.example"
	cfg.Key = w.IssuerKey
	raw, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// checkReceipt runs the receipt checks in strict and debug mode. Strict mode
// must refuse with want in the error, debug mode must store and return want
// among the findings. An empty want expects no finding at all.
func checkReceipt(t *testing.T, w *Wallet, resp, metadata map[string]any, configID, want string) {
	t.Helper()
	w.ValidationMode = ValidationModeStrict
	_, err := w.checkReceivedCredentials(resp, metadata, configID, "https://issuer.example")
	switch {
	case want == "" && err != nil:
		t.Errorf("strict mode refused: %v", err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Errorf("strict mode: error %v, want %q", err, want)
	}
	w.ValidationMode = ValidationModeDebug
	findings, err := w.checkReceivedCredentials(resp, metadata, configID, "https://issuer.example")
	if err != nil {
		t.Fatalf("debug mode refused: %v", err)
	}
	joined := strings.Join(findings, "\n")
	if want == "" && len(findings) != 0 || want != "" && !strings.Contains(joined, want) {
		t.Errorf("debug mode findings %v, want %q", findings, want)
	}
}

func arfReceiptWallet(t *testing.T) *Wallet {
	w := generateTestWallet(t)
	w.RequireARF = true
	return w
}

// ARF ISSU_06: the wallet checks that the received type is the requested one.
func TestReceiptReportsACredentialOfAnotherType(t *testing.T) {
	w := arfReceiptWallet(t)
	resp := receiptResponse(receiptSDJWT(t, w, mock.SDJWTConfig{}))
	metadata := func(vct string) map[string]any {
		return map[string]any{"credential_configurations_supported": map[string]any{
			"requested": map[string]any{"format": "dc+sd-jwt", "vct": vct},
		}}
	}
	checkReceipt(t, w, resp, metadata("urn:example:receipt:1"), "requested", "")
	checkReceipt(t, w, resp, metadata("urn:example:other:1"), "requested", "ARF ISSU_06")
	w.RequireARF = false
	checkReceipt(t, w, resp, metadata("urn:example:other:1"), "requested", "")
}

// OpenID4VCI 1.0 §3.3.2: the copies of a batch share the Credential Dataset.
// The rule binds the issuer, so the wallet checks it without --arf.
func TestReceiptReportsABatchWithOtherAttributeValues(t *testing.T) {
	w := generateTestWallet(t)
	first := receiptSDJWT(t, w, mock.SDJWTConfig{Claims: map[string]any{"given_name": "Erika"}})
	same := receiptSDJWT(t, w, mock.SDJWTConfig{Claims: map[string]any{"given_name": "Erika"}})
	other := receiptSDJWT(t, w, mock.SDJWTConfig{Claims: map[string]any{"given_name": "Max"}})
	checkReceipt(t, w, receiptResponse(first, same), nil, "", "")
	checkReceipt(t, w, receiptResponse(first, other), nil, "", "OpenID4VCI 1.0 §3.3.2")

	firstID := receiptSDJWT(t, w, mock.SDJWTConfig{Claims: map[string]any{"given_name": "Erika", "jti": "copy-1"}})
	secondID := receiptSDJWT(t, w, mock.SDJWTConfig{Claims: map[string]any{"given_name": "Erika", "jti": "copy-2"}})
	checkReceipt(t, w, receiptResponse(firstID, secondID), nil, "", "")
}

// ARF ISSU_11a: the copies of a batch share the technical validity period.
func TestReceiptReportsABatchWithAnotherValidityPeriod(t *testing.T) {
	w := arfReceiptWallet(t)
	issued := time.Now().Truncate(time.Second)
	first := receiptSDJWT(t, w, mock.SDJWTConfig{IssuedAt: &issued, ExpiresIn: time.Hour})
	same := receiptSDJWT(t, w, mock.SDJWTConfig{IssuedAt: &issued, ExpiresIn: time.Hour})
	longer := receiptSDJWT(t, w, mock.SDJWTConfig{IssuedAt: &issued, ExpiresIn: 2 * time.Hour})
	checkReceipt(t, w, receiptResponse(first, same), nil, "", "")
	checkReceipt(t, w, receiptResponse(first, longer), nil, "", "ARF ISSU_11a")
}

// CIR (EU) 2024/2982 Article 4(3)(d): the wallet verifies the validity of a
// received credential.
func TestReceiptReportsAnExpiredOrNotYetValidCredential(t *testing.T) {
	w := arfReceiptWallet(t)
	past := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(time.Hour)
	expired := receiptSDJWT(t, w, mock.SDJWTConfig{IssuedAt: &past, ExpiresIn: time.Hour})
	notYet := receiptSDJWT(t, w, mock.SDJWTConfig{NotBefore: &future})
	checkReceipt(t, w, receiptResponse(expired), nil, "", "Article 4(3)(d): the received urn:example:receipt:1 expired")
	checkReceipt(t, w, receiptResponse(notYet), nil, "", "Article 4(3)(d): the received urn:example:receipt:1 is valid only from")
}

// The wallet reads the status of a received credential from the issuer's
// status list, and from its own list for a credential of its own issuer. A
// revocation service on the trusted list of the credential's issuer must sign
// the status list.
func TestReceiptReportsARevokedCredential(t *testing.T) {
	const vct = "urn:example:receipt:1"
	issuer := generateTestWallet(t)
	issuer.BaseURL = "https://issuer.example"
	stranger := generateTestWallet(t)
	signer := issuer
	var listURL string
	revoked := -1
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		key, chain, err := signer.Signer().StatusList()
		if err != nil {
			t.Error(err)
		}
		bitstring := make([]byte, 16)
		if revoked >= 0 {
			bitstring[revoked/8] |= 1 << (revoked % 8)
		}
		token, err := statuslist.GenerateStatusListJWT(bitstring, key, statuslist.StatusListConfig{URI: listURL, Issuer: listURL, Bits: 1, CertChain: chain})
		if err != nil {
			t.Error(err)
		}
		rw.Header().Set("Content-Type", statuslist.MediaTypeJWT)
		_, _ = rw.Write([]byte(token))
	}))
	t.Cleanup(srv.Close)
	listURL = srv.URL

	result, err := issuer.IssueCredential(IssueOptions{Format: "sdjwt", VCT: vct, Claims: map[string]any{"given_name": "Erika"}, StatusListURI: &listURL, Category: credtemplate.CategoryEAA})
	if err != nil {
		t.Fatal(err)
	}
	group, _ := issuer.TrustedLists().FindGroup(credtemplate.CategoryEAA, "", "")
	trustedList, err := issuer.TrustedLists().SignedGroupList(issuer.BaseURL, group, "/api/trustlists/"+group.ID)
	if err != nil {
		t.Fatal(err)
	}
	listSite := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(trustedList)) }))
	t.Cleanup(listSite.Close)

	w := arfReceiptWallet(t)
	w.TrustSettings.ListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Signer().TrustAnchor().Raw})
	isLOTE := true
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
		Name:        "Receipt",
		Category:    credtemplate.CategoryEAA,
		Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: vct}},
		Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: listSite.URL, IsLOTE: &isLOTE}}},
	}); err != nil {
		t.Fatal(err)
	}
	checkReceipt(t, w, receiptResponse(result.Raw), nil, "", "")
	revoked = CredentialStatusRef(*result.Credential).Idx
	checkReceipt(t, w, receiptResponse(result.Raw), nil, "", "is INVALID on its status list")

	revoked = -1
	signer = stranger
	checkReceipt(t, w, receiptResponse(result.Raw), nil, "", "does not chain to a revocation service on the trusted list of its issuer")

	srv.Close()
	checkReceipt(t, w, receiptResponse(result.Raw), nil, "", "the status of the received urn:example:receipt:1 cannot be read")

	w.BaseURL = "https://wallet.example"
	own, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:own:1", Claims: map[string]any{"given_name": "Erika"}})
	if err != nil {
		t.Fatal(err)
	}
	checkReceipt(t, w, receiptResponse(own.Raw), nil, "", "")
	if _, ok := w.SetCredentialStatus(own.Credential.ID, 1); !ok {
		t.Fatal("revoking the own credential failed")
	}
	checkReceipt(t, w, receiptResponse(own.Raw), nil, "", "is INVALID on its status list")
}
