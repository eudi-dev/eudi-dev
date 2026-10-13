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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func txCodeIssuer(t *testing.T, w *Wallet, wantCode string) (*httptest.Server, string) {
	t.Helper()
	return txCodeIssuerWithObject(t, w, wantCode, map[string]any{
		"input_mode":  "numeric",
		"length":      float64(4),
		"description": "The code from your letter",
	})
}

func txCodeIssuerWithObject(t *testing.T, w *Wallet, wantCode string, txCode map[string]any) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("tx_code") {
			case "":
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{
					"error": "invalid_request", "error_description": "Missing required 'tx_code' in request",
				})
			case wantCode:
				json.NewEncoder(rw).Encode(map[string]any{
					"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
				})
			default:
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{
					"error": "invalid_grant", "error_description": "Invalid 'tx_code' provided",
				})
			}

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
				"tx_code":             txCode,
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?" + oid4vc.EncodeURIQuery(url.Values{"credential_offer": {string(offerJSON)}})
}

// The transaction code from consent approval reaches the token request.
func TestApproveRequest_CarriesTxCodeIntoIssuance(t *testing.T) {
	w := generateTestWallet(t)
	srv, offerURI := txCodeIssuer(t, w, "1234")
	defer srv.Close()

	server := NewServer(w, 0, nil)

	for _, tc := range []struct {
		name    string
		code    string
		wantErr string
	}{
		{"correct code", "1234", ""},
		{"wrong code", "9999", "Invalid 'tx_code'"},
		// An offer with a tx_code is refused before the issuer is called.
		// §4.1.1 puts it in the grant because the Authorization Server
		// expects one. A request without it would spend the pre-authorized
		// code on a request that cannot succeed.
		{"no code", "", "this offer requires a transaction code"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consentReq, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
			if err != nil {
				t.Fatalf("prepareIssuanceConsentRequest: %v", err)
			}
			details := consentReq.OfferDetails
			if !details.TxCode {
				t.Fatal("offer details do not report a required transaction code")
			}
			if details.TxCodeInputMode != "numeric" || details.TxCodeLength != 4 {
				t.Errorf("input shape = %q/%d, want numeric/4", details.TxCodeInputMode, details.TxCodeLength)
			}
			if details.TxCodeDescription != "The code from your letter" {
				t.Errorf("description = %q, want the issuer's own wording", details.TxCodeDescription)
			}

			w.Consents().Create(consentReq)
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.awaitOfferConsent(noopResponseWriter{}, consentReq, "test issuer", OfferOptions{})
			}()

			consentReq.ResultCh <- consent.Result{Approved: true, TxCode: tc.code}
			submission := <-consentReq.SubmissionCh
			<-done

			if tc.wantErr == "" {
				if submission.Error != "" {
					t.Fatalf("issuance failed: %s", submission.Error)
				}
				return
			}
			if !strings.Contains(submission.Error, tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", submission.Error, tc.wantErr)
			}
		})
	}
}

// The wallet fetches and embeds the issuer logo with address checks, so the
// consent dialog never loads it from the issuer directly.
func TestDescribeCredentialOfferEmbedsTheIssuerLogo(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":                   serverURL,
				"credential_endpoint":                 serverURL + "/credential",
				"credential_configurations_supported": map[string]any{},
				"display": []any{map[string]any{
					"name": "Test Issuer",
					"logo": map[string]any{"uri": serverURL + "/logo.png"},
				}},
			})
		case strings.HasSuffix(r.URL.Path, "/logo.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(tinyPNG)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	details, _ := generateTestWallet(t).describeCredentialOffer(t.Context(), &oid4vc.CredentialOffer{CredentialIssuer: srv.URL})
	if details.IssuerName != "Test Issuer" {
		t.Errorf("issuer name = %q, want Test Issuer", details.IssuerName)
	}
	if !strings.HasPrefix(details.IssuerLogo, "data:image/") {
		t.Errorf("issuer logo was not fetched and embedded, got %.30q", details.IssuerLogo)
	}

	// --adhoc-display-images keeps card art as a URL. The issuer logo is still
	// embedded because it shows once at consent and is never stored.
	adhoc := generateTestWallet(t)
	adhoc.AdhocDisplayImages = true
	adhocDetails, _ := adhoc.describeCredentialOffer(t.Context(), &oid4vc.CredentialOffer{CredentialIssuer: srv.URL})
	if !strings.HasPrefix(adhocDetails.IssuerLogo, "data:image/") {
		t.Errorf("issuer logo not embedded under adhoc mode, got %.30q", adhocDetails.IssuerLogo)
	}
}

// An offer can list many configurations that share one logo. The wallet
// fetches each image URL once per offer, and stops fetching when the client
// goes away.
func TestDescribeCredentialOfferFetchesEachImageOnce(t *testing.T) {
	var serverURL string
	var logoFetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			logo := map[string]any{"uri": serverURL + "/logo.png"}
			configs := map[string]any{}
			for i := range 5 {
				configs[fmt.Sprintf("config-%d", i)] = map[string]any{
					"format": "dc+sd-jwt",
					"vct":    "urn:example:vct",
					"credential_metadata": map[string]any{
						"display": []any{map[string]any{"name": "Card", "logo": logo, "background_image": logo}},
					},
				}
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":                   serverURL,
				"credential_endpoint":                 serverURL + "/credential",
				"credential_configurations_supported": configs,
				"display":                             []any{map[string]any{"name": "Test Issuer", "logo": logo}},
			})
		case strings.HasSuffix(r.URL.Path, "/logo.png"):
			logoFetches.Add(1)
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(tinyPNG)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer:           srv.URL,
		CredentialConfigurationIDs: []string{"config-0", "config-1", "config-2", "config-3", "config-4"},
	}

	details, _ := generateTestWallet(t).describeCredentialOffer(t.Context(), offer)
	if got := logoFetches.Load(); got != 1 {
		t.Errorf("logo fetched %d times, want 1", got)
	}
	for _, credential := range details.Credentials {
		if credential.Display == nil || !strings.HasPrefix(credential.Display.LogoURI, "data:image/png") {
			t.Errorf("%s has no embedded logo", credential.ID)
		}
	}

	logoFetches.Store(0)
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	details, _ = generateTestWallet(t).describeCredentialOffer(gone, offer)
	if got := logoFetches.Load(); got != 0 {
		t.Errorf("logo fetched %d times after the client went away, want 0", got)
	}
	if details.IssuerLogo != "" {
		t.Errorf("issuer logo = %.30q, want none", details.IssuerLogo)
	}
}

// The dialog shows the transaction code's input mode, length and description.
// Without a description it builds a hint from the input mode and length.
func TestDescribeCredentialOffer_TxCodeShape(t *testing.T) {
	for _, tc := range []struct {
		name      string
		txCode    map[string]any
		wantHint  string
		wantMode  string
		wantLen   int
		wantDescr string
	}{
		{
			name:     "numeric with length",
			txCode:   map[string]any{"input_mode": "numeric", "length": float64(6)},
			wantHint: "6 numeric characters", wantMode: "numeric", wantLen: 6,
		},
		{
			name:      "issuer description wins the hint",
			txCode:    map[string]any{"input_mode": "text", "length": float64(8), "description": "From the letter"},
			wantHint:  "From the letter",
			wantMode:  "text",
			wantLen:   8,
			wantDescr: "From the letter",
		},
		{
			name:     "empty object still requires a code",
			txCode:   map[string]any{},
			wantHint: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offer := &oid4vc.CredentialOffer{
				CredentialIssuer: "https://issuer.invalid",
				Grants:           oid4vc.OfferGrants{PreAuthorizedCode: "code", TxCode: tc.txCode},
			}
			details, _ := generateTestWallet(t).describeCredentialOffer(t.Context(), offer)
			if !details.TxCode {
				t.Fatal("expected tx_code to be reported as required")
			}
			if details.TxCodeHint != tc.wantHint {
				t.Errorf("hint = %q, want %q", details.TxCodeHint, tc.wantHint)
			}
			if details.TxCodeInputMode != tc.wantMode {
				t.Errorf("input_mode = %q, want %q", details.TxCodeInputMode, tc.wantMode)
			}
			if details.TxCodeLength != tc.wantLen {
				t.Errorf("length = %d, want %d", details.TxCodeLength, tc.wantLen)
			}
			if details.TxCodeDescription != tc.wantDescr {
				t.Errorf("description = %q, want %q", details.TxCodeDescription, tc.wantDescr)
			}
		})
	}
}

// TestOfferNeedingATxCodeIsRefusedBeforeTheCodeIsSpent covers an offer with a
// tx_code that reaches issuance without a code. This happens with auto-accept
// or when an API caller omits it. §4.1.1 puts tx_code in the grant because the
// Authorization Server expects one. The pre-authorized code is not spent on a
// request that cannot succeed.
func TestOfferNeedingATxCodeIsRefusedBeforeTheCodeIsSpent(t *testing.T) {
	w := generateTestWallet(t)
	srv, offerURI := txCodeIssuer(t, w, "1234")
	defer srv.Close()

	_, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{})
	if err == nil {
		t.Fatal("expected the issuance to say what it is missing")
	}
	for _, want := range []string{"requires a transaction code", "--tx-code", "The code from your letter"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}

	if _, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{TxCode: "1234"}); err != nil {
		t.Fatalf("issuance with the code: %v", err)
	}
}

// OID4VCI 1.0 §4.1.1: a tx_code object means "a Transaction Code is required if
// present, even if empty". §6.1 makes the token request carry it.
func TestEmptyTxCodeObjectRequiresACode(t *testing.T) {
	w := generateTestWallet(t)
	srv, offerURI := txCodeIssuerWithObject(t, w, "1234", map[string]any{})
	defer srv.Close()

	_, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{})
	if err == nil || !strings.Contains(err.Error(), "requires a transaction code") {
		t.Fatalf("error = %v, want the missing transaction code named", err)
	}
	if _, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{TxCode: "1234"}); err != nil {
		t.Fatalf("issuance with the code: %v", err)
	}
}
