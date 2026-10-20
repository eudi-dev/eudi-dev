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

package demorp

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func TestAConfiguredIssuerIdentitySignsTheMetadata(t *testing.T) {
	w := newIssuanceWallet(t)
	d, ts := serveDemoStack(t, w)
	signingKey, accessLeaf, issuerInfo := registerOwnIssuer(t, w)
	identity, err := ParseConfiguredIdentity(signingKey, issuerInfo)
	if err != nil {
		t.Fatal(err)
	}
	d.SetIssuerIdentity(identity)

	for _, tt := range []struct {
		path string
		info any
	}{
		{path: "/issuer", info: issuerInfo},
		{path: "/issuer/unregistered", info: nil},
	} {
		wellKnown := ts.URL + "/.well-known/openid-credential-issuer" + tt.path
		got := getJSONFrom(t, wellKnown)["issuer_info"]
		if tt.info == nil && got != nil || tt.info != nil && !reflect.DeepEqual(got, tt.info) {
			t.Errorf("%s: issuer_info = %v, want %v", tt.path, got, tt.info)
		}
		if x5c := signedMetadataX5C(t, wellKnown); len(x5c) == 0 || x5c[0] != accessLeaf {
			t.Errorf("%s: the signed metadata does not carry the configured access certificate", tt.path)
		}
	}

	created := postJSONTo(t, ts.URL+"/issuer/api/offers", "")
	if _, err := w.ProcessCredentialOffer(created["scheme_uri"].(string)); err != nil {
		t.Fatalf("issuance failed: %v", err)
	}

	page := getText(t, ts.URL+"/issuer/")
	if !strings.Contains(page, `data-configured-identity="true"`) {
		t.Error("the issuer page does not describe the configured identity")
	}
}

func TestAConfiguredVerifierIdentitySignsTheRequestObject(t *testing.T) {
	w := customTestWallet(t)
	d, _ := serveDemoStack(t, w)
	bundle := signingKeyPEM(t)
	verifierInfo := []any{map[string]any{"format": "registration_cert", "data": "configured"}}
	identity, err := ParseConfiguredIdentity(bundle, verifierInfo)
	if err != nil {
		t.Fatal(err)
	}
	d.SetVerifierIdentity(identity)

	_, doc := doJSON(t, d.VerifierHandler(), "POST", "/api/requests", `{"type":"pid"}`, map[string]string{"Content-Type": "application/json"})
	walletURL, err := url.Parse(doc["wallet_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if want := oid4vp.X509HashClientID(identity.Chain[0]); walletURL.Query().Get("client_id") != want {
		t.Errorf("client_id = %q, want %q from the configured certificate", walletURL.Query().Get("client_id"), want)
	}
	payload := fetchRequestObject(t, d.VerifierHandler(), walletURL.Query().Get("request_uri"))
	if got := payload["verifier_info"]; !reflect.DeepEqual(got, verifierInfo) {
		t.Errorf("verifier_info = %v, want the configured %v", got, verifierInfo)
	}
}

func TestAConfiguredIdentityNeedsTheKeyOfItsCertificate(t *testing.T) {
	bundle, other := signingKeyPEM(t), signingKeyPEM(t)
	keyOnly := bundle[:strings.Index(bundle, "-----BEGIN CERTIFICATE-----")]
	certOnly := other[strings.Index(other, "-----BEGIN CERTIFICATE-----"):]
	if _, err := ParseConfiguredIdentity(keyOnly+certOnly, nil); err == nil || !strings.Contains(err.Error(), "does not belong to the private key") {
		t.Fatalf("err = %v, want a key mismatch", err)
	}
}

func getText(t *testing.T, target string) string {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
