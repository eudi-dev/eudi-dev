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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// customTestWallet is a demo wallet holding the default PID. HAIP and strict
// validation are off, so it answers both signed and unsigned custom requests.
func customTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	return w
}

func driveWallet(t *testing.T, ts *httptest.Server, walletURL string) {
	t.Helper()
	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("authorize returned %d: %s", resp.StatusCode, body)
	}
}

func customNationalities(t *testing.T, status map[string]any) []any {
	t.Helper()
	claims, ok := status["claims"].(map[string]any)
	if !ok {
		t.Fatalf("no claims in status: %v", status)
	}
	cred, ok := claims["cred_0"].(map[string]any)
	if !ok {
		t.Fatalf("no cred_0 in claims: %v", claims)
	}
	nats, ok := cred["nationalities"].([]any)
	if !ok {
		t.Fatalf("nationalities is not an array: %v", cred["nationalities"])
	}
	return nats
}

// createCustom creates a request, lets the wallet answer it and returns the
// transaction_id for reading the result.
func createCustom(t *testing.T, ts *httptest.Server, body string) string {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/verifier/api/requests", body)
	transactionID, _ := created["transaction_id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	if transactionID == "" || walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}
	driveWallet(t, ts, walletURL)
	return transactionID
}

// OpenID4VP 1.0 §7.1: a path that ends at an array of selectively disclosable
// elements, without null or an index, discloses none of the elements. The
// verifier sees an empty array.
func TestVerifierCustomRequestBareArrayDisclosesEmpty(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["nationalities"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	if nats := customNationalities(t, status); len(nats) != 0 {
		t.Errorf("disclosed nationalities = %v, want an empty array", nats)
	}
}

// A path that ends with null selects every element, so the wallet discloses
// all of them.
func TestVerifierCustomRequestNullArrayDisclosesElements(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["nationalities",null]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	nats := customNationalities(t, status)
	if len(nats) != 1 || nats[0] != "NL" {
		t.Errorf("disclosed nationalities = %v, want [NL]", nats)
	}
}

func TestVerifierCustomRequestMDoc(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"mso_mdoc","doctype":"`+PIDDocType+`","claims":[["`+PIDDocType+`","given_name"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	cred, _ := claims["cred_0"].(map[string]any)
	if cred["given_name"] == nil {
		t.Errorf("disclosed mdoc claims = %v, want given_name", cred)
	}
}

func clientIDOf(walletURL string) string {
	u, err := url.Parse(walletURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("client_id")
}

func signingKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Custom Verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A caller-supplied EC key and certificate (as PEM) sign the request object.
// The client id is derived from that certificate. A malformed bundle is a
// client error.
func TestVerifierCustomRequestSigningKey(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	defaultDoc := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`)
	defaultURL, _ := defaultDoc["wallet_url"].(string)

	body := `{"type":"custom","signing_key":` + jsonString(signingKeyPEM(t)) + `,"credentials":[{"format":"dc+sd-jwt","vct":"` + PIDVCT + `","claims":[["given_name"]]}]}`
	customDoc := postJSONTo(t, ts.URL+"/verifier/api/requests", body)
	customURL, _ := customDoc["wallet_url"].(string)
	if customURL == "" {
		t.Fatalf("no wallet_url for a custom signing key: %v", customDoc)
	}
	if clientIDOf(customURL) == clientIDOf(defaultURL) {
		t.Errorf("client_id did not change with a custom signing key: %q", clientIDOf(customURL))
	}

	resp, err := http.Post(ts.URL+"/verifier/api/requests", "application/json",
		strings.NewReader(`{"type":"custom","signing_key":"not a pem","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed signing_key returned %d, want 400", resp.StatusCode)
	}
}

func TestVerifierCustomRequestRedirectURIUnsigned(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","client_id_scheme":"redirect_uri","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	cred, _ := claims["cred_0"].(map[string]any)
	if cred["given_name"] == nil {
		t.Errorf("disclosed claims = %v, want given_name", cred)
	}
}

// The verifier checks the status list of an mdoc as it does for an SD-JWT VC.
func TestTheVerifierRejectsARevokedMDoc(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)
	for _, cred := range w.GetCredentials() {
		w.RemoveCredential(cred.ID)
	}
	created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential=pid-mdoc&status=true", "")
	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(created["scheme_uri"].(string))+`}`)
	id, _ := result["credential_id"].(string)
	if id == "" {
		t.Fatalf("issuing the mdoc: %v", result)
	}
	if _, ok := w.SetCredentialStatus(id, 1); !ok {
		t.Fatal("the mdoc has no entry on the wallet's status list")
	}

	request := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"mso_mdoc","doctype":"`+PIDDocType+`","claims":[["`+PIDDocType+`","given_name"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+request)
	if status["status"] != "failed" || !strings.Contains(fmt.Sprint(status["checks"]), "name:cred_0: status ok:false") {
		t.Errorf("status = %v, want failed on the revocation check (checks %v)", status["status"], status["checks"])
	}
}

// A DCQL claims path points into the disclosed claims (OpenID4VP 1.0 §7.1).
func TestAClaimsPathPointsIntoTheClaims(t *testing.T) {
	claims := map[string]any{
		"address":                 map[string]any{"locality": "Berlin"},
		"nationalities":           []any{"DE", "NL"},
		"eu.europa.ec.eudi.pid.1": map[string]any{"given_name": "Erika"},
		"middle_name":             nil,
	}
	for _, tc := range []struct {
		path []any
		want bool
	}{
		{[]any{"address", "locality"}, true},
		{[]any{"address", "street_address"}, false},
		{[]any{"nationalities", nil}, true},
		{[]any{"nationalities", float64(1)}, true},
		{[]any{"nationalities", float64(2)}, false},
		{[]any{"eu.europa.ec.eudi.pid.1", "given_name"}, true},
		{[]any{"eu.europa.ec.eudi.pid.de.1", "given_name"}, false},
		{[]any{"middle_name"}, true},
	} {
		if got := len(missingClaimPaths(claims, [][]any{tc.path})) == 0; got != tc.want {
			t.Errorf("%v: %t, want %t", tc.path, got, tc.want)
		}
	}
}
