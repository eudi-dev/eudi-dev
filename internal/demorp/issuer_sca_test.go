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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/typemetadata"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// walletWithPaymentAccount serves the demo stack over TLS. A strict wallet
// with --arf accepts the payment account. The registration certificate of
// the demo issuer lists the issued vct (ARF RPRC_23), so the wallet accepts
// the offer.
func walletWithPaymentAccount(t *testing.T) (*wallet.Wallet, *httptest.Server) {
	t.Helper()
	w := newIssuanceWallet(t)
	insecure := false
	w.TLSVerify = &insecure
	w.RequireARF = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStackOn(t, w, httptest.NewTLSServer)
	created := tlsPost(t, ts, ts.URL+"/issuer/api/offers?credential="+paymentAccountConfigurationID, "")
	schemeURI, _ := created["scheme_uri"].(string)
	if result := tlsPost(t, ts, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`); result["error"] != nil {
		t.Fatalf("accepting the offer failed: %v", result["error"])
	}
	return w, ts
}

func tlsPost(t *testing.T, ts *httptest.Server, target, body string) map[string]any {
	t.Helper()
	res, err := ts.Client().Post(target, "application/json", strings.NewReader(body))
	return decodeTLSAnswer(t, target, res, err)
}

func tlsGet(t *testing.T, ts *httptest.Server, target string) map[string]any {
	t.Helper()
	res, err := ts.Client().Get(target)
	return decodeTLSAnswer(t, target, res, err)
}

func decodeTLSAnswer(t *testing.T, target string, res *http.Response, err error) map[string]any {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	defer res.Body.Close()
	doc := map[string]any{}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("%s: decoding response: %v", target, err)
	}
	return doc
}

// EUDI TS12 v1.0.1 §3 and §4.1: the payment account is an SCA Attestation
// whose Type Metadata lists the four TS12 types, and the credential pins the
// document with vct#integrity (§4.1.2).
func TestThePaymentAccountIsAnSCAAttestation(t *testing.T) {
	w, ts := walletWithPaymentAccount(t)
	vct := ts.URL + "/issuer" + paymentAccountTypePath
	i := slices.IndexFunc(w.GetCredentials(), func(c wallet.StoredCredential) bool { return c.VCT == vct })
	if i < 0 {
		t.Fatalf("the wallet holds no credential of %s", vct)
	}
	cred := w.GetCredentials()[i]
	if !cred.TypeMetadata.IsSCA() {
		t.Fatalf("Type Metadata = %+v, want the SCA category", cred.TypeMetadata)
	}
	for _, typ := range oid4vp.TS12TransactionDataTypes {
		entry, ok := cred.TypeMetadata.TransactionDataTypes[typ]
		if !ok || string(entry.Schema) != `"`+typ+`"` || len(entry.UILabels["affirmative_action_label"]) == 0 {
			t.Errorf("transaction_data_types[%s] = %+v, want its schema URN and an affirmative label", typ, entry)
		}
	}

	res, err := ts.Client().Get(vct)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	document, _ := io.ReadAll(res.Body)
	token, err := sdjwt.Parse(cred.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := token.Payload["vct#integrity"]; got != typemetadata.Integrity(document) {
		t.Errorf("vct#integrity = %v, want the integrity of the served document", got)
	}
}

// EUDI TS12 v1.0.1 §3.3.2: the Type Metadata describes each payload claim of a
// type, so a wallet can label every member of the transaction.
func TestThePaymentAccountTypeMetadataLabelsEveryPayloadClaim(t *testing.T) {
	data, err := staticFiles.ReadFile("static/payment-account-type.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc typemetadata.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, typ := range oid4vp.TS12TransactionDataTypes {
		labelled := map[string]bool{}
		for _, claim := range doc.TransactionDataTypes[typ].Claims {
			if len(claim.Display) > 0 {
				labelled[claimPathKey(claim.Path)] = true
			}
		}
		for _, leaf := range schemaLeaves(t, ts12SchemaFile(typ)) {
			if !labelled[leaf] {
				t.Errorf("%s: no claim with a display for %s", typ, leaf)
			}
		}
	}
}

func ts12SchemaFile(typ string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(typ, "urn:eudi:sca:"), ":1")
	return "ts12-urn-eudi-sca-" + name + "-1-data-model.json"
}

func claimPathKey(path []any) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ".")
}

// schemaLeaves lists the payload paths of the scalar members of a bundled
// TS12 schema, following $ref into the other bundled schemas.
func schemaLeaves(t *testing.T, file string) []string {
	t.Helper()
	load := func(name string) map[string]any {
		data, err := os.ReadFile(filepath.Join("..", "oid4vp", "ts12schema", filepath.Base(name)))
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		return schema
	}
	var leaves []string
	var walk func(node, root map[string]any, path string)
	walk = func(node, root map[string]any, path string) {
		for ref, ok := node["$ref"].(string); ok; ref, ok = node["$ref"].(string) {
			name, fragment, _ := strings.Cut(ref, "#")
			if name != "" {
				root = load(name)
			}
			node = root
			for _, part := range strings.FieldsFunc(fragment, func(r rune) bool { return r == '/' }) {
				node, _ = node[part].(map[string]any)
			}
		}
		combined := false
		for _, keyword := range []string{"allOf", "oneOf", "anyOf"} {
			subs, _ := node[keyword].([]any)
			for _, sub := range subs {
				combined = true
				if m, ok := sub.(map[string]any); ok {
					walk(m, root, path)
				}
			}
		}
		if properties, ok := node["properties"].(map[string]any); ok {
			for name, sub := range properties {
				if m, ok := sub.(map[string]any); ok {
					walk(m, root, path+"."+name)
				}
			}
			return
		}
		if !combined && path != "payload" {
			leaves = append(leaves, path)
		}
	}
	schema := load(file)
	walk(schema, schema, "payload")
	slices.Sort(leaves)
	return slices.Compact(leaves)
}

// SD-JWT VC §5.3.1 retrieves Type Metadata only for an HTTPS vct. A demo
// issuer on a plain HTTP base URL takes the wallet's HTTPS issuer URL.
func TestThePaymentAccountVCTIsHTTPSBehindAnHTTPBaseURL(t *testing.T) {
	w := newIssuanceWallet(t)
	w.IssuerURL = "https://localhost:8086/"
	d := New(w, func() string { return "http://localhost:8085" })
	if got, want := d.paymentAccountVCT(), "https://localhost:8086/issuer"+paymentAccountTypePath; got != want {
		t.Errorf("vct = %s, want %s", got, want)
	}
}

// A request for the demo payment account carries a TS12 payment for its
// query (OpenID4VP 1.0 §5.1). The wallet binds it to the SCA Attestation,
// and the verifier checks the hash.
func TestAPaymentRequestBindsToThePaymentAccount(t *testing.T) {
	w, ts := walletWithPaymentAccount(t)
	acceptTransactionData(t, w)
	created := tlsPost(t, ts, ts.URL+"/verifier/api/requests", `{"type":"payment","transaction_data":[{"type":"urn:eudi:sca:payment:1","credential_ids":["payment"],"transaction_data_hashes_alg":["sha-256"],`+
		`"payload":{"transaction_id":"T-1","payee":{"name":"Shop","id":"DE89370400440532013000"},"currency":"EUR","amount":12.5}}]}`)
	walletURL, _ := created["wallet_url"].(string)
	if walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}
	driveWallet(t, ts, walletURL)
	status := tlsGet(t, ts, ts.URL+"/verifier/api/requests/"+created["transaction_id"].(string))
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	if names := strings.Join(checkNames(status), "\n"); !strings.Contains(names, "transaction_data_hashes match the request") {
		t.Errorf("checks %s, want the hash check", names)
	}
	for _, entry := range w.GetLog() {
		if entry.Details["event"] == "transaction_data_sca" {
			t.Errorf("TS12 §3.2 finding: %s", entry.Detail)
		}
	}
}
