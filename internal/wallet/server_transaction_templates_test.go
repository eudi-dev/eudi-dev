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
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
)

func TestTransactionTemplatesCRUD(t *testing.T) {
	srv := newTestServer(t, true)

	var names []string
	for _, item := range decodeJSONArray(t, serverRequest(t, srv, http.MethodGet, "/api/transaction-templates", "")) {
		tpl := item.(map[string]any)
		names = append(names, tpl["name"].(string))
		if tpl["predefined"] != true || tpl["warnings"] != nil {
			t.Errorf("predefined template %v", tpl)
		}
	}
	if !slices.Equal(names, []string{"account-access", "emandate", "login", "payment"}) {
		t.Errorf("predefined transaction templates = %v", names)
	}

	body := `{"description":"A refund","transaction_data":{"type":"urn:example:refund","amount":3}}`
	resp := serverRequest(t, srv, http.MethodPut, "/api/transaction-templates/refund", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", resp.Code, resp.Body.String())
	}
	if saved := decodeJSON(t, resp); saved["name"] != "refund" || saved["predefined"] != nil {
		t.Errorf("saved %v", saved)
	}
	if resp := serverRequest(t, srv, http.MethodGet, "/api/transaction-templates/refund", ""); resp.Code != http.StatusOK {
		t.Errorf("GET = %d", resp.Code)
	}
	if resp := serverRequest(t, srv, http.MethodDelete, "/api/transaction-templates/refund", ""); resp.Code != http.StatusOK {
		t.Errorf("DELETE = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := serverRequest(t, srv, http.MethodGet, "/api/transaction-templates/refund", ""); resp.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE = %d, want 404", resp.Code)
	}
	if resp := serverRequest(t, srv, http.MethodDelete, "/api/transaction-templates/payment", ""); resp.Code != http.StatusBadRequest {
		t.Errorf("deleting a predefined template = %d, want 400", resp.Code)
	}
	if resp := serverRequest(t, srv, http.MethodPut, "/api/transaction-templates/untyped", `{"transaction_data":{}}`); resp.Code != http.StatusBadRequest {
		t.Errorf("PUT without a type = %d, want 400", resp.Code)
	}
}

// A template may break TS12 on purpose. It is saved and carries the findings.
func TestTransactionTemplateWarnsAboutAnInvalidTS12Payload(t *testing.T) {
	srv := newTestServer(t, true)
	body := `{"transaction_data":{"type":"urn:eudi:sca:payment:1","transaction_data_hashes_alg":["sha-256"],"payload":{"transaction_id":"1","currency":"EUR","amount":1}}}`
	resp := serverRequest(t, srv, http.MethodPut, "/api/transaction-templates/no-payee", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", resp.Code, resp.Body.String())
	}
	if warnings, _ := decodeJSON(t, resp)["warnings"].([]any); len(warnings) != 1 {
		t.Errorf("warnings = %v, want the missing payee", warnings)
	}
}

func TestDemoVisitorTransactionTemplates(t *testing.T) {
	srv := newDemoTestServer(t)
	for _, tt := range []struct {
		method, path, body string
		want               int
	}{
		{"PUT", "/api/transaction-templates/mine", `{"transaction_data":{"type":"urn:example:mine"}}`, http.StatusOK},
		{"PUT", "/api/transaction-templates/payment", `{"transaction_data":{"type":"urn:example:mine"}}`, http.StatusForbidden},
		{"DELETE", "/api/transaction-templates/payment", "", http.StatusForbidden},
	} {
		if w := serverRequest(t, srv, tt.method, tt.path, tt.body); w.Code != tt.want {
			t.Errorf("%s %s = %d, want %d: %s", tt.method, tt.path, w.Code, tt.want, w.Body.String())
		}
	}
	if err := srv.demoReset(); err != nil {
		t.Fatal(err)
	}
	if _, err := txtemplate.Load(srv.wallet.TransactionTemplates, "mine"); err == nil {
		t.Error("the reset kept the visitor's transaction template")
	}
}

func TestDemoCapsVisitorTransactionTemplates(t *testing.T) {
	srv := newDemoTestServer(t)
	for i := range maxDemoTxTemplates {
		tpl := txtemplate.Template{Name: fmt.Sprintf("visitor-%d", i), TransactionData: map[string]any{"type": "urn:example:t"}, Visitor: true}
		if err := txtemplate.Save(srv.wallet.TransactionTemplates, tpl); err != nil {
			t.Fatal(err)
		}
	}
	if w := serverRequest(t, srv, "PUT", "/api/transaction-templates/one-more", `{"transaction_data":{"type":"urn:example:t"}}`); w.Code != http.StatusForbidden {
		t.Errorf("template %d = %d, want 403", maxDemoTxTemplates+1, w.Code)
	}
	if w := serverRequest(t, srv, "PUT", "/api/transaction-templates/visitor-0", `{"transaction_data":{"type":"urn:example:u"}}`); w.Code != http.StatusOK {
		t.Errorf("replacing a visitor template at the cap = %d, want 200", w.Code)
	}
}

// The editor offers the TS12 types with their payload members and the
// registered types.
func TestTransactionDataTypesListTS12AndRegisteredTypes(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.ConformanceSettings.TransactionDataTypes = []string{"urn:example:refund", "urn:eudi:sca:payment:1"}
	doc := decodeJSON(t, serverRequest(t, srv, http.MethodGet, "/api/transaction-data-types", ""))
	var types []string
	for _, item := range doc["types"].([]any) {
		types = append(types, item.(map[string]any)["type"].(string))
	}
	want := []string{"urn:eudi:sca:payment:1", "urn:eudi:sca:login_risk_transaction:1", "urn:eudi:sca:account_access:1", "urn:eudi:sca:emandate:1", "urn:example:refund"}
	if !slices.Equal(types, want) {
		t.Fatalf("types = %v, want %v", types, want)
	}
	payment := doc["types"].([]any)[0].(map[string]any)
	first := payment["fields"].([]any)[0].(map[string]any)
	if payment["ts12"] != true || first["name"] != "transaction_id" || first["required"] != true {
		t.Fatalf("payment = %v", payment)
	}
	if fmt.Sprint(doc["hash_algs"]) != "[sha-256 sha-384 sha-512]" {
		t.Fatalf("hash_algs = %v", doc["hash_algs"])
	}
}

func TestAStorageFailureOfATransactionTemplateIsAServerError(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.TransactionTemplates = txtemplate.Location{Store: storage.NewFile(unwritableDir(t))}

	rec := serverRequest(t, srv, http.MethodPut, "/api/transaction-templates/refund", `{"transaction_data":{"type":"urn:example:refund","amount":3}}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "--transaction-templates") {
		t.Errorf("body = %s, want the --transaction-templates hint", rec.Body.String())
	}
}
