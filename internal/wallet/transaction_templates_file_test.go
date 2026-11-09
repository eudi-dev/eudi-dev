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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
)

const testTransactionTemplates = `name: refund
description: A refund
transaction_data:
  type: urn:example:refund
  amount: 3
---
- name: top-up
  transaction_data: {type: urn:example:top-up}
`

func TestTransactionTemplateFilesHoldSeveralDocumentsAndRefuseUnknownFields(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "transactions.yaml")
	if err := os.WriteFile(file, []byte(testTransactionTemplates), 0o600); err != nil {
		t.Fatal(err)
	}
	templates, err := LoadTransactionTemplateFiles(file)
	if err != nil || templates.Len() != 2 {
		t.Fatalf("loaded %d templates, err %v, want 2", templates.Len(), err)
	}
	if err := os.WriteFile(file, []byte(testTransactionTemplates+"---\nname: other\npredefined: true\ntransaction_data: {type: urn:example:other}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTransactionTemplateFiles(file); err == nil || !strings.Contains(err.Error(), "YAML document 3") || !strings.Contains(err.Error(), "predefined") {
		t.Fatalf("error = %v, want the document and the unknown field", err)
	}
}

func TestAFileWithOneNamelessTransactionTemplateNamesItAfterTheFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shop-payment.yaml"), []byte("transaction_data: {type: urn:example:pay}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	templates, err := LoadTransactionTemplateFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var configured txtemplate.Configured
	configured.Set(templates)
	if got := configured.Templates(); len(got) != 1 || got[0].Name != "shop-payment" {
		t.Fatalf("templates = %+v, want one named shop-payment", got)
	}
}

func TestTheAPIRefusesToChangeAConfiguredTransactionTemplate(t *testing.T) {
	srv := newTestServer(t, true)
	file := filepath.Join(t.TempDir(), "transactions.yaml")
	if err := os.WriteFile(file, []byte(testTransactionTemplates), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := LoadTransactionTemplateFiles(file)
	if err != nil {
		t.Fatal(err)
	}
	srv.wallet.TransactionTemplates.Configured = &txtemplate.Configured{}
	srv.wallet.TransactionTemplates.Configured.Set(parsed)

	resp := serverRequest(t, srv, http.MethodGet, "/api/transaction-templates/refund", "")
	if resp.Code != http.StatusOK || decodeJSON(t, resp)["configured"] != true {
		t.Fatalf("GET: %d %s, want a configured template", resp.Code, resp.Body.String())
	}
	resp = serverRequest(t, srv, http.MethodPut, "/api/transaction-templates/refund", `{"transaction_data": {"type": "urn:example:refund"}}`)
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "transactions.yaml") {
		t.Fatalf("PUT: %d %s, want 409 naming the file", resp.Code, resp.Body.String())
	}
	resp = serverRequest(t, srv, http.MethodDelete, "/api/transaction-templates/refund", "")
	if resp.Code != http.StatusConflict {
		t.Fatalf("DELETE: %d %s, want 409", resp.Code, resp.Body.String())
	}
}
