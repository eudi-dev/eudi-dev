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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// catalog add --issuer-ca adds the entry and its CA together. When the CA
// can't go on the list, the entry is taken out again.
func TestCatalogAddRemovesTheEntryWhenTheIssuerCAFails(t *testing.T) {
	resetRemoteTestState(t)
	var mu sync.Mutex
	var deleted []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/catalog/attestations":
			fmt.Fprint(w, `{"name":"Diploma","category":"eaa","schema":{"id":"s1"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/trust/entities":
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"storage unavailable"}`)
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resetFlags(rootCmd) })

	rootCmd.SetArgs([]string{"catalog", "add", "--name", "Diploma", "--type", "dc+sd-jwt:urn:example:diploma:1", "--issuer-ca", ca, "--remote", ts.URL})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "storage unavailable") {
		t.Fatalf("catalog add: %v, want the CA failure", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(deleted, []string{"/api/catalog/schemas/s1"}) {
		t.Fatalf("deleted %v, want the added entry", deleted)
	}
}

func TestTheCatalogCommandAddsAndDeletes(t *testing.T) {
	resetRemoteTestState(t)
	added := runJSON(t, "catalog", "add", "--name", "University diploma",
		"--type", "dc+sd-jwt:urn:example:diploma:1", "--type", "mso_mdoc:org.example.diploma.1",
		"--claim", "dc+sd-jwt:address.locality", "--claim", "mso_mdoc:degree", "--claim", "mso_mdoc:org.example.other:grade",
		"--los", "moderate")
	schema := added["schema"].(map[string]any)
	if schema["attestationLoS"] != "iso_18045_moderate" || len(schema["schemaURIs"].([]any)) != 2 {
		t.Fatalf("added %v", added)
	}
	credentials := added["credentials"].([]any)
	sdjwt := credentials[0].(map[string]any)["claims"]
	mdoc := credentials[1].(map[string]any)["claims"]
	if !reflect.DeepEqual(sdjwt, []any{[]any{"address", "locality"}}) ||
		!reflect.DeepEqual(mdoc, []any{[]any{"org.example.diploma.1", "degree"}, []any{"org.example.other", "grade"}}) {
		t.Fatalf("claims %v and %v", sdjwt, mdoc)
	}

	id := schema["id"].(string)
	if deleted := runJSON(t, "catalog", "rm", id); deleted["removed"] != id {
		t.Fatalf("delete: %v", deleted)
	}
}

// A claim takes the same syntax as in the web UI: dots nest, [*] selects every
// element and [n] one element.
func TestCatalogueClaimsParseLikeTheWebUI(t *testing.T) {
	for _, tc := range []struct {
		format, claim string
		want          []any
	}{
		{"dc+sd-jwt", "address.locality", []any{"address", "locality"}},
		{"dc+sd-jwt", "nationalities[*]", []any{"nationalities", nil}},
		{"mso_mdoc", "degree", []any{"org.example.diploma.1", "degree"}},
		{"mso_mdoc", "org.example.ns:degree", []any{"org.example.ns", "degree"}},
	} {
		if got := catalogClaimPath(tc.format, "org.example.diploma.1", tc.claim); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %q: %v, want %v", tc.format, tc.claim, got, tc.want)
		}
	}
}
