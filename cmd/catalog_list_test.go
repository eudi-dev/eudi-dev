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
	"regexp"
	"strings"
	"testing"
)

func catalogRow(out, id string) []string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, id+" ") {
			return regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), -1)
		}
	}
	return nil
}

func TestTheCatalogListsItsEntriesAsATable(t *testing.T) {
	resetRemoteTestState(t)
	added := runJSON(t, "catalog", "add", "--name", "Library card",
		"--type", "dc+sd-jwt:urn:example:library-card:1", "--type", "mso_mdoc:org.example.library_card.1", "--los", "moderate")
	id := added["schema"].(map[string]any)["id"].(string)

	for _, args := range [][]string{{"catalog"}, {"catalog", "list"}} {
		out, err := runCommand(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if header := strings.Fields(strings.SplitN(out, "\n", 2)[0]); strings.Join(header, " ") != "ID NAME CATEGORY TYPES LEVEL OF SECURITY" {
			t.Errorf("%v: header %q", args, header)
		}
		want := []string{id, "Library card", "eaa", "dc+sd-jwt:urn:example:library-card:1 mso_mdoc:org.example.library_card.1", "iso_18045_moderate"}
		if row := catalogRow(out, id); strings.Join(row, "|") != strings.Join(want, "|") {
			t.Errorf("%v: row %q, want %q", args, row, want)
		}
		if !strings.Contains(out, "EUDI PID (template)") {
			t.Errorf("%v: printed %q, want the PID template entry", args, out)
		}
	}
}

func TestTheCatalogMarksPreRegisteredEntries(t *testing.T) {
	resetRemoteTestState(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/catalog/attestations" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"name":"Ticket","category":"eaa","operator":true,"credentials":[{"format":"dc+sd-jwt","type":"urn:example:ticket:1"}],"schema":{"id":"op1","attestationLoS":"iso_18045_basic"}}]`)
	}))
	defer ts.Close()

	out, err := runCommand(t, "catalog", "--remote", ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"op1", "Ticket (pre-registered)", "eaa", "dc+sd-jwt:urn:example:ticket:1", "iso_18045_basic"}
	if row := catalogRow(out, "op1"); strings.Join(row, "|") != strings.Join(want, "|") {
		t.Errorf("row %q, want %q", row, want)
	}
}

func TestTheCatalogReportsAnUnreadableWallet(t *testing.T) {
	resetRemoteTestState(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"storage unavailable"}`)
	}))
	defer ts.Close()

	if _, err := runCommand(t, "catalog", "--remote", ts.URL); err == nil || !strings.Contains(err.Error(), "storage unavailable") {
		t.Errorf("error %v, want the wallet's error", err)
	}
}
