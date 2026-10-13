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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const shopRelyingPartyYAML = `identifier:
  - identifier: NLTEST.00000042
tradeName: Example Shop
legalPerson:
  legalName: ["Example Shop B.V."]
services:
  - serviceIdentifier: checkout
    intendedUses:
      - intendedUseIdentifier: age-check
        purpose:
          - lang: en
            content: Check that you are of age
        credentials:
          - format: dc+sd-jwt
            meta:
              vct_values: [urn:eudi:pid:1]
            claims:
              - path: [birthdate]
`

const libraryRelyingPartiesJSON = `[{
  "identifier": [{"identifier": "NLTEST.00000043"}],
  "tradeName": "Example Library",
  "legalPerson": {"legalName": ["Example Library"]},
  "services": [{"serviceIdentifier": "lending", "intendedUses": [{
    "intendedUseIdentifier": "membership",
    "purpose": [{"lang": "en", "content": "Check your membership"}],
    "credentials": [{"format": "mso_mdoc", "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"}, "claims": [{"path": ["eu.europa.ec.eudi.pid.1", "family_name"]}]}]
  }]}]
}]`

func loadRelyingParties(t *testing.T, path string) *RelyingPartiesFile {
	t.Helper()
	file, err := LoadRelyingPartiesFile(path)
	if err != nil {
		t.Fatalf("LoadRelyingPartiesFile: %v", err)
	}
	return file
}

func TestLoadRelyingPartiesFileReadsFilesDirectoriesAndLists(t *testing.T) {
	dir := t.TempDir()
	writeCatalogFile(t, dir, "a-shop.yaml", shopRelyingPartyYAML)
	writeCatalogFile(t, dir, "b-library.json", libraryRelyingPartiesJSON)
	writeCatalogFile(t, dir, "notes.txt", "not a registration")

	file := loadRelyingParties(t, dir)
	if got := strings.Join(file.Identifiers(), ","); got != "NLTEST.00000042,NLTEST.00000043" {
		t.Errorf("identifiers = %s", got)
	}
}

// Every start registers the file again, so it holds the identifiers the
// registrar would otherwise generate.
func TestLoadRelyingPartiesFileNeedsStableIdentifiers(t *testing.T) {
	cases := map[string]struct{ content, want string }{
		"identifier":    {strings.Replace(shopRelyingPartyYAML, "  - identifier: NLTEST.00000042", "  - identifier: \" \"", 1), "needs an identifier"},
		"intended use":  {strings.Replace(shopRelyingPartyYAML, "intendedUseIdentifier: age-check", "intendedUseIdentifier: \"\"", 1), "needs an intendedUseIdentifier"},
		"unknown field": {shopRelyingPartyYAML + "tradeNmae: typo\n", "unknown field"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeCatalogFile(t, t.TempDir(), "rp.yaml", c.content)
			if _, err := LoadRelyingPartiesFile(path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}

	dir := t.TempDir()
	writeCatalogFile(t, dir, "a.yaml", shopRelyingPartyYAML)
	writeCatalogFile(t, dir, "b.yaml", shopRelyingPartyYAML)
	if _, err := LoadRelyingPartiesFile(dir); err == nil || !strings.Contains(err.Error(), "appears in "+filepath.Join(dir, "a.yaml")) {
		t.Errorf("duplicate: err = %v", err)
	}
}

// Applying the file again keeps the registration and its certificates. A
// change made through the API is replaced by the file.
func TestApplyRelyingPartiesFileRegistersOnEveryStart(t *testing.T) {
	srv := newTestServer(t, true)
	file := loadRelyingParties(t, writeCatalogFile(t, t.TempDir(), "shop.yaml", shopRelyingPartyYAML))

	if changed, err := srv.wallet.ApplyRelyingPartiesFile(file); err != nil || !changed {
		t.Fatalf("first apply: changed %v, err %v", changed, err)
	}
	if changed, err := srv.wallet.ApplyRelyingPartiesFile(file); err != nil || changed {
		t.Fatalf("second apply: changed %v, err %v", changed, err)
	}
	padded := loadRelyingParties(t, writeCatalogFile(t, t.TempDir(), "shop.yaml", strings.Replace(shopRelyingPartyYAML, "identifier: NLTEST.00000042", "identifier: \" NLTEST.00000042 \"", 1)))
	if changed, err := srv.wallet.ApplyRelyingPartiesFile(padded); err != nil || changed {
		t.Fatalf("apply with a padded identifier: changed %v, err %v", changed, err)
	}

	stored, _ := srv.wallet.Registrar().RelyingParty("NLTEST.00000042")
	stored.TradeName = "Renamed Shop"
	if w := serverRequest(t, srv, "PUT", "/api/registrar/wrp", mustJSON(t, stored)); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body.String())
	}
	if changed, err := srv.wallet.ApplyRelyingPartiesFile(file); err != nil || !changed {
		t.Fatalf("apply after the change: changed %v, err %v", changed, err)
	}
	if rp, _ := srv.wallet.Registrar().RelyingParty("NLTEST.00000042"); rp.TradeName != "Example Shop" {
		t.Errorf("trade name = %q, want the file's", rp.TradeName)
	}
}

// On a public demo visitors can't change the operator's registrations, and a
// demo reset registers them again.
func TestDemoProtectsTheOperatorsRelyingParties(t *testing.T) {
	srv := newTestServer(t, true)
	file := loadRelyingParties(t, writeCatalogFile(t, t.TempDir(), "shop.yaml", shopRelyingPartyYAML))
	baseline := func() error {
		_, err := srv.wallet.ApplyRelyingPartiesFile(file)
		return err
	}
	if err := srv.SetDemo(DemoOptions{ResetInterval: time.Hour, Baseline: baseline}); err != nil {
		t.Fatal(err)
	}
	srv.SetOperatorRelyingParties(file.Identifiers())
	if err := baseline(); err != nil {
		t.Fatal(err)
	}

	if w := serverRequest(t, srv, "DELETE", "/api/registrar/wrp/NLTEST.00000042", ""); w.Code != http.StatusForbidden {
		t.Errorf("DELETE = %d %s, want 403", w.Code, w.Body.String())
	}
	if err := srv.demoReset(); err != nil {
		t.Fatalf("demoReset: %v", err)
	}
	if _, ok := srv.wallet.Registrar().RelyingParty("NLTEST.00000042"); !ok {
		t.Error("after reset the registration is missing")
	}
}
