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
	"net/http"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

// The issuer metadata lists every credential template beside the ticket,
// named after the template, with the type the template carries.
func TestIssuerMetadataListsTheTemplates(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	if code != http.StatusOK {
		t.Fatalf("metadata: %d %v", code, doc)
	}
	configs, _ := doc["credential_configurations_supported"].(map[string]any)
	for id, want := range map[string]map[string]string{
		ticketConfigurationID: {"format": "dc+sd-jwt", "vct": TicketVCT},
		"pid-sdjwt":           {"format": "dc+sd-jwt", "vct": mock.DefaultPIDVCT},
		"german-pid-sdjwt":    {"format": "dc+sd-jwt", "vct": mock.GermanPIDVCT},
		"pid-mdoc":            {"format": "mso_mdoc", "doctype": mock.PIDNamespace},
		"german-pid-mdoc":     {"format": "mso_mdoc", "doctype": mock.PIDNamespace},
	} {
		entry, _ := configs[id].(map[string]any)
		if entry == nil {
			t.Errorf("configuration %s is missing", id)
			continue
		}
		for key, value := range want {
			if entry[key] != value {
				t.Errorf("configuration %s %s = %v, want %s", id, key, entry[key], value)
			}
		}
	}
}

// The eudi-dev wallet redeems a German PID offer into a German PID in each
// format, signed by the wallet's PID signer. Each format gets its own offer
// because the wallet redeems only the first configuration in an offer.
func TestOfferOfTemplatesIssuesThem(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential=german-pid-sdjwt&credential=german-pid-mdoc", "")
	offerURI, _ := created["offer_uri"].(string)
	if offerURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}
	offer := getJSONFrom(t, offerURI)
	ids, _ := offer["credential_configuration_ids"].([]any)
	if len(ids) != 2 || ids[0] != "german-pid-sdjwt" || ids[1] != "german-pid-mdoc" {
		t.Fatalf("offer names %v, want the two German PID configurations", ids)
	}

	known := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		known[c.ID] = true
	}
	for _, id := range []string{"german-pid-sdjwt", "german-pid-mdoc"} {
		created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential="+id, "")
		schemeURI, _ := created["scheme_uri"].(string)
		result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
		if result["error"] != nil {
			t.Fatalf("accepting the %s offer failed: %v", id, result["error"])
		}
	}
	var sdjwt, mdoc int
	for _, c := range w.GetCredentials() {
		switch {
		case c.Format == "dc+sd-jwt" && c.VCT == mock.GermanPIDVCT:
			sdjwt++
		case c.Format == "mso_mdoc" && c.DocType == mock.PIDNamespace && !known[c.ID]:
			mdoc++
		}
	}
	if sdjwt == 0 || mdoc == 0 {
		t.Errorf("wallet holds %d German PID SD-JWT and %d demo-issued PID mdoc credentials, want one of each", sdjwt, mdoc)
	}
}

// An offer for a configuration the issuer does not have is refused, and a
// credential request for a configuration the offer did not name is refused.
func TestOfferRefusesUnknownConfigurations(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?credential=no-such-template", "", nil)
	if code != http.StatusBadRequest {
		t.Errorf("offer for an unknown configuration: %d %v, want 400", code, doc)
	}
	if status, errResp := d.checkRequestedCredential(credentialRequest{CredentialConfigurationID: "german-pid-sdjwt"}, []string{ticketConfigurationID}); status != http.StatusBadRequest || errResp["error"] != "unknown_credential_configuration" {
		t.Errorf("credential request outside the offer: %d %v", status, errResp)
	}
}
