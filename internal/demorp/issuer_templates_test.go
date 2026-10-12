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
	"encoding/base64"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// The issuer metadata lists every credential template beside the ticket,
// named after the template and with the template's type.
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
		"german-pid-sdjwt":    {"format": "dc+sd-jwt", "vct": germanPIDVCT},
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

// readCounter counts the template blobs the issuer reads.
type readCounter struct {
	storage.Store
	reads int
}

func (c *readCounter) Read(key string) ([]byte, error) {
	c.reads++
	return c.Store.Read(key)
}

// A credential request names one configuration, so the issuer reads that
// template and not every stored one.
func TestACredentialRequestReadsOneTemplate(t *testing.T) {
	d, w, _ := newDemoRP(t)
	counter := &readCounter{Store: storage.NewMemory()}
	w.Templates = credtemplate.Location{Store: counter}
	for _, name := range []string{"one", "two", "three"} {
		if _, err := credtemplate.Save(w.Templates, credtemplate.Template{Name: name, Format: "sdjwt", VCT: "urn:test:" + name}); err != nil {
			t.Fatal(err)
		}
	}
	counter.reads = 0
	cfg, ok := d.templateConfiguration("two")
	if !ok || cfg.vct != "urn:test:two" {
		t.Fatalf("configuration %+v, %t", cfg, ok)
	}
	if counter.reads != 1 {
		t.Errorf("the issuer read %d template blobs, want 1", counter.reads)
	}
}

// Every metadata request lists the templates. An unreadable template is
// logged once, not on every request.
func TestAnUnreadableTemplateIsLoggedOnce(t *testing.T) {
	d, w, _ := newDemoRP(t)
	store := storage.NewMemory()
	w.Templates = credtemplate.Location{Store: store}
	if _, err := store.Write("broken.json", []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	d.templateConfigurations()
	d.templateConfigurations()
	if n := strings.Count(out.String(), "WARNING"); n != 1 {
		t.Errorf("logged %d warnings, want 1:\n%s", n, out.String())
	}
}

// A template's logo and card image reach the issuer metadata. The issuer
// serves bundled and uploaded images itself and links an https image directly.
func TestIssuerMetadataCarriesTheTemplateImages(t *testing.T) {
	d, w, _ := newDemoRP(t)
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{
		Name: "uploaded-badge", Format: "sdjwt", VCT: "urn:example:badge", Claims: map[string]any{"name": "x"},
		Display: &credtemplate.TemplateDisplay{
			Logo:            "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg)),
			LogoAltText:     "Badge",
			BackgroundImage: "https://images.example/badge.png",
		},
	}); err != nil {
		t.Fatal(err)
	}
	_, doc := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	configs, _ := doc["credential_configurations_supported"].(map[string]any)
	issuer := d.issuerID()
	for id, want := range map[string][2]string{
		"pid-sdjwt":        {issuer + "/templates/pid-sdjwt/logo", ""},
		"german-pid-sdjwt": {issuer + "/templates/german-pid-sdjwt/logo", issuer + "/templates/german-pid-sdjwt/background_image"},
		"italian-pid-mdoc": {issuer + "/templates/italian-pid-mdoc/logo", issuer + "/templates/italian-pid-mdoc/background_image"},
		"uploaded-badge":   {issuer + "/templates/uploaded-badge/logo", "https://images.example/badge.png"},
	} {
		entry, _ := configs[id].(map[string]any)
		metadata, _ := entry["credential_metadata"].(map[string]any)
		displays, _ := metadata["display"].([]any)
		if len(displays) != 1 {
			t.Fatalf("configuration %s display %v", id, metadata["display"])
		}
		display := displays[0].(map[string]any)
		logo, _ := display["logo"].(map[string]any)
		if logo["uri"] != want[0] || logo["alt_text"] == "" {
			t.Errorf("configuration %s logo %v, want %s", id, logo, want[0])
		}
		background, _ := display["background_image"].(map[string]any)
		if want[1] == "" && background != nil || want[1] != "" && (background == nil || background["uri"] != want[1]) {
			t.Errorf("configuration %s background_image %v, want %q", id, background, want[1])
		}
	}

	for path, wantType := range map[string]string{
		"/templates/uploaded-badge/logo":               "image/svg+xml",
		"/templates/german-pid-sdjwt/logo":             "image/svg+xml",
		"/templates/german-pid-sdjwt/background_image": "image/jpeg",
	} {
		rec := httptest.NewRecorder()
		d.IssuerHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != wantType || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("GET %s = %d %q %q", path, rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Content-Security-Policy"))
		}
	}
	for _, path := range []string{"/templates/uploaded-badge/background_image", "/templates/unknown/logo", "/templates/pid-sdjwt/other"} {
		rec := httptest.NewRecorder()
		d.IssuerHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
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
		case c.Format == "dc+sd-jwt" && c.VCT == germanPIDVCT:
			sdjwt++
		case c.Format == "mso_mdoc" && c.DocType == mock.PIDNamespace && !known[c.ID]:
			mdoc++
		}
	}
	if sdjwt == 0 || mdoc == 0 {
		t.Errorf("wallet holds %d German PID SD-JWT and %d demo-issued PID mdoc credentials, want one of each", sdjwt, mdoc)
	}
	// The wallet fetches the card images from the issuer metadata and keeps them.
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" && c.VCT == germanPIDVCT && !known[c.ID] {
			if c.Display == nil || !strings.HasPrefix(c.Display.LogoURI, "data:image/svg+xml") || !strings.HasPrefix(c.Display.BackgroundURI, "data:image/jpeg") {
				t.Errorf("issued German PID display %+v, want the flag logo and the specimen image", c.Display)
			}
		}
	}
}

// The issuer refuses an offer for an unknown configuration. It also refuses a
// credential request for a configuration outside the offer.
func TestOfferRefusesUnknownConfigurations(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?credential=no-such-template", "", nil)
	if code != http.StatusBadRequest {
		t.Errorf("offer for an unknown configuration: %d %v, want 400", code, doc)
	}
	granted := tokenState{offerSettings: offerSettings{configIDs: []string{ticketConfigurationID}}}
	if _, errResp := requestedConfiguration(credentialRequest{CredentialConfigurationID: "german-pid-sdjwt"}, granted); errResp["error"] != "unknown_credential_configuration" {
		t.Errorf("credential request outside the offer: %v", errResp)
	}
}

// The demo issuer authenticates as the ARF requires: its metadata is signed
// with an access certificate and carries a registration certificate that
// lists the ticket and the PID types (ARF ISSU_24, ISSU_34, RPRC_22a and
// RPRC_23). A strict wallet with --arf therefore accepts its offers.
func TestTheDemoIssuerPassesTheARFChecks(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireARF = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStack(t, w)

	for _, id := range []string{ticketConfigurationID, "german-pid-sdjwt", "pid-mdoc"} {
		created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential="+id, "")
		schemeURI, _ := created["scheme_uri"].(string)
		result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
		if result["error"] != nil {
			t.Fatalf("accepting the %s offer failed: %v", id, result["error"])
		}
	}
	for _, entry := range w.GetLog() {
		if entry.Details["event"] == "arf_finding" {
			t.Errorf("ARF finding: %s", entry.Detail)
		}
	}
}

// With --arf a strict wallet doesn't store a credential that fails the
// trusted list of its catalogue entry (ARF ISSU_10, ISSU_11b).
func TestAStrictWalletRefusesACredentialOutsideItsTrustedList(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireARF = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStack(t, w)

	other := newIssuanceWallet(t)
	group := other.TrustedLists().DefaultGroup()
	list, err := other.TrustedLists().SignedGroupList(other.IssuerURL, group, "/api/trustlists/"+group.ID)
	if err != nil {
		t.Fatal(err)
	}
	foreign := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
	t.Cleanup(foreign.Close)
	// The wallet trusts the other list operator, so the list gives anchors.
	w.TrustSettings.ListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Signer().TrustAnchor().Raw})

	const vct = "urn:example:badge:1"
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{Name: "badge", Format: "sdjwt", VCT: vct, Claims: map[string]any{"level": "gold"}}); err != nil {
		t.Fatal(err)
	}
	isLOTE := true
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
		Name:        "Badge",
		Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: vct}},
		Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: foreign.URL, IsLOTE: &isLOTE}}},
	}); err != nil {
		t.Fatal(err)
	}
	// The demo issuer registers the new type, so only the trusted list fails.
	if _, err := w.EnsureDemoRegistrations(); err != nil {
		t.Fatal(err)
	}

	before := len(w.GetCredentials())
	created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential=badge", "")
	schemeURI, _ := created["scheme_uri"].(string)
	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if msg, _ := result["error_description"].(string); !strings.Contains(msg, "ARF ISSU_10") {
		t.Errorf("result %v, want a refusal citing ISSU_10", result)
	}
	if got := len(w.GetCredentials()); got != before {
		t.Errorf("credentials %d, want %d (nothing stored)", got, before)
	}
}

// The demo issuer offers every template, so its registration certificate
// lists a template saved while the wallet runs and one saved while it was
// stopped (ARF RPRC_23 and ISSU_34b).
func TestTheDemoIssuerPassesTheARFChecksForATemplateAddedLater(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireARF = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStack(t, w)

	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/templates/club-card", strings.NewReader(`{"format":"sdjwt","vct":"urn:example:club-card:1","claims":{"member":"yes"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("saving a template = %d", resp.StatusCode)
	}
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{Name: "gym-card", Format: "sdjwt", VCT: "urn:example:gym-card:1", Claims: map[string]any{"member": "yes"}}); err != nil {
		t.Fatal(err)
	}
	// A restart registers the demo parties again.
	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"club-card", "gym-card"} {
		created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential="+id, "")
		schemeURI, _ := created["scheme_uri"].(string)
		result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
		if result["error"] != nil {
			t.Fatalf("accepting the %s offer failed: %v", id, result["error"])
		}
	}
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "RPRC_23") {
			t.Errorf("ARF finding: %s", entry.Detail)
		}
	}
}
