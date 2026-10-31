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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

func displayed(format, typ, name string) map[string]any {
	configuration := map[string]any{"format": format, "credential_metadata": map[string]any{"display": []any{map[string]any{"name": name}}}}
	if format == credtype.FormatMDOC {
		configuration["doctype"] = typ
	} else {
		configuration["vct"] = typ
	}
	return configuration
}

// National PIDs share one doctype. An entry gets its own mdoc configuration and
// one configuration per format (ARF ISSU_12a).
func TestAnEntryMatchesOneConfigurationPerFormat(t *testing.T) {
	configurations := map[string]any{
		"dutch-sdjwt":  displayed(credtype.FormatSDJWT, "urn:dutch", "Dutch PID"),
		"dutch-mdoc":   displayed(credtype.FormatMDOC, "eu.pid", "Dutch PID"),
		"german-mdoc":  displayed(credtype.FormatMDOC, "eu.pid", "German PID"),
		"german-sdjwt": displayed(credtype.FormatSDJWT, "urn:german", "German PID"),
	}
	entry := registrar.CatalogAttestation{Name: "Dutch PID", Credentials: []registrar.CatalogCredential{
		{Format: credtype.FormatSDJWT, Type: "urn:dutch"}, {Format: credtype.FormatMDOC, Type: "eu.pid"},
	}}
	got := matchingConfigurations(configurations, entry)
	if !slices.Equal(got, []string{"dutch-mdoc", "dutch-sdjwt"}) {
		t.Errorf("configurations = %v", got)
	}
	if formats := configurationFormats(configurations, got); !slices.Equal(formats, []string{credtype.FormatMDOC, credtype.FormatSDJWT}) {
		t.Errorf("formats = %v", formats)
	}
}

// The request has no issuer_state, because no issuer started it.
func TestAWalletInitiatedOfferHasNoIssuerState(t *testing.T) {
	uri, err := walletInitiatedOffer("https://issuer.example", []string{"pid"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	var offer map[string]any
	if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offer); err != nil {
		t.Fatal(err)
	}
	if offer["credential_issuer"] != "https://issuer.example" || strings.Contains(uri, "issuer_state") {
		t.Errorf("offer = %v", offer)
	}
}

func TestTheDemoRequestsCredentialsFromKnownIssuersOnly(t *testing.T) {
	srv := newDemoTestServer(t)
	w := serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"https://elsewhere.example","credential_configuration_ids":["pid"]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST = %d: %s", w.Code, w.Body)
	}
}

// A query without a credential names the catalogue entry that answers it. A
// query with a credential or an unknown type names none.
func TestAQueryWithoutACredentialNamesItsCatalogueEntry(t *testing.T) {
	srv := newTestServer(t, true)
	entries := srv.wallet.Registrar().CatalogAttestations()
	if len(entries) == 0 || len(entries[0].Credentials) == 0 {
		t.Fatal("the test wallet has no catalogue")
	}
	entry, credential := entries[0], entries[0].Credentials[0]
	meta := map[string]any{"vct_values": []any{credential.Type}}
	if credential.Format == credtype.FormatMDOC {
		meta = map[string]any{"doctype_value": credential.Type}
	}
	query := map[string]any{"credentials": []any{
		map[string]any{"id": "known", "format": credential.Format, "meta": meta},
		map[string]any{"id": "unknown", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:unknown"}}},
		map[string]any{"id": "held", "format": credential.Format, "meta": meta},
	}}
	options := &consent.CredentialOptions{Queries: []consent.QueryOptions{
		{ID: "known"}, {ID: "unknown"}, {ID: "held", Candidates: []consent.Match{{CredentialID: "a"}}},
	}}
	srv.wallet.flagObtainableCredentials(query, options)
	if got := options.Queries[0].Obtainable; !slices.Contains(got, consent.Obtainable{ID: entry.Schema.ID, Name: entry.Name}) {
		t.Errorf("known query: %+v, want %q", got, entry.Name)
	}
	if options.Queries[1].Obtainable != nil || options.Queries[2].Obtainable != nil {
		t.Errorf("queries = %+v, want no entry for the unknown type and the held credential", options.Queries)
	}
}

// OpenID4VCI 1.0 §5.1.2: scope carries several credentials. One configuration
// without a scope moves all of them to authorization_details (§5.1.1).
func TestOneAuthorizationCoversEveryConfiguration(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"credential_configurations_supported": map[string]any{
		"sdjwt": map[string]any{"scope": "pid"},
		"mdoc":  map[string]any{"scope": "pid"},
		"other": map[string]any{"scope": "ticket"},
		"plain": map[string]any{},
	}}
	scoped, err := w.authorizationCredentialRequest(metadata, []string{"sdjwt", "mdoc", "other"})
	if err != nil || scoped.Get("scope") != "pid ticket" {
		t.Errorf("scope = %q (%v), want each scope once", scoped.Get("scope"), err)
	}
	mixed, err := w.authorizationCredentialRequest(metadata, []string{"sdjwt", "plain"})
	if err != nil {
		t.Fatal(err)
	}
	var details []map[string]any
	if err := json.Unmarshal([]byte(mixed.Get("authorization_details")), &details); err != nil {
		t.Fatal(err)
	}
	if mixed.Get("scope") != "" || len(details) != 2 || details[1]["credential_configuration_id"] != "plain" {
		t.Errorf("request = %v", mixed)
	}
}

// A credential that arrives while the dialog is open answers its query. A dialog
// with an answer for every query keeps what the user selected.
func TestAnIssuedCredentialReachesTheWaitingDialog(t *testing.T) {
	w := generateTestWalletWithPID(t)
	cred := w.GetCredentials()[0]
	meta := map[string]any{"vct_values": []any{cred.VCT}}
	format := cred.Format
	if format == credtype.FormatMDOC {
		meta = map[string]any{"doctype_value": cred.DocType}
	}
	query := map[string]any{"credentials": []any{map[string]any{"id": "wanted", "format": format, "meta": meta}}}

	waiting := consent.NewRequest(consent.TypePresentation, "")
	waiting.DCQLQuery = query
	waiting.CredentialOptions = &consent.CredentialOptions{Queries: []consent.QueryOptions{{ID: "wanted"}}}
	answered := consent.NewRequest(consent.TypePresentation, "")
	answered.DCQLQuery = query
	keep := &consent.CredentialOptions{Queries: []consent.QueryOptions{{ID: "wanted", Candidates: []consent.Match{{CredentialID: "kept"}}}}}
	answered.CredentialOptions = keep
	for _, req := range []*consent.Request{waiting, answered} {
		if err := w.Consents().Create(req); err != nil {
			t.Fatal(err)
		}
	}
	announced, unsubscribe := w.Consents().Subscribe()
	defer unsubscribe()

	w.refreshWaitingPresentations()

	if len(waiting.MatchedCreds) == 0 || len(waiting.CredentialOptions.Queries[0].Candidates) == 0 {
		t.Errorf("waiting dialog: %+v", waiting.CredentialOptions)
	}
	if answered.CredentialOptions != keep {
		t.Errorf("answered dialog changed: %+v", answered.CredentialOptions)
	}
	select {
	case req := <-announced:
		if req.ID != waiting.ID || !req.Updated {
			t.Errorf("announced %s, want the waiting dialog", req.ID)
		}
	default:
		t.Error("the update was not announced")
	}
}

func TestARequestListsEachConfigurationOnce(t *testing.T) {
	srv := newTestServer(t, true)
	w := serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"https://issuer.example","credential_configuration_ids":["pid","pid"]}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "twice") {
		t.Errorf("POST = %d: %s", w.Code, w.Body)
	}
}

// A token that leaves out a configuration has no credential for it. The
// identifier of another configuration stays with that configuration.
func TestATokenWithoutTheConfigurationIssuesNothingForIt(t *testing.T) {
	w := generateTestWallet(t)
	grant := &accessGrant{response: map[string]any{"authorization_details": []any{
		map[string]any{"credential_configuration_id": "sdjwt", "credential_identifiers": []any{"id-1"}},
	}}}
	_, err := w.issueAdditionalConfiguration(issuanceSession{renewal: CredentialRenewal{ConfigurationID: "mdoc"}}, grant)
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("err = %v", err)
	}
}

func TestARotatedRefreshTokenReachesEveryFormat(t *testing.T) {
	w := generateTestWallet(t)
	w.Credentials = []StoredCredential{
		{ID: "sdjwt", Renewal: &CredentialRenewal{RefreshToken: "old"}},
		{ID: "mdoc", Renewal: &CredentialRenewal{RefreshToken: "old"}},
		{ID: "other", Renewal: &CredentialRenewal{RefreshToken: "unrelated"}},
	}
	w.DeferredIssuances = []DeferredIssuance{{CredentialRenewal: CredentialRenewal{RefreshToken: "old"}}}
	w.replaceRefreshToken("old", "new")
	if w.Credentials[0].Renewal.RefreshToken != "new" || w.Credentials[1].Renewal.RefreshToken != "new" || w.DeferredIssuances[0].RefreshToken != "new" {
		t.Errorf("credentials %+v, deferred %+v", w.Credentials, w.DeferredIssuances)
	}
	if w.Credentials[2].Renewal.RefreshToken != "unrelated" {
		t.Errorf("another authorization's token changed: %+v", w.Credentials[2].Renewal)
	}
}

// One format that fails or waits leaves the others in the wallet, and the result
// tells each outcome.
func TestEachFormatReportsItsOwnOutcome(t *testing.T) {
	w := generateTestWallet(t)
	issuer, offerURI := setupMockIssuer(t, w, mockIssuerOpts{additionalResponses: map[string]map[string]any{
		"later":   {"transaction_id": "tx-1", "interval": 3600},
		"refused": {"error": "invalid_credential_request"},
	}})
	defer issuer.Close()
	before := len(w.GetCredentials())

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{ConfigurationID: "test-config", AdditionalConfigurations: []string{"later", "refused"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialID == "" || len(result.Additional) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if later := result.Additional[0]; !later.Pending || later.TransactionID != "tx-1" {
		t.Errorf("deferred format = %+v", later)
	}
	if refused := result.Additional[1]; refused.Error == "" || refused.CredentialID != "" {
		t.Errorf("refused format = %+v", refused)
	}
	if got := len(w.GetCredentials()) - before; got != 1 {
		t.Errorf("%d credentials stored, want the one that arrived", got)
	}
}

// A request the user started does not consent to what the issuer asks for
// afterwards.
func TestAnIssuerRequestedPresentationAsksTheUser(t *testing.T) {
	srv := newTestServer(t, false)
	wallet := srv.wallet
	wallet.AutoAccept = false
	wallet.VCIVersion = VCIVersion11
	wallet.VCIClientID = "wallet-client"
	issuer := newInteractiveIssuer(t, wallet)

	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		finished <- serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"`+issuer.url+`","credential_configuration_ids":["test-config"]}`)
	}()
	var prompt *consent.Request
	for deadline := time.Now().Add(5 * time.Second); prompt == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, req := range wallet.Consents().Pending() {
			prompt = req
		}
	}
	if prompt == nil {
		t.Fatal("the wallet did not ask the user")
	}
	if issuer.intermediateForm != nil {
		t.Error("the wallet presented before the user answered")
	}
	serverRequest(t, srv, http.MethodPost, "/api/requests/"+prompt.ID+"/deny", "")
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the flow kept waiting after the denial")
	}
	if strings.Contains(issuer.intermediateForm.Get("openid4vp_response"), "vp_token") {
		t.Error("the wallet presented after a denial")
	}
}

func TestACatalogueEntryNamesAnIssuer(t *testing.T) {
	w := generateTestWallet(t)
	entry := registrar.CatalogAttestation{Name: "Diploma", CredentialIssuer: "https://issuer.example/",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}
	if _, err := w.Registrar().AddCatalogAttestation(entry); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(w.knownIssuers(), KnownIssuer{Name: "issuer.example", URL: "https://issuer.example"}) {
		t.Errorf("known issuers = %+v", w.knownIssuers())
	}
	entry.Name, entry.CredentialIssuer = "Other", "ftp://issuer.example"
	entry.Credentials[0].Type = "urn:example:other:1"
	if _, err := w.Registrar().AddCatalogAttestation(entry); err == nil {
		t.Error("the catalogue took an issuer that is not a web URL")
	}
}

// An empty wallet has no other credential to offer, so only the catalogue decides
// whether the dialog opens.
func TestAnEmptyWalletOffersWhatTheCatalogueHas(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}); err != nil {
		t.Fatal(err)
	}
	query := func(vct string) map[string]any {
		return map[string]any{"credentials": []any{map[string]any{"id": "q", "format": credtype.FormatSDJWT, "meta": map[string]any{"vct_values": []any{vct}}}}}
	}
	options := w.obtainableOptions(query("urn:example:diploma:1"))
	if options == nil || len(options.Queries) != 1 || options.Queries[0].Candidates == nil || len(options.Queries[0].Obtainable) != 1 {
		t.Fatalf("options = %+v", options)
	}
	if got := w.obtainableOptions(query("urn:example:unknown:1")); got != nil {
		t.Errorf("options = %+v for a type outside the catalogue", got)
	}
}

// Visitors of a public demo share the registrar, so an issuer one of them names
// reaches nobody else.
func TestAPublicDemoKnowsTheOperatorsIssuersOnly(t *testing.T) {
	srv := newTestServer(t, false)
	if err := srv.SetDemo(DemoOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.wallet.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Visitor's", CredentialIssuer: "https://visitor.example",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:visitor:1"}}}); err != nil {
		t.Fatal(err)
	}
	if got := srv.wallet.knownIssuers(); len(got) != 0 {
		t.Errorf("known issuers = %+v", got)
	}
}
