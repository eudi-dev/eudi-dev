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

package registrar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// testAPI serves the registrar API of a test wallet through the routes the
// wallet server registers.
type testAPI struct {
	*testWallet
	h       *Server
	mux     *http.ServeMux
	changes int
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	api := &testAPI{testWallet: generateTestWallet(t)}
	api.h = &Server{
		Registrar: func() *Registrar { return api.Registrar },
		Mutate: func(change func() bool) {
			if change() {
				api.changes++
			}
		},
	}
	api.mux = http.NewServeMux()
	for pattern, handler := range api.h.Routes() {
		api.mux.HandleFunc(pattern, handler)
	}
	return api
}

const acceptJSON = "application/json"

// do sends body as it is when it is a string, and as JSON otherwise.
func (a *testAPI) do(method, target string, body any, accept string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		encoded, _ := json.Marshal(b)
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, target, reader)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	a.mux.ServeHTTP(rec, req)
	return rec
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, code, contains string) {
	t.Helper()
	var body apierror.Body
	if rec.Code != status || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Error != code || !strings.Contains(body.Description, contains) {
		t.Errorf("%d %s, want %d %s containing %q", rec.Code, rec.Body, status, code, contains)
	}
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	return v
}

// wrpResponse is the unsigned form of a TS05 v1.5 §3.2 response.
type wrpResponse[T any] struct {
	Data       T      `json:"data"`
	Iss        string `json:"iss"`
	Iat        int64  `json:"iat"`
	Pagination struct {
		HasNextPage bool   `json:"has_next_page"`
		NextCursor  string `json:"next_cursor"`
	} `json:"pagination"`
}

func shopRegistration() WalletRelyingParty {
	return WalletRelyingParty{TradeName: "Example Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}}
}

func TestTheWRPAPIRegistersUpdatesAndDeletes(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodPost, "/api/registrar/wrp", shopRegistration(), "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	stored := decodeBody[WalletRelyingParty](t, rec)
	id := stored.Identifier[0].Identifier
	if api.changes != 1 || stored.TradeName != "Example Shop" || stored.RegistryURI != "https://wallet.example/api/registrar/wrp/"+id {
		t.Fatalf("stored %+v after %d changes", stored, api.changes)
	}

	stored.TradeName = "Renamed Shop"
	rec = api.do(http.MethodPut, "/api/registrar/wrp", stored, acceptJSON)
	if updated := decodeBody[wrpResponse[WalletRelyingParty]](t, rec); rec.Code != http.StatusOK || updated.Data.TradeName != "Renamed Shop" || updated.Iss != "https://wallet.example" || updated.Iat == 0 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	rec = api.do(http.MethodGet, "/api/registrar/wrp/"+url.PathEscape("NTRNL-"+id), nil, acceptJSON)
	if got := decodeBody[wrpResponse[WalletRelyingParty]](t, rec); rec.Code != http.StatusOK || got.Data.TradeName != "Renamed Shop" {
		t.Fatalf("read through the semantics identifier: %d %s", rec.Code, rec.Body)
	}

	if rec = api.do(http.MethodDelete, "/api/registrar/wrp/"+id, nil, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if api.changes != 3 {
		t.Errorf("%d changes saved, want 3", api.changes)
	}
	wantError(t, api.do(http.MethodGet, "/api/registrar/wrp/"+id, nil, acceptJSON), http.StatusNotFound, apierror.NotFound, "not registered")
	wantError(t, api.do(http.MethodDelete, "/api/registrar/wrp/"+id, nil, ""), http.StatusNotFound, apierror.NotFound, id)
	wantError(t, api.do(http.MethodPut, "/api/registrar/wrp", stored, ""), http.StatusNotFound, apierror.NotFound, id)
	if api.changes != 3 {
		t.Errorf("%d changes saved, want the refused requests to save nothing", api.changes)
	}
}

func TestTheWRPAPIRefusesBadRegistrations(t *testing.T) {
	api := newTestAPI(t)
	api.env.maxRelyingParties = 1
	if rec := api.do(http.MethodPost, "/api/registrar/wrp", shopRegistration(), ""); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	oversized := WalletRelyingParty{TradeName: "Shop", Identifier: make([]Identifier, maxRegistrationItems+1)}
	for _, tc := range []struct {
		name   string
		method string
		body   any
		status int
		code   string
		want   string
	}{
		{"register malformed JSON", http.MethodPost, "{", http.StatusBadRequest, apierror.InvalidRequest, "invalid relying party"},
		{"update malformed JSON", http.MethodPut, "[]", http.StatusBadRequest, apierror.InvalidRequest, "invalid relying party"},
		{"too many identifiers", http.MethodPost, oversized, http.StatusBadRequest, apierror.InvalidRequest, "at most 20 identifiers"},
		{"no trade name", http.MethodPost, WalletRelyingParty{Country: "DE"}, http.StatusBadRequest, apierror.InvalidRequest, "needs a trade name"},
		{"update without identifier", http.MethodPut, shopRegistration(), http.StatusBadRequest, apierror.InvalidRequest, "needs the identifier"},
		{"full registrar", http.MethodPost, WalletRelyingParty{TradeName: "Second Shop"}, http.StatusConflict, apierror.Conflict, "maximum number of relying parties"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantError(t, api.do(tc.method, "/api/registrar/wrp", tc.body, ""), tc.status, tc.code, tc.want)
		})
	}
	api.env.maxRelyingParties = 0
	taken := api.RegisteredRelyingParties()[0].Identifier
	wantError(t, api.do(http.MethodPost, "/api/registrar/wrp", WalletRelyingParty{TradeName: "Copy", Identifier: taken}, ""), http.StatusConflict, apierror.Conflict, "already registered")
}

// Size limits apply to every list of a registration that the API takes.
func TestTheRegistrationSizeIsLimited(t *testing.T) {
	use := func(credentials []RegisteredCredential) []IntendedUse {
		return []IntendedUse{{Credentials: credentials}}
	}
	for _, tc := range []struct {
		name string
		rp   WalletRelyingParty
		want string
	}{
		{"services", WalletRelyingParty{Services: make([]WalletRelyingPartyService, 21)}, "at most 20 services"},
		{"provided attestations", WalletRelyingParty{Services: []WalletRelyingPartyService{{ProvidesAttestations: make([]ProvidedAttestation, 21)}}}, "at most 20 provided attestations per service"},
		{"intended uses", WalletRelyingParty{Services: []WalletRelyingPartyService{{IntendedUses: make([]IntendedUse, 21)}}}, "at most 20 intended uses per service"},
		{"credentials", WalletRelyingParty{Services: []WalletRelyingPartyService{{IntendedUses: use(make([]RegisteredCredential, 21))}}}, "at most 20 credentials per intended use"},
		{"claims", WalletRelyingParty{Services: []WalletRelyingPartyService{{IntendedUses: use([]RegisteredCredential{{Claims: make([]RegisteredClaim, 101)}})}}}, "at most 100 claims per credential"},
		{"at the limits", WalletRelyingParty{Identifier: make([]Identifier, 20), Services: []WalletRelyingPartyService{{IntendedUses: use([]RegisteredCredential{{Claims: make([]RegisteredClaim, 100)}})}}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRegistrationSize(tc.rp)
			if (err == nil) != (tc.want == "") || err != nil && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// The public demo's own registrations stay as they are, whichever identifier
// a request names them by.
func TestProtectedRegistrationsRefuseChanges(t *testing.T) {
	api := newTestAPI(t)
	demo := registerTestRelyingParty(t, api.testWallet)
	other, err := api.RegisterRelyingParty(WalletRelyingParty{TradeName: "Visitor Shop"})
	if err != nil {
		t.Fatal(err)
	}
	api.h.Protected = func(rp WalletRelyingParty) bool { return rp.TradeName == demo.TradeName }
	id := demo.Identifier[0].Identifier
	semantic := "NTRNL-" + id
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	use := demo.Services[0].IntendedUses[0].IntendedUseIdentifier
	renamed := demo
	renamed.Identifier = []Identifier{{Identifier: semantic}}
	for _, tc := range []struct {
		name, method, target string
		body                 any
	}{
		{"update", http.MethodPut, "/api/registrar/wrp", renamed},
		{"delete", http.MethodDelete, "/api/registrar/wrp/" + semantic, nil},
		{"enrolment update", http.MethodPut, "/api/registrar/enrolments", Enrolment{RelyingParty: renamed}},
		{"registration certificate", http.MethodPost, "/api/registrar/registration-certificates", RegistrationCertificateRequest{Identifier: semantic, IntendedUseIdentifier: use}},
		{"revocation", http.MethodPost, "/api/registrar/registration-certificates/status", map[string]any{"identifier": id, "revoked": true}},
		{"access certificate", http.MethodPost, "/api/registrar/access-certificates", AccessCertificateRequest{Identifier: semantic, CSR: testAccessCSR(t, key)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantError(t, api.do(tc.method, tc.target, tc.body, ""), http.StatusForbidden, apierror.Forbidden, "can't change it")
		})
	}
	if api.changes != 0 || len(api.RegistrationStatuses) != 0 {
		t.Errorf("%d changes and statuses %+v, want none", api.changes, api.RegistrationStatuses)
	}
	if after, _ := api.RelyingParty(id); after.TradeName != demo.TradeName {
		t.Errorf("the protected registration changed to %+v", after)
	}
	if rec := api.do(http.MethodDelete, "/api/registrar/wrp/"+other.Identifier[0].Identifier, nil, ""); rec.Code != http.StatusNoContent {
		t.Errorf("deleting an unprotected registration: %d %s", rec.Code, rec.Body)
	}
}

// listTestParties registers a verifier with two services and an attestation
// provider.
func listTestParties(t *testing.T, api *testAPI) (shop, university WalletRelyingParty) {
	t.Helper()
	shop, err := api.RegisterRelyingParty(WalletRelyingParty{
		TradeName:   "Example Shop",
		LegalPerson: LegalPerson{LegalName: []string{"Example Shop GmbH"}},
		Services: []WalletRelyingPartyService{
			{ServiceIdentifier: "checkout", IntendedUses: []IntendedUse{ageCheckUse("Age check")}},
			{ServiceIdentifier: "tickets", ServiceTradeName: "Shop Tickets", IntendedUses: []IntendedUse{{
				Purpose:     []MultiLangString{{Lang: "en", Content: "Ticket check"}},
				Credentials: []RegisteredCredential{{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": mock.PIDNamespace}, Claims: []RegisteredClaim{{Path: []any{mock.PIDNamespace, "family_name"}}}}},
			}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	university, err = api.RegisterRelyingParty(WalletRelyingParty{
		TradeName: "Example University",
		Services:  []WalletRelyingPartyService{{ServiceIdentifier: "diplomas", ProvidesAttestations: []ProvidedAttestation{{Format: "dc+sd-jwt", Type: testDiplomaVCT}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return shop, university
}

// TS05 v1.5 §3.2.2 lists the search parameters of GET /wrp.
func TestTheWRPSearchFilters(t *testing.T) {
	api := newTestAPI(t)
	shop, university := listTestParties(t, api)
	ticketUse := shop.Services[1].IntendedUses[0]
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"", []string{"Example Shop", "Example University"}},
		{"identifier=" + university.Identifier[0].Identifier, []string{"Example University"}},
		{"serviceidentifier=tickets", []string{"Example Shop"}},
		{"legalname=shop+gmbh", []string{"Example Shop"}},
		{"tradename=TICKETS", []string{"Example Shop"}},
		{"tradename=example", []string{"Example Shop", "Example University"}},
		{"entitlement=" + url.QueryEscape(NonQEAAProviderEntitlement), []string{"Example University"}},
		{"providedattestation=" + url.QueryEscape(testDiplomaVCT), []string{"Example University"}},
		{"intendeduseidentifier=" + ticketUse.IntendedUseIdentifier, []string{"Example Shop"}},
		{"credentialformat=mso_mdoc", []string{"Example Shop"}},
		{"credentialmeta=" + url.QueryEscape(mock.DefaultPIDVCT), []string{"Example Shop"}},
		{"claimpath=" + url.QueryEscape(mock.PIDNamespace+".family_name"), []string{"Example Shop"}},
		{"claimpath=family_name", nil},
		{"policy=" + url.QueryEscape(ticketUse.PrivacyPolicy[0].PolicyURI), []string{"Example Shop"}},
		{"isintermediary=false", []string{"Example Shop", "Example University"}},
		{"isintermediary=true", nil},
		{"isintermediary=maybe", nil},
		{"usesintermediary=true", nil},
		{"tradename=shop&credentialformat=dc%2Bsd-jwt", []string{"Example Shop"}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := api.do(http.MethodGet, "/api/registrar/wrp?"+tc.query, nil, acceptJSON)
			var names []string
			for _, rp := range decodeBody[wrpResponse[[]WalletRelyingParty]](t, rec).Data {
				names = append(names, rp.TradeName)
			}
			if rec.Code != http.StatusOK || !slices.Equal(names, tc.want) {
				t.Errorf("%d: %v, want %v", rec.Code, names, tc.want)
			}
		})
	}
}

func TestTheWRPSearchIsolatesAServiceAndPages(t *testing.T) {
	api := newTestAPI(t)
	listTestParties(t, api)

	rec := api.do(http.MethodGet, "/api/registrar/wrp?serviceidentifier=tickets&isolateService=true", nil, acceptJSON)
	found := decodeBody[wrpResponse[[]WalletRelyingParty]](t, rec).Data
	if len(found) != 1 || len(found[0].Services) != 1 || found[0].Services[0].ServiceIdentifier != "tickets" {
		t.Errorf("isolated search %+v, want the tickets service alone", found)
	}

	first := decodeBody[wrpResponse[[]WalletRelyingParty]](t, api.do(http.MethodGet, "/api/registrar/wrp?limit=1", nil, acceptJSON))
	if len(first.Data) != 1 || first.Data[0].TradeName != "Example Shop" || !first.Pagination.HasNextPage || first.Pagination.NextCursor != "1" {
		t.Errorf("first page %+v", first)
	}
	second := decodeBody[wrpResponse[[]WalletRelyingParty]](t, api.do(http.MethodGet, "/api/registrar/wrp?limit=1&cursor="+first.Pagination.NextCursor, nil, acceptJSON))
	if len(second.Data) != 1 || second.Data[0].TradeName != "Example University" || second.Pagination.HasNextPage || second.Pagination.NextCursor != "" {
		t.Errorf("second page %+v", second)
	}
	wantError(t, api.do(http.MethodGet, "/api/registrar/wrp?cursor=x", nil, acceptJSON), http.StatusBadRequest, apierror.InvalidRequest, "cursor must be a non-negative integer")
}

// GET /wrp/{identifier}/services/{serviceidentifier} narrows the record to one
// service (TS05 v1.5 §3.2.2).
func TestTheWRPServiceEndpoint(t *testing.T) {
	api := newTestAPI(t)
	shop, _ := listTestParties(t, api)
	id := shop.Identifier[0].Identifier
	rec := api.do(http.MethodGet, "/api/registrar/wrp/"+id+"/services/tickets", nil, acceptJSON)
	got := decodeBody[wrpResponse[WalletRelyingParty]](t, rec).Data
	if rec.Code != http.StatusOK || len(got.Services) != 1 || got.Services[0].ServiceTradeName != "Shop Tickets" {
		t.Errorf("%d %+v, want the tickets service", rec.Code, got.Services)
	}
	if stored, _ := api.RelyingParty(id); len(stored.Services) != 2 {
		t.Errorf("the stored registration lost a service: %+v", stored.Services)
	}
	wantError(t, api.do(http.MethodGet, "/api/registrar/wrp/"+id+"/services/newsletter", nil, acceptJSON), http.StatusNotFound, apierror.NotFound, "service not found")
	wantError(t, api.do(http.MethodGet, "/api/registrar/wrp/NLTEST.UNKNOWN/services/tickets", nil, acceptJSON), http.StatusNotFound, apierror.NotFound, "service not found")
}

// TS05 v1.5 §3.2.2 check-intended-use. Every parameter narrows the intended
// uses that match, and one intended use has to match all of them.
func TestCheckIntendedUse(t *testing.T) {
	api := newTestAPI(t)
	shop, university := listTestParties(t, api)
	ageUse := shop.Services[0].IntendedUses[0]
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"", true},
		{"identifier=" + shop.Identifier[0].Identifier, true},
		{"identifier=" + university.Identifier[0].Identifier, false},
		{"credentialformat=dc%2Bsd-jwt&claimpath=given_name", true},
		{"credentialformat=mso_mdoc&claimpath=given_name", false},
		{"credentialmeta=" + url.QueryEscape(mock.PIDNamespace) + "&claimpath=" + url.QueryEscape(mock.PIDNamespace+".family_name"), true},
		{"serviceidentifier=checkout&credentialformat=mso_mdoc", false},
		{"serviceidentifier=tickets&credentialformat=mso_mdoc", true},
		{"intendeduseidentifier=" + ageUse.IntendedUseIdentifier + "&policyurl=" + url.QueryEscape(ageUse.PrivacyPolicy[0].PolicyURI), true},
		{"intendeduseidentifier=" + ageUse.IntendedUseIdentifier + "&policyurl=" + url.QueryEscape("https://elsewhere.example/privacy"), false},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := api.do(http.MethodGet, "/api/registrar/wrp/check-intended-use?"+tc.query, nil, acceptJSON)
			got := decodeBody[wrpResponse[map[string]bool]](t, rec).Data
			if rec.Code != http.StatusOK || got["isRegistered"] != tc.want {
				t.Errorf("%d %v, want isRegistered %v", rec.Code, got, tc.want)
			}
		})
	}
	wantError(t, api.do(http.MethodGet, "/api/registrar/wrp/check-intended-use?identifier=NLTEST.UNKNOWN", nil, acceptJSON), http.StatusNotFound, apierror.NotFound, "not registered")
}

// TS05 v1.5 §3.2: the registrar signs its answers. A client that accepts JSON
// but not a JWT gets the payload unsigned.
func TestRegistrarResponsesAreSignedByTheRegistrar(t *testing.T) {
	api := newTestAPI(t)
	rp := registerTestRelyingParty(t, api.testWallet)
	target := "/api/registrar/wrp/" + rp.Identifier[0].Identifier
	for _, accept := range []string{"", "application/jwt", "application/json, application/jwt"} {
		rec := api.do(http.MethodGet, target, nil, accept)
		if rec.Header().Get("Content-Type") != "application/jwt" {
			t.Fatalf("Accept %q: %d %s %s", accept, rec.Code, rec.Header().Get("Content-Type"), rec.Body)
		}
		payload, err := jws.Verify(rec.Body.String(), &api.env.registrarKey.PublicKey)
		if err != nil {
			t.Fatalf("Accept %q: %v", accept, err)
		}
		var claims wrpResponse[WalletRelyingParty]
		if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss != "https://wallet.example" || claims.Iat == 0 || claims.Data.TradeName != rp.TradeName {
			t.Errorf("Accept %q: payload %s", accept, payload)
		}
		header, err := base64.RawURLEncoding.DecodeString(strings.Split(rec.Body.String(), ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		var h struct {
			Alg string   `json:"alg"`
			Typ string   `json:"typ"`
			X5c []string `json:"x5c"`
		}
		// The x5c of the response leaves out the self-signed trust anchor
		// (HAIP 1.0 §6.1).
		if err := json.Unmarshal(header, &h); err != nil || h.Alg != "ES256" || h.Typ != "JWT" || len(h.X5c) != 1 ||
			h.X5c[0] != base64.StdEncoding.EncodeToString(api.env.registrarChain[0].Raw) {
			t.Errorf("Accept %q: header %s", accept, header)
		}
	}
	api.env.signErr = errors.New("signer down")
	wantError(t, api.do(http.MethodGet, target, nil, ""), http.StatusInternalServerError, apierror.ServerError, "signer down")
	if rec := api.do(http.MethodGet, target, nil, acceptJSON); rec.Code != http.StatusOK {
		t.Errorf("an unsigned answer needs no signer: %d %s", rec.Code, rec.Body)
	}
}
