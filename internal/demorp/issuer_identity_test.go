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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// Each identity is its own Credential Issuer Identifier, and the metadata at
// it names its own endpoints (OpenID4VCI 1.0 §12.2.2).
func TestEachIssuerIdentityPublishesItsOwnMetadata(t *testing.T) {
	_, ts := serveDemoStack(t, newIssuanceWallet(t))
	registered := ts.URL + "/issuer"
	unregistered := ts.URL + "/issuer/unregistered"

	for _, target := range []string{
		ts.URL + "/.well-known/openid-credential-issuer/issuer/unregistered",
		unregistered + "/.well-known/openid-credential-issuer",
	} {
		metadata := getJSONFrom(t, target)
		if metadata["credential_issuer"] != unregistered {
			t.Errorf("%s: credential_issuer %v, want %s", target, metadata["credential_issuer"], unregistered)
		}
		if metadata["credential_endpoint"] != unregistered+"/credential" || metadata["nonce_endpoint"] != unregistered+"/nonce" {
			t.Errorf("%s: endpoints %v and %v are not below %s", target, metadata["credential_endpoint"], metadata["nonce_endpoint"], unregistered)
		}
		if _, ok := metadata["issuer_info"]; ok {
			t.Errorf("%s: issuer_info %v, want none for the unregistered identity", target, metadata["issuer_info"])
		}
	}

	authServer := getJSONFrom(t, ts.URL+"/.well-known/oauth-authorization-server/issuer/unregistered")
	if authServer["issuer"] != unregistered || authServer["token_endpoint"] != unregistered+"/token" {
		t.Errorf("authorization server metadata %v, want the endpoints of %s", authServer, unregistered)
	}

	metadata := getJSONFrom(t, ts.URL+"/.well-known/openid-credential-issuer/issuer")
	if metadata["credential_issuer"] != registered || metadata["issuer_info"] == nil {
		t.Errorf("registered metadata: credential_issuer %v, issuer_info %v, want %s with its registration certificate", metadata["credential_issuer"], metadata["issuer_info"], registered)
	}
}

// The issuer page and its API belong to the registered identifier only.
func TestOnlyTheRegisteredIdentityServesTheIssuerPage(t *testing.T) {
	_, ts := serveDemoStack(t, newIssuanceWallet(t))
	for target, want := range map[string]int{
		ts.URL + "/issuer/":                                                 http.StatusOK,
		ts.URL + "/issuer/unregistered/":                                    http.StatusNotFound,
		ts.URL + "/issuer/unregistered/api/offers":                          http.StatusNotFound,
		ts.URL + "/issuer/own/unknown/.well-known/openid-credential-issuer": http.StatusNotFound,
		ts.URL + "/.well-known/openid-credential-issuer/issuer/own/unknown": http.StatusNotFound,
		ts.URL + "/issuer/unregisteredx/":                                   http.StatusNotFound,
	} {
		resp, err := http.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: %d, want %d", target, resp.StatusCode, want)
		}
	}
}

// An offer belongs to the identity it was made for. Another identity does not
// know it.
func TestAnOfferRedeemsOnlyAtItsIdentity(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()
	code, created := doJSON(t, h, "POST", "/api/offers?identity=unregistered", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("create offer: %d %v", code, created)
	}
	if created["issuer"] != "http://demo.example/issuer/unregistered" {
		t.Errorf("issuer %v, want the unregistered identifier", created["issuer"])
	}
	offerURI, _ := created["offer_uri"].(string)
	path, ok := strings.CutPrefix(offerURI, "http://demo.example/issuer")
	if !ok || !strings.HasPrefix(path, "/unregistered/offer/") {
		t.Fatalf("offer_uri %q is not below the unregistered identifier", offerURI)
	}

	code, offer := doJSON(t, h, "GET", path, "", nil)
	if code != http.StatusOK || offer["credential_issuer"] != "http://demo.example/issuer/unregistered" {
		t.Fatalf("offer: %d %v, want the unregistered credential_issuer", code, offer)
	}
	if code, _ := doJSON(t, h, "GET", strings.TrimPrefix(path, "/unregistered"), "", nil); code != http.StatusNotFound {
		t.Errorf("the registered identity serves the offer: %d, want 404", code)
	}

	preAuth := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)["pre-authorized_code"].(string)
	d.mu.Lock()
	defer d.mu.Unlock()
	grantKey := func(o *offerState) string { return o.preAuthCode }
	if d.redeemOfferLocked(preAuth, registeredIssuer, grantKey) != nil {
		t.Error("the registered identity redeemed the code of an unregistered offer")
	}
	if d.redeemOfferLocked(preAuth, unregisteredIssuer, grantKey) == nil {
		t.Error("the unregistered identity did not redeem its own code")
	}
}

func TestAnOfferRefusesABadIdentity(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()
	for _, tc := range []struct {
		query, body, want string
	}{
		{"?identity=someone", "", `"registered", "unregistered", "unsigned" or "own"`},
		{"?identity=own", "", "JSON body"},
		{"?identity=own", `{"issuer_info":[]}`, "signing_key is required"},
		{"?identity=own", `{"signing_key":"not a pem"}`, "no private key"},
		{"?identity_check=someone", "", `"registered", "unregistered" or "own"`},
		{"?identity_check=own", `{"identity_check":{}}`, "identity_check.signing_key is required"},
	} {
		code, doc := doJSON(t, h, "POST", "/api/offers"+tc.query, tc.body, map[string]string{"Content-Type": "application/json"})
		if description, _ := doc["error_description"].(string); code != http.StatusBadRequest || !strings.Contains(description, tc.want) {
			t.Errorf("%s %s: %d %v, want 400 with %q", tc.query, tc.body, code, doc, tc.want)
		}
	}
}

// A wallet with ARF checks warns about an issuer without a registration
// certificate. Wallets must check one only from 11 August 2028 (CIR (EU)
// 2026/1731), so the unregistered identity still issues.
func TestTheUnregisteredIdentityIssuesWithAWarning(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireARF = true
	_, ts := serveDemoStack(t, w)
	for _, tc := range []struct {
		identity string
		warned   bool
	}{
		{"registered", false},
		{"unregistered", true},
	} {
		created := postJSONTo(t, ts.URL+"/issuer/api/offers?identity="+tc.identity, "")
		result, err := w.ProcessCredentialOffer(created["scheme_uri"].(string))
		if err != nil {
			t.Fatalf("%s: issuance failed: %v", tc.identity, err)
		}
		if result.Issuer != created["issuer"] {
			t.Errorf("%s: issued by %s, want %v", tc.identity, result.Issuer, created["issuer"])
		}
		if warned := strings.Contains(strings.Join(result.Findings, "\n"), "RPRC_22a"); warned != tc.warned {
			t.Errorf("%s: findings %v, RPRC_22a warning want %t", tc.identity, result.Findings, tc.warned)
		}
	}
}

// An own identity signs its metadata with the visitor's access certificate
// and publishes the visitor's issuer_info. A strict ARF wallet accepts it
// when the registrar registered it for the ticket.
func TestAnOwnIdentityCarriesTheSuppliedCertificates(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireARF = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStack(t, w)
	signingKey, accessLeaf, issuerInfo := registerOwnIssuer(t, w)

	body, _ := json.Marshal(ownIdentityBody{SigningKey: signingKey, IssuerInfo: issuerInfo})
	created := postJSONTo(t, ts.URL+"/issuer/api/offers?identity=own", string(body))
	issuer, _ := created["issuer"].(string)
	if !strings.HasPrefix(issuer, ts.URL+"/issuer/own/") {
		t.Fatalf("issuer %q, want an identifier below /issuer/own/ (%v)", issuer, created)
	}

	wellKnown := ts.URL + "/.well-known/openid-credential-issuer/issuer/" + strings.TrimPrefix(issuer, ts.URL+"/issuer/")
	metadata := getJSONFrom(t, wellKnown)
	if metadata["credential_issuer"] != issuer || !reflect.DeepEqual(metadata["issuer_info"], issuerInfo) {
		t.Errorf("metadata credential_issuer %v, issuer_info %v, want %s with the supplied issuer_info", metadata["credential_issuer"], metadata["issuer_info"], issuer)
	}
	if x5c := signedMetadataX5C(t, wellKnown); len(x5c) == 0 || x5c[0] != accessLeaf {
		t.Error("the signed metadata does not carry the supplied access certificate")
	}

	result, err := w.ProcessCredentialOffer(created["scheme_uri"].(string))
	if err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
	if result.Issuer != issuer {
		t.Errorf("issued by %s, want %s", result.Issuer, issuer)
	}
}

// An own identity serves one offer, so its metadata advertises the copies of
// that offer. A single copy leaves out batch_credential_issuance, because
// OpenID4VCI 1.0 §12.2.4 requires a batch_size of at least 2.
func TestAnOwnIdentityAdvertisesTheBatchSizeOfItsOffer(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)
	signingKey, _, issuerInfo := registerOwnIssuer(t, w)
	body, _ := json.Marshal(ownIdentityBody{SigningKey: signingKey, IssuerInfo: issuerInfo})

	for _, tt := range []struct {
		batch string
		want  any
	}{
		{batch: "", want: nil},
		{batch: "3", want: map[string]any{"batch_size": float64(3)}},
	} {
		created := postJSONTo(t, ts.URL+"/issuer/api/offers?identity=own&batch="+tt.batch, string(body))
		issuer, _ := created["issuer"].(string)
		metadata := getJSONFrom(t, ts.URL+"/.well-known/openid-credential-issuer/issuer/"+strings.TrimPrefix(issuer, ts.URL+"/issuer/"))
		if got := metadata["batch_credential_issuance"]; !reflect.DeepEqual(got, tt.want) {
			t.Errorf("batch=%q: batch_credential_issuance = %v, want %v", tt.batch, got, tt.want)
		}
	}
	if metadata := getJSONFrom(t, ts.URL+"/.well-known/openid-credential-issuer/issuer"); metadata["batch_credential_issuance"] == nil {
		t.Error("the registered identity must advertise batch issuance")
	}
}

func TestAnOwnIdentityCanListOnlyTheJWTProofType(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)
	signingKey, _, issuerInfo := registerOwnIssuer(t, w)
	body, _ := json.Marshal(ownIdentityBody{SigningKey: signingKey, IssuerInfo: issuerInfo})

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?identity=own&proof_types=jwt", string(body))
	issuer, _ := created["issuer"].(string)
	metadata := getJSONFrom(t, ts.URL+"/.well-known/openid-credential-issuer/issuer/"+strings.TrimPrefix(issuer, ts.URL+"/issuer/"))
	configurations, _ := metadata["credential_configurations_supported"].(map[string]any)
	ticket, _ := configurations[ticketConfigurationID].(map[string]any)
	proofTypes, _ := ticket["proof_types_supported"].(map[string]any)
	if _, jwt := proofTypes["jwt"]; !jwt || len(proofTypes) != 1 {
		t.Fatalf("proof_types_supported = %v, want jwt alone", proofTypes)
	}

	result, err := w.ProcessCredentialOffer(created["scheme_uri"].(string))
	if err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
	if result.Issuer != issuer {
		t.Errorf("issued by %s, want %s", result.Issuer, issuer)
	}
}

// The identity check has its own identity, like the demo verifier. The
// registered one carries the registration certificate of the identity check,
// and an own one signs with the supplied key and sends the supplied
// verifier_info.
func TestTheIdentityCheckHasItsOwnIdentity(t *testing.T) {
	d, w, _ := newDemoRP(t)
	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}
	signingKey, accessLeaf, issuerInfo := registerOwnIssuer(t, w)
	ownIssuer, err := d.newOwnIssuer(ownIdentityBody{SigningKey: signingKey, IssuerInfo: issuerInfo}, offerIssuerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unregistered, err := newIdentityCheck(identityUnregistered, identityCheckBody{})
	if err != nil {
		t.Fatal(err)
	}
	someVerifierInfo := []any{map[string]any{"format": "registration_cert", "data": "a registration certificate"}}
	ownCheck, err := newIdentityCheck(identityOwn, identityCheckBody{SigningKey: signingKey, VerifierInfo: someVerifierInfo})
	if err != nil {
		t.Fatal(err)
	}
	ownWithoutInfo, err := newIdentityCheck(identityOwn, identityCheckBody{SigningKey: signingKey, VerifierInfo: []any{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		issuer       *issuerIdentity
		check        *identityCheck
		verifierInfo bool
		signedByOwn  bool
	}{
		{"registered", registeredIssuer, registeredIdentityCheck, true, false},
		{"unregistered", registeredIssuer, unregistered, false, false},
		{"own", registeredIssuer, ownCheck, true, true},
		{"own with an empty verifier_info", registeredIssuer, ownWithoutInfo, false, true},
		{"registered for an own issuer", ownIssuer, registeredIdentityCheck, true, false},
	} {
		pidRequest, err := d.newInteractivePIDRequest(tc.issuer)
		if err != nil {
			t.Fatal(err)
		}
		request, err := d.interactivePresentationRequest(pidRequest, tc.issuer, tc.check)
		if err != nil {
			t.Fatal(err)
		}
		jar := request["request"].(string)
		if _, ok := signedRequestClaims(t, jar)["verifier_info"]; ok != tc.verifierInfo {
			t.Errorf("%s: verifier_info present %t, want %t", tc.name, ok, tc.verifierInfo)
		}
		x5c := jwsX5C(t, jar)
		if signedByOwn := len(x5c) > 0 && x5c[0] == accessLeaf; signedByOwn != tc.signedByOwn {
			t.Errorf("%s: signed with the supplied access certificate %t, want %t", tc.name, signedByOwn, tc.signedByOwn)
		}
	}
}

// Codes, tokens, pushed requests and authorization sessions work only at the
// identity of their grant.
func TestAGrantWorksOnlyAtItsIdentity(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()
	settings := offerSettings{configIDs: []string{ticketConfigurationID}, issuer: unregisteredIssuer}
	verifier := "a-code-verifier-of-sufficient-length-0123456789"
	challenge := sha256.Sum256([]byte(verifier))
	grant := authGrant{clientID: "wallet", redirectURI: "https://wallet.example/cb", codeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), settings: settings}
	expires := time.Now().Add(time.Minute)
	d.codes["code"] = &authRequestState{authGrant: grant, codeIssued: true, expires: expires}
	d.authRequests["urn:request"] = &authRequestState{requestURI: "urn:request", authGrant: grant, expires: expires}
	d.tokens["token"] = &tokenState{offerSettings: settings, expires: expires}
	d.interactive["session"] = &interactiveSession{id: "session", authGrant: grant, expires: expires}

	tokenRequest := url.Values{"grant_type": {authCodeGrant}, "code": {"code"}, "client_id": {"wallet"}, "redirect_uri": {grant.redirectURI}, "code_verifier": {verifier}}.Encode()
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	bearer := map[string]string{"Authorization": "Bearer token"}
	for _, tc := range []struct {
		name, method, path, body string
		header                   map[string]string
		elsewhere, own           int
	}{
		{"pushed request", "GET", "/authorize?request_uri=urn:request", "", nil, http.StatusBadRequest, http.StatusOK},
		{"access token", "POST", "/credential", "{}", bearer, http.StatusUnauthorized, http.StatusBadRequest},
		{"authorization code", "POST", "/token", tokenRequest, form, http.StatusBadRequest, http.StatusOK},
	} {
		for prefix, want := range map[string]int{"": tc.elsewhere, unregisteredPath: tc.own} {
			req := httptest.NewRequest(tc.method, prefix+tc.path, strings.NewReader(tc.body))
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != want {
				t.Errorf("%s at %q: %d %s, want %d", tc.name, prefix+tc.path, rec.Code, rec.Body.String(), want)
			}
		}
	}

	if _, errResp := d.takeInteractiveSession("session", registeredIssuer, "", ""); errResp == nil {
		t.Error("the registered identity took the authorization session of the unregistered identity")
	}
	if _, errResp := d.takeInteractiveSession("session", unregisteredIssuer, "", ""); errResp != nil {
		t.Errorf("the unregistered identity did not take its own session: %v", errResp)
	}
	scoped, errResp := d.resolveAuthGrant(unregisteredIssuer, authGrant{}, ticketConfigurationID, "")
	if errResp != nil || scoped.settings.issuer != unregisteredIssuer {
		t.Errorf("a grant by scope at the unregistered identity belongs to %v (%v)", scoped.settings.issuer, errResp)
	}
}

// registerOwnIssuer registers a ticket issuer with the wallet's registrar. It
// returns the PEM key and access certificate chain, the base64 access
// certificate and the issuer_info with its registration certificate.
func registerOwnIssuer(t *testing.T, w *wallet.Wallet) (string, string, []any) {
	t.Helper()
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Own Ticket Issuer",
		Services: []registrar.WalletRelyingPartyService{{
			ServiceIdentifier:    "tickets",
			Entitlements:         []string{registrar.CategoryOf(credtemplate.CategoryEAA).Entitlement},
			ProvidesAttestations: []registrar.ProvidedAttestation{{Format: "dc+sd-jwt", Type: TicketVCT}},
		}},
	})
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	identifier := rp.Identifier[0].Identifier
	access, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{
		Identifier: identifier,
		CSR:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
	})
	if err != nil {
		t.Fatalf("IssueAccessCertificate: %v", err)
	}
	registration, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{
		Identifier:        identifier,
		ServiceIdentifier: rp.Services[0].ServiceIdentifier,
	})
	if err != nil {
		t.Fatalf("IssueRegistrationCertificate: %v", err)
	}
	var issuerInfo []any
	if err := json.Unmarshal([]byte(registration.IssuerInfo), &issuerInfo); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pem.Decode([]byte(access.Certificate))
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})) + access.Chain,
		base64.StdEncoding.EncodeToString(leaf.Bytes), issuerInfo
}

func signedMetadataX5C(t *testing.T, target string) []string {
	t.Helper()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return jwsX5C(t, string(raw))
}

// jwsX5C reads the x5c header of a compact JWS.
func jwsX5C(t *testing.T, compact string) []string {
	t.Helper()
	header, _, _, err := format.ParseJWTParts(compact)
	if err != nil {
		t.Fatalf("parsing %q: %v", compact, err)
	}
	var x5c []string
	for _, cert := range jsonutil.List(header["x5c"]) {
		if s, ok := cert.(string); ok {
			x5c = append(x5c, s)
		}
	}
	return x5c
}

// OpenID4VCI 1.0 §6.2 lets an issuer return authorization_details to a wallet
// that asked by scope, as Keycloak does. The wallet then has to request by
// credential_identifier (§8.2).
func TestAnOfferCanAlwaysReturnCredentialIdentifiers(t *testing.T) {
	d, _, _ := newDemoRP(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/token", strings.NewReader("grant_type="+url.QueryEscape(preAuthGrant)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	granted := tokenState{offerSettings: offerSettings{configIDs: []string{ticketConfigurationID}, issuer: registeredIssuer, alwaysIdentifiers: true}}
	d.issueToken(rec, req, granted, false)
	var resp struct {
		AuthorizationDetails []struct {
			CredentialConfigurationID string   `json:"credential_configuration_id"`
			CredentialIdentifiers     []string `json:"credential_identifiers"`
		} `json:"authorization_details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.AuthorizationDetails) != 1 || resp.AuthorizationDetails[0].CredentialConfigurationID != ticketConfigurationID || len(resp.AuthorizationDetails[0].CredentialIdentifiers) != 1 {
		t.Errorf("token response %s, want the ticket with one credential identifier", rec.Body.String())
	}
}

func TestTheWalletRequestsByTheReturnedCredentialIdentifier(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)
	if ticket := redeemDemoTicket(t, w, ts, "?credential_identifiers=always"); ticket == nil {
		t.Fatal("no ticket")
	}
}

// The unsigned identity answers like an issuer without an access certificate:
// plain JSON without issuer_info, also when the wallet asks for signed metadata.
func TestTheUnsignedIdentityServesPlainJSON(t *testing.T) {
	_, ts := serveDemoStack(t, newIssuanceWallet(t))
	req, err := http.NewRequest("GET", ts.URL+"/.well-known/openid-credential-issuer/issuer/unsigned", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatalf("content type %s: %v", resp.Header.Get("Content-Type"), err)
	}
	if metadata["credential_issuer"] != ts.URL+"/issuer/unsigned" {
		t.Errorf("credential_issuer %v, want the unsigned identifier", metadata["credential_issuer"])
	}
	if _, ok := metadata["issuer_info"]; ok {
		t.Error("the unsigned identity publishes issuer_info")
	}
}

// An offer records its identity check. Its own material arrives in the
// identity_check object of the body.
func TestAnOfferRecordsItsIdentityCheck(t *testing.T) {
	d, w, _ := newDemoRP(t)
	signingKey, _, _ := registerOwnIssuer(t, w)
	verifierInfo := []any{map[string]any{"format": "registration_cert", "data": "a registration certificate"}}
	body, err := json.Marshal(map[string]any{"identity_check": map[string]any{"signing_key": signingKey, "verifier_info": verifierInfo}})
	if err != nil {
		t.Fatal(err)
	}
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?grant=authorization_code&authorization=presentation&identity_check=own", string(body), map[string]string{"Content-Type": "application/json"})
	if code != http.StatusCreated {
		t.Fatalf("offer: %d %v", code, doc)
	}
	d.mu.Lock()
	offer := d.offers[doc["id"].(string)]
	d.mu.Unlock()
	if offer.identityCheck.kind != identityOwn || !reflect.DeepEqual(offer.identityCheck.verifierInfo, verifierInfo) {
		t.Errorf("identity check %+v, want the own one with the supplied verifier_info", offer.identityCheck)
	}
	if offer.issuer != registeredIssuer {
		t.Errorf("issuer identity %s, want the registered one", offer.issuer.kind)
	}
}

// A shared identity serves one metadata document, so an offer that changes it
// gets an issuer identifier of its own that presents itself the same way.
func TestAJWTOnlyOfferGetsAVariantOfItsIdentity(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?proof_types=jwt", "")
	issuer, _ := created["issuer"].(string)
	if !strings.HasPrefix(issuer, ts.URL+"/issuer/variant/") {
		t.Fatalf("issuer %q, want an identifier below /issuer/variant/", issuer)
	}
	wellKnown := ts.URL + "/.well-known/openid-credential-issuer/issuer/" + strings.TrimPrefix(issuer, ts.URL+"/issuer/")
	metadata := getJSONFrom(t, wellKnown)
	registered := getJSONFrom(t, ts.URL+"/.well-known/openid-credential-issuer/issuer")
	if !reflect.DeepEqual(metadata["issuer_info"], registered["issuer_info"]) {
		t.Error("the variant does not carry the registered issuer_info")
	}
	if x5c, want := signedMetadataX5C(t, wellKnown), signedMetadataX5C(t, ts.URL+"/.well-known/openid-credential-issuer/issuer"); len(x5c) == 0 || x5c[0] != want[0] {
		t.Error("the variant is not signed with the registered access certificate")
	}
	configurations, _ := metadata["credential_configurations_supported"].(map[string]any)
	ticket, _ := configurations[ticketConfigurationID].(map[string]any)
	if proofTypes, _ := ticket["proof_types_supported"].(map[string]any); len(proofTypes) != 1 || proofTypes["jwt"] == nil {
		t.Errorf("proof_types_supported = %v, want jwt alone", proofTypes)
	}

	if _, err := w.ProcessCredentialOffer(created["scheme_uri"].(string)); err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
}
