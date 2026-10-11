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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

// arfRequest returns a request signed with an access certificate from the
// registrar. The request carries the relying party's registration certificate.
func arfRequest(t *testing.T, reg *Wallet, checking *Wallet) *AuthorizationRequestParams {
	t.Helper()
	key, chain, verifierInfo := registeredVerifier(t, reg)
	return signedARFRequest(t, checking, key, chain, verifierInfo)
}

// registeredVerifier registers a relying party with the registrar and returns
// its key, its access certificate chain and its verifier_info.
func registeredVerifier(t *testing.T, reg *Wallet) (*ecdsa.PrivateKey, []*x509.Certificate, string) {
	t.Helper()
	rp := registerTestRelyingParty(t, reg)
	key, chain := issueTestAccessCertificate(t, reg, rp.Identifier[0].Identifier)
	return key, chain, issueTestRegistrationCertificate(t, reg, rp).VerifierInfo
}

// issueTestAccessCertificate creates a key and has the registrar issue an
// access certificate for it. It returns the key and the chain, leaf first.
func issueTestAccessCertificate(t *testing.T, w *Wallet, identifier string) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{Identifier: identifier, CSR: testAccessCSR(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for rest := []byte(access.Chain); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return key, chain
}

func signedARFRequest(t *testing.T, checking *Wallet, key *ecdsa.PrivateKey, chain []*x509.Certificate, verifierInfo string) *AuthorizationRequestParams {
	t.Helper()
	var info []any
	if err := json.Unmarshal([]byte(verifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	clientID := X509HashClientID(chain[0])
	claims := map[string]any{"client_id": clientID, "response_type": "vp_token", "nonce": "n", "verifier_info": info}
	raw, err := SignRequestObjectJWT(claims, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := decodeCompactJWT(raw)
	if err != nil {
		t.Fatal(err)
	}
	params := &AuthorizationRequestParams{
		ClientID:       clientID,
		ResponseType:   "vp_token",
		Nonce:          "n",
		RequestObject:  &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload},
		RequestPayload: payload,
	}
	checking.RequireARF = true
	checking.PrepareARFChecks(params)
	return params
}

// An unsigned request that copies a relying party's x5c and registration
// certificate does not authenticate as that relying party (ARF RPA_03).
func TestARFRequiresTheAccessCertificateToSignTheRequest(t *testing.T) {
	w := generateTestWallet(t)
	params := arfRequest(t, w, w)
	params.RequestObject.Header["alg"] = "none"
	if findings := ARFFindings(params); !containsSubstring(findings, "RPA_03") {
		t.Errorf("findings %v, want RPA_03 for an unsigned request with a copied x5c", findings)
	}
}

// An expired access certificate is an ARF finding: debug mode warns and
// strict mode refuses.
func TestAnExpiredAccessCertificate(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := w.CertChain[len(w.CertChain)-1]
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Expired Shop", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: rp.Identifier[0].Identifier}}},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, w.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	params := signedARFRequest(t, w, key, []*x509.Certificate{expired}, issueTestRegistrationCertificate(t, w, rp).VerifierInfo)

	findings, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeDebug, RequireARF: true}, params)
	if err != nil || !containsSubstring(findings, "RPA_04") {
		t.Errorf("debug mode: findings %v (%v), want the RPA_04 warning", findings, err)
	}
	if _, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeStrict, RequireARF: true}, params); err == nil || !strings.Contains(err.Error(), "RPA_04") {
		t.Errorf("strict mode: err %v, want the RPA_04 refusal", err)
	}
}

func TestARFTrustsTheWalletsOwnRegistrar(t *testing.T) {
	w := generateTestWallet(t)
	findings := ARFFindings(arfRequest(t, w, w))
	for _, rule := range []string{"RPA_03", "RPA_04", "RPRC_02a", "RPRC_17a"} {
		if containsSubstring(findings, rule) {
			t.Errorf("findings %v, want no %s finding", findings, rule)
		}
	}
}

func TestARFRefusesUnknownAuthorities(t *testing.T) {
	foreign := generateTestWallet(t)
	w := generateTestWallet(t)
	params := arfRequest(t, foreign, w)
	findings := ARFFindings(params)
	if !containsSubstring(findings, "RPA_04") || !containsSubstring(findings, "RPRC_02a") {
		t.Errorf("findings %v, want RPA_04 and RPRC_02a", findings)
	}

	// --relying-party-ca trusts the foreign access CA and registrar CA.
	_, foreignAccessCA, err := foreign.RelyingPartyAccessCA()
	if err != nil {
		t.Fatal(err)
	}
	_, foreignRegistrarCA, err := foreign.RegistrarCA()
	if err != nil {
		t.Fatal(err)
	}
	w.RelyingPartyCAPEM = append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreignRegistrarCA.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreignAccessCA.Raw})...)
	w.PrepareARFChecks(params)
	if findings := ARFFindings(params); containsSubstring(findings, "RPA_04") || containsSubstring(findings, "RPRC_02a") {
		t.Errorf("findings %v with --relying-party-ca, want the foreign CA trusted", findings)
	}
}

func TestARFRequiresAnAccessCertificate(t *testing.T) {
	findings := ARFFindings(&AuthorizationRequestParams{ClientID: "redirect_uri:https://verifier.example/response"})
	if !containsSubstring(findings, "RPA_03") {
		t.Errorf("findings %v, want the RPA_03 finding", findings)
	}
}

// A presentation request fetches each registration certificate's status list
// only once, because another party may serve the list.
func TestAPresentationRequestReadsTheStatusListOnce(t *testing.T) {
	reg := newTestServer(t, true)
	var fetches atomic.Int32
	registrarHandler := reg.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == registrar.RegistrationStatusListPath {
			fetches.Add(1)
		}
		registrarHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	reg.wallet.IssuerURL = ts.URL
	key, chain, verifierInfo := registeredVerifier(t, reg.wallet)

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{})
	}))
	t.Cleanup(verifier.Close)
	var info []any
	if err := json.Unmarshal([]byte(verifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	clientID := X509HashClientID(chain[0])
	requestObject, err := SignRequestObjectJWT(map[string]any{
		"client_id":     clientID,
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  verifier.URL,
		"nonce":         "n",
		"state":         "s",
		"verifier_info": info,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claims": []any{map[string]any{"path": []any{"given_name"}}},
		}}},
	}, key, chain)
	if err != nil {
		t.Fatal(err)
	}

	wallet := newTestServer(t, true)
	wallet.wallet.RequireARF = true
	uri := "openid4vp://authorize?" + url.Values{"client_id": {clientID}, "request": {requestObject}}.Encode()
	body, _ := json.Marshal(map[string]string{"uri": uri})
	serverRequest(t, wallet, http.MethodPost, "/api/presentations", string(body))
	if n := fetches.Load(); n != 1 {
		t.Errorf("the status list was read %d times, want once", n)
	}
}

// A seeded wallet on memory storage restarts with the same registrar and
// access CA keys, so certificates issued before the restart still pass --arf.
// Revocations are lost on restart.
func TestRegistrarCertificatesPassAfterASeededRestart(t *testing.T) {
	start := func() *Wallet {
		store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
		store.SetSeed("restart")
		w, err := store.LoadOrCreate()
		if err != nil {
			t.Fatal(err)
		}
		w.IssuerURL = "https://wallet.example"
		return w
	}
	before, after := start(), start()
	if findings := ARFFindings(arfRequest(t, before, after)); len(findings) != 0 {
		t.Errorf("findings after a restart %v, want none", findings)
	}
}

// The relying party access CA signs any visitor's CSR, so an access
// certificate must not vouch for a registration (ARF RPRC_02a).
func TestARFRefusesARegistrationSignedWithAnAccessCertificate(t *testing.T) {
	w := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, w)
	var info []map[string]any
	if err := json.Unmarshal([]byte(verifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	_, payload, err := decodeCompactJWT(info[0]["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	payload["purpose"] = []map[string]any{{"lang": "en", "value": "Anything at all"}}
	forged, err := registrar.SignRegistrationCertificateJWT(payload, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	params := signedARFRequest(t, w, key, chain, `[{"format":"registration_cert","data":"`+forged+`"}]`)
	if findings := ARFFindings(params); !containsSubstring(findings, "RPRC_02a") {
		t.Errorf("findings %v, want RPRC_02a for a registration certificate signed with an access certificate", findings)
	}
	if findings := ARFFindings(arfRequest(t, w, w)); containsSubstring(findings, "RPRC_02a") {
		t.Errorf("findings %v, want the registrar's own certificate trusted", findings)
	}
}

// A request carries a single registration certificate for its intended use
// (ARF RPRC_19).
func TestARFRefusesSeveralRegistrationCertificates(t *testing.T) {
	reg := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, reg)
	var entries []any
	if err := json.Unmarshal([]byte(verifierInfo), &entries); err != nil {
		t.Fatal(err)
	}
	twice, _ := json.Marshal(append(entries, entries...))
	findings := ARFFindings(signedARFRequest(t, reg, key, chain, string(twice)))
	if !slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, "ARF RPRC_19: the request carries 2") }) {
		t.Errorf("findings %v, want RPRC_19 for two certificates", findings)
	}
}

// ETSI TS 119 475 V1.2.1 Annex B.2.9 requires format and meta, so an entry
// without them registers nothing (ARF RPRC_21).
func TestARegisteredEntryWithoutFormatOrTypeRegistersNothing(t *testing.T) {
	query := map[string]any{"credentials": []any{map[string]any{
		"id": "pid", "format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
	// A registration certificate lists the claims of an entry under "claim"
	// (ETSI TS 119 475 V1.2.1 Annex B.2.9).
	claims := []any{map[string]any{"path": []any{"given_name"}}}
	for name, tc := range map[string]struct {
		entry    map[string]any
		findings int
	}{
		"format and type": {map[string]any{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}, "claim": claims}, 0},
		"no format":       {map[string]any{"meta": map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}, "claim": claims}, 1},
		"no type":         {map[string]any{"format": "dc+sd-jwt", "claim": claims}, 1},
	} {
		cert := map[string]any{"credentials": []any{tc.entry}}
		if findings := overAskingFindings(cert, query); len(findings) != tc.findings {
			t.Errorf("%s: findings %v, want %d", name, findings, tc.findings)
		}
	}
}

// Debug mode presents and lists the findings in the API response.
func TestDebugARFListsTheFindingsInTheResponse(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.RequireARF = true
	srv.wallet.ValidationMode = ValidationModeDebug
	key, chain, _ := registeredVerifier(t, srv.wallet)
	verifier := newCaptureVerifier(t)
	clientID := X509HashClientID(chain[0])
	requestObject, err := SignRequestObjectJWT(map[string]any{
		"client_id": clientID, "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": verifier.URL, "nonce": "n", "state": "s",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claims": []any{map[string]any{"path": []any{"given_name"}}},
		}}},
	}, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	uri := "openid4vp://authorize?" + url.Values{"client_id": {clientID}, "request": {requestObject}}.Encode()
	body, _ := json.Marshal(map[string]string{"uri": uri})
	rec := serverRequest(t, srv, http.MethodPost, "/api/presentations", string(body))
	var response struct {
		Status   string
		Findings []string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "submitted" || !slices.ContainsFunc(response.Findings, func(f string) bool { return strings.Contains(f, "RPRC_19") }) {
		t.Errorf("response %s, want a submitted presentation with the RPRC_19 finding", rec.Body)
	}
}

// A relying party that authenticated with a trusted access certificate gets
// access_denied when strict --arf refuses its request (RFC 6749 §4.1.2.1).
func TestStrictARFAnswersAnAuthenticatedVerifierWithAccessDenied(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.RequireARF = true
	srv.wallet.ValidationMode = ValidationModeStrict
	key, chain, verifierInfo := registeredVerifier(t, srv.wallet)
	verifier := newCaptureVerifier(t)
	var info []any
	if err := json.Unmarshal([]byte(verifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	clientID := X509HashClientID(chain[0])
	requestObject, err := SignRequestObjectJWT(map[string]any{
		"client_id": clientID, "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": verifier.URL, "nonce": "n", "state": "s", "verifier_info": info,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claims": []any{map[string]any{"path": []any{"birthdate"}}},
		}}},
	}, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	uri := "openid4vp://authorize?" + url.Values{"client_id": {clientID}, "request": {requestObject}}.Encode()
	body, _ := json.Marshal(map[string]string{"uri": uri})
	serverRequest(t, srv, http.MethodPost, "/api/presentations", string(body))
	if form := verifier.received(t); form.Get("error") != "access_denied" || form.Get("state") != "s" || !strings.Contains(form.Get("error_description"), "RPRC_21") {
		t.Errorf("the verifier received %v, want access_denied naming RPRC_21", form)
	}
}
