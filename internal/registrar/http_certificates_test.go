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
	"compress/zlib"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

func TestTheEnrolmentAPI(t *testing.T) {
	api := newTestAPI(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rec := api.do(http.MethodPost, "/api/registrar/enrolments", Enrolment{
		RelyingParty: shopRegistration(),
		Access:       &AccessCertificateRequest{CSR: testAccessCSR(t, key), DNSNames: []string{"shop.example"}},
		Registration: &EnrolmentRegistration{},
	}, "")
	created := decodeBody[EnrolmentResult](t, rec)
	if rec.Code != http.StatusCreated || created.Access == nil || created.Registration == nil || created.Registration.VerifierInfo == "" {
		t.Fatalf("enrol: %d %s", rec.Code, rec.Body)
	}
	if ids := created.Access.ClientIDs; len(ids) != 2 || !strings.HasPrefix(ids[0], "x509_hash:") || ids[1] != "x509_san_dns:shop.example" {
		t.Errorf("client ids %v", ids)
	}

	updated := created.RelyingParty
	updated.Services[0].IntendedUses = append(updated.Services[0].IntendedUses, ageCheckUse("Second check"))
	rec = api.do(http.MethodPut, "/api/registrar/enrolments", Enrolment{RelyingParty: updated, Registration: &EnrolmentRegistration{}}, "")
	if result := decodeBody[EnrolmentResult](t, rec); rec.Code != http.StatusOK || len(result.RelyingParty.Services[0].IntendedUses) != 2 || result.Registration == nil {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if api.changes != 2 {
		t.Errorf("%d changes saved, want 2", api.changes)
	}

	oversized := Enrolment{RelyingParty: WalletRelyingParty{TradeName: "Shop", Services: make([]WalletRelyingPartyService, 21)}}
	wantError(t, api.do(http.MethodPost, "/api/registrar/enrolments", "{", ""), http.StatusBadRequest, apierror.InvalidRequest, "invalid enrolment")
	wantError(t, api.do(http.MethodPost, "/api/registrar/enrolments", oversized, ""), http.StatusBadRequest, apierror.InvalidRequest, "at most 20 services")
	wantError(t, api.do(http.MethodPost, "/api/registrar/enrolments", Enrolment{RelyingParty: created.RelyingParty}, ""), http.StatusConflict, apierror.Conflict, "already registered")
	// A verifier has no provider service.
	provider := Enrolment{RelyingParty: WalletRelyingParty{TradeName: "Other Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}}, Registration: &EnrolmentRegistration{Provider: true}}
	wantError(t, api.do(http.MethodPost, "/api/registrar/enrolments", provider, ""), http.StatusNotFound, apierror.NotFound, "as an attestation provider")
	if api.changes != 2 {
		t.Errorf("%d changes saved, want the refused enrolments to save nothing", api.changes)
	}
}

// Revoking through the API sets the certificate's bit in the registrar's
// Token Status List (ETSI TS 119 475 V1.2.1 §6.2.6.1), and activating clears
// it.
func TestRevocationReachesTheStatusList(t *testing.T) {
	api := newTestAPI(t)
	shop, _ := listTestParties(t, api)
	id := shop.Identifier[0].Identifier
	var indices []int
	for _, service := range shop.Services {
		use := service.IntendedUses[0].IntendedUseIdentifier
		rec := api.do(http.MethodPost, "/api/registrar/registration-certificates", RegistrationCertificateRequest{Identifier: id, IntendedUseIdentifier: use}, "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue: %d %s", rec.Code, rec.Body)
		}
		indices = append(indices, api.RegistrationStatuses[len(api.RegistrationStatuses)-1].Index)
	}

	setStatus := func(body map[string]any) int {
		t.Helper()
		rec := api.do(http.MethodPost, "/api/registrar/registration-certificates/status", body, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%v: %d %s", body, rec.Code, rec.Body)
		}
		return decodeBody[map[string]int](t, rec)["changed"]
	}
	if n := setStatus(map[string]any{"identifier": id, "serviceIdentifier": "tickets", "revoked": true}); n != 1 {
		t.Errorf("revoked %d in the tickets service, want 1", n)
	}
	if revoked := statusListBits(t, api, indices); revoked[0] || !revoked[1] {
		t.Errorf("bits %v, want only the tickets certificate revoked", revoked)
	}
	if n := setStatus(map[string]any{"identifier": id, "revoked": true}); n != 1 {
		t.Errorf("revoked %d more, want the checkout certificate", n)
	}
	if n := setStatus(map[string]any{"identifier": id, "intendedUseIdentifier": shop.Services[1].IntendedUses[0].IntendedUseIdentifier, "revoked": false}); n != 1 {
		t.Errorf("activated %d, want the tickets certificate", n)
	}
	if revoked := statusListBits(t, api, indices); !revoked[0] || revoked[1] {
		t.Errorf("bits %v, want only the checkout certificate revoked", revoked)
	}

	for _, tc := range []struct {
		name string
		body any
		code string
		want string
	}{
		{"malformed JSON", "{", apierror.InvalidRequest, "invalid request body"},
		{"unknown party", map[string]any{"identifier": "NLTEST.UNKNOWN", "revoked": true}, apierror.NotFound, "not registered"},
		{"unknown intended use", map[string]any{"identifier": id, "intendedUseIdentifier": "x", "revoked": true}, apierror.NotFound, `no intended use "x"`},
		{"unknown service", map[string]any{"identifier": id, "serviceIdentifier": "newsletter", "revoked": true}, apierror.NotFound, `no service "newsletter"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := api.do(http.MethodPost, "/api/registrar/registration-certificates/status", tc.body, "")
			status := http.StatusNotFound
			if tc.code == apierror.InvalidRequest {
				status = http.StatusBadRequest
			}
			wantError(t, rec, status, tc.code, tc.want)
		})
	}
}

// statusListBits fetches the status list and reads the bits at indices
// (Token Status List §4.1: bit i of the list is bit i%8 of byte i/8).
func statusListBits(t *testing.T, api *testAPI, indices []int) []bool {
	t.Helper()
	rec := api.do(http.MethodGet, RegistrationStatusListPath, nil, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != statuslist.MediaTypeJWT || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("status list: %d %v", rec.Code, rec.Header())
	}
	payload, err := jws.Verify(rec.Body.String(), &api.env.registrarKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub        string `json:"sub"`
		Iss        string `json:"iss"`
		StatusList struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "https://wallet.example"+RegistrationStatusListPath || claims.Iss != "https://wallet.example" || claims.StatusList.Bits != 1 {
		t.Errorf("status list claims %s", payload)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(claims.StatusList.Lst)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	bitstring, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	bits := make([]bool, len(indices))
	for i, index := range indices {
		bits[i] = bitstring[index/8]&(1<<(index%8)) != 0
	}
	return bits
}

func TestTheStatusListNeedsTheRegistrarSigner(t *testing.T) {
	api := newTestAPI(t)
	api.env.signErr = errors.New("signer down")
	wantError(t, api.do(http.MethodGet, RegistrationStatusListPath, nil, ""), http.StatusInternalServerError, apierror.ServerError, "signer down")
	wantError(t, api.do(http.MethodPost, "/api/registrar/registration-certificates", "{", ""), http.StatusBadRequest, apierror.InvalidRequest, "invalid request body")
}

func TestTheCertificateListFiltersByRelyingParty(t *testing.T) {
	api := newTestAPI(t)
	shop := registerTestRelyingParty(t, api.testWallet)
	issueTestRegistrationCertificate(t, api.testWallet, shop)
	other, err := api.RegisterRelyingParty(WalletRelyingParty{TradeName: "Other Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}})
	if err != nil {
		t.Fatal(err)
	}
	issueTestRegistrationCertificate(t, api.testWallet, other)
	for query, want := range map[string]int{"": 2, "?identifier=" + other.Identifier[0].Identifier: 1, "?identifier=NLTEST.UNKNOWN": 0} {
		rec := api.do(http.MethodGet, "/api/registrar/registration-certificates"+query, nil, "")
		if got := decodeBody[[]RegistrationStatusView](t, rec); len(got) != want {
			t.Errorf("%q: %d certificates, want %d", query, len(got), want)
		}
	}
}

// ETSI TS 119 411-8 V1.1.1 GEN-6.6.1-10: the access certificate takes the
// subject from the registration and only the key from the CSR.
func TestTheAccessCertificateAPI(t *testing.T) {
	api := newTestAPI(t)
	rp, err := api.RegisterRelyingParty(WalletRelyingParty{
		TradeName: "Example Shop", Country: "DE", LegalPerson: LegalPerson{LegalName: []string{"Example Shop GmbH"}},
		Services: []WalletRelyingPartyService{{ServiceIdentifier: "checkout", IntendedUses: []IntendedUse{ageCheckUse("Age check")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id := rp.Identifier[0].Identifier
	rec := api.do(http.MethodPost, "/api/registrar/access-certificates", AccessCertificateRequest{Identifier: id, CSR: testAccessCSR(t, key), Validity: "720h"}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	result := decodeBody[AccessCertificateResult](t, rec)
	block, _ := pem.Decode([]byte(result.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(api.env.accessCA); err != nil {
		t.Errorf("the access CA did not sign the certificate: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("the certificate does not carry the key of the CSR")
	}
	subject, legalName, country := AccessCertificateSubject(cert)
	if subject != "NTRDE-"+id || legalName != "Example Shop GmbH" || country != "DE" || cert.Subject.CommonName != "Example Shop" || cert.Subject.OrganizationalUnit[0] != "checkout" {
		t.Errorf("subject %q %q %q, %+v", subject, legalName, country, cert.Subject)
	}
	if want := []string{strings.TrimRight(api.env.base, "/") + AccessCACertificatePath}; !slices.Equal(cert.IssuingCertificateURL, want) {
		t.Errorf("caIssuers %v, want %v", cert.IssuingCertificateURL, want)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore).Hours(); got > 721 || got < 719 {
		t.Errorf("valid for %.0fh, want 720h", got)
	}
	if !strings.HasPrefix(result.Chain, result.Certificate) || strings.Count(result.Chain, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain %s, want the leaf and the CA", result.Chain)
	}

	wantError(t, api.do(http.MethodPost, "/api/registrar/access-certificates", "{", ""), http.StatusBadRequest, apierror.InvalidRequest, "invalid request body")
	wantError(t, api.do(http.MethodPost, "/api/registrar/access-certificates", AccessCertificateRequest{Identifier: "NLTEST.UNKNOWN", CSR: testAccessCSR(t, key)}, ""), http.StatusNotFound, apierror.NotFound, "not registered")
	wantError(t, api.do(http.MethodPost, "/api/registrar/access-certificates", AccessCertificateRequest{Identifier: id, ServiceIdentifier: "newsletter", CSR: testAccessCSR(t, key)}, ""), http.StatusNotFound, apierror.NotFound, `no service "newsletter"`)
	api.env.accessCAErr = errors.New("CA offline")
	wantError(t, api.do(http.MethodPost, "/api/registrar/access-certificates", AccessCertificateRequest{Identifier: id, CSR: testAccessCSR(t, key)}, ""), http.StatusInternalServerError, apierror.ServerError, "CA offline")
}

// An access certificate without an organizationIdentifier is read by its
// common name.
func TestTheAccessCertificateSubjectFallsBackToTheCommonName(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mock.GenerateNamedCACert(key, "Legacy Verifier")
	if err != nil {
		t.Fatal(err)
	}
	identifier, legalName, country := AccessCertificateSubject(cert)
	if identifier != "Legacy Verifier" || legalName != cert.Subject.Organization[0] || country != cert.Subject.Country[0] {
		t.Errorf("subject %q %q %q of %+v", identifier, legalName, country, cert.Subject)
	}
}
