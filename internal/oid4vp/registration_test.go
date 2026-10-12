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

package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

const (
	relyingPartyID = "LEIEU-TEST"
	serviceID      = "age-check"
)

// arfFixture is a relying party with an access certificate issued by an
// access CA and a registrar that issues its registration certificates.
type arfFixture struct {
	accessCA     *x509.Certificate
	access       *x509.Certificate
	accessKey    *ecdsa.PrivateKey
	registrarCA  *x509.Certificate
	registrarKey *ecdsa.PrivateKey
}

func newARFFixture(t *testing.T) arfFixture {
	t.Helper()
	caKey, caCert := testCA(t, "Access CA")
	registrarKey, registrarCert := testCA(t, "Registrar CA")
	accessKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// ETSI TS 119 411-8 puts the relying party identifier in
	// organizationIdentifier and the service in organizationalUnit.
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject: pkix.Name{
			CommonName:         "Verifier",
			OrganizationalUnit: []string{serviceID},
			ExtraNames:         []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: relyingPartyID}},
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"verifier.example"},
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}, caCert, &accessKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	access, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return arfFixture{accessCA: caCert, access: access, accessKey: accessKey, registrarCA: registrarCert, registrarKey: registrarKey}
}

func registrationClaims(sub string) map[string]any {
	return map[string]any{
		"name":                           "Test Verifier",
		"sub":                            sub,
		registrar.ServiceIdentifierClaim: serviceID,
		"country":                        "EU",
		"registry_uri":                   "https://registrar.example",
		"policy_id":                      []any{"0.4.0.19475.3.1"},
		"certificate_policy":             "https://registrar.example/policy",
		"srv_description":                []any{map[string]any{"lang": "en", "value": "Age check"}},
		"purpose":                        []any{map[string]any{"lang": "de", "value": "Altersprüfung"}, map[string]any{"lang": "en", "value": "Check the age of the user"}},
		"entitlements":                   []any{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy":                 "https://verifier.example/privacy",
		"support_uri":                    "https://verifier.example/support",
		"supervisory_authority":          map[string]any{"name": "Test DPA", "country": "NL", "email": "dpa@example"},
		"iat":                            float64(time.Now().Unix()),
		"credentials": []any{map[string]any{
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claim":  []any{map[string]any{"path": []any{"given_name"}}},
		}},
	}
}

// registration returns a verifier_info entry with a registration certificate
// that the registrar signed. ETSI TS 119 472-2 RO-16 base64url-encodes it.
func (f arfFixture) registration(t *testing.T, claims map[string]any) map[string]any {
	t.Helper()
	header := map[string]any{"alg": "ES256", "typ": registrar.RegistrationCertificateTyp, "x5c": []any{base64.StdEncoding.EncodeToString(f.registrarCA.Raw)}}
	compact, err := jws.Sign(header, claims, f.registrarKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"format": "registration_cert", "data": format.EncodeBase64URL([]byte(compact))}
}

// request signs a valid x509_san_dns request with the access certificate.
func (f arfFixture) request(t *testing.T, verifierInfo ...map[string]any) *Request {
	t.Helper()
	info := make([]any, len(verifierInfo))
	for i, entry := range verifierInfo {
		info[i] = entry
	}
	claims := map[string]any{
		"client_id": sanDNSClientID, "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": "https://verifier.example/response", "nonce": "n-arf", "aud": SelfIssuedAudience,
		"dcql_query": sdjwtVCTQuery("urn:eudi:pid:1"), "verifier_info": info,
	}
	raw, err := SignRequestObjectJWT(claims, f.accessKey, []*x509.Certificate{f.access, f.accessCA})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthorizationRequestWithOptions(raw, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	params := RequestFrom(parsed)
	params.RelyingPartyCAs = []*x509.Certificate{f.accessCA}
	params.RegistrarCAs = []*x509.Certificate{f.registrarCA}
	return params
}

// ARF RPA_10 shows the registered purposes. OpenID4VP 1.0 §5.1 requires the
// wallet to "validate the signature and ensure binding" of verifier_info it
// uses.
func TestConsentShowsTheBoundRegistration(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims(relyingPartyID)))

	purposes, policies := ConsentRegistration(params)
	if !reflect.DeepEqual(purposes, []string{"Check the age of the user"}) || !reflect.DeepEqual(policies, []string{"https://verifier.example/privacy"}) {
		t.Errorf("purposes %v policies %v, want the English purpose and the privacy policy", purposes, policies)
	}
	if got := RegisteredName(params); got != "Test Verifier" {
		t.Errorf("registered name = %q", got)
	}
}

// ETSI TS 119 475 GEN-5.1.1-03 binds the registration certificate to the
// access certificate through the relying party identifier.
func TestARegistrationForAnotherRelyingPartyIsNotShown(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims("LEIEU-OTHER")))

	if purposes, policies := ConsentRegistration(params); len(purposes) != 0 || len(policies) != 0 {
		t.Errorf("purposes %v policies %v from an unbound registration", purposes, policies)
	}
	if got := RegisteredName(params); got != "" {
		t.Errorf("registered name = %q from an unbound registration", got)
	}
	want := `ARF RPRC_17a: the registration certificate identifies "LEIEU-OTHER", but the access certificate's organizationIdentifier is "LEIEU-TEST"`
	if findings := ARFFindings(params); !containsSubstring(findings, want) {
		t.Errorf("findings = %v, want %q", findings, want)
	}
}

// A registration certificate needs an access certificate that signed the
// request. An unsigned request has none.
func TestConsentRegistrationNeedsASignedRequest(t *testing.T) {
	f := newARFFixture(t)
	info, err := json.Marshal([]any{f.registration(t, registrationClaims(relyingPartyID))})
	if err != nil {
		t.Fatal(err)
	}
	params := redirectRequest(func(r *Request) { r.FullParams = map[string]string{"verifier_info": string(info)} })
	if purposes, _ := ConsentRegistration(params); len(purposes) != 0 {
		t.Errorf("purposes %v from an unsigned request", purposes)
	}
	if purposes, _ := ConsentRegistration(nil); len(purposes) != 0 {
		t.Errorf("purposes %v without a request", purposes)
	}
	// The registration certificate in the plain verifier_info parameter is
	// read, and the missing access certificate is the finding.
	findings := ARFFindings(params)
	if !containsSubstring(findings, "ARF RPA_03: the request is not signed with a relying party access certificate in x5c") {
		t.Errorf("findings = %v, want the RPA_03 finding", findings)
	}
	if containsSubstring(findings, "carries no registration certificate") {
		t.Errorf("findings = %v, the verifier_info parameter carries one", findings)
	}
}

func TestARFFindingsOfATrustedRelyingParty(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims(relyingPartyID)))
	want := []string{"ETSI TS 119 475 V1.2.1 Table 7: the registration certificate has no status (its entry in the registrar's status list), so the wallet cannot check revocation"}
	if findings := ARFFindings(params); !reflect.DeepEqual(findings, want) {
		t.Errorf("findings = %v, want %v", findings, want)
	}
}

// ARF RPA_04 anchors the access certificate and RPRC_02a the registration
// certificate in the trusted lists.
func TestARFFindingsNeedTrustAnchors(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims(relyingPartyID)))
	params.RelyingPartyCAs, params.RegistrarCAs = nil, nil
	findings := ARFFindings(params)
	for _, want := range []string{
		`ARF RPA_04: the access certificate "CN=Verifier,OU=age-check,2.5.4.97=LEIEU-TEST" does not chain to a trusted access certificate authority`,
		"ARF RPRC_02a: the registration certificate of Test Verifier does not chain to a trusted registrar",
	} {
		if !containsSubstring(findings, want) {
			t.Errorf("findings = %v, want %q", findings, want)
		}
	}
}

// ARF RPRC_19: a request carries exactly one registration certificate.
func TestARFFindingsCountTheRegistrationCertificates(t *testing.T) {
	f := newARFFixture(t)
	entry := f.registration(t, registrationClaims(relyingPartyID))
	params := f.request(t, entry, entry)
	if findings := ARFFindings(params); !containsSubstring(findings, "ARF RPRC_19: the request carries 2 registration certificates. It must carry exactly one") {
		t.Errorf("findings = %v, want the RPRC_19 finding", findings)
	}
}

func TestARFFindingsReportABrokenRegistrationCertificate(t *testing.T) {
	f := newARFFixture(t)
	entry := f.registration(t, registrationClaims(relyingPartyID))
	compact, err := format.DecodeBase64URL(entry["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(compact), ".")
	entry["data"] = parts[0] + "." + parts[1] + ".AAAA"
	findings := ARFFindings(f.request(t, entry))
	if !containsSubstring(findings, "ARF RPRC_17: the registration certificate has a signature that does not verify with its x5c leaf") {
		t.Errorf("findings = %v, want the signature problem", findings)
	}
}

// ARF RPRC_21 compares the request with the registered credentials.
func TestARFFindingsReportOverAsking(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims(relyingPartyID)))
	params.DCQLQuery = sdjwtVCTQuery("urn:eudi:other:1")
	if findings := ARFFindings(params); !containsSubstring(findings, "RPRC_21") {
		t.Errorf("findings = %v, want the RPRC_21 finding", findings)
	}
}

// The relying party signed with a trusted access certificate, so strict mode
// answers its ARF findings with access_denied (RFC 6749 §4.1.2.1).
func TestStrictARFRefusalOfAnAuthenticatedRelyingParty(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims(relyingPartyID)))

	_, err := ValidateAuthorizationRequest(Checks{Strict: true, ARF: true}, params)
	var refusal *ARFRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want an ARFRefusal", err)
	}
	if len(refusal.Findings) != 1 || !strings.Contains(refusal.Findings[0], "Table 7") {
		t.Errorf("refusal findings = %v", refusal.Findings)
	}
	if !strings.HasPrefix(refusal.Error(), "authorization request validation failed: ETSI TS 119 475 V1.2.1 Table 7") {
		t.Errorf("refusal = %q", refusal.Error())
	}

	findings, err := ValidateAuthorizationRequest(Checks{ARF: true}, params)
	if err != nil || !reflect.DeepEqual(findings, refusal.Findings) {
		t.Errorf("findings %v err %v, want the ARF findings as warnings", findings, err)
	}

	// Without a trusted access certificate the relying party is not
	// authenticated, and the refusal is an ordinary validation error.
	params.RelyingPartyCAs = nil
	_, err = ValidateAuthorizationRequest(Checks{Strict: true, ARF: true}, params)
	if err == nil || errors.As(err, &refusal) || !strings.Contains(err.Error(), "ARF RPA_04") {
		t.Errorf("err = %v, want a plain refusal naming RPA_04", err)
	}
}

// requestAccessChain uses x5c only when its leaf signed the request.
func TestTheAccessCertificateMustSignTheRequest(t *testing.T) {
	f := newARFFixture(t)
	params := f.request(t, f.registration(t, registrationClaims(relyingPartyID)))
	parts := strings.Split(params.RequestObject.Raw, ".")
	params.RequestObject.Raw = parts[0] + "." + parts[1] + ".AAAA"
	if findings := ARFFindings(params); !containsSubstring(findings, "ARF RPA_03") {
		t.Errorf("findings = %v, want RPA_03 for a signature the leaf did not make", findings)
	}
	if purposes, _ := ConsentRegistration(params); len(purposes) != 0 {
		t.Errorf("purposes %v from a request the access certificate did not sign", purposes)
	}

	params.RequestObject.Header["alg"] = "none"
	if findings := ARFFindings(params); !containsSubstring(findings, "ARF RPA_03") {
		t.Errorf("findings = %v, want RPA_03 for alg none", findings)
	}
}
