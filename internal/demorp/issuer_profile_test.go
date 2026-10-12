package demorp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// TS 119 472-3 V1.1.1 §4.2 requires signed metadata from the actual issuer.
func TestIssuerProfileMetadata(t *testing.T) {
	d, w, _ := newDemoRP(t)
	w.IssuerURL = "https://demo.example"
	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}
	code, unsigned := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	if code != http.StatusOK {
		t.Fatal(code)
	}
	info, ok := unsigned["issuer_info"].([]any)
	if !ok || len(info) != 1 {
		t.Fatalf("issuer_info %v, want the registration certificate", unsigned["issuer_info"])
	}
	registration := info[0].(map[string]any)
	if registration["format"] != "registration_cert" {
		t.Fatal("issuer metadata has no registration certificate")
	}
	registrationJWT, err := jose.ParseSigned(registration["data"].(string), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	_, registrarChain, err := w.Signer().Registrar()
	if err != nil {
		t.Fatal(err)
	}
	registeredPayload, err := registrationJWT.Verify(registrarChain[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var registered map[string]any
	if err := json.Unmarshal(registeredPayload, &registered); err != nil {
		t.Fatal(err)
	}
	if registered["sub"] != "NTRNL-NLTEST.00000000" || registered["provides_attestations"] == nil {
		t.Fatal("registration certificate does not identify the provider and its credentials")
	}
	if want := w.RegistrarBase() + "/api/registrar/wrp/NLTEST.00000000"; registered["registry_uri"] != want {
		t.Errorf("registry_uri %v, want %s", registered["registry_uri"], want)
	}
	configs := unsigned["credential_configurations_supported"].(map[string]any)
	for id, config := range configs {
		entry := config.(map[string]any)
		if entry["format"] == "mso_mdoc" {
			algs, ok := entry["credential_signing_alg_values_supported"].([]any)
			if !ok || len(algs) != 1 || algs[0] != float64(-7) {
				t.Errorf("%s advertises %v, want COSE -7", id, entry["credential_signing_alg_values_supported"])
			}
		}
	}
	req := httptest.NewRequest("GET", "/.well-known/openid-credential-issuer", nil)
	req.Header.Set("Accept", "application/jwt")
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	if rec.Header().Get("Content-Type") != "application/jwt" {
		t.Fatalf("signed metadata content type = %s", rec.Header().Get("Content-Type"))
	}
	jws, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		X5C []string `json:"x5c"`
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(rec.Body.String(), ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	x5c, ok := header.X5C, len(header.X5C) > 0
	if !ok || len(x5c) == 0 {
		t.Fatal("missing protected x5c")
	}
	der, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKey.(*ecdsa.PublicKey).Equal(&w.IssuerKey.PublicKey) {
		t.Error("credential key signs issuer metadata")
	}
	if len(cert.PolicyIdentifiers) != 1 || cert.PolicyIdentifiers[0].String() != "0.4.0.194118.1.2" {
		t.Errorf("access certificate policies = %v", cert.PolicyIdentifiers)
	}
	payload, err := jws.Verify(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var signed map[string]any
	if err := json.Unmarshal(payload, &signed); err != nil {
		t.Fatal(err)
	}
	if signed["sub"] != unsigned["credential_issuer"] || signed["issuer_info"] == nil {
		t.Errorf("signed metadata does not identify the issuer: %v", signed)
	}
}

// The identity check of the demo issuer carries the registration certificate
// of its intended use. It names the subject of the access certificate (ETSI
// TS 119 475 V1.2.1 §5.1.1) and its trade name (ARF RPRC_06).
func TestDemoRegistrationMatchesAccessCertificate(t *testing.T) {
	_, w, _ := newDemoRP(t)
	// The registrar publishes under the issuer URL, which differs from the
	// base URL without --base-url.
	w.IssuerURL = "https://localhost:9999"
	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}
	_, chain, err := w.AccessSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	info, err := w.DemoIdentityCheckVerifierInfo()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := base64.RawURLEncoding.DecodeString(info[0].(map[string]any)["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(string(certificate), ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub, Country, Name string
		RegistryURI        string `json:"registry_uri"`
		Status             struct {
			StatusList struct{ URI string } `json:"status_list"`
		}
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	var identifier string
	for _, attribute := range chain[0].Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			identifier, _ = attribute.Value.(string)
		}
	}
	if claims.Sub != identifier || claims.Country != chain[0].Subject.Country[0] || claims.Name != chain[0].Subject.CommonName {
		t.Errorf("registered identity %+v, want the access certificate subject %v", claims, chain[0].Subject)
	}
	rp, ok := w.Registrar().RelyingParty(identifier)
	if !ok {
		t.Fatalf("no registration for the access certificate's %s", identifier)
	}
	if claims.RegistryURI != w.RegistrarBase()+"/api/registrar/wrp/"+rp.Identifier[0].Identifier || claims.Status.StatusList.URI != w.Registrar().RegistrationStatusListURL() {
		t.Errorf("registry URI %q and status list %q, want the wallet's registrar", claims.RegistryURI, claims.Status.StatusList.URI)
	}
}

// A local wallet lets the user delete the demo issuer's registration. Its
// metadata then goes out without issuer_info.
func TestTheDemoIssuerMetadataGoesOutWithoutARegistration(t *testing.T) {
	d, w, _ := newDemoRP(t)
	w.IssuerURL = "https://demo.example"
	code, metadata := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	if code != http.StatusOK || metadata["credential_issuer"] == nil {
		t.Fatalf("issuer metadata = %d: %v", code, metadata)
	}
	if metadata["issuer_info"] != nil {
		t.Errorf("issuer_info = %v, want none", metadata["issuer_info"])
	}
}
