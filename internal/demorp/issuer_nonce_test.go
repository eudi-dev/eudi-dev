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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// OpenID4VCI 1.0 wallets fetch c_nonce from the Nonce Endpoint. Omitting that endpoint
// leaves them unable to create a valid proof.
func TestIssuerMetadataAdvertisesTheNonceEndpoint(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	endpoint, _ := metadata["nonce_endpoint"].(string)
	if endpoint == "" {
		t.Fatal("issuer metadata advertises no nonce_endpoint")
	}
	if !strings.HasSuffix(endpoint, "/nonce") {
		t.Errorf("nonce_endpoint = %q, want it to end in /nonce", endpoint)
	}
}

// OpenID4VCI 1.0 §12.2.4 puts display and claims inside credential_metadata. Wallets
// need that structure to populate consent dialogs.
func TestIssuerMetadataPutsDisplayAndClaimsUnderCredentialMetadata(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	config, _ := configs[ticketConfigurationID].(map[string]any)
	if config == nil {
		t.Fatalf("no %s configuration in %v", ticketConfigurationID, configs)
	}
	if _, present := config["display"]; present {
		t.Error("display is still a top-level member of the credential configuration")
	}
	if _, present := config["claims"]; present {
		t.Error("claims is still a top-level member of the credential configuration")
	}

	credentialMetadata, _ := config["credential_metadata"].(map[string]any)
	if credentialMetadata == nil {
		t.Fatalf("configuration has no credential_metadata object: %v", config)
	}
	display, _ := credentialMetadata["display"].([]any)
	if len(display) == 0 {
		t.Fatalf("credential_metadata carries no display array: %v", credentialMetadata)
	}
	first, _ := display[0].(map[string]any)
	if first["name"] != "Demo Event Ticket" {
		t.Errorf("display name = %v, want Demo Event Ticket", first["name"])
	}
	claims, _ := credentialMetadata["claims"].([]any)
	described := map[string]bool{}
	for _, entry := range claims {
		claim, _ := entry.(map[string]any)
		path, _ := claim["path"].([]any)
		if len(path) == 0 {
			t.Errorf("claim entry has no path: %v", entry)
			continue
		}
		name, _ := path[0].(string)
		described[name] = true
	}
	for _, name := range []string{"event", "tier", "seat", "given_name", "family_name", "wallet_attestation"} {
		if !described[name] {
			t.Errorf("credential_metadata describes no %s claim: %v", name, claims)
		}
	}
}

func TestNonceEndpoint(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()

	get := func() (map[string]any, *httptest.ResponseRecorder) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/nonce", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding nonce response: %v (%s)", err, rec.Body.String())
		}
		return resp, rec
	}

	resp, rec := get()
	nonce, _ := resp["c_nonce"].(string)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if nonce == "" {
		t.Fatal("the nonce endpoint returned no c_nonce")
	}
	// §7.2 defines c_nonce as the one parameter of a Nonce Response.
	if _, present := resp["c_nonce_expires_in"]; present {
		t.Errorf("nonce response carries c_nonce_expires_in, which §7.2 does not define: %v", resp)
	}
	// Disable caching so another client cannot receive the same challenge from a
	// cache.
	if store := rec.Header().Get("Cache-Control"); !strings.Contains(store, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", store)
	}

	secondResp, _ := get()
	if secondResp["c_nonce"] == nonce {
		t.Error("the nonce endpoint handed out the same challenge twice")
	}

	if !d.nonceIssued(nonce) {
		t.Error("a nonce this issuer handed out was not recognised")
	}
	if d.nonceIssued("never-issued") {
		t.Error("a nonce nobody issued was accepted")
	}
	if d.nonceIssued("") {
		t.Error("an empty nonce was accepted")
	}
}

func TestNonceIssuedRejectsAnExpiredNonce(t *testing.T) {
	d, _, _ := newDemoRP(t)
	if d.nonceIssued(d.newNonce(time.Now().Add(-time.Minute))) {
		t.Error("an expired nonce was accepted")
	}
}

// Visitors share the Nonce Endpoint. A nonce stays valid until it expires,
// however many nonces other clients fetch meanwhile.
func TestANonceOutlastsTheNoncesOfOtherClients(t *testing.T) {
	d, _, _ := newDemoRP(t)
	get := func() string {
		rec := httptest.NewRecorder()
		d.handleNonce(rec, httptest.NewRequest(http.MethodPost, "/nonce", nil))
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp["c_nonce"]
	}
	first := get()
	for range maxEntries + 1 {
		get()
	}
	if !d.nonceIssued(first) {
		t.Error("the first nonce expired early")
	}
}

// Vary one Appendix F.1 proof field at a time to isolate each validation rule.
type proofOptions struct {
	audience  string
	nonce     string
	iat       time.Time
	typ       string
	alg       string
	omitIAT   bool
	keyHeader string // "jwk" (default), "x5c", "kid", "none", "jwk+kid"
}

func proofJWTWith(t *testing.T, d *DemoRP, opts proofOptions) string {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return proofJWTForKey(t, d, key, opts)
}

func proofJWTForKey(t *testing.T, d *DemoRP, key *ecdsa.PrivateKey, opts proofOptions) string {
	t.Helper()
	audience := opts.audience
	if audience == "" {
		audience = d.issuerID()
	}
	issuedAt := opts.iat
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	typ := opts.typ
	if typ == "" {
		typ = "openid4vci-proof+jwt"
	}
	alg := opts.alg
	if alg == "" {
		alg = "ES256"
	}

	payload := map[string]any{"aud": audience}
	if !opts.omitIAT {
		payload["iat"] = issuedAt.Unix()
	}
	if opts.nonce != "" {
		payload["nonce"] = opts.nonce
	}

	header := map[string]any{"alg": alg, "typ": typ}
	switch opts.keyHeader {
	case "", "jwk":
		header["jwk"] = mock.SigningJWKMap(&key.PublicKey)
	case "x5c":
		header["x5c"] = []any{base64.StdEncoding.EncodeToString(selfSignedDER(t, key))}
	case "kid":
		header["kid"] = "did:example:123#key-1"
	case "jwk+kid":
		header["jwk"] = mock.SigningJWKMap(&key.PublicKey)
		header["kid"] = "did:example:123#key-1"
	case "none":
	}

	compact, err := jws.Sign(header, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func selfSignedDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proof key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func issuedNonce(t *testing.T, d *DemoRP) string {
	t.Helper()
	return d.newNonce(time.Now().Add(time.Minute))
}

func TestVerifyProofJWTAcceptsANonceFromTheNonceEndpoint(t *testing.T) {
	d, _, _ := newDemoRP(t)
	nonce := issuedNonce(t, d)

	if _, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce}), d.issuerID()); err != nil {
		t.Errorf("a nonce from the nonce endpoint was refused: %v", err)
	}
}

// The Nonce Endpoint is this issuer's only source of a challenge, per §8.2:
// "The c_nonce value is retrieved from the Nonce Endpoint as defined in
// Section 7." Any other nonce is refused.
func TestVerifyProofJWTRejectsANonceItNeverHandedOut(t *testing.T) {
	d, _, _ := newDemoRP(t)

	_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: "invented"}), d.issuerID())
	if err == nil {
		t.Fatal("a nonce this issuer never handed out was accepted")
	}
	// §8.3.1.2: invalid_nonce tells a wallet to fetch a fresh challenge and try
	// again.
	if err.code != "invalid_nonce" {
		t.Errorf("error code = %q, want invalid_nonce", err.code)
	}
}

// §8.3.1.2 puts a missing challenge under invalid_proof: "(3) if at least one
// of the key proofs does not contain a c_nonce value".
func TestVerifyProofJWTRejectsAProofWithNoNonce(t *testing.T) {
	d, _, _ := newDemoRP(t)

	_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{}), d.issuerID())
	if err == nil {
		t.Fatal("a proof with no nonce was accepted")
	}
	if err.code != "invalid_proof" {
		t.Errorf("error code = %q, want invalid_proof", err.code)
	}
	if !strings.Contains(err.description, "nonce endpoint") {
		t.Errorf("description = %q, want it to point at the nonce endpoint", err.description)
	}
}

// Appendix F.1 makes aud "REQUIRED (string). The value of this claim MUST be
// the Credential Issuer Identifier", and F.4 makes checking it the issuer's
// job. The check stops a proof created for another issuer from being
// replayed here.
func TestVerifyProofJWTRejectsAProofMintedForAnotherIssuer(t *testing.T) {
	d, _, _ := newDemoRP(t)
	nonce := issuedNonce(t, d)

	_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{
		nonce:    nonce,
		audience: "https://another-issuer.example",
	}), d.issuerID())
	if err == nil {
		t.Fatal("a proof addressed to another credential issuer was accepted")
	}
	if !strings.Contains(err.description, "aud") {
		t.Errorf("description = %q, want it to name the aud claim", err.description)
	}
}

func TestVerifyProofJWTRejectsAProofOutsideTheAcceptedIATWindow(t *testing.T) {
	d, _, _ := newDemoRP(t)
	nonce := issuedNonce(t, d)

	t.Run("issued long ago", func(t *testing.T) {
		_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{
			nonce: nonce,
			iat:   time.Now().Add(-2 * freshnessWindow),
		}), d.issuerID())
		if err == nil {
			t.Fatal("a proof issued long before now was accepted")
		}
		if !strings.Contains(err.description, "iat") {
			t.Errorf("description = %q, want it to name iat", err.description)
		}
	})

	t.Run("issued in the future", func(t *testing.T) {
		_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{
			nonce: nonce,
			iat:   time.Now().Add(2 * freshnessWindow),
		}), d.issuerID())
		if err == nil {
			t.Fatal("a proof issued in the future was accepted")
		}
	})

	t.Run("no iat at all", func(t *testing.T) {
		_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce, omitIAT: true}), d.issuerID())
		if err == nil {
			t.Fatal("a proof with no iat was accepted")
		}
	})
}

// Appendix F.4: "the key proof is explicitly typed using header parameters as
// defined for that proof type", and F.1 fixes that type as
// openid4vci-proof+jwt.
func TestVerifyProofJWTRejectsAWronglyTypedProof(t *testing.T) {
	d, _, _ := newDemoRP(t)
	nonce := issuedNonce(t, d)

	_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce, typ: "JWT"}), d.issuerID())
	if err == nil {
		t.Fatal("a proof typed JWT was accepted")
	}
	if !strings.Contains(err.description, "typ") {
		t.Errorf("description = %q, want it to name typ", err.description)
	}
}

// Appendix F.1 offers jwk, kid and x5c and allows exactly one of them.
func TestVerifyProofJWTKeyMaterialForms(t *testing.T) {
	d, _, _ := newDemoRP(t)

	t.Run("x5c", func(t *testing.T) {
		nonce := issuedNonce(t, d)
		if _, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce, keyHeader: "x5c"}), d.issuerID()); err != nil {
			t.Errorf("a proof carrying its key in x5c was refused: %v", err)
		}
	})

	t.Run("kid names a key this issuer cannot resolve", func(t *testing.T) {
		nonce := issuedNonce(t, d)
		_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce, keyHeader: "kid"}), d.issuerID())
		if err == nil {
			t.Fatal("a proof identifying its key only by kid was accepted")
		}
		if !strings.Contains(err.description, "kid") {
			t.Errorf("description = %q, want it to say why kid cannot be used", err.description)
		}
	})

	t.Run("two key parameters at once", func(t *testing.T) {
		nonce := issuedNonce(t, d)
		_, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce, keyHeader: "jwk+kid"}), d.issuerID())
		if err == nil {
			t.Fatal("a proof carrying both jwk and kid was accepted")
		}
	})

	t.Run("no key parameter at all", func(t *testing.T) {
		nonce := issuedNonce(t, d)
		if _, err := d.verifyProofJWT(proofJWTWith(t, d, proofOptions{nonce: nonce, keyHeader: "none"}), d.issuerID()); err == nil {
			t.Fatal("a proof carrying no key material was accepted")
		}
	})
}

func TestVerifyProofJWTRejectsBadProofs(t *testing.T) {
	d, _, _ := newDemoRP(t)
	nonce := issuedNonce(t, d)

	t.Run("not a JWT", func(t *testing.T) {
		if _, err := d.verifyProofJWT("nonsense", d.issuerID()); err == nil {
			t.Error("something that is not a JWT was accepted")
		}
	})

	t.Run("a signature made by another key", func(t *testing.T) {
		other, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		signing, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		compact, err := jws.Sign(map[string]any{
			"alg": "ES256",
			"typ": "openid4vci-proof+jwt",
			"jwk": mock.SigningJWKMap(&other.PublicKey),
		}, map[string]any{"aud": d.issuerID(), "iat": time.Now().Unix(), "nonce": nonce}, signing)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.verifyProofJWT(compact, d.issuerID()); err == nil {
			t.Error("a proof whose signature does not match its jwk was accepted")
		}
	})

	t.Run("a signature that is not valid base64", func(t *testing.T) {
		parts := strings.Split(proofJWTWith(t, d, proofOptions{nonce: nonce}), ".")
		if _, err := d.verifyProofJWT(parts[0]+"."+parts[1]+".!!!", d.issuerID()); err == nil {
			t.Error("an unreadable signature was accepted")
		}
	})

	t.Run("a header that is not JSON", func(t *testing.T) {
		bad := base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".e30.AAAA"
		if _, err := d.verifyProofJWT(bad, d.issuerID()); err == nil {
			t.Error("a header that is not JSON was accepted")
		}
	})
}
