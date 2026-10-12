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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

const demoIssuerID = "http://demo.example/issuer"

func postForm(t *testing.T, h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Reject invalid client authentication before saving a pushed request or issuing a
// request_uri.
func TestPushedAuthorizationRequestRejections(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()

	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		wantError  string
	}{
		{
			// Without a DPoP proof only client authentication is checked. A
			// client that presents none is refused.
			name: "no client authentication",
			form: url.Values{
				"client_id":             {"wallet"},
				"response_type":         {"code"},
				"code_challenge_method": {"S256"},
				"code_challenge":        {"abc"},
				"redirect_uri":          {"http://wallet.example/cb"},
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postForm(t, h, "/par", tt.form)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantError) {
				t.Errorf("body = %s, want it to name %s", rec.Body.String(), tt.wantError)
			}
		})
	}
}

// A request_uri nobody pushed cannot be resolved. The error is shown on the
// authorization endpoint because the caller supplied the redirect URL.
func TestAuthorizeRejectsAnUnknownRequestURI(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape("urn:ietf:params:oauth:request_uri:nope"), nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("body = %s, want an invalid_request error", rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("Location = %q, want the error kept here rather than redirected", location)
	}
}

func TestAuthorizeRejectsAMissingRequestURI(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestAuthorizeSubmitRejectsAnUnknownRequest(t *testing.T) {
	d, _, _ := newDemoRP(t)

	rec := postForm(t, d.IssuerHandler(), "/authorize", url.Values{
		"request_uri": {"urn:ietf:params:oauth:request_uri:nope"},
		"username":    {"erika"},
		"password":    {"whatever"},
	})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("body = %s, want an invalid_request error", rec.Body.String())
	}
}

func TestAuthorizeSubmitRejectsAMissingRequestURI(t *testing.T) {
	d, _, _ := newDemoRP(t)

	rec := postForm(t, d.IssuerHandler(), "/authorize", url.Values{"username": {"erika"}})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

type walletProvider struct {
	key  *ecdsa.PrivateKey
	leaf *x509.Certificate
}

func foreignWalletProvider(t *testing.T) walletProvider {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating attester CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating attester CA certificate: %v", err)
	}
	signingKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating attester signing key: %v", err)
	}
	leaf, err := mock.GenerateLeafCert(caKey, caCert, &signingKey.PublicKey)
	if err != nil {
		t.Fatalf("generating attester leaf certificate: %v", err)
	}
	return walletProvider{key: signingKey, leaf: leaf}
}

// attest issues a Client Attestation JWT for a client and the key it holds.
// The claims are those draft-ietf-oauth-attestation-based-client-auth-10 §4
// requires, which from draft -08 on do not include iss.
func (p walletProvider) attest(t *testing.T, clientID string, clientKey *ecdsa.PrivateKey) string {
	t.Helper()
	return signES256(t, p.key,
		map[string]any{
			"alg": "ES256",
			"typ": "oauth-client-attestation+jwt",
			"x5c": []any{base64.StdEncoding.EncodeToString(p.leaf.Raw)},
		},
		map[string]any{
			"sub": clientID,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"cnf": map[string]any{"jwk": holderJWK(t, clientKey)},
		},
	)
}

// attestationPoP proves possession of the attested key for one request, with
// the claims §5.1 requires and no others.
func attestationPoP(t *testing.T, clientKey *ecdsa.PrivateKey, audience string) string {
	t.Helper()
	return signES256(t, clientKey,
		map[string]any{"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "jwk": holderJWK(t, clientKey)},
		map[string]any{"aud": audience, "iat": time.Now().Unix(), "jti": "pop-" + audience},
	)
}

func dpopProof(t *testing.T, key *ecdsa.PrivateKey, method, htu string) string {
	t.Helper()
	return dpopProofForToken(t, key, method, htu, "")
}

// dpopProofForToken adds the ath claim RFC 9449 requires of a proof that
// accompanies an access token.
func dpopProofForToken(t *testing.T, key *ecdsa.PrivateKey, method, htu, accessToken string) string {
	t.Helper()
	payload := map[string]any{"htm": method, "htu": htu, "iat": time.Now().Unix(), "jti": "dpop-" + htu}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = format.EncodeBase64URL(sum[:])
	}
	return signES256(t, key,
		map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, key)},
		payload,
	)
}

// pushAuthorizationRequest pushes a minimal but complete authorization request
// with whatever client authentication the headers carry. A nil dpopKey pushes
// without a DPoP proof, which RFC 9449 §10.1 leaves to the client.
func pushAuthorizationRequest(t *testing.T, h http.Handler, clientID string, dpopKey *ecdsa.PrivateKey, challenge string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {challenge},
		"redirect_uri":          {"http://wallet.example/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopKey != nil {
		req.Header.Set("DPoP", dpopProof(t, dpopKey, "POST", demoIssuerID+"/par"))
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// RFC 9449 §10 makes dpop_jkt OPTIONAL, and §10.1 lets the client send a DPoP
// header at the PAR endpoint. Binding the code to a DPoP key is the client's
// choice, so a pushed request with an attestation and a PoP JWT is accepted
// without a DPoP proof.
func TestPushedAuthorizationRequestWithoutDPoP(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", nil, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
}

// External wallets may use unknown attestation CAs. Accept them for interoperability
// testing and record the missing trust on the ticket.
func TestPushedAuthorizationRequestAcceptsAnUntrustedAttester(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
}

// ABCA draft -10 §5.2 defines the DPoP-combined method. The request carries
// the attestation and a DPoP proof signed by the attested key, with no
// separate PoP JWT. A DPoP proof from any other key is refused.
func TestPushedAuthorizationRequestAcceptsADPoPCombinedProof(t *testing.T) {
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating second key: %v", err)
	}

	t.Run("the DPoP proof is signed by the attested key", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
			"OAuth-Client-Attestation": provider.attest(t, "http://wallet.example", clientKey),
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("the DPoP proof is signed by another key", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", otherKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
			"OAuth-Client-Attestation": provider.attest(t, "http://wallet.example", clientKey),
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid_client_attestation") {
			t.Errorf("body = %s, want an invalid_client_attestation error", rec.Body.String())
		}
	})
}

// ABCA draft-10 §7.4 distinguishes an invalid attestation from missing client
// authentication.
func TestPushedAuthorizationRequestNamesABrokenAttestation(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "the attestation names another client",
			headers: map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "http://somebody.else", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			},
		},
		{
			name: "the PoP is signed by a key the attestation does not attest",
			headers: map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, provider.key, demoIssuerID),
			},
		},
		{
			name: "the PoP is addressed to another server",
			headers: map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, "http://another.example"),
			},
		},
		{
			name: "a PoP arrives without the attestation it proves",
			headers: map[string]string{
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", tt.headers)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_client_attestation") {
				t.Errorf("body = %s, want an invalid_client_attestation error", rec.Body.String())
			}
		})
	}
}

// Requests without client authentication return invalid_client.
func TestPushedAuthorizationRequestWithoutClientAuthentication(t *testing.T) {
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	t.Run("required by default", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"invalid_client"`) {
			t.Errorf("body = %s, want an invalid_client error", rec.Body.String())
		}
	})

	t.Run("optional", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		d.SetClientAuthMode(ClientAuthOptional)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
		}
	})

	// An unauthenticated client is identified by client_id alone, so a request
	// that carries neither identifies nobody.
	t.Run("optional and nameless", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		d.SetClientAuthMode(ClientAuthOptional)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
		}
	})
}

// A token endpoint refusal is a 400: RFC 6749 §5.2 responds "with an HTTP 400
// (Bad Request) status code (unless specified otherwise)", and reserves 401
// for a client that "attempted to authenticate via the Authorization request
// header field", which the attestation headers are not. Attestation-based
// client authentication delegates its error responses to that section
// (draft-ietf-oauth-attestation-based-client-auth-10 §7.4).
func TestTokenEndpointRefusesABrokenAttestationWith400(t *testing.T) {
	d, _, _ := newDemoRP(t)

	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/token",
		url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {"whatever"}}.Encode(),
		map[string]string{
			"Content-Type":             "application/x-www-form-urlencoded",
			"OAuth-Client-Attestation": "not-a-jwt",
		})

	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%v)", code, doc)
	}
	if doc["error"] != "invalid_client_attestation" {
		t.Fatalf("error = %v, want invalid_client_attestation", doc["error"])
	}
}

// A client that authenticates at the token endpoint may omit client_id there:
// RFC 6749 §4.1.3 has it "REQUIRED, if the client is not authenticating with
// the authorization server", and the server ensures "that the authorization
// code was issued to the authenticated confidential client". The attestation's
// sub identifies the client, so the code check runs against it.
func TestAuthorizationCodeTokenExchangeWithoutClientIDParameter(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	clientID := "http://wallet.example"

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	challenge := format.EncodeBase64URL(sum[:])

	pushed := pushAuthorizationRequest(t, h, clientID, holderKey, challenge, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, clientID, clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	})
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)

	login := postForm(t, h, "/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {demoAccountUsername},
		"password":    {demoAccountPassword},
	})
	if login.Code != http.StatusFound {
		t.Fatalf("signing in: %d %s", login.Code, login.Body.String())
	}
	redirect, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the callback: %v", err)
	}
	authCode := redirect.Query().Get("code")

	tokenForm := url.Values{
		"grant_type":    {authCodeGrant},
		"code":          {authCode},
		"redirect_uri":  {"http://wallet.example/cb"},
		"code_verifier": {verifier},
	}
	code, tokenDoc := doJSON(t, h, "POST", "/token", tokenForm.Encode(), map[string]string{
		"Content-Type":                 "application/x-www-form-urlencoded",
		"DPoP":                         dpopProof(t, holderKey, "POST", demoIssuerID+"/token"),
		"OAuth-Client-Attestation":     provider.attest(t, clientID, clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	})
	if code != http.StatusOK {
		t.Fatalf("token request without client_id: %d %v", code, tokenDoc)
	}
	if accessToken, _ := tokenDoc["access_token"].(string); accessToken == "" {
		t.Fatalf("no access token in %v", tokenDoc)
	}
}

// Optional mode allows the full authorization code flow without client authentication.
// The ticket records that choice.
func TestAuthorizationCodeFlowWithoutClientAuthentication(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	challenge := format.EncodeBase64URL(sum[:])

	code, offerDoc := doJSON(t, h, "POST", "/api/offers?grant="+authCodeGrant, "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}

	pushed := pushAuthorizationRequest(t, h, "http://wallet.example", holderKey, challenge, nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("no request_uri in %v", pushedDoc)
	}

	login := postForm(t, h, "/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {demoAccountUsername},
		"password":    {demoAccountPassword},
	})
	if login.Code != http.StatusFound {
		t.Fatalf("signing in: %d %s", login.Code, login.Body.String())
	}
	redirect, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the callback: %v", err)
	}
	authCode := redirect.Query().Get("code")
	if authCode == "" {
		t.Fatalf("the callback %q carries no code", redirect)
	}

	tokenForm := url.Values{
		"grant_type":    {authCodeGrant},
		"code":          {authCode},
		"client_id":     {"http://wallet.example"},
		"redirect_uri":  {"http://wallet.example/cb"},
		"code_verifier": {verifier},
	}
	code, tokenDoc := doJSON(t, h, "POST", "/token", tokenForm.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         dpopProof(t, holderKey, "POST", demoIssuerID+"/token"),
	})
	if code != http.StatusOK {
		t.Fatalf("token request: %d %v", code, tokenDoc)
	}
	accessToken, _ := tokenDoc["access_token"].(string)

	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": demoIssuerID, "iat": time.Now().Unix(), "nonce": nonceDoc["c_nonce"]},
	)
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q]}}`, ticketConfigurationID, proof)
	code, credDoc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "DPoP " + accessToken,
		"Content-Type":  "application/json",
		"DPoP":          dpopProofForToken(t, holderKey, "POST", demoIssuerID+"/credential", accessToken),
	})
	if code != http.StatusOK {
		t.Fatalf("credential request: %d %v", code, credDoc)
	}

	creds, _ := credDoc["credentials"].([]any)
	first, _ := creds[0].(map[string]any)
	raw, _ := first["credential"].(string)
	issued, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the issued credential: %v", err)
	}
	// The ticket must state that the client supplied no wallet attestation.
	if got := issued.ResolvedClaims["wallet_attestation"]; got != "none" {
		t.Errorf("wallet_attestation = %v, want none", got)
	}
	if got := issued.ResolvedClaims["given_name"]; got != demoAccountGivenName {
		t.Errorf("given_name = %v, want %q", got, demoAccountGivenName)
	}
}

// RFC 9126 §4 gives a client one use of a request_uri. A second authorization
// request with the same request_uri fails.
func TestAuthorizeSpendsTheRequestURI(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	pushed := pushAuthorizationRequest(t, h, "http://wallet.example", holderKey, format.EncodeBase64URL(sum[:]), nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("no request_uri in %v", pushedDoc)
	}

	authorize := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape(requestURI), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if first := authorize(); first.Code != http.StatusOK {
		t.Fatalf("the first authorization request: %d %s", first.Code, first.Body.String())
	}
	second := authorize()
	if second.Code != http.StatusBadRequest {
		t.Errorf("the second authorization request: %d, want 400 (%s)", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "already") {
		t.Errorf("body = %s, want it to say the request_uri is spent", second.Body.String())
	}

	// The issuer's own login form posts the request_uri again. That post is
	// allowed.
	login := postForm(t, h, "/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {demoAccountUsername},
		"password":    {demoAccountPassword},
	})
	if login.Code != http.StatusFound {
		t.Fatalf("signing in after the login page was served: %d %s", login.Code, login.Body.String())
	}
}

// Allow the redirect URI in form-action so browser policy does not block the
// post-login redirect to another origin or a mobile wallet scheme.
func TestLoginPageAllowsTheRedirectTarget(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	pushed := pushAuthorizationRequest(t, h, "http://wallet.example", holderKey, format.EncodeBase64URL(sum[:]), nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)

	req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape(requestURI), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("serving the login page: %d %s", rec.Code, rec.Body.String())
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://wallet.example;") {
		t.Errorf("login CSP must allow the redirect origin, got %q", csp)
	}
}

// Keep the submitted client authentication visible in the sign-in debug panel.
func TestLoginPageDebugPanelShowsClientAuthentication(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	attestation := provider.attest(t, "wallet", clientKey)
	pop := attestationPoP(t, clientKey, demoIssuerID)

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	pushed := pushAuthorizationRequest(t, h, "wallet", holderKey, format.EncodeBase64URL(sum[:]), map[string]string{
		"OAuth-Client-Attestation":     attestation,
		"OAuth-Client-Attestation-PoP": pop,
	})
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)

	req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape(requestURI), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("serving the login page: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{">wallet<", attestation, pop} {
		if !strings.Contains(body, want) {
			t.Errorf("the debug panel does not show %q\nbody = %s", want, body)
		}
	}
}

func TestRedirectFormActionSource(t *testing.T) {
	cases := map[string]string{
		"https://wallet.example/cb":           "https://wallet.example",
		"http://wallet.example:8080/cb":       "http://wallet.example:8080",
		"openid-credential-offer://authorize": "openid-credential-offer:",
		"eudi-openid4ci://cb":                 "eudi-openid4ci:",
		"not a url":                           "",
		"":                                    "",
	}
	for in, want := range cases {
		if got := redirectFormActionSource(in); got != want {
			t.Errorf("redirectFormActionSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthorizationServerMetadata(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"pushed_authorization_request_endpoint",
		"authorization_endpoint",
		"token_endpoint",
		"S256",
		// draft-ietf-oauth-attestation-based-client-auth-10 §8 requires
		// both of a server that supports the method.
		"client_attestation_signing_alg_values_supported",
		"client_attestation_pop_signing_alg_values_supported",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata does not mention %s: %s", want, body)
		}
	}
}

// Advertised authentication methods must match the endpoints, because wallets use this
// list to choose how to authenticate.
func TestAuthorizationServerMetadataFollowsTheClientAuthMode(t *testing.T) {
	authMethods := func(d *DemoRP) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()
		d.IssuerHandler().ServeHTTP(rec, req)
		var metadata map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
			t.Fatalf("decoding metadata: %v", err)
		}
		raw, _ := metadata["token_endpoint_auth_methods_supported"].([]any)
		methods := make([]string, 0, len(raw))
		for _, entry := range raw {
			method, _ := entry.(string)
			methods = append(methods, method)
		}
		return methods
	}
	has := func(methods []string, want string) bool {
		for _, method := range methods {
			if method == want {
				return true
			}
		}
		return false
	}

	required, _, _ := newDemoRP(t)
	methods := authMethods(required)
	for _, want := range []string{attestationClientAuth, attestationDPoPClientAuth} {
		if !has(methods, want) {
			t.Errorf("methods = %v, want it to offer %s", methods, want)
		}
	}
	if has(methods, unauthenticatedClientAuth) {
		t.Errorf("methods = %v, want no unauthenticated client where HAIP requires one", methods)
	}

	optional, _, _ := newDemoRP(t)
	optional.SetClientAuthMode(ClientAuthOptional)
	methods = authMethods(optional)
	if !has(methods, unauthenticatedClientAuth) {
		t.Errorf("methods = %v, want the unauthenticated client offered in optional mode", methods)
	}
	if !has(methods, attestationClientAuth) {
		t.Errorf("methods = %v, want the attestation still offered in optional mode", methods)
	}
}
