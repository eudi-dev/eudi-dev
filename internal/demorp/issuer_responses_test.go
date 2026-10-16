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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// redeemPreAuthOffer creates an offer with the query, redeems its
// pre-authorized code with the extra token form fields and returns the token
// response.
func redeemPreAuthOffer(t *testing.T, d *DemoRP, offerQuery string, extra url.Values) map[string]any {
	t.Helper()
	h := d.IssuerHandler()
	code, offerDoc := doJSON(t, h, "POST", "/api/offers?"+offerQuery, "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}
	offerURI := offerDoc["offer_uri"].(string)
	_, offer := doJSON(t, h, "GET", "/offer/"+offerURI[strings.LastIndex(offerURI, "/")+1:], "", nil)
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grants["pre-authorized_code"].(string)}}
	for name, values := range extra {
		form[name] = values
	}
	code, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), attestedTokenHeaders(t))
	if code != http.StatusOK {
		t.Fatalf("token request: %d %v", code, tokenDoc)
	}
	return tokenDoc
}

// requestCredential sends a credential request with the members and one fresh
// key proof under a bearer access token.
func requestCredential(t *testing.T, d *DemoRP, accessToken, members string) (int, map[string]any) {
	t.Helper()
	h := d.IssuerHandler()
	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	proof := proofJWTForKey(t, d, key, proofOptions{nonce: nonceDoc["c_nonce"].(string)})
	body := fmt.Sprintf(`{%s"proofs":{"jwt":[%q]}}`, members, proof)
	return doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
	})
}

// OpenID4VCI 1.0 §8.3: a credential issuer that cannot issue at once "MUST
// also use the HTTP status code 202", and interval is "REQUIRED if
// transaction_id is present".
func TestADeferredCredentialRequestIsAccepted(t *testing.T) {
	d, _, _ := newDemoRP(t)
	tokenDoc := redeemPreAuthOffer(t, d, "deferred=true", nil)

	code, doc := requestCredential(t, d, tokenDoc["access_token"].(string), `"credential_configuration_id":"demo-ticket",`)
	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%v)", code, doc)
	}
	if txID, _ := doc["transaction_id"].(string); txID == "" {
		t.Errorf("response carries no transaction_id: %v", doc)
	}
	if interval, _ := doc["interval"].(float64); interval <= 0 {
		t.Errorf("interval = %v, want a positive number", doc["interval"])
	}
}

// OpenID4VCI 1.0 §9.2: the Deferred Credential Endpoint delivers the
// credentials of the transaction once they are ready, only to the access
// token of the issuance, and only once.
func TestTheDeferredCredentialEndpointDeliversTheCredentialOnce(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.deferredDelay = 0
	token := redeemPreAuthOffer(t, d, "deferred=true", nil)["access_token"].(string)
	_, accepted := requestCredential(t, d, token, `"credential_configuration_id":"demo-ticket",`)
	txID, _ := accepted["transaction_id"].(string)
	poll := func(accessToken string) (int, map[string]any) {
		return doJSON(t, d.IssuerHandler(), "POST", "/deferred_credential", `{"transaction_id":"`+txID+`"}`, map[string]string{
			"Authorization": "Bearer " + accessToken,
			"Content-Type":  "application/json",
		})
	}

	other := redeemPreAuthOffer(t, d, "deferred=true", nil)["access_token"].(string)
	if code, doc := poll(other); code != http.StatusUnauthorized {
		t.Errorf("another access token: %d %v, want 401", code, doc)
	}
	code, doc := poll(token)
	if code != http.StatusOK {
		t.Fatalf("collecting the credential: %d %v", code, doc)
	}
	credentials, _ := doc["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("credentials = %v, want one", doc["credentials"])
	}
	raw, _ := credentials[0].(map[string]any)["credential"].(string)
	issued, err := sdjwt.ParseLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Payload["vct"] != TicketVCT || issued.Payload["cnf"] == nil {
		t.Errorf("vct %v, cnf %v, want a ticket bound to the proof key", issued.Payload["vct"], issued.Payload["cnf"])
	}
	if code, doc := poll(token); code != http.StatusBadRequest || doc["error"] != "invalid_transaction_id" {
		t.Errorf("collecting again: %d %v, want invalid_transaction_id", code, doc)
	}
}

// OpenID4VCI 1.0 §9.1 marks transaction_id REQUIRED, and §8.3.1.2 answers a
// request "missing a required parameter" with invalid_credential_request.
func TestADeferredRequestWithoutTransactionIDIsMalformed(t *testing.T) {
	d, _, _ := newDemoRP(t)
	token := redeemPreAuthOffer(t, d, "deferred=true", nil)["access_token"].(string)

	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/deferred_credential", `{}`, map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	})
	if code != http.StatusBadRequest || doc["error"] != "invalid_credential_request" {
		t.Errorf("%d %v, want 400 invalid_credential_request", code, doc)
	}
}

// ticketDetails is an authorization_details value that asks for the ticket.
const ticketDetails = `[{"type":"openid_credential","credential_configuration_id":"demo-ticket"}]`

// tokenCredentialIdentifier returns the one credential identifier that the
// token response returns for configID.
func tokenCredentialIdentifier(t *testing.T, tokenDoc map[string]any, configID string) string {
	t.Helper()
	details, _ := tokenDoc["authorization_details"].([]any)
	for _, entry := range details {
		detail, _ := entry.(map[string]any)
		if detail["type"] != "openid_credential" || detail["credential_configuration_id"] != configID {
			continue
		}
		ids, _ := detail["credential_identifiers"].([]any)
		if len(ids) != 1 {
			t.Fatalf("credential_identifiers = %v, want one identifier", detail["credential_identifiers"])
		}
		return ids[0].(string)
	}
	t.Fatalf("the token response %v has no authorization_details entry for %s", tokenDoc, configID)
	return ""
}

// OpenID4VCI 1.0 §6.2 makes authorization_details with credential_identifiers
// "REQUIRED when the authorization_details parameter [...] is used in either
// the Authorization Request or Token Request". §8.2 then requires the
// credential_identifier in the credential request and forbids the
// credential_configuration_id. A token request may narrow the offer (§6.1.1).
func TestATokenRequestWithAuthorizationDetailsGetsCredentialIdentifiers(t *testing.T) {
	d, _, _ := newDemoRP(t)
	tokenDoc := redeemPreAuthOffer(t, d, "credential=demo-ticket&credential=pid-sdjwt",
		url.Values{"authorization_details": {ticketDetails}})
	if details, _ := tokenDoc["authorization_details"].([]any); len(details) != 1 {
		t.Errorf("authorization_details = %v, want the one requested entry", tokenDoc["authorization_details"])
	}
	identifier := tokenCredentialIdentifier(t, tokenDoc, ticketConfigurationID)
	accessToken := tokenDoc["access_token"].(string)

	if code, doc := requestCredential(t, d, accessToken, `"credential_configuration_id":"demo-ticket",`); code != http.StatusBadRequest || doc["error"] != "invalid_credential_request" {
		t.Errorf("request by configuration id: %d %v, want 400 invalid_credential_request", code, doc)
	}
	if code, doc := requestCredential(t, d, accessToken, `"credential_identifier":"another-dataset",`); code != http.StatusBadRequest || doc["error"] != "unknown_credential_identifier" {
		t.Errorf("request by an unknown identifier: %d %v, want 400 unknown_credential_identifier", code, doc)
	}
	if code, doc := requestCredential(t, d, accessToken, fmt.Sprintf(`"credential_identifier":%q,`, identifier)); code != http.StatusOK {
		t.Errorf("request by the returned identifier: %d %v, want 200", code, doc)
	}
}

// A token request can only narrow what the grant covers (RFC 9396 §6).
func TestATokenRequestCannotWidenTheGrant(t *testing.T) {
	d, _, _ := newDemoRP(t)
	form := preAuthTokenForm(t, d)
	form.Set("authorization_details", `[{"type":"openid_credential","credential_configuration_id":"pid-sdjwt"}]`)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/token", form.Encode(), attestedTokenHeaders(t))
	if code != http.StatusBadRequest || doc["error"] != "invalid_authorization_details" {
		t.Errorf("token request beyond the offer: %d %v, want 400 invalid_authorization_details", code, doc)
	}
}

// authorization_details in the authorization request reach the token
// response for the resulting code (OpenID4VCI 1.0 §6.2). Next to an
// issuer_state they narrow the offer.
func TestAuthorizationDetailsOfTheAuthorizationRequestReachTheToken(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()
	_, offerDoc := doJSON(t, h, "POST", "/api/offers?grant=authorization_code&credential=demo-ticket&credential=pid-sdjwt", "", nil)
	offerURI := offerDoc["offer_uri"].(string)
	_, offer := doJSON(t, h, "GET", "/offer/"+offerURI[strings.LastIndex(offerURI, "/")+1:], "", nil)
	issuerState := offer["grants"].(map[string]any)[authCodeGrant].(map[string]any)["issuer_state"].(string)

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	grant, errResp := d.resolveAuthGrant(registeredIssuer, authGrant{
		clientID:      "wallet",
		codeChallenge: format.EncodeBase64URL(sum[:]),
		redirectURI:   "http://wallet.example/cb",
		issuerState:   issuerState,
	}, "", ticketDetails)
	if errResp != nil {
		t.Fatalf("resolving the grant: %v", errResp)
	}
	if !slices.Equal(grant.settings.configIDs, []string{ticketConfigurationID}) {
		t.Errorf("granted configurations = %v, want only the ticket", grant.settings.configIDs)
	}
	d.mu.Lock()
	d.codes["the-code"] = &authRequestState{authGrant: grant, expires: time.Now().Add(time.Minute)}
	d.mu.Unlock()

	form := url.Values{
		"grant_type":    {authCodeGrant},
		"code":          {"the-code"},
		"client_id":     {"wallet"},
		"redirect_uri":  {"http://wallet.example/cb"},
		"code_verifier": {verifier},
	}
	code, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if code != http.StatusOK {
		t.Fatalf("token request: %d %v", code, tokenDoc)
	}
	tokenCredentialIdentifier(t, tokenDoc, ticketConfigurationID)
}

// dpopBoundToken redeems a pre-authorized offer with a DPoP proof of key and
// returns the access token bound to that key.
func dpopBoundToken(t *testing.T, d *DemoRP, key *ecdsa.PrivateKey) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(preAuthTokenForm(t, d).Encode()))
	for name, value := range attestedTokenHeaders(t) {
		req.Header.Set(name, value)
	}
	req.Header.Set("DPoP", dpopProof(t, key, "POST", demoIssuerID+"/token"))
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	var tokenDoc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenDoc); err != nil || tokenDoc["token_type"] != "DPoP" {
		t.Fatalf("token request: %d %s", rec.Code, rec.Body.String())
	}
	return tokenDoc["access_token"].(string)
}

// sendCredentialRequest posts an empty credential request with the headers.
func sendCredentialRequest(t *testing.T, d *DemoRP, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/credential", strings.NewReader("{}"))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	return rec
}

// RFC 9449 §7.2: a resource server that supports both schemes "MUST reject a
// DPoP-bound access token received as a bearer token".
func TestADPoPBoundTokenIsRefusedAsABearerToken(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	accessToken := dpopBoundToken(t, d, key)
	rec := sendCredentialRequest(t, d, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"DPoP":          dpopProofForToken(t, key, "POST", demoIssuerID+"/credential", accessToken),
	})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_token") {
		t.Errorf("a DPoP-bound token sent as a bearer token: %d %s, want 401 invalid_token", rec.Code, rec.Body.String())
	}
}

// OpenID4VCI 1.0 Appendix F.4: the issuer "MUST ensure that [...] the header
// parameter does not contain a private key".
func TestAKeyProofWithAPrivateKeyIsRefused(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, nonceDoc := doJSON(t, d.IssuerHandler(), "POST", "/nonce", "", nil)
	jwk := holderJWK(t, key)
	private, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk["d"] = format.EncodeBase64URL(private)
	proof := signES256(t, key,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": jwk},
		map[string]any{"aud": demoIssuerID, "iat": time.Now().Unix(), "nonce": nonceDoc["c_nonce"]},
	)
	if _, err := d.verifyProofJWT(proof, d.issuerID()); err == nil || err.code != "invalid_proof" || !strings.Contains(err.description, "private key") {
		t.Errorf("a proof with a private jwk: %v, want invalid_proof naming the private key", err)
	}
}

// RFC 9449 §4.3 lists the checks of a DPoP proof. The server "MUST ensure"
// that "there is not more than one DPoP HTTP request header field", that the
// proof is a well-formed JWT with typ dpop+jwt, a supported alg, a valid
// signature by its jwk and all claims of §4.2, that htm and htu match the
// request, that iat is recent and that ath is the hash of the access token.
func TestDPoPProofChecks(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const accessToken = "the-access-token"
	htu := demoIssuerID + "/credential"
	ath := func(token string) string {
		sum := sha256.Sum256([]byte(token))
		return format.EncodeBase64URL(sum[:])
	}
	// proof signs a complete proof for the access token after edit changes
	// its header and payload.
	proof := func(signer *ecdsa.PrivateKey, edit func(header, payload map[string]any)) string {
		header := map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, key)}
		payload := map[string]any{"htm": "POST", "htu": htu, "iat": time.Now().Unix(), "jti": randToken(), "ath": ath(accessToken)}
		if edit != nil {
			edit(header, payload)
		}
		return signES256(t, signer, header, payload)
	}
	for _, tc := range []struct {
		name   string
		proofs []string
		want   string
	}{
		{"one complete proof", []string{proof(key, nil)}, ""},
		{"no proof", nil, "required"},
		{"an empty header", []string{" "}, "required"},
		{"two proofs", []string{proof(key, nil), proof(key, nil)}, "header fields"},
		{"a proof that is no JWT", []string{"not-a-jwt"}, "parsing"},
		{"another typ", []string{proof(key, func(h, _ map[string]any) { h["typ"] = "JWT" })}, "typ"},
		{"an alg outside SA-1", []string{proof(key, func(h, _ map[string]any) { h["alg"] = "RS256" })}, "alg"},
		{"an ES384 proof", []string{signJWT(t, p384Key,
			map[string]any{"typ": "dpop+jwt", "jwk": holderJWK(t, p384Key)},
			map[string]any{"htm": "POST", "htu": htu, "iat": time.Now().Unix(), "jti": randToken(), "ath": ath(accessToken)})}, ""},
		{"no jwk", []string{proof(key, func(h, _ map[string]any) { delete(h, "jwk") })}, "no jwk"},
		{"a jwk that is no key", []string{proof(key, func(h, _ map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
		})}, "jwk"},
		{"a signature by another key", []string{proof(otherKey, nil)}, "signature"},
		{"no jti", []string{proof(key, func(_, p map[string]any) { delete(p, "jti") })}, "jti"},
		{"another method", []string{proof(key, func(_, p map[string]any) { p["htm"] = "GET" })}, "htm"},
		{"another URI", []string{proof(key, func(_, p map[string]any) { p["htu"] = demoIssuerID + "/token" })}, "htu"},
		{"a stale iat", []string{proof(key, func(_, p map[string]any) { p["iat"] = time.Now().Add(-2 * freshnessWindow).Unix() })}, "iat"},
		{"the hash of another access token", []string{proof(key, func(_, p map[string]any) { p["ath"] = ath("another-token") })}, "ath"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/credential", nil)
			for _, proof := range tc.proofs {
				req.Header.Add("DPoP", proof)
			}
			_, err := d.verifyDPoPProof(req, htu, accessToken)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// RFC 9449 §4.3 matches htu "ignoring any query and fragment parts" after the
// syntax-based and scheme-based normalization of RFC 3986 §6.2.2 and §6.2.3.
func TestSameHTU(t *testing.T) {
	const target = "https://issuer.example/a/token"
	for htu, same := range map[string]bool{
		target:                                  true,
		target + "?x=1#frag":                    true,
		"HTTPS://Issuer.EXAMPLE:443/a/token":    true,
		"https://issuer.example/a/%74oken":      true,
		"https://issuer.example/a/./b/../token": true,
		"https://issuer.example:8443/a/token":   false,
		"http://issuer.example/a/token":         false,
		"https://other.example/a/token":         false,
		"https://issuer.example/a/token/":       false,
		"https://issuer.example/a/TOKEN":        false,
		"/a/token":                              false,
		"":                                      false,
	} {
		if got := sameHTU(htu, target); got != same {
			t.Errorf("sameHTU(%q) = %v, want %v", htu, got, same)
		}
	}
	if !sameHTU("http://issuer.example:80", "http://issuer.example/") {
		t.Error("an empty path and the default port differ from / without a port")
	}
}

// RFC 9449 §7.1: a request with the DPoP scheme carries a valid proof, and
// its key is the key bound to the access token. An access token without a
// DPoP key matches no proof.
func TestTheDPoPSchemeNeedsAProofOfTheBoundKey(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bearer := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
	bound := dpopBoundToken(t, d, key)
	target := demoIssuerID + "/credential"
	for _, tc := range []struct {
		name    string
		headers map[string]string
		code    int
		error   string
	}{
		{"a bearer token with the DPoP scheme and no proof", map[string]string{"Authorization": "DPoP " + bearer}, http.StatusUnauthorized, "invalid_dpop_proof"},
		{"a bearer token with the DPoP scheme and a proof", map[string]string{
			"Authorization": "DPoP " + bearer,
			"DPoP":          dpopProofForToken(t, key, "POST", target, bearer),
		}, http.StatusUnauthorized, "invalid_token"},
		{"a bound token without a proof", map[string]string{"Authorization": "DPoP " + bound}, http.StatusUnauthorized, "invalid_dpop_proof"},
		{"a bound token with its proof", map[string]string{
			"Authorization": "DPoP " + bound,
			"DPoP":          dpopProofForToken(t, key, "POST", target, bound),
		}, http.StatusBadRequest, "invalid_credential_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := sendCredentialRequest(t, d, tc.headers)
			if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.error) {
				t.Errorf("%d %s, want %d %s", rec.Code, rec.Body.String(), tc.code, tc.error)
			}
		})
	}
}

// OpenID4VCI 1.0 §8.2: proofs "contains exactly one parameter named as the
// proof type in Appendix F".
func TestACredentialRequestCarriesOneProofType(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()
	token := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	proof := proofJWTWith(t, d, proofOptions{nonce: nonceDoc["c_nonce"].(string)})
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q],"attestation":["x"]}}`, ticketConfigurationID, proof)
	code, doc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	})
	if code != http.StatusBadRequest || doc["error"] != "invalid_proof" {
		t.Errorf("two proof types: %d %v, want 400 invalid_proof", code, doc)
	}
}

// OpenID4VCI 1.0 §8.3.1.1: an access token that "does not [...] enable
// issuance of a requested Credential" gets an RFC 6750 §3 authorization
// error. §3.1 answers insufficient_scope with 403.
func TestAConfigurationOutsideTheTokenIsAnAuthorizationError(t *testing.T) {
	d, _, _ := newDemoRP(t)
	token := redeemPreAuthOffer(t, d, "", nil)["access_token"].(string)
	code, doc := requestCredential(t, d, token, `"credential_configuration_id":"german-pid-sdjwt",`)
	if code != http.StatusForbidden || doc["error"] != "insufficient_scope" {
		t.Errorf("%d %v, want 403 insufficient_scope", code, doc)
	}
}

// RFC 9449 §11.1: "HTTP requests to the same URI for which the jti value has
// been seen before would be declined."
func TestADPoPProofIsAcceptedOncePerTargetURI(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	send := func(htu string, proof string) map[string]string {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("DPoP", proof)
		_, errResp := d.dpopKey(req, htu)
		return errResp
	}
	proofFor := func(htu string) string {
		return signES256(t, key,
			map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, key)},
			map[string]any{"htm": "POST", "htu": htu, "iat": time.Now().Unix(), "jti": "one-jti"},
		)
	}
	token, par := demoIssuerID+"/token", demoIssuerID+"/par"
	if errResp := send(token, proofFor(token)); errResp != nil {
		t.Fatalf("first use: %v", errResp)
	}
	if errResp := send(token, proofFor(token)); errResp == nil || !strings.Contains(errResp["error_description"], "jti") {
		t.Errorf("replayed jti at the same URI: %v, want it refused naming jti", errResp)
	}
	if errResp := send(par, proofFor(par)); errResp != nil {
		t.Errorf("same jti at another URI: %v", errResp)
	}
}

// RFC 9449 §11.1: a seen jti is declined while its proof would be accepted.
// A full replay cache evicts the proofs that expire first, so new proofs are
// still accepted. A replay of an evicted proof is still refused.
func TestAFullDPoPReplayCacheEvictsTheFirstExpiringJTI(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	send := func(jti string, iat time.Time) map[string]string {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("DPoP", signES256(t, key,
			map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, key)},
			map[string]any{"htm": "POST", "htu": demoIssuerID + "/token", "iat": iat.Unix(), "jti": jti},
		))
		_, errResp := d.dpopKey(req, demoIssuerID+"/token")
		return errResp
	}
	earlier := time.Now().Add(-time.Minute)
	if errResp := send("first", earlier); errResp != nil {
		t.Fatalf("first use: %v", errResp)
	}
	d.mu.Lock()
	for i := len(d.seenJTIs); i < maxSeenJTIs; i++ {
		d.seenJTIs[fmt.Sprint("other-", i)] = time.Now().Add(freshnessWindow)
	}
	d.mu.Unlock()
	if errResp := send("second", time.Now()); errResp != nil {
		t.Errorf("a full replay cache refused a new proof: %v", errResp)
	}
	if errResp := send("first", earlier); errResp == nil {
		t.Error("a replay of the evicted proof was accepted")
	}
	if errResp := send("second", time.Now()); errResp == nil {
		t.Error("a replay of a cached proof was accepted")
	}
	d.mu.Lock()
	held := len(d.seenJTIs)
	d.mu.Unlock()
	if held > maxSeenJTIs {
		t.Errorf("the replay cache holds %d proofs, want at most %d", held, maxSeenJTIs)
	}
}

// RFC 6749 §5.1: the token response carries "Cache-Control" "no-store" and
// "Pragma" "no-cache".
func TestTheTokenResponseIsNotCached(t *testing.T) {
	d, _, _ := newDemoRP(t)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(preAuthTokenForm(t, d).Encode()))
	for name, value := range attestedTokenHeaders(t) {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token request: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
}

// RFC 6750 §3: a refused protected resource request carries a
// WWW-Authenticate challenge, with the error when an access token was sent
// and without any error information when none was (§3.1). A DPoP request gets
// the DPoP challenge of RFC 9449 §7.1.
func TestARefusedAccessTokenGetsAChallenge(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	accessToken := dpopBoundToken(t, d, key)
	for _, tc := range []struct {
		name     string
		endpoint string
		headers  map[string]string
		want     []string
		absent   string
	}{
		{"no access token", "/credential", nil, []string{`Bearer realm="` + demoIssuerID + `"`, `DPoP algs="ES256 ES384 ES512"`}, "error="},
		{"an unknown bearer token", "/credential", map[string]string{"Authorization": "Bearer unknown"}, []string{`Bearer error="invalid_token"`}, ""},
		{"a proof of another key", "/credential", map[string]string{
			"Authorization": "DPoP " + accessToken,
			"DPoP":          dpopProofForToken(t, otherKey, "POST", demoIssuerID+"/credential", accessToken),
		}, []string{`DPoP error="invalid_token"`, `algs="ES256 ES384 ES512"`}, ""},
		{"an unknown token at the deferred endpoint", "/deferred_credential", map[string]string{"Authorization": "Bearer unknown"}, []string{`Bearer error="invalid_token"`}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.endpoint, strings.NewReader("{}"))
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			rec := httptest.NewRecorder()
			d.IssuerHandler().ServeHTTP(rec, req)
			challenge := rec.Header().Get("WWW-Authenticate")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(challenge, want) {
					t.Errorf("WWW-Authenticate = %q, want it to contain %s", challenge, want)
				}
			}
			if tc.absent != "" && strings.Contains(challenge, tc.absent) {
				t.Errorf("WWW-Authenticate = %q, want no %s", challenge, tc.absent)
			}
		})
	}
}

// Every JWT made for one request carries an iat within the freshness window.
// An attestation needs an exp. A present exp or nbf is always checked.
func TestCheckTimeClaims(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) float64 { return float64(now.Add(d).Unix()) }
	for _, tc := range []struct {
		name              string
		payload           map[string]any
		fresh, requireExp bool
		ok                bool
	}{
		{"a fresh proof", map[string]any{"iat": at(0)}, true, false, true},
		{"a proof without iat", map[string]any{}, true, false, false},
		{"an old proof", map[string]any{"iat": at(-2 * freshnessWindow)}, true, false, false},
		{"a proof from the future", map[string]any{"iat": at(2 * freshnessWindow)}, true, false, false},
		{"an attestation with exp", map[string]any{"iat": at(-24 * time.Hour), "exp": at(time.Hour)}, false, true, true},
		{"an attestation without exp", map[string]any{"iat": at(0)}, false, true, false},
		{"an expired proof", map[string]any{"iat": at(0), "exp": at(-time.Second)}, true, false, false},
		{"a proof not valid yet", map[string]any{"iat": at(0), "nbf": at(2 * clockSkew)}, true, false, false},
	} {
		if err := checkTimeClaims(tc.payload, tc.fresh, tc.requireExp); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", tc.name, err, tc.ok)
		}
	}
}
