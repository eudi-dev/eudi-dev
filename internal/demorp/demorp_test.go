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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func newDemoRP(t *testing.T) (*DemoRP, *wallet.Wallet, *ecdsa.PrivateKey) {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	return New(w, func() string { return "http://demo.example" }), w, holderKey
}

func doJSON(t *testing.T, h http.Handler, method, target, body string, header map[string]string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	doc := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s %s: parsing response %q: %v", method, target, rec.Body.String(), err)
		}
	}
	return rec.Code, doc
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	encode := func(doc map[string]any) string {
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshaling: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signingInput := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func holderJWK(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	jwk := map[string]any{}
	for k, v := range mock.PublicKeyJWKMap(&key.PublicKey) {
		jwk[k] = v
	}
	return jwk
}

func TestIssuerPreAuthFlow(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	code, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]

	code, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	if code != http.StatusOK {
		t.Fatalf("fetching offer: %d %v", code, offer)
	}
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	preAuthCode := grants["pre-authorized_code"].(string)

	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {preAuthCode}}
	code, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), attestedTokenHeaders(t))
	if code != http.StatusOK {
		t.Fatalf("token request: %d %v", code, tokenDoc)
	}
	accessToken := tokenDoc["access_token"].(string)
	// OpenID4VCI 1.0 §6.2 defines no c_nonce in the token response, and §8.2
	// says "The c_nonce value is retrieved from the Nonce Endpoint as defined in
	// Section 7".
	if _, present := tokenDoc["c_nonce"]; present {
		t.Errorf("token response carries a c_nonce, which OpenID4VCI 1.0 does not define: %v", tokenDoc)
	}
	code, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	if code != http.StatusOK {
		t.Fatalf("nonce request: %d %v", code, nonceDoc)
	}
	cNonce := nonceDoc["c_nonce"].(string)

	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": cNonce},
	)
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q]}}`, ticketConfigurationID, proof)
	code, credDoc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
	})
	if code != http.StatusOK {
		t.Fatalf("credential request: %d %v", code, credDoc)
	}
	creds := credDoc["credentials"].([]any)
	raw := creds[0].(map[string]any)["credential"].(string)

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("parsing issued credential: %v", err)
	}
	if vct := token.ResolvedClaims["vct"]; vct != TicketVCT {
		t.Errorf("vct = %v, want %s", vct, TicketVCT)
	}
	if _, ok := token.Payload["cnf"].(map[string]any); !ok {
		t.Error("issued credential has no cnf claim")
	}
	x5c, ok := token.Header["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		t.Fatal("issued credential has no x5c chain")
	}
	der, err := base64.StdEncoding.DecodeString(x5c[0].(string))
	if err != nil {
		t.Fatalf("decoding leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}
	// The ticket is signed under the local trust profile of its attestation
	// spec. The leaf therefore identifies the issuer of that profile.
	if !strings.HasPrefix(leaf.Subject.CommonName, "EUDI Dev Wallet Issuer") {
		t.Errorf("ticket leaf names %q, want the local trust profile issuer", leaf.Subject.CommonName)
	}
	var registered bool
	for _, spec := range d.wallet.IssuedAttestations {
		if spec.VCT == TicketVCT {
			registered = true
		}
	}
	if !registered {
		t.Error("issuing a ticket must register it as an issued attestation")
	}
}

func TestIssuerRejectsWrongNonce(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	_, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]
	_, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grants["pre-authorized_code"].(string)}}
	_, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), attestedTokenHeaders(t))

	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": "wrong"},
	)
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q]}}`, ticketConfigurationID, proof)
	code, doc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + tokenDoc["access_token"].(string),
		"Content-Type":  "application/json",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("credential request with wrong nonce: %d %v, want 400", code, doc)
	}
	// §8.3.1.2 reserves invalid_nonce for this case. A wallet that reads it
	// fetches a fresh challenge and tries again.
	if doc["error"] != "invalid_nonce" {
		t.Errorf("error = %v, want invalid_nonce", doc["error"])
	}
}

// OpenID4VCI 1.0 §8.2 requires exactly one of credential_identifier and
// credential_configuration_id. §8.3.1.2 defines the error codes for a request
// that breaks this rule. Without the check any request would get the credential.
func TestIssuerChecksTheRequestedCredential(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	_, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]
	_, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grants["pre-authorized_code"].(string)}}
	_, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), attestedTokenHeaders(t))
	accessToken := tokenDoc["access_token"].(string)

	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": nonceDoc["c_nonce"]},
	)

	request := func(members string) (int, map[string]any) {
		t.Helper()
		body := fmt.Sprintf(`{%s"proofs":{"jwt":[%q]}}`, members, proof)
		return doJSON(t, h, "POST", "/credential", body, map[string]string{
			"Authorization": "Bearer " + accessToken,
			"Content-Type":  "application/json",
		})
	}

	for _, tc := range []struct {
		name    string
		members string
		want    string
	}{
		{"neither member", "", "invalid_credential_request"},
		{"both members", `"credential_configuration_id":"demo-ticket","credential_identifier":"whatever",`, "invalid_credential_request"},
		{"an unknown configuration", `"credential_configuration_id":"not-a-configuration",`, "unknown_credential_configuration"},
		{"an identifier this issuer never handed out", `"credential_identifier":"whatever",`, "unknown_credential_identifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc := request(tc.members)
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%v)", code, doc)
			}
			if doc["error"] != tc.want {
				t.Errorf("error = %v, want %s", doc["error"], tc.want)
			}
		})
	}
}

// OpenID4VCI 1.0 §8.2 defines only the proofs member. A request with a
// singular proof member is refused.
func TestIssuerRejectsTheSingularProofMember(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	_, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]
	_, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grants["pre-authorized_code"].(string)}}
	_, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), attestedTokenHeaders(t))

	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": nonceDoc["c_nonce"]},
	)
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proof":{"proof_type":"jwt","jwt":%q}}`, ticketConfigurationID, proof)
	code, doc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + tokenDoc["access_token"].(string),
		"Content-Type":  "application/json",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%v)", code, doc)
	}
	if doc["error"] != "invalid_proof" {
		t.Errorf("error = %v, want invalid_proof", doc["error"])
	}
}

func newIssuanceWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	w.RequireHAIP = true
	return w
}

func jsonString(v string) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func presentTicket(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey, clientID, nonce string) string {
	t.Helper()
	credential, err := d.signTicket(&holderKey.PublicKey, ticketGrant{})
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}
	return presentCredential(t, holderKey, credential, clientID, nonce)
}

// The ticket's time claims are rounded to the hour. RFC 9901 §10.1 asks
// issuers to keep credentials unlinkable. Batch copies that share the exact
// issuance second could be correlated through iat and exp.
func TestTicketTimeClaimsAreRounded(t *testing.T) {
	d, _, holderKey := newDemoRP(t)

	credential, err := d.signTicket(&holderKey.PublicKey, ticketGrant{})
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}
	token, err := sdjwt.Parse(credential)
	if err != nil {
		t.Fatalf("parsing ticket: %v", err)
	}
	iat, _ := token.Payload["iat"].(float64)
	exp, _ := token.Payload["exp"].(float64)
	if int64(iat)%3600 != 0 {
		t.Errorf("iat = %d, want a value on an hour boundary", int64(iat))
	}
	if int64(exp)%3600 != 0 {
		t.Errorf("exp = %d, want a value on an hour boundary", int64(exp))
	}
}

func presentCredential(t *testing.T, holderKey *ecdsa.PrivateKey, credential, clientID, nonce string) string {
	t.Helper()
	return presentCredentialAt(t, holderKey, credential, clientID, nonce, time.Now())
}

func presentCredentialAt(t *testing.T, holderKey *ecdsa.PrivateKey, credential, clientID, nonce string, iat time.Time) string {
	t.Helper()
	prefix := credential
	if !strings.HasSuffix(prefix, "~") {
		prefix += "~"
	}
	digest := sha256.Sum256([]byte(prefix))
	kb := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "kb+jwt"},
		map[string]any{
			"iat":     iat.Unix(),
			"aud":     clientID,
			"nonce":   nonce,
			"sd_hash": base64.RawURLEncoding.EncodeToString(digest[:]),
		},
	)
	return prefix + kb
}

// RFC 9901 §7.3 has the verifier "check that the creation time of the Key
// Binding JWT, as determined by the iat claim, is within an acceptable
// window". A binding created long before or after now belongs to another
// session.
func TestVerifierRejectsKeyBindingOutsideTheAcceptableWindow(t *testing.T) {
	for name, iat := range map[string]time.Time{
		"a year in the past":   time.Now().AddDate(-1, 0, 0),
		"a year in the future": time.Now().AddDate(1, 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			d, _, holderKey := newDemoRP(t)
			h := d.VerifierHandler()
			id, params := startVerification(t, h, "ticket")

			credential, err := d.signTicket(&holderKey.PublicKey, ticketGrant{})
			if err != nil {
				t.Fatalf("signing ticket: %v", err)
			}
			presentation := presentCredentialAt(t, holderKey, credential, params.Get("client_id"), params.Get("nonce"), iat)
			postPresentation(t, h, id, "ticket", presentation)

			_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
			if status["status"] != "failed" {
				t.Fatalf("status = %v, want failed for a key binding created %s", status["status"], name)
			}
		})
	}
}

func TestVerifierFlow(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")
	nonce := params.Get("nonce")
	clientID := params.Get("client_id")
	if id == "" || nonce == "" || !strings.HasPrefix(clientID, "x509_hash:") {
		t.Fatalf("unexpected authorization parameters: %v", params)
	}
	if got := params.Get("response_mode"); got != "direct_post.jwt" {
		t.Errorf("response_mode = %q, want direct_post.jwt", got)
	}

	presentation := presentTicket(t, d, holderKey, clientID, nonce)
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("presentation response = %d, want 200", code)
	}

	code, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if code != http.StatusOK || status["status"] != "verified" {
		t.Fatalf("request status = %d %v, want verified", code, status)
	}
	claims := status["claims"].(map[string]any)
	if claims["event"] != "EUDI Interop Fest" {
		t.Errorf("verified claims = %v, want the ticket event", claims)
	}
}

// An external issuer's credential must fail without its CA and verify after that CA is
// configured.
func TestVerifierTrustAnchors(t *testing.T) {
	foreignCAKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating foreign CA key: %v", err)
	}
	foreignCA, err := mock.GenerateCACert(foreignCAKey)
	if err != nil {
		t.Fatalf("generating foreign CA certificate: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating foreign issuer key: %v", err)
	}
	leaf, err := mock.GenerateLeafCert(foreignCAKey, foreignCA, &issuerKey.PublicKey)
	if err != nil {
		t.Fatalf("generating foreign issuer leaf: %v", err)
	}

	present := func(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey) string {
		h := d.VerifierHandler()
		id, params := startVerificationWith(t, h, `{"type":"pid","format":"sd-jwt"}`)
		credential, err := mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:    "https://foreign-issuer.example",
			VCT:       PIDVCT,
			ExpiresIn: time.Hour,
			Claims:    map[string]any{"given_name": "Erika", "family_name": "Mustermann"},
			Key:       issuerKey,
			HolderKey: &holderKey.PublicKey,
			CertChain: []*x509.Certificate{leaf},
		})
		if err != nil {
			t.Fatalf("signing foreign credential: %v", err)
		}
		presentation := presentCredential(t, holderKey, credential, params.Get("client_id"), params.Get("nonce"))
		postPresentation(t, h, id, "pid", presentation)
		_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
		outcome, _ := status["status"].(string)
		return outcome
	}

	t.Run("without the foreign anchor", func(t *testing.T) {
		d, _, holderKey := newDemoRP(t)
		if got := present(t, d, holderKey); got != "failed" {
			t.Fatalf("status = %q, want failed for a chain under an unknown CA", got)
		}
	})

	t.Run("with the foreign anchor", func(t *testing.T) {
		d, _, holderKey := newDemoRP(t)
		d.SetVerifierTrustAnchors([]*x509.Certificate{foreignCA})
		if got := present(t, d, holderKey); got != "verified" {
			t.Fatalf("status = %q, want verified with the CA added as a trust anchor", got)
		}
	})
}

func TestVerifierRejectsWrongNonce(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), "wrong-nonce")
	postPresentation(t, h, id, "ticket", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed on nonce mismatch", status["status"])
	}
}

func serveStatusList(t *testing.T, d *DemoRP, w *wallet.Wallet) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(nil)
	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/statuslist", func(rw http.ResponseWriter, r *http.Request) {
		jwt, err := statuslist.GenerateStatusListJWT([]byte{0b00000010}, w.IssuerKey, statuslist.StatusListConfig{
			URI:       srv.URL + "/statuslist",
			Issuer:    srv.URL,
			CertChain: chain,
		})
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = rw.Write([]byte(jwt))
	})
	srv.Config.Handler = mux
	return srv
}

func signTicketWithStatus(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey, uri string, idx int) string {
	t.Helper()
	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        d.issuerID(),
		VCT:           TicketVCT,
		ExpiresIn:     24 * time.Hour,
		Claims:        ticketClaims("", nil, nil),
		Key:           d.wallet.IssuerKey,
		HolderKey:     &holderKey.PublicKey,
		CertChain:     chain,
		StatusListURI: uri,
		StatusListIdx: idx,
	})
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}
	return raw
}

// A revoked credential must fail verification even when its signature is valid.
func TestVerifierRejectsRevokedCredential(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	statusSrv := serveStatusList(t, d, w)
	defer statusSrv.Close()
	h := d.VerifierHandler()

	for _, tc := range []struct {
		name       string
		idx        int
		wantStatus string
	}{
		{"valid entry", 0, "verified"},
		{"revoked entry", 1, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, params := startVerification(t, h, "ticket")

			credential := signTicketWithStatus(t, d, holderKey, statusSrv.URL+"/statuslist", tc.idx)
			presentation := presentCredential(t, holderKey, credential, params.Get("client_id"), params.Get("nonce"))
			postPresentation(t, h, id, "ticket", presentation)

			_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
			if status["status"] != tc.wantStatus {
				t.Fatalf("status = %v, want %v (checks: %v)", status["status"], tc.wantStatus, status["checks"])
			}
		})
	}
}

// HAIP request parameters are inside the signed request object. Fetch and parse it as
// the wallet does.
func startVerification(t *testing.T, h http.Handler, kind string) (string, url.Values) {
	t.Helper()
	return startVerificationWith(t, h, `{"type":"`+kind+`"}`)
}

func startVerificationWith(t *testing.T, h http.Handler, body string) (string, url.Values) {
	t.Helper()
	_, doc := doJSON(t, h, "POST", "/api/requests", body, map[string]string{"Content-Type": "application/json"})
	walletURL, err := url.Parse(doc["wallet_url"].(string))
	if err != nil {
		t.Fatalf("parsing wallet_url: %v", err)
	}
	requestURI := walletURL.Query().Get("request_uri")
	if requestURI == "" {
		t.Fatalf("expected a request_uri in %s", walletURL)
	}
	payload := fetchRequestObject(t, h, requestURI)

	params := url.Values{}
	for _, name := range []string{"client_id", "response_type", "response_mode", "response_uri", "nonce", "state"} {
		if v, ok := payload[name].(string); ok {
			params.Set(name, v)
		}
	}
	return params.Get("state"), params
}

func fetchRequestObject(t *testing.T, h http.Handler, requestURI string) map[string]any {
	t.Helper()
	parsed, err := url.Parse(requestURI)
	if err != nil {
		t.Fatalf("parsing request_uri: %v", err)
	}
	// The handler is mounted with the /verifier prefix stripped.
	path := strings.TrimPrefix(parsed.Path, "/verifier")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/oauth-authz-req+jwt" {
		t.Errorf("request object Content-Type = %q", ct)
	}
	parts := strings.Split(strings.TrimSpace(rec.Body.String()), ".")
	if len(parts) != 3 {
		t.Fatalf("request object is not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding request object payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("parsing request object payload: %v", err)
	}
	return payload
}

func responseEncryptionKey(t *testing.T, payload map[string]any) (*ecdsa.PublicKey, string) {
	t.Helper()
	meta, ok := payload["client_metadata"].(map[string]any)
	if !ok {
		t.Fatal("request object has no client_metadata")
	}
	jwks, ok := meta["jwks"].(map[string]any)
	if !ok {
		t.Fatal("client_metadata has no jwks")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("client_metadata jwks has no keys")
	}
	jwk, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatal("jwks key is not an object")
	}
	if alg, _ := jwk["alg"].(string); alg != "ECDH-ES" {
		t.Errorf("jwk alg = %q, want ECDH-ES (the wallet rejects a JWK without it)", alg)
	}
	xb, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	if err != nil {
		t.Fatalf("decoding jwk x: %v", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
	if err != nil {
		t.Fatalf("decoding jwk y: %v", err)
	}
	kid, _ := jwk["kid"].(string)
	pub, err := format.ECPublicKeyFromCoords(elliptic.P256(), xb, yb)
	if err != nil {
		t.Fatalf("building the jwk public key: %v", err)
	}
	return pub, kid
}

func postPresentation(t *testing.T, h http.Handler, id, queryID, presentation string) int {
	t.Helper()
	return postPresentationTo(t, h, id, id, queryID, presentation)
}

// postPresentationTo lets the state inside the encrypted payload differ from
// the request it is posted to. Tests use this to check how the verifier binds
// a response to its request.
func postPresentationTo(t *testing.T, h http.Handler, requestID, state, queryID, presentation string) int {
	t.Helper()
	payload := fetchRequestObject(t, h, "/request/"+requestID)
	pub, kid := responseEncryptionKey(t, payload)

	body, err := json.Marshal(map[string]any{
		"vp_token": map[string][]string{queryID: {presentation}},
		"state":    state,
	})
	if err != nil {
		t.Fatalf("building response payload: %v", err)
	}
	jwe, _, err := wallet.EncryptJWE(body, pub, kid, "ECDH-ES", "A128GCM", nil, nil)
	if err != nil {
		t.Fatalf("encrypting response: %v", err)
	}

	code, _ := doJSON(t, h, "POST", "/response/"+requestID, url.Values{"response": {jwe}}.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	return code
}

// TestVerifierRejectsWrongCredentialType checks that the verifier enforces the
// type it asked for. The wallet decides what to send, so a PID answering a
// ticket request must not verify.
func TestVerifierRejectsWrongCredentialType(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	pid, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       PIDVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika", "family_name": "Mustermann"},
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing pid: %v", err)
	}

	presentation := presentCredential(t, holderKey, pid, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "ticket", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed for a mismatched vct (checks: %v)", status["status"], status["checks"])
	}
}

// The German PID extends the base PID type and must satisfy a request for it.
func TestVerifierAcceptsAnExtendingCredentialType(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "pid")

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	german, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       mock.GermanPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    mock.SDJWTGermanPIDClaims,
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing the German PID: %v", err)
	}

	presentation := presentCredential(t, holderKey, german, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "pid", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified for a type extending the requested one (checks: %v)", status["status"], status["checks"])
	}
}

// A base PID cannot satisfy a request for national attributes. Inheritance works only
// from the domestic type to its base.
func TestVerifierDomesticPIDRequestRefusesTheCountryIndependentPID(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerificationWith(t, h, `{"type":"pid","vct":"urn:eudi:pid:de:1"}`)

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	eu, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    mock.SDJWTPIDClaims,
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing the country-independent PID: %v", err)
	}

	presentation := presentCredential(t, holderKey, eu, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "pid", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed for the extended type answering its extension (checks: %v)", status["status"], status["checks"])
	}
}

func TestVerifierDomesticPIDRequestAcceptsThatType(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerificationWith(t, h, `{"type":"pid","vct":"urn:eudi:pid:de:1"}`)

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	german, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       mock.GermanPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    mock.SDJWTGermanPIDClaims,
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing the German PID: %v", err)
	}

	presentation := presentCredential(t, holderKey, german, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "pid", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (checks: %v)", status["status"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	if claims["vct"] != mock.GermanPIDVCT {
		t.Errorf("vct presented = %v, want %v", claims["vct"], mock.GermanPIDVCT)
	}
}

// A credential type exists only in SD-JWT VC. All PIDs share one mdoc
// doctype, so any PID would answer a national PID request in mdoc. The
// verifier refuses such a request.
func TestVerifierDomesticPIDHasNoMDocForm(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	code, body := doJSON(t, h, "POST", "/api/requests", `{"type":"pid","vct":"urn:eudi:pid:de:1","format":"mdoc"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("POST /api/requests = %d, want 400 (body: %v)", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "no mdoc form") {
		t.Errorf("error = %q, want it to say a credential type has no mdoc form", msg)
	}
}

// PID_14 in Annex 2 of the ARF puts every PID type under urn:eudi:pid:. A PID
// request for any other type is refused.
func TestVerifierPIDRequestRefusesATypeOutsideThePIDNamespace(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	code, body := doJSON(t, h, "POST", "/api/requests", `{"type":"pid","vct":"urn:example:membership:1"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("POST /api/requests = %d, want 400 (body: %v)", code, body)
	}
}

// PID_14 applies to domestic types even when this tool has no country-specific
// definition.
func TestVerifierPIDRequestTakesAnyDomesticType(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	const frenchPID = "urn:eudi:pid:fr:1"
	id, params := startVerificationWith(t, h, `{"type":"pid","vct":"`+frenchPID+`"}`)

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	french, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       frenchPID,
		ExpiresIn: time.Hour,
		Claims:    mock.SDJWTPIDClaims,
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing the French PID: %v", err)
	}

	presentation := presentCredential(t, holderKey, french, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "pid", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (checks: %v)", status["status"], status["checks"])
	}
}

// HAIP 1.0 section 6.1.1 asks a credential to carry its issuer's signing
// certificate and trust chain in x5c, without the trust anchor. The demo
// reports a credential that breaks this profile rule and still accepts the
// presentation.
func TestVerifierWarnsWhenTheCredentialChainCarriesTheTrustAnchor(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "pid")

	caCert := d.wallet.CertChain[len(d.wallet.CertChain)-1]
	leaf, err := mock.GenerateLeafCert(d.wallet.CAKey, caCert, &d.wallet.IssuerKey.PublicKey)
	if err != nil {
		t.Fatalf("generating a leaf: %v", err)
	}
	// The generator strips one trailing anchor. Adding the CA twice leaves the
	// leaf and the self-signed CA in the x5c header.
	cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    mock.SDJWTPIDClaims,
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: []*x509.Certificate{leaf, caCert, caCert},
	})
	if err != nil {
		t.Fatalf("signing a credential whose chain carries the anchor: %v", err)
	}

	presentation := presentCredential(t, holderKey, cred, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "pid", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (checks: %v)", status["status"], status["checks"])
	}
	var warned bool
	for _, entry := range status["checks"].([]any) {
		check := entry.(map[string]any)
		if warning, ok := check["warning"].(string); ok && strings.Contains(warning, "trust anchor") {
			warned = true
			if check["ok"] != true {
				t.Error("a warning must not mark the check as failed")
			}
		}
	}
	if !warned {
		t.Errorf("no warning about the anchor in the chain: %v", status["checks"])
	}
}

// OpenID4VP 1.0 §8.2: the Response URI answers 200 to an Authorization Error
// Response. The request fails with the wallet's error so the page shows it.
func TestVerifierRecordsTheWalletErrorResponse(t *testing.T) {
	for name, post := range map[string]func(t *testing.T, h http.Handler, id string) int{
		"encrypted": func(t *testing.T, h http.Handler, id string) int {
			pub, kid := responseEncryptionKey(t, fetchRequestObject(t, h, "/request/"+id))
			body, err := json.Marshal(map[string]string{
				"error":             "access_denied",
				"error_description": "User denied presentation",
				"state":             id,
			})
			if err != nil {
				t.Fatalf("building error payload: %v", err)
			}
			jwe, _, err := wallet.EncryptJWE(body, pub, kid, "ECDH-ES", "A128GCM", nil, nil)
			if err != nil {
				t.Fatalf("encrypting error response: %v", err)
			}
			return postResponseForm(t, h, id, url.Values{"response": {jwe}})
		},
		// §8.3.1: "If a Wallet is unable to generate an encrypted response, it
		// MAY send an error response without encryption as per Section 8.2."
		"unencrypted": func(t *testing.T, h http.Handler, id string) int {
			return postResponseForm(t, h, id, url.Values{
				"error":             {"access_denied"},
				"error_description": {"User denied presentation"},
				"state":             {id},
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, _, _ := newDemoRP(t)
			h := d.VerifierHandler()
			id, _ := startVerification(t, h, "ticket")

			if code := post(t, h, id); code != http.StatusOK {
				t.Fatalf("error response = %d, want 200", code)
			}
			_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
			want := "the wallet answered with the error access_denied: User denied presentation"
			if status["status"] != "failed" || status["error"] != want {
				t.Fatalf("request = %v %v, want failed with %q", status["status"], status["error"], want)
			}
		})
	}
}

// A response that is neither encrypted nor an error response is malformed.
func TestVerifierRejectsAMalformedResponse(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()
	id, _ := startVerification(t, h, "ticket")

	if code := postResponseForm(t, h, id, url.Values{"vp_token": {"{}"}}); code != http.StatusBadRequest {
		t.Fatalf("malformed response = %d, want 400", code)
	}
	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("request status = %v, want failed", status["status"])
	}
}

func postResponseForm(t *testing.T, h http.Handler, id string, form url.Values) int {
	t.Helper()
	code, _ := doJSON(t, h, "POST", "/response/"+id, form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	return code
}

// Consume verification requests after use so captured responses cannot be replayed.
func TestVerifierRejectsReplay(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")
	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce"))

	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("first response = %d, want 200", code)
	}
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusConflict {
		t.Fatalf("replayed response = %d, want 409", code)
	}

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("replay must not change the original result, got %v", status["status"])
	}
}

// Expire unanswered requests so abandoned browser tabs stop polling.
func TestVerifierRequestExpires(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	id, _ := startVerification(t, h, "ticket")

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "pending" {
		t.Fatalf("fresh request status = %v, want pending", status["status"])
	}

	d.mu.Lock()
	d.requests[id].expires = time.Now().Add(-time.Second)
	d.mu.Unlock()

	code, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if code != http.StatusOK || status["status"] != "expired" {
		t.Fatalf("expired request status = %d %v, want 200 expired", code, status["status"])
	}
}

// Keep completed results available after request expiry so the redirected browser can
// still display them.
func TestVerifierKeepsResultOfAnsweredRequest(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")
	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce"))
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("presentation response = %d, want 200", code)
	}

	d.mu.Lock()
	d.requests[id].expires = time.Now().Add(-time.Second)
	d.mu.Unlock()

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want the verified result to survive expiry", status["status"])
	}
}

// TestVerifierRejectsInjectedDisclosure models a malicious holder. The holder
// owns the key binding key, so it can append a disclosure and re-sign a
// matching sd_hash. Only the rule that every disclosure is referenced catches
// this.
func TestVerifierRejectsInjectedDisclosure(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	credential, err := d.signTicket(&holderKey.PublicKey, ticketGrant{})
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}

	// A well-formed disclosure the issuer never created.
	forged, err := json.Marshal([]any{"injectedsalt", "tier", "vip-forged"})
	if err != nil {
		t.Fatalf("building disclosure: %v", err)
	}
	tampered := credential + base64.RawURLEncoding.EncodeToString(forged) + "~"

	// Re-sign the key binding over the tampered presentation, so sd_hash,
	// nonce and audience all still check out.
	digest := sha256.Sum256([]byte(tampered))
	kb := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "kb+jwt"},
		map[string]any{
			"iat":     time.Now().Unix(),
			"aud":     params.Get("client_id"),
			"nonce":   params.Get("nonce"),
			"sd_hash": base64.RawURLEncoding.EncodeToString(digest[:]),
		},
	)
	postPresentation(t, h, id, "ticket", tampered+kb)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed for an injected disclosure (checks: %v)", status["status"], status["checks"])
	}
	// RFC 9901 §7.1 step 5 rejects unreferenced disclosures during parsing. The error
	// must identify the injected disclosure.
	checks := status["checks"].([]any)
	last := checks[len(checks)-1].(map[string]any)
	if last["ok"] != false {
		t.Fatalf("expected a failing check, got %v", last)
	}
	detail, _ := last["error"].(string)
	if !strings.Contains(detail, "not referenced") {
		t.Fatalf("expected the failure to name the unreferenced disclosure, got %v", last)
	}
}

func serveDemoStack(t *testing.T, w *wallet.Wallet) (*DemoRP, *httptest.Server) {
	t.Helper()
	srv := wallet.NewServer(w, 0, nil)

	var base string
	d := New(w, func() string { return base })

	mux := http.NewServeMux()
	mux.Handle("/verifier/", http.StripPrefix("/verifier", d.VerifierHandler()))
	mux.Handle("/issuer/", http.StripPrefix("/issuer", d.IssuerHandler()))
	// The well-known segment comes before the issuer path, so both metadata
	// documents live at the server root.
	mux.HandleFunc("GET /.well-known/openid-credential-issuer/issuer", d.IssuerMetadataHandler())
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/issuer", d.AuthorizationServerMetadataHandler())
	mux.Handle("/", srv.Handler())

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	base = ts.URL
	w.BaseURL = ts.URL
	// The authorization code flow needs a client identity and a redirect
	// target on this origin. Demo mode configures both.
	if w.VCIRedirectURI == "" {
		w.VCIRedirectURI = ts.URL + "/callback"
	}
	if w.VCIClientID == "" {
		w.VCIClientID = ts.URL
	}
	return d, ts
}

// Exercise a real HAIP presentation with a signed request by reference, x509_hash
// client ID and encrypted response.
func TestVerifierIsHAIPCompliantEndToEnd(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	w.RequireHAIP = true
	w.ValidationMode = wallet.ValidationModeStrict
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}

	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid"}`)
	id, _ := created["id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	if id == "" || walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}

	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode < 300 {
		t.Fatalf("authorize returned %d: %s", resp.StatusCode, body)
	}

	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error: %v, checks: %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	if claims["family_name"] != "'t Hart" {
		t.Errorf("verified claims = %v, want the PID holder", claims)
	}
}

func TestHAIPEnforcementRejectsPlainRequest(t *testing.T) {
	holderKey, _ := mock.GenerateKey()
	issuerKey, _ := mock.GenerateKey()
	w := wallet.New(holderKey, issuerKey, true)
	w.RequireHAIP = true
	// Use strict mode so HAIP findings reject the request.
	w.ValidationMode = wallet.ValidationModeStrict
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	_, ts := serveDemoStack(t, w)

	params := url.Values{
		"client_id":     {"redirect_uri:" + ts.URL + "/nowhere"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {ts.URL + "/nowhere"},
		"nonce":         {"n-0S6_WzA2Mj"},
		"dcql_query":    {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["` + PIDVCT + `"]},"claims":[{"path":["given_name"]}]}]}`},
	}
	resp, err := ts.Client().Get(ts.URL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("driving the plain request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain request returned %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "HAIP") {
		t.Errorf("expected a HAIP violation, got: %s", body)
	}
}

func postJSONTo(t *testing.T, target, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(target, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("POST %s: decoding response: %v", target, err)
	}
	return doc
}

func getJSONFrom(t *testing.T, target string) map[string]any {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("GET %s: decoding response: %v", target, err)
	}
	return doc
}

// HAIP 1.0 §4 requires an issuer to support the authorization code flow, and
// its pushed authorization request rule covers only the authorization
// endpoint. A pre-authorized code offer is therefore conformant. The wallet
// accepts it with enforcement on, and only the transport rule applies.
func TestIssuanceHAIPAcceptsPreAuthorizedOffer(t *testing.T) {
	legacy := httptest.NewServer(legacyIssuerHandler(t))
	t.Cleanup(legacy.Close)

	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	offerURI := "openid-credential-offer://?credential_offer=" +
		url.QueryEscape(`{"credential_issuer":"`+legacy.URL+`","credential_configuration_ids":["legacy"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc"}}}`)

	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(offerURI)+`}`)
	errText, _ := result["error"].(string)
	// The test issuer's token endpoint refuses the grant. That is the expected
	// failure, and HAIP enforcement must not cause it.
	if strings.Contains(errText, "HAIP") {
		t.Errorf("a pre-authorized code offer must not be rejected by HAIP enforcement, got %q", errText)
	}
}

// Create the offer before sign-in, then authenticate during redemption. This checks
// the ordering of PAR, login, PKCE code exchange and the DPoP credential request.
func TestIssuerAuthorizationCodeFlowEndToEnd(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireHAIP = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?grant=authorization_code", "")
	schemeURI, _ := created["scheme_uri"].(string)
	if schemeURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}

	// The wallet returns the sign-in URL while issuance waits for the callback.
	accepted := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if accepted["status"] != "authorization_required" {
		t.Fatalf("redeeming the offer did not ask for a sign-in: %v", accepted)
	}
	authURL, _ := accepted["authorization_url"].(string)
	offerID, _ := accepted["offer_id"].(string)
	if !strings.Contains(authURL, "/issuer/authorize") || !strings.Contains(authURL, "request_uri=") {
		t.Fatalf("unexpected authorization URL %q", authURL)
	}
	if offerID == "" {
		t.Fatal("the wallet gave no offer id to follow the flow at")
	}

	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	page, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("opening the authorization URL: %v", err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") {
		t.Fatalf("the authorization endpoint did not ask for a login: %d %s", page.StatusCode, truncate(string(body)))
	}
	requestURI := requestURIFromLoginPage(t, string(body))

	login, err := client.PostForm(ts.URL+"/issuer/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {"alice"},
		"password":    {"alice"},
	})
	if err != nil {
		t.Fatalf("signing in: %v", err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d, want a redirect back to the wallet", login.StatusCode)
	}
	callback := login.Header.Get("Location")
	if !strings.Contains(callback, "code=") {
		t.Fatalf("login redirect %q carries no authorization code", callback)
	}
	cb, err := client.Get(callback)
	if err != nil {
		t.Fatalf("following the callback: %v", err)
	}
	cb.Body.Close()

	deadline := time.Now().Add(20 * time.Second)
	for {
		status := getJSONFrom(t, ts.URL+"/api/offers/"+offerID)
		state, _ := status["status"].(string)
		if state == "completed" {
			break
		}
		if state == "failed" {
			t.Fatalf("the authorization code flow failed: %v", status["error"])
		}
		if time.Now().After(deadline) {
			t.Fatalf("the issuance never completed after the login, last status %v", status)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The ticket must identify the account authenticated during this flow.
	var ticket *wallet.StoredCredential
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			credential := c
			ticket = &credential
		}
	}
	if ticket == nil {
		t.Fatal("no demo ticket was stored in the wallet")
	}
	if got := ticket.Claims["given_name"]; got != demoAccountGivenName {
		t.Errorf("ticket given_name = %v, want %q from the logged-in account", got, demoAccountGivenName)
	}
	// The issuer trusts the wallet attestation through its configured CA. The ticket
	// records that trust result.
	if got := ticket.Claims["wallet_attestation"]; got != "trusted" {
		t.Errorf("ticket wallet_attestation = %v, want trusted", got)
	}

	// OpenID4VCI 1.0 §6.2 defines no c_nonce in a token response, and this
	// issuer advertises a Nonce Endpoint (§7), so the token response carries
	// none.
	sawTokenResponse := false
	for _, entry := range w.GetLog() {
		if entry.Details == nil || entry.Details["endpoint"] != "token" || entry.Details["direction"] != "inbound" {
			continue
		}
		response, _ := entry.Details["response"].(map[string]any)
		if response == nil {
			continue
		}
		sawTokenResponse = true
		if _, present := response["c_nonce"]; present {
			t.Errorf("the token response carries a c_nonce, which OpenID4VCI 1.0 does not define: %v", response)
		}
		if _, present := response["c_nonce_expires_in"]; present {
			t.Errorf("the token response carries c_nonce_expires_in: %v", response)
		}
	}
	if !sawTokenResponse {
		t.Error("the activity log recorded no token response to check")
	}
}

func requestURIFromLoginPage(t *testing.T, page string) string {
	t.Helper()
	const marker = `name="request_uri" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("login page carries no request_uri field: %s", truncate(page))
	}
	rest := page[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed request_uri field: %s", truncate(rest))
	}
	return rest[:end]
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// HAIP requires client authentication. The authorization server refuses a
// pushed authorization request without a wallet attestation.
func TestPushedAuthorizationRequestRequiresWalletAttestation(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	// A valid DPoP proof, so what is left missing is the wallet attestation.
	dpop := signES256(t, clientKey,
		map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, clientKey)},
		map[string]any{"htm": "POST", "htu": ts.URL + "/issuer/par", "iat": time.Now().Unix(), "jti": "par-1"},
	)
	req, err := http.NewRequest("POST", ts.URL+"/issuer/par", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpop)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("pushing the authorization request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("PAR without client authentication was accepted: %s", body)
	}
	if !strings.Contains(string(body), "attestation") {
		t.Errorf("expected the error to name the missing attestation, got %s", body)
	}
}

func legacyIssuerHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"credential_issuer":                   "http://" + r.Host,
			"credential_endpoint":                 "http://" + r.Host + "/credential",
			"token_endpoint":                      "http://" + r.Host + "/token",
			"credential_configurations_supported": map[string]any{"legacy": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:legacy"}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
	})
	return mux
}

// Issuance with a profile override runs on a wallet clone. Forward the credential to
// the real wallet or the successful flow would store nothing.
func TestIssuanceWithOverrideStillStoresTheCredential(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	before := len(w.GetCredentials())
	created := postJSONTo(t, ts.URL+"/issuer/api/offers", "")
	schemeURI, _ := created["scheme_uri"].(string)

	// haip:true matches the server default. The only difference is that a
	// clone serves the request.
	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`,"haip":true}`)
	if result["error"] != nil {
		t.Fatalf("accepting the offer failed: %v", result["error"])
	}

	after := w.GetCredentials()
	if len(after) != before+1 {
		t.Fatalf("wallet holds %d credentials, want %d: the clone's import was lost", len(after), before+1)
	}
	var found bool
	for _, c := range after {
		if c.VCT == TicketVCT {
			found = true
		}
	}
	if !found {
		t.Error("the issued ticket is not in the wallet")
	}
}

// Batch copies use separate holder keys so presentations can rotate through unused
// copies.
func TestIssuerBatchOfferStoresEveryCopy(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	before := len(w.GetCredentials())
	redeemDemoTicket(t, w, ts, "?batch=true")

	var group string
	holderCopies := 0
	for _, c := range w.GetCredentials() {
		if c.VCT != TicketVCT {
			continue
		}
		if c.BatchGroup == "" {
			t.Fatalf("batch copy %s carries no batch group", c.ID)
		}
		if group == "" {
			group = c.BatchGroup
		} else if c.BatchGroup != group {
			t.Fatalf("batch copies landed in different groups: %s vs %s", group, c.BatchGroup)
		}
		if c.BindingKeyPEM == "" {
			holderCopies++
		}
	}
	if added := len(w.GetCredentials()) - before; added < 2 {
		t.Fatalf("a batch offer stored %d copies, want at least 2", added)
	}
	if holderCopies != 1 {
		t.Fatalf("a batch must have exactly one holder-key copy, got %d", holderCopies)
	}
}

func TestIssuerBatchSizeIsHonored(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	redeemDemoTicket(t, w, ts, "?batch=5")
	count := 0
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("a batch of 5 stored %d copies, want 5", count)
	}
}

// Advertising batch support alone must not make a single-credential offer issue a
// batch.
func TestIssuerPlainOfferStaysSingle(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	ticket := redeemDemoTicket(t, w, ts, "")
	if ticket.BatchGroup != "" {
		t.Fatalf("a plain offer produced a batch (group %s)", ticket.BatchGroup)
	}
	count := 0
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("a plain offer stored %d ticket copies, want 1", count)
	}
}

func TestIssuerOffersTicketWithoutStatusByDefault(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	ticket := redeemDemoTicket(t, w, ts, "")
	if _, ok := ticket.Claims["status"]; ok {
		t.Errorf("ticket carries a status claim without the toggle: %v", ticket.Claims["status"])
	}
	if _, managed := w.StatusEntryFor(ticket.ID); managed {
		t.Error("the wallet registered a status entry for a ticket without one")
	}
}

// A ticket with a wallet status reference must verify until the wallet revokes it.
func TestIssuerOffersRevocableTicket(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	ticket := redeemDemoTicket(t, w, ts, "?status=true")
	ref := wallet.CredentialStatusRef(*ticket)
	if ref == nil {
		t.Fatalf("ticket carries no status reference: %v", ticket.Claims)
	}
	if ref.URI != w.StatusListURL() {
		t.Errorf("status uri = %q, want the wallet's own list %q", ref.URI, w.StatusListURL())
	}
	// The wallet needs its own status entry to flip the bit and to show the
	// Revoke button.
	entry, managed := w.StatusEntryFor(ticket.ID)
	if !managed {
		t.Fatal("the wallet did not adopt the status entry of the ticket it issued to itself")
	}
	if entry.Index != ref.Idx {
		t.Errorf("adopted index = %d, want the one in the credential %d", entry.Index, ref.Idx)
	}

	if got := presentDemoTicket(t, ts); got["status"] != "verified" {
		t.Fatalf("a fresh ticket did not verify: %v (checks: %v)", got, got["checks"])
	}

	if _, ok := w.SetCredentialStatus(ticket.ID, 1); !ok {
		t.Fatal("revoking the ticket failed")
	}
	result := presentDemoTicket(t, ts)
	if result["status"] != "failed" {
		t.Fatalf("a revoked ticket still verified: %v (checks: %v)", result, result["checks"])
	}
	if !strings.Contains(fmt.Sprint(result["error"]), "revoked") {
		t.Errorf("verification failed for the wrong reason: %v", result["error"])
	}
}

// Each batch copy needs a distinct status index to avoid correlation. Revoking the
// batch must revoke every copy.
func TestIssuerRevokesAWholeBatch(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	rep := redeemDemoTicket(t, w, ts, "?status=true&batch=true")
	var copies []wallet.StoredCredential
	for _, c := range w.GetCredentials() {
		if c.BatchGroup != "" && c.BatchGroup == rep.BatchGroup {
			copies = append(copies, c)
		}
	}
	if len(copies) < 2 {
		t.Fatalf("a batch offer stored %d copies, want at least 2", len(copies))
	}
	seenIdx := make(map[int]bool)
	for _, c := range copies {
		ref := wallet.CredentialStatusRef(c)
		if ref == nil {
			t.Fatalf("copy %s carries no status reference", c.ID)
		}
		if seenIdx[ref.Idx] {
			t.Fatalf("two copies share status index %d, which links them", ref.Idx)
		}
		seenIdx[ref.Idx] = true
	}

	for round := 0; round <= len(copies); round++ {
		if got := presentDemoTicket(t, ts); got["status"] != "verified" {
			t.Fatalf("a fresh batch copy did not verify on round %d: %v", round, got["checks"])
		}
	}

	if _, ok := w.SetCredentialStatus(rep.ID, 1); !ok {
		t.Fatal("revoking the batch failed")
	}

	for round := 0; round <= len(copies); round++ {
		result := presentDemoTicket(t, ts)
		if result["status"] != "failed" {
			t.Fatalf("a revoked batch copy still verified on round %d: %v", round, result["checks"])
		}
		if !strings.Contains(fmt.Sprint(result["error"]), "revoked") {
			t.Errorf("round %d failed for the wrong reason: %v", round, result["error"])
		}
	}
}

// Two tickets issued with a status reference must land on different indices,
// or revoking one would revoke the other.
func TestIssuerReservesOneStatusIndexPerTicket(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	first := wallet.CredentialStatusRef(*redeemDemoTicket(t, w, ts, "?status=true"))
	second := wallet.CredentialStatusRef(*redeemDemoTicket(t, w, ts, "?status=true"))
	if first == nil || second == nil {
		t.Fatalf("a ticket carries no status reference: %v %v", first, second)
	}
	if first.Idx == second.Idx {
		t.Errorf("both tickets sit on status index %d", first.Idx)
	}
}

// A wallet with no status list URL cannot issue a status reference, so it
// refuses the offer.
func TestIssuerRefusesStatusOfferWithoutAStatusList(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?status=true", "", nil)
	if code != http.StatusConflict {
		t.Fatalf("creating the offer = %d %v, want 409", code, doc)
	}
}

// Reserving an index changes wallet state that every wallet API request
// reloads from disk, so it has to be persisted right away.
func TestIssuerPersistsTheReservedStatusIndex(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	w.BaseURL = "http://demo.example"
	saves := 0
	d.SetOnWalletChange(func() { saves++ })

	if _, err := d.signTicket(&holderKey.PublicKey, ticketGrant{}); err != nil {
		t.Fatalf("signing a ticket without a status reference: %v", err)
	}
	if saves != 0 {
		t.Errorf("a ticket without a status reference saved the wallet %d times", saves)
	}
	if _, err := d.signTicket(&holderKey.PublicKey, ticketGrant{withStatus: true}); err != nil {
		t.Fatalf("signing a ticket with a status reference: %v", err)
	}
	if saves != 1 {
		t.Errorf("the wallet was saved %d times after reserving an index, want 1", saves)
	}
}

// The authorization code flow creates a second state for the same offer, so the
// choice made when the offer was created has to survive the sign-in.
func TestAuthorizationCodeOfferKeepsTheStatusChoice(t *testing.T) {
	d, w, _ := newDemoRP(t)
	w.BaseURL = "http://demo.example"
	h := d.IssuerHandler()

	code, doc := doJSON(t, h, "POST", "/api/offers?grant=authorization_code&status=true", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating the offer: %d %v", code, doc)
	}
	offerURI := doc["offer_uri"].(string)
	_, offer := doJSON(t, h, "GET", "/offer/"+offerURI[strings.LastIndex(offerURI, "/")+1:], "", nil)
	grants := offer["grants"].(map[string]any)[authCodeGrant].(map[string]any)
	issuerState := grants["issuer_state"].(string)

	if src := d.offerByIssuerState(issuerState); src == nil || !src.withStatus {
		t.Error("the status choice was lost between the offer and its issuer_state")
	}
	if d.offerByIssuerState("some-other-state") != nil {
		t.Error("an unknown issuer_state must not resolve to an offer")
	}
}

func redeemDemoTicket(t *testing.T, w *wallet.Wallet, ts *httptest.Server, query string) *wallet.StoredCredential {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/issuer/api/offers"+query, "")
	schemeURI, _ := created["scheme_uri"].(string)
	if schemeURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}
	known := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		known[c.ID] = true
	}

	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if result["error"] != nil {
		t.Fatalf("accepting the offer failed: %v", result["error"])
	}
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT && !known[c.ID] {
			ticket := c
			return &ticket
		}
	}
	t.Fatal("the issued ticket is not in the wallet")
	return nil
}

func presentDemoTicket(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"ticket"}`)
	id, _ := created["id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	if id == "" || walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}
	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	resp.Body.Close()
	return getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
}

func TestVerifierPIDRequestAsksForTheChosenFormats(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	for _, tc := range []struct {
		name        string
		body        string
		wantFormats []string
		wantSets    bool
	}{
		{"default", `{"type":"pid"}`, []string{"dc+sd-jwt", "mso_mdoc"}, true},
		{"both", `{"type":"pid","format":"both"}`, []string{"dc+sd-jwt", "mso_mdoc"}, true},
		{"sd-jwt only", `{"type":"pid","format":"sd-jwt"}`, []string{"dc+sd-jwt"}, false},
		{"mdoc only", `{"type":"pid","format":"mdoc"}`, []string{"mso_mdoc"}, false},
		{"ticket", `{"type":"ticket"}`, []string{"dc+sd-jwt"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, doc := doJSON(t, h, "POST", "/api/requests", tc.body, map[string]string{"Content-Type": "application/json"})
			walletURL, err := url.Parse(doc["wallet_url"].(string))
			if err != nil {
				t.Fatalf("parsing wallet_url: %v", err)
			}
			payload := fetchRequestObject(t, h, walletURL.Query().Get("request_uri"))
			dcql, ok := payload["dcql_query"].(map[string]any)
			if !ok {
				t.Fatalf("request object carries no dcql_query: %v", payload)
			}
			credentials, _ := dcql["credentials"].([]any)
			var formats []string
			for _, c := range credentials {
				entry, _ := c.(map[string]any)
				format, _ := entry["format"].(string)
				formats = append(formats, format)
			}
			if strings.Join(formats, ",") != strings.Join(tc.wantFormats, ",") {
				t.Errorf("requested formats = %v, want %v", formats, tc.wantFormats)
			}
			// Two credentials without a credential set would mean the wallet
			// has to present both, which no wallet holding one format can do.
			if _, hasSets := dcql["credential_sets"]; hasSets != tc.wantSets {
				t.Errorf("credential_sets present = %v, want %v", hasSets, tc.wantSets)
			}
		})
	}
}

func TestVerifierRejectsAnImpossibleFormat(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	for _, tc := range []struct{ name, body string }{
		{"unknown format", `{"type":"pid","format":"jwt_vc_json"}`},
		{"mdoc ticket", `{"type":"ticket","format":"mdoc"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc := doJSON(t, h, "POST", "/api/requests", tc.body, map[string]string{"Content-Type": "application/json"})
			if code != http.StatusBadRequest {
				t.Fatalf("creating the request = %d %v, want 400", code, doc)
			}
		})
	}
}

func TestVerifierSteersThePIDFormatEndToEnd(t *testing.T) {
	for _, tc := range []struct{ name, format, wantCheck string }{
		{"sd-jwt only", "sd-jwt", "presentation parses as SD-JWT"},
		{"mdoc only", "mdoc", "presentation parses as an mdoc DeviceResponse"},
		{"both", "both", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holderKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating holder key: %v", err)
			}
			issuerKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating issuer key: %v", err)
			}
			w := wallet.New(holderKey, issuerKey, true)
			w.RequireHAIP = true
			w.ValidationMode = wallet.ValidationModeStrict
			if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
				t.Fatalf("generating PID: %v", err)
			}
			_, ts := serveDemoStack(t, w)

			created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid","format":"`+tc.format+`"}`)
			id, _ := created["id"].(string)
			walletURL, _ := created["wallet_url"].(string)
			if id == "" || walletURL == "" {
				t.Fatalf("unexpected create response: %v", created)
			}
			resp, err := ts.Client().Get(walletURL)
			if err != nil {
				t.Fatalf("driving the authorization request: %v", err)
			}
			resp.Body.Close()

			status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
			if status["status"] != "verified" {
				t.Fatalf("status = %v, want verified (error: %v, checks: %v)", status["status"], status["error"], status["checks"])
			}
			if tc.wantCheck != "" && !hasCheck(status, tc.wantCheck) {
				t.Errorf("the presentation was not verified as the requested format, checks: %v", status["checks"])
			}
		})
	}
}

func hasCheck(status map[string]any, name string) bool {
	checks, _ := status["checks"].([]any)
	for _, entry := range checks {
		check, _ := entry.(map[string]any)
		if check["name"] == name {
			return true
		}
	}
	return false
}

// Return the presented credential even when verification fails so it can be inspected
// in the decoder.
func TestVerifierReportsTheReceivedPresentation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nonce      func(params url.Values) string
		wantStatus string
	}{
		{"verified", func(p url.Values) string { return p.Get("nonce") }, "verified"},
		{"failed", func(url.Values) string { return "wrong-nonce" }, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, holderKey := newDemoRP(t)
			h := d.VerifierHandler()

			id, params := startVerification(t, h, "ticket")
			presentation := presentTicket(t, d, holderKey, params.Get("client_id"), tc.nonce(params))
			postPresentation(t, h, id, "ticket", presentation)

			_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
			if status["status"] != tc.wantStatus {
				t.Fatalf("status = %v, want %v", status["status"], tc.wantStatus)
			}
			if status["presentation"] != presentation {
				t.Errorf("the result does not carry the presentation that arrived: %v", status["presentation"])
			}
		})
	}
}

func TestVerifierReportsNoPresentationWhilePending(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	id, _ := startVerification(t, h, "ticket")
	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if _, ok := status["presentation"]; ok {
		t.Errorf("a pending request reported a presentation: %v", status["presentation"])
	}
}

// Keep the full mdoc DeviceResponse for the decoder, including the device
// authentication bound to this request.
func TestVerifierReportsTheReceivedMDOCPresentation(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid","format":"mdoc"}`)
	id, _ := created["id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	resp.Body.Close()

	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (checks: %v)", status["status"], status["checks"])
	}
	presentation, _ := status["presentation"].(string)
	if presentation == "" {
		t.Fatal("the result carries no presentation")
	}
	doc, err := mdoc.Parse(presentation)
	if err != nil {
		t.Fatalf("the reported presentation does not parse as a DeviceResponse: %v", err)
	}
	if doc.DeviceSigned == nil {
		t.Error("the reported presentation carries no device auth")
	}
}

// A signing failure is a server fault. The §8.3.1.2 codes describe faults in
// the request and are answered with 400. credential_request_denied says "The
// Wallet SHOULD treat this error as unrecoverable, meaning if received from a
// Credential Issuer the Credential cannot be issued". The next attempt may
// succeed, so the wallet must not give up.
func TestIssuerReportsASigningFailureAsAServerFault(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	_, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]
	_, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grants["pre-authorized_code"].(string)}}
	_, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), attestedTokenHeaders(t))

	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": nonceDoc["c_nonce"]},
	)

	// With no certificate chain the ticket cannot be signed.
	w.CertChain = nil

	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q]}}`, ticketConfigurationID, proof)
	code, doc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + tokenDoc["access_token"].(string),
		"Content-Type":  "application/json",
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (%v)", code, doc)
	}
	if doc["error"] == "credential_request_denied" {
		t.Errorf("a signing failure was reported as %v, which tells the wallet to give up for good", doc["error"])
	}
}

// OpenID4VP 1.0 §5.1 carries registered purposes in verifier_info.
func TestVerifierRequestCarriesARegistrationCertificate(t *testing.T) {
	d, w, _ := newDemoRP(t)
	h := d.VerifierHandler()

	_, doc := doJSON(t, h, "POST", "/api/requests", `{"type":"pid"}`, map[string]string{"Content-Type": "application/json"})
	walletURL, err := url.Parse(doc["wallet_url"].(string))
	if err != nil {
		t.Fatalf("parsing wallet_url: %v", err)
	}
	payload := fetchRequestObject(t, h, walletURL.Query().Get("request_uri"))

	entries, _ := payload["verifier_info"].([]any)
	if len(entries) != 1 {
		t.Fatalf("verifier_info = %v, want one attestation", payload["verifier_info"])
	}
	entry, _ := entries[0].(map[string]any)
	if got, _ := entry["format"].(string); got != "registration_cert" {
		t.Errorf("format = %q, want registration_cert (ETSI TS 119 472-2)", got)
	}
	data, _ := entry["data"].(string)
	cert, err := parseCompactJWT(data)
	if err != nil {
		t.Fatalf("parsing registration certificate: %v", err)
	}
	if typ, _ := cert.header["typ"].(string); typ != "rc-wrp+jwt" {
		t.Errorf("typ = %q, want rc-wrp+jwt (ETSI TS 119 475)", typ)
	}
	// The purpose is localized as {lang, value} entries, like the EUDI
	// reference certificate.
	entries2, _ := cert.payload["purpose"].([]any)
	if len(entries2) != 1 {
		t.Fatalf("purpose = %v, want one localized entry", cert.payload["purpose"])
	}
	localized, _ := entries2[0].(map[string]any)
	if value, _ := localized["value"].(string); !strings.Contains(value, "identity") {
		t.Errorf("purpose = %v, want the PID request's purpose", localized)
	}

	_, chain, err := w.RegistrarSigningMaterial()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	leafKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("leaf certificate does not hold an EC key")
	}
	if !verifyES256(leafKey, cert.signingInput, cert.signature) {
		t.Error("the registration certificate is not signed by the registrar's signing key")
	}
}

// The two ticket shapes a PID request can carry: "combined" puts the ticket
// into one option next to the SD-JWT PID, "optional" adds a set the wallet
// may skip. Both list the ticket as its own credential query.
func TestVerifierTicketRequestShapes(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	create := func(body string) map[string]any {
		t.Helper()
		code, doc := doJSON(t, h, "POST", "/api/requests", body, map[string]string{"Content-Type": "application/json"})
		if code != http.StatusCreated {
			t.Fatalf("creating request: %d %v", code, doc)
		}
		id, _ := doc["id"].(string)
		payload := fetchRequestObject(t, h, "/request/"+id)
		dcql, _ := payload["dcql_query"].(map[string]any)
		if dcql == nil {
			t.Fatalf("request object carries no dcql_query: %v", payload)
		}
		return dcql
	}

	queryIDsOf := func(dcql map[string]any) []string {
		var ids []string
		for _, c := range dcql["credentials"].([]any) {
			ids = append(ids, c.(map[string]any)["id"].(string))
		}
		return ids
	}
	optionsOf := func(set any) [][]string {
		var out [][]string
		for _, opt := range set.(map[string]any)["options"].([]any) {
			var ids []string
			for _, id := range opt.([]any) {
				ids = append(ids, id.(string))
			}
			out = append(out, ids)
		}
		return out
	}

	t.Run("combined", func(t *testing.T) {
		dcql := create(`{"type":"pid","ticket":"combined"}`)
		if ids := queryIDsOf(dcql); !reflect.DeepEqual(ids, []string{"pid", "pid_mdoc", "ticket"}) {
			t.Fatalf("credential queries = %v", ids)
		}
		sets := dcql["credential_sets"].([]any)
		if len(sets) != 1 {
			t.Fatalf("got %d sets, want 1", len(sets))
		}
		want := [][]string{{"pid", "ticket"}, {"pid"}, {"pid_mdoc"}}
		if got := optionsOf(sets[0]); !reflect.DeepEqual(got, want) {
			t.Errorf("options = %v, want %v", got, want)
		}
	})

	t.Run("optional", func(t *testing.T) {
		dcql := create(`{"type":"pid","ticket":"optional"}`)
		sets := dcql["credential_sets"].([]any)
		if len(sets) != 2 {
			t.Fatalf("got %d sets, want 2", len(sets))
		}
		if got := optionsOf(sets[0]); !reflect.DeepEqual(got, [][]string{{"pid"}, {"pid_mdoc"}}) {
			t.Errorf("PID set options = %v", got)
		}
		if got := optionsOf(sets[1]); !reflect.DeepEqual(got, [][]string{{"ticket"}}) {
			t.Errorf("ticket set options = %v", got)
		}
		if required, ok := sets[1].(map[string]any)["required"].(bool); !ok || required {
			t.Errorf("the ticket set must carry required: false, got %v", sets[1])
		}
	})

	t.Run("refused shapes", func(t *testing.T) {
		for name, body := range map[string]string{
			"ticket on a ticket request": `{"type":"ticket","ticket":"optional"}`,
			"combined without SD-JWT":    `{"type":"pid","format":"mdoc","ticket":"combined"}`,
			"unknown mode":               `{"type":"pid","ticket":"maybe"}`,
		} {
			code, _ := doJSON(t, h, "POST", "/api/requests", body, map[string]string{"Content-Type": "application/json"})
			if code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", name, code)
			}
		}
	})
}
