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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/experimental"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

// delegateWallet accepts the transaction data type delegate (ADR-0033).
func delegateWallet(t *testing.T, mode string) (*Wallet, StoredCredential) {
	t.Helper()
	w, cred := transactionDataWallet(t, mode)
	settings := w.Conformance()
	settings.DelegateSDJWT = true
	w.SetConformance(settings)
	return w, cred
}

func testDisclosure(t *testing.T, parts ...any) string {
	t.Helper()
	encoded, err := json.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	return format.EncodeBase64URL(encoded)
}

// mandate is a delegate transaction data entry
// (draft-ietf-oauth-delegate-sd-jwt-00 §7.1). Its delegate payload holds the
// agent key as cnf and has one selectively disclosable audience per verifier.
type mandate struct {
	entry     map[string]any
	payload   string
	audiences []string
}

func newMandate(t *testing.T, agent *ecdsa.PublicKey, sdAlg string) mandate {
	t.Helper()
	m := mandate{audiences: []string{
		testDisclosure(t, "salt-1", "https://supplier.example"),
		testDisclosure(t, "salt-2", "https://api.example"),
	}}
	elements := make([]any, 0, len(m.audiences))
	for _, audience := range m.audiences {
		digest, err := sdjwt.SDHash(audience, sdAlg)
		if err != nil {
			t.Fatal(err)
		}
		elements = append(elements, map[string]any{"...": digest})
	}
	claims := map[string]any{
		"vct": "urn:example:agent-mandate:1", "exp": time.Now().Add(time.Hour).Unix(),
		"mandate": map[string]any{"actions": []any{"order.create"}, "audiences": elements},
	}
	if agent != nil {
		claims["cnf"] = map[string]any{"jwk": mock.SigningJWKMap(agent)}
	}
	m.payload = testDisclosure(t, "salt-p", claims)
	m.entry = map[string]any{
		"type": "delegate", "credential_ids": []any{"pid"}, "format": delegate.FormatDSDJWTKB,
		"delegate_payload_disclosure": m.payload, "delegate_disclosures": []any{m.audiences[0], m.audiences[1]},
	}
	return m
}

func presentDelegation(t *testing.T, w *Wallet, cred StoredCredential, entries ...map[string]any) (string, []string, error) {
	t.Helper()
	encoded := make([]string, 0, len(entries))
	for _, entry := range entries {
		encoded = append(encoded, encodedTransactionData(t, entry))
	}
	match := consent.Match{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format, SelectedKeys: []string{"given_name", "family_name"}}
	result, err := w.createVPTokenMap([]consent.Match{match}, transactionDataPresentationRequest(encoded...))
	if err != nil {
		return "", encoded, err
	}
	return result.TokenMap["pid"][0], encoded, nil
}

func agentKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// §7.1: "To delegate an dSD-JWT or dSD-JWT+KB the transaction data type
// delegate MAY be used."
func TestDelegateTransactionDataIsAnsweredWithADelegateSDJWT(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	agent := agentKey(t)
	m := newMandate(t, &agent.PublicKey, "sha-256")
	token, encoded, err := presentDelegation(t, w, cred, m.entry)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("vp_token: %s", token)

	// §5.1.1: <SD-JWT>~~<KB-JWT>~<Delegated Disclosure 1>~...~
	sdJWT, kbSDJWT, ok := strings.Cut(token, "~~")
	if !ok {
		t.Fatalf("the vp_token has no empty component: %s", token)
	}
	if want := "~" + strings.Join(append([]string{m.payload}, m.audiences...), "~") + "~"; !strings.HasSuffix(kbSDJWT, want) {
		t.Errorf("the KB-SD-JWT is followed by %q, want the disclosures of the entry unchanged", kbSDJWT[strings.Index(kbSDJWT, "~"):])
	}

	delegation, err := delegate.Verify(token, &w.IssuerKey.PublicKey, delegate.Options{Audience: "https://verifier.example", Nonce: "n", MaxAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	// RFC 9901 §4.3.1: sd_hash covers the Issuer-signed JWT and the selected
	// Disclosures.
	if got := len(delegation.Credential.Disclosures); got != 2 {
		t.Errorf("the SD-JWT has %d disclosures, want given_name and family_name", got)
	}
	if delegation.Format() != delegate.FormatDSDJWT || len(delegation.Links) != 1 {
		t.Fatalf("format = %s with %d KB-SD-JWTs, want a dSD-JWT with 1", delegation.Format(), len(delegation.Links))
	}
	link := delegation.Links[0]
	if want := map[string]any{"typ": delegate.TypeKBSDJWTKB, "alg": "ES256"}; !reflect.DeepEqual(link.Token.Header, want) {
		t.Errorf("KB-SD-JWT header = %v, want %v", link.Token.Header, want)
	}
	payload := link.Token.Payload
	payloadDigest, _ := sdjwt.SDHash(m.payload, "sha-256")
	sdHash, _ := sdjwt.SDHash(sdJWT+"~", "sha-256")
	entryHash, _ := sdjwt.SDHash(encoded[0], "sha-256")
	want := map[string]any{
		"iat": payload["iat"], "aud": "https://verifier.example", "nonce": "n", "sd_hash": sdHash, "_sd_alg": "sha-256",
		"delegate_payload":        []any{map[string]any{"...": payloadDigest}},
		"transaction_data_hashes": []any{entryHash},
	}
	if !reflect.DeepEqual(payload, want) {
		t.Errorf("KB-SD-JWT payload = %v, want %v", payload, want)
	}
	if _, ok := payload["iat"].(float64); !ok {
		t.Errorf("iat = %v, want a number", payload["iat"])
	}
	mandateClaims, _ := link.Payload["mandate"].(map[string]any)
	if want := []any{"https://supplier.example", "https://api.example"}; !reflect.DeepEqual(mandateClaims["audiences"], want) {
		t.Errorf("audiences = %v, want %v", mandateClaims["audiences"], want)
	}
}

// §5.1.1: the Delegate Holder shows a Verifier its own audience and appends a
// KB-JWT signed with the cnf key of the Delegate Payload.
func TestDelegateHolderPresentsTheDelegateSDJWT(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	agent := agentKey(t)
	m := newMandate(t, &agent.PublicKey, "sha-256")
	token, _, err := presentDelegation(t, w, cred, m.entry)
	if err != nil {
		t.Fatal(err)
	}
	presented := strings.TrimSuffix(token, m.audiences[1]+"~")
	kbSDJWT := presented[strings.Index(presented, "~~")+2:]
	sdHash, _ := sdjwt.SDHash(kbSDJWT, "sha-256")
	kbJWT, err := jws.Sign(map[string]any{"typ": "kb+jwt", "alg": jws.AlgES256},
		map[string]any{"iat": time.Now().Unix(), "aud": "https://supplier.example", "nonce": "n-2", "sd_hash": sdHash}, agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dSD-JWT+KB: %s", presented+kbJWT)

	delegation, err := delegate.Verify(presented+kbJWT, &w.IssuerKey.PublicKey,
		delegate.Options{Audience: "https://supplier.example", Nonce: "n-2", MaxAge: time.Minute, RequireKeyBinding: true})
	if err != nil {
		t.Fatal(err)
	}
	mandateClaims, _ := delegation.Links[0].Payload["mandate"].(map[string]any)
	if want := []any{"https://supplier.example"}; !reflect.DeepEqual(mandateClaims["audiences"], want) {
		t.Errorf("audiences = %v, want %v", mandateClaims["audiences"], want)
	}
}

func delegationHeaderAndPayload(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()
	delegation, err := delegate.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	return delegation.Links[0].Token.Header, delegation.Links[0].Token.Payload
}

// §5.1.4: with the typ kb+sd-jwt the KB-SD-JWT ends the chain. With
// kb-sd-jwt+kb the Delegate Holder can append a KB-JWT.
func TestDelegateFormatSelectsTheKBSDJWTType(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	m := newMandate(t, nil, "sha-256")
	m.entry["format"] = delegate.FormatDSDJWT
	token, _, err := presentDelegation(t, w, cred, m.entry)
	if err != nil {
		t.Fatal(err)
	}
	if header, _ := delegationHeaderAndPayload(t, token); header["typ"] != delegate.TypeKBSDJWT {
		t.Errorf("typ = %v, want %s", header["typ"], delegate.TypeKBSDJWT)
	}
}

// §7.1: "_sd_alg may use any hash algorithm specified for hashing the
// transaction_data."
func TestDelegateSDAlgIsTheTransactionDataHashAlg(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	m := newMandate(t, &agentKey(t).PublicKey, "sha-384")
	m.entry["transaction_data_hashes_alg"] = []any{"sha-384"}
	token, _, err := presentDelegation(t, w, cred, m.entry)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := delegationHeaderAndPayload(t, token)
	if payload["_sd_alg"] != "sha-384" || payload["transaction_data_hashes_alg"] != "sha-384" {
		t.Errorf("_sd_alg = %v, transaction_data_hashes_alg = %v, want sha-384 for both", payload["_sd_alg"], payload["transaction_data_hashes_alg"])
	}
	if _, err := delegate.Verify(token, &w.IssuerKey.PublicKey, delegate.Options{Audience: "https://verifier.example", Nonce: "n", MaxAge: time.Minute}); err != nil {
		t.Error(err)
	}
}

// §7.1: "Multiple delegate transaction_data MAY be included in the same
// request. In that case, each MUST have their digest included in the
// delegate_payload."
func TestSeveralDelegateEntriesShareOneKBSDJWT(t *testing.T) {
	w, cred := delegateWallet(t, "strict")
	first := newMandate(t, &agentKey(t).PublicKey, "sha-256")
	second := newMandate(t, &agentKey(t).PublicKey, "sha-256")
	token, _, err := presentDelegation(t, w, cred, first.entry, second.entry)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := delegationHeaderAndPayload(t, token)
	var want []any
	for _, m := range []mandate{first, second} {
		digest, _ := sdjwt.SDHash(m.payload, "sha-256")
		want = append(want, map[string]any{"...": digest})
	}
	if !reflect.DeepEqual(payload["delegate_payload"], want) {
		t.Errorf("delegate_payload = %v, want %v", payload["delegate_payload"], want)
	}
	if hashes, _ := payload["transaction_data_hashes"].([]any); len(hashes) != 2 {
		t.Errorf("transaction_data_hashes = %v, want 2 hashes", payload["transaction_data_hashes"])
	}
}

// Without --delegate-sd-jwt, the wallet answers a delegate entry with an
// SD-JWT+KB (ADR-0033).
func TestADelegateEntryGetsAKeyBindingJWTWithoutDelegateSDJWT(t *testing.T) {
	w, cred := transactionDataWallet(t, "debug")
	token, encoded, err := presentDelegation(t, w, cred, newMandate(t, &agentKey(t).PublicKey, "sha-256").entry)
	if err != nil {
		t.Fatal(err)
	}
	if delegate.IsChain(token) {
		t.Fatalf("the vp_token is a dSD-JWT: %s", token)
	}
	entryHash, _ := sdjwt.SDHash(encoded[0], "sha-256")
	if got := keyBindingPayload(t, token)["transaction_data_hashes"]; !reflect.DeepEqual(got, []any{entryHash}) {
		t.Errorf("transaction_data_hashes = %v, want [%s]", got, entryHash)
	}
}

// One KB-SD-JWT has one typ and one _sd_alg for all its delegate payloads.
// §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate Payload MUST include a
// cnf claim."
func TestDelegateEntriesThatDoNotFitOneKBSDJWTAreRefused(t *testing.T) {
	withoutCnf := func(t *testing.T) []map[string]any {
		plain := newMandate(t, nil, "sha-256")
		plain.entry["format"] = delegate.FormatDSDJWT
		return []map[string]any{newMandate(t, &agentKey(t).PublicKey, "sha-256").entry, plain.entry}
	}
	otherAlg := func(t *testing.T) []map[string]any {
		sha384 := newMandate(t, &agentKey(t).PublicKey, "sha-384")
		sha384.entry["transaction_data_hashes_alg"] = []any{"sha-384"}
		return []map[string]any{newMandate(t, &agentKey(t).PublicKey, "sha-256").entry, sha384.entry}
	}
	// Both entries allow sha-384, so it becomes _sd_alg.
	digestsUnderAnotherAlg := func(t *testing.T) []map[string]any {
		sha256 := newMandate(t, &agentKey(t).PublicKey, "sha-256")
		sha256.entry["transaction_data_hashes_alg"] = []any{"sha-256", "sha-384"}
		sha384 := newMandate(t, &agentKey(t).PublicKey, "sha-384")
		sha384.entry["transaction_data_hashes_alg"] = []any{"sha-384"}
		return []map[string]any{sha256.entry, sha384.entry}
	}
	for _, tt := range []struct {
		name    string
		entries func(t *testing.T) []map[string]any
		want    string
	}{
		{"digests under another algorithm than _sd_alg", digestsUnderAnotherAlg, "the Delegate Payload of transaction_data[0] contains the sha-384 digest"},
		{"a payload without cnf under kb-sd-jwt+kb", withoutCnf, "shares a KB-SD-JWT of typ kb-sd-jwt+kb with another entry, but its Delegate Payload has no cnf claim"},
		{"entries without a common hash algorithm", otherAlg, "have no common hash algorithm"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w, cred := delegateWallet(t, "strict")
			_, _, err := presentDelegation(t, w, cred, tt.entries(t)...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
			// OpenID4VP 1.0 §8.5: invalid_transaction_data.
			if _, ok := asTransactionDataRefusal(err); !ok {
				t.Errorf("err = %v, want a transaction data refusal", err)
			}

			w, cred = delegateWallet(t, "debug")
			token, _, err := presentDelegation(t, w, cred, tt.entries(t)...)
			if err != nil {
				t.Fatal(err)
			}
			if !delegate.IsChain(token) {
				t.Errorf("the debug wallet answered without a KB-SD-JWT: %s", token)
			}
		})
	}
}

func delegateAuthorizationRequest(t *testing.T, verifierURL string, entry map[string]any) url.Values {
	t.Helper()
	transactionData, err := json.Marshal([]string{encodedTransactionData(t, entry)})
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{
		"client_id": {"redirect_uri:" + verifierURL}, "response_type": {"vp_token"}, "response_mode": {"direct_post"},
		"nonce": {"n"}, "state": {"s"}, "response_uri": {verifierURL}, "transaction_data": {string(transactionData)},
		"dcql_query": {dcqlQueryParam(t, map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		}}})},
	}
}

func delegateServer(t *testing.T) *Server {
	t.Helper()
	srv := newStrictTestServer(t, true)
	settings := srv.wallet.Conformance()
	settings.TransactionData = true
	settings.DelegateSDJWT = true
	srv.wallet.SetConformance(settings)
	return srv
}

func TestTheVerifierReceivesTheDelegateSDJWT(t *testing.T) {
	srv := delegateServer(t)
	verifier := newCaptureVerifier(t)
	authorizeRequest(t, srv, delegateAuthorizationRequest(t, verifier.URL, newMandate(t, &agentKey(t).PublicKey, "sha-256").entry))

	var vpToken map[string][]string
	if err := json.Unmarshal([]byte(verifier.received(t).Get("vp_token")), &vpToken); err != nil || len(vpToken["pid"]) != 1 {
		t.Fatalf("vp_token = %v (%v), want one presentation for pid", vpToken, err)
	}
	delegation, err := delegate.Verify(vpToken["pid"][0], &srv.wallet.IssuerKey.PublicKey, delegate.Options{Audience: "redirect_uri:" + verifier.URL, Nonce: "n", MaxAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if delegation.Links[0].Payload["vct"] != "urn:example:agent-mandate:1" {
		t.Errorf("delegate payload = %v", delegation.Links[0].Payload)
	}
}

// §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate Payload MUST include a
// cnf claim."
func TestStrictModeRefusesADelegationWithoutAConfirmationKey(t *testing.T) {
	srv := delegateServer(t)
	rec := authorizeRequest(t, srv, delegateAuthorizationRequest(t, "https://verifier.example/response", newMandate(t, nil, "sha-256").entry))
	// Strict mode refuses the request before consent. The error goes back in
	// the response.
	if !strings.Contains(rec.Body.String(), oid4vp.ErrorInvalidTransactionData) {
		t.Fatalf("%d %s, want %s", rec.Code, rec.Body, oid4vp.ErrorInvalidTransactionData)
	}
}

func TestTheConsentRequestSumsUpADelegation(t *testing.T) {
	srv := delegateServer(t)
	srv.wallet.AutoAccept = false
	agent := agentKey(t)
	req := transactionDataPresentationRequest(encodedTransactionData(t, newMandate(t, &agent.PublicKey, "sha-256").entry))
	var shown consent.TransactionData
	ctx, cancel := context.WithCancel(context.Background())
	i := slices.IndexFunc(srv.wallet.GetCredentials(), func(c StoredCredential) bool { return c.Format == "dc+sd-jwt" })
	if i < 0 {
		t.Fatal("no SD-JWT credential")
	}
	cred := srv.wallet.GetCredentials()[i]
	outcome := presentationOutcome{matches: []consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}}
	_, _, _, _, err := srv.wallet.askPresentationConsent(ctx, "vp", "", "", req, outcome, time.Second, func(r *consent.Request) {
		shown = r.TransactionData[0]
		cancel()
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(shown.Summary, "Delegate this credential to the key ") || !strings.HasSuffix(shown.Summary, " UTC") {
		t.Errorf("summary = %q, want the key and the end of the delegation", shown.Summary)
	}
	if shown.DelegatePayload["vct"] != "urn:example:agent-mandate:1" {
		t.Errorf("delegate payload = %v, want the decoded payload", shown.DelegatePayload)
	}
}

// Without Delegate SD-JWT, delegate is an ordinary transaction data type
// (ADR-0033). Listed in --transaction-data-type, it gets an SD-JWT+KB that
// signs the entry's hash, even when the entry breaks §7.1.
func TestAListedDelegateTypeIsOrdinaryWithoutDelegateSDJWT(t *testing.T) {
	srv := newStrictTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPut, "/api/config/conformance", `{"transaction_data":true,"transaction_data_types":["delegate"]}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT answered %d: %s", resp.Code, resp.Body.String())
	}
	if got := srv.wallet.Conformance().TransactionDataTypes; !slices.Equal(got, []string{"delegate"}) {
		t.Errorf("transaction data types = %v, want [delegate]", got)
	}
	verifier := newCaptureVerifier(t)
	entry := newMandate(t, nil, "sha-256").entry
	authorizeRequest(t, srv, delegateAuthorizationRequest(t, verifier.URL, entry))

	var vpToken map[string][]string
	if err := json.Unmarshal([]byte(verifier.received(t).Get("vp_token")), &vpToken); err != nil || len(vpToken["pid"]) != 1 {
		t.Fatalf("vp_token = %v (%v), want one presentation for pid", vpToken, err)
	}
	token := vpToken["pid"][0]
	if delegate.IsChain(token) {
		t.Fatalf("the vp_token is a dSD-JWT: %s", token)
	}
	entryHash, _ := sdjwt.SDHash(encodedTransactionData(t, entry), "sha-256")
	if got := keyBindingPayload(t, token)["transaction_data_hashes"]; !reflect.DeepEqual(got, []any{entryHash}) {
		t.Errorf("transaction_data_hashes = %v, want [%s]", got, entryHash)
	}
}

func TestDelegateSDJWTNeedsTransactionData(t *testing.T) {
	w := generateTestWalletWithPID(t)
	on := true
	if err := w.UpdateConformance(ConformancePatch{Patch: experimental.Patch{DelegateSDJWT: &on}}); err != nil {
		t.Fatal(err)
	}
	if w.Conformance().Delegates() || slices.Contains(w.Conformance().acceptedTransactionDataTypes(), oid4vp.DelegateTransactionDataType) {
		t.Error("the wallet accepts delegate without transaction data")
	}
}

// Only an SD-JWT with a cnf key can sign a KB-SD-JWT, so the consent dialog
// offers a delegation only for one.
func TestOnlyABoundSDJWTCanDelegate(t *testing.T) {
	w, bound := delegateWallet(t, "debug")
	noStatus := ""
	unbound, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:bearer", Unbound: true, StatusListURI: &noStatus})
	if err != nil {
		t.Fatal(err)
	}
	req := transactionDataPresentationRequest(encodedTransactionData(t, newMandate(t, &agentKey(t).PublicKey, "sha-256").entry))
	entries := w.transactionData(req)
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want 1", entries)
	}
	for _, tt := range []struct {
		name string
		cred StoredCredential
		want bool
	}{{"bound", bound, true}, {"unbound", *unbound.Credential, false}} {
		match := consent.Match{QueryID: "pid", CredentialID: tt.cred.ID, Format: tt.cred.Format}
		if got := w.canDelegate(entries[0], []consent.Match{match}); got != tt.want {
			t.Errorf("%s SD-JWT: canDelegate = %t, want %t", tt.name, got, tt.want)
		}
	}
}
