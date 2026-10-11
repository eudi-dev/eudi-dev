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
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

func testEncJWK(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	jwkJSON := mock.PublicKeyJWK(pub)
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("parsing JWK: %v", err)
	}
	jwk["alg"] = "ECDH-ES"
	return jwk
}

func TestEncryptResponse_DirectPostJWTPayloadIncludesStateAsTopLevelMember(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
				"encrypted_response_enc_values_supported": []any{"A128GCM"},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	vpToken := map[string][]string{"pid": {"token1"}}
	jweStr, _, err := w.encryptResponse(vpToken, "eyJ.id.token", "state-123", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	plaintext, err := oid4vp.DecryptRequestObjectJWE(jweStr, key)
	if err != nil {
		t.Fatalf("oid4vp.DecryptRequestObjectJWE error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if payload["state"] != "state-123" {
		t.Fatalf("expected state inside encrypted payload, got %v", payload["state"])
	}
	if payload["id_token"] != "eyJ.id.token" {
		t.Fatalf("expected id_token inside encrypted payload, got %v", payload["id_token"])
	}

	rawVPToken, ok := payload["vp_token"].(map[string]any)
	if !ok {
		t.Fatalf("expected vp_token object inside encrypted payload, got %T", payload["vp_token"])
	}
	pidValues, ok := rawVPToken["pid"].([]any)
	if !ok || len(pidValues) != 1 || pidValues[0] != "token1" {
		t.Fatalf("expected pid array with token1 inside encrypted payload, got %v", rawVPToken["pid"])
	}
}

func TestEncryptErrorResponse_DirectPostJWTPayloadIncludesStateAsTopLevelMember(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
				"encrypted_response_enc_values_supported": []any{"A128GCM"},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	jweStr, _, err := w.encryptErrorResponse("access_denied", "testing", "state-123", params)
	if err != nil {
		t.Fatalf("EncryptErrorResponse error: %v", err)
	}

	plaintext, err := oid4vp.DecryptRequestObjectJWE(jweStr, key)
	if err != nil {
		t.Fatalf("oid4vp.DecryptRequestObjectJWE error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if payload["error"] != "access_denied" {
		t.Fatalf("expected error inside encrypted payload, got %v", payload["error"])
	}
	if payload["error_description"] != "testing" {
		t.Fatalf("expected error_description inside encrypted payload, got %v", payload["error_description"])
	}
	if payload["state"] != "state-123" {
		t.Fatalf("expected state inside encrypted payload, got %v", payload["state"])
	}
}

func TestEncryptResponse_MDocISOIncludesAPUAndAPV(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
				"encrypted_response_enc_values_supported": []any{"A128GCM"},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-auth-request-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	jweStr, _, err := w.encryptResponse(map[string][]string{"pid": {"token1"}}, "", "state-123", "mdoc-generated-nonce", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	if len(parts) != 5 {
		t.Fatalf("expected compact JWE with 5 parts, got %d", len(parts))
	}

	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding protected header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parsing protected header: %v", err)
	}

	apuVal, ok := header["apu"].(string)
	if !ok {
		t.Fatal("expected apu in protected header")
	}
	decodedAPU, err := format.DecodeBase64URL(apuVal)
	if err != nil {
		t.Fatalf("decoding apu: %v", err)
	}
	if string(decodedAPU) != "mdoc-generated-nonce" {
		t.Fatalf("expected apu=mdoc-generated-nonce, got %q", decodedAPU)
	}

	apvVal, ok := header["apv"].(string)
	if !ok {
		t.Fatal("expected apv in protected header")
	}
	decodedAPV, err := format.DecodeBase64URL(apvVal)
	if err != nil {
		t.Fatalf("decoding apv: %v", err)
	}
	if string(decodedAPV) != "test-auth-request-nonce" {
		t.Fatalf("expected apv=test-auth-request-nonce, got %q", decodedAPV)
	}
}

func TestCreateVPToken_SDJWT(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var sdCred StoredCredential
	for _, c := range creds {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	match := consent.Match{
		QueryID:      "test_query",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name", "family_name"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	if result.Token == "" {
		t.Fatal("expected non-empty VP token")
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	if parsed.KeyBindingJWT == nil {
		t.Fatal("expected key binding JWT in VP token")
	}

	if typ, ok := parsed.KeyBindingJWT.Header["typ"].(string); !ok || typ != "kb+jwt" {
		t.Errorf("expected KB-JWT typ kb+jwt, got %v", parsed.KeyBindingJWT.Header["typ"])
	}

	if nonce, ok := parsed.KeyBindingJWT.Payload["nonce"].(string); !ok || nonce != "test-nonce" {
		t.Errorf("expected nonce test-nonce, got %v", parsed.KeyBindingJWT.Payload["nonce"])
	}
	if aud, ok := parsed.KeyBindingJWT.Payload["aud"].(string); !ok || aud != "https://verifier.example" {
		t.Errorf("expected aud https://verifier.example, got %v", parsed.KeyBindingJWT.Payload["aud"])
	}
	if _, ok := parsed.KeyBindingJWT.Payload["sd_hash"]; !ok {
		t.Error("expected sd_hash in KB-JWT payload")
	}

	discNames := make(map[string]bool)
	for _, d := range parsed.Disclosures {
		if !d.IsArrayEntry {
			discNames[d.Name] = true
		}
	}
	if !discNames["given_name"] {
		t.Error("expected given_name disclosure in VP token")
	}
	if !discNames["family_name"] {
		t.Error("expected family_name disclosure in VP token")
	}
}

func TestCreateVPToken_SDJWTNoDisclosuresParses(t *testing.T) {
	w := generateTestWalletWithPID(t)

	var sdCred StoredCredential
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	result, err := vpToken(w, consent.Match{
		QueryID:      "pid",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: nil,
	}, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}
	if strings.Contains(result.Token, "~~") {
		t.Fatalf("expected no empty disclosure segment in SD-JWT presentation: %s", result.Token)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}
	if parsed.KeyBindingJWT == nil {
		t.Fatal("expected key binding JWT in VP token")
	}
	if len(parsed.Disclosures) != 0 {
		t.Fatalf("expected no disclosures, got %d", len(parsed.Disclosures))
	}
}

func TestCreateVPToken_SDJWTBrowserAPIUsesOriginAudience(t *testing.T) {
	w := generateTestWalletWithPID(t)

	var sdCred StoredCredential
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	result, err := vpToken(w, consent.Match{
		QueryID:      "pid",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name"},
	}, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "x509_hash:test-client", ResponseMode: "dc_api.jwt"}, RequestOrigin: "https://rp.example"})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}
	if parsed.KeyBindingJWT == nil {
		t.Fatal("expected key binding JWT in VP token")
	}
	if aud, ok := parsed.KeyBindingJWT.Payload["aud"].(string); !ok || aud != "origin:https://rp.example" {
		t.Fatalf("expected aud origin:https://rp.example, got %v", parsed.KeyBindingJWT.Payload["aud"])
	}
}

func TestCreateVPToken_SDJWT_SelectiveDisclosure(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var sdCred StoredCredential
	for _, c := range creds {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}

	match := consent.Match{
		QueryID:      "test",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "client", ResponseURI: "response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	var names []string
	for _, d := range parsed.Disclosures {
		if !d.IsArrayEntry {
			names = append(names, d.Name)
		}
	}

	if len(names) != 1 {
		t.Errorf("expected 1 disclosure, got %d: %v", len(names), names)
	}
	if len(names) > 0 && names[0] != "given_name" {
		t.Errorf("expected given_name, got %s", names[0])
	}
}

func TestCreateVPToken_SDJWT_NestedSelectiveDisclosure(t *testing.T) {
	w := generateTestWalletWithPID(t)

	var sdCred StoredCredential
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	match := consent.Match{
		QueryID:      "test",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name", "address.postal_code"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "client", ResponseURI: "response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	got := make(map[string]bool)
	for _, d := range parsed.Disclosures {
		if d.IsArrayEntry {
			continue
		}
		got[d.Name] = true
	}

	for _, name := range []string{"given_name", "address", "postal_code"} {
		if !got[name] {
			t.Errorf("expected disclosure %q in VP token", name)
		}
	}
	for _, name := range []string{"country", "locality", "street_address"} {
		if got[name] {
			t.Errorf("did not expect disclosure %q in VP token", name)
		}
	}
}

// The address itself is cleartext, but its children require disclosures.
func TestCreateSDJWTPresentation_ClearTextParentChildIsDisclosed(t *testing.T) {
	w := generateTestWallet(t)

	disclosureRaw := format.EncodeBase64URL([]byte(`["0123456789abcdef","postal_code","12345"]`))
	sum := sha256.Sum256([]byte(disclosureRaw))
	digest := format.EncodeBase64URL(sum[:])

	header := format.EncodeBase64URL([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`))
	payload := format.EncodeBase64URL([]byte(`{"vct":"urn:test:address","iss":"https://issuer.example","_sd_alg":"sha-256","address":{"country":"DE","_sd":["` + digest + `"]}}`))
	cred := StoredCredential{
		ID:     "addr",
		Format: "dc+sd-jwt",
		Raw:    header + "." + payload + ".not-verified~" + disclosureRaw + "~",
		Disclosures: []sdjwt.Disclosure{{
			Raw:    disclosureRaw,
			Name:   "postal_code",
			Value:  "12345",
			Digest: digest,
		}},
	}

	token, err := w.createSDJWTPresentation(cred, []string{"address.postal_code"}, "nonce", "client", w.HolderKey)
	if err != nil {
		t.Fatalf("createSDJWTPresentation: %v", err)
	}
	if !strings.Contains(token, disclosureRaw) {
		t.Error("the postal_code disclosure under a cleartext address parent was dropped from the presentation")
	}
}

func TestCreateVPToken_PlainJWT(t *testing.T) {
	w := generateTestWallet(t)

	jwt, err := signJWT(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"sub": "user123", "vct": "urn:test:credential", "given_name": "Erika"},
		w.IssuerKey,
	)
	if err != nil {
		t.Fatalf("creating test JWT: %v", err)
	}
	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatalf("importing plain JWT: %v", err)
	}

	cred := w.GetCredentials()[0]
	match := consent.Match{
		QueryID:      "test",
		CredentialID: cred.ID,
		Format:       "jwt_vc_json",
		SelectedKeys: []string{"given_name"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "client", ResponseURI: "response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	// A plain JWT is presented as is, without a ~ separator or a KB-JWT.
	if result.Token != jwt {
		t.Errorf("expected raw JWT to be returned as-is")
	}

	parts := strings.Split(result.Token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}

	if strings.Contains(result.Token, "~") {
		t.Error("plain JWT presentation should not contain ~ separator")
	}
}

func TestCreateVPToken_MDoc(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var mdocCred StoredCredential
	for _, c := range creds {
		if c.Format == "mso_mdoc" {
			mdocCred = c
			break
		}
	}
	if mdocCred.ID == "" {
		t.Fatal("no mdoc credential found")
	}

	var selectedKeys []string
	for k := range mdocCred.Claims {
		selectedKeys = append(selectedKeys, k)
		if len(selectedKeys) >= 2 {
			break
		}
	}

	match := consent.Match{
		QueryID:      "mdoc_query",
		CredentialID: mdocCred.ID,
		Format:       "mso_mdoc",
		SelectedKeys: selectedKeys,
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "nonce123", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	if result.Token == "" {
		t.Fatal("expected non-empty VP token")
	}

	if strings.Contains(result.Token, " ") || strings.Contains(result.Token, "\n") {
		t.Error("VP token should not contain whitespace")
	}
}

func TestCreateVPToken_MDocUsesTaggedDeviceNamespaces(t *testing.T) {
	w := generateTestWalletWithPID(t)

	var mdocCred StoredCredential
	for _, c := range w.GetCredentials() {
		if c.Format == "mso_mdoc" {
			mdocCred = c
			break
		}
	}
	if mdocCred.ID == "" {
		t.Fatal("no mdoc credential found")
	}

	match := consent.Match{
		QueryID:      "pid",
		CredentialID: mdocCred.ID,
		Format:       "mso_mdoc",
		SelectedKeys: []string{"eu.europa.ec.eudi.pid.1:given_name", "eu.europa.ec.eudi.pid.1:family_name"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	deviceResponseBytes, err := format.DecodeBase64URL(result.Token)
	if err != nil {
		t.Fatalf("decode DeviceResponse: %v", err)
	}

	var deviceResponse map[any]any
	if err := cbor.Unmarshal(deviceResponseBytes, &deviceResponse); err != nil {
		t.Fatalf("parse DeviceResponse: %v", err)
	}

	documents, ok := deviceResponse["documents"].([]any)
	if !ok || len(documents) != 1 {
		t.Fatalf("expected 1 document, got %v", deviceResponse["documents"])
	}
	document, ok := documents[0].(map[any]any)
	if !ok {
		t.Fatalf("invalid document type %T", documents[0])
	}
	deviceSigned, ok := document["deviceSigned"].(map[any]any)
	if !ok {
		t.Fatalf("missing deviceSigned: %T", document["deviceSigned"])
	}

	nameSpacesTag, ok := deviceSigned["nameSpaces"].(cbor.Tag)
	if !ok {
		t.Fatalf("expected deviceSigned.nameSpaces Tag 24, got %T", deviceSigned["nameSpaces"])
	}
	if nameSpacesTag.Number != 24 {
		t.Fatalf("expected deviceSigned.nameSpaces tag 24, got %d", nameSpacesTag.Number)
	}

	deviceAuth, ok := deviceSigned["deviceAuth"].(map[any]any)
	if !ok {
		t.Fatalf("missing deviceAuth: %T", deviceSigned["deviceAuth"])
	}
	var sign1 []cbor.RawMessage
	sign1Content, err := cbor.Marshal(deviceAuth["deviceSignature"])
	if err != nil {
		t.Fatalf("re-encode deviceSignature: %v", err)
	}
	if err := cbor.Unmarshal(sign1Content, &sign1); err != nil {
		t.Fatalf("parse deviceSignature COSE array: %v", err)
	}
	if len(sign1) != 4 {
		t.Fatalf("expected deviceSignature COSE_Sign1 with 4 elements, got %d", len(sign1))
	}

	var detachedPayload any
	if err := cbor.Unmarshal(sign1[2], &detachedPayload); err != nil {
		t.Fatalf("decode deviceSignature payload slot: %v", err)
	}
	if detachedPayload != nil {
		t.Fatalf("expected detached deviceSignature payload, got %T (%v)", detachedPayload, detachedPayload)
	}
}

func TestCreateVPToken_CredentialNotFound(t *testing.T) {
	w := generateTestWallet(t)

	match := consent.Match{
		QueryID:      "test",
		CredentialID: "nonexistent",
		Format:       "dc+sd-jwt",
	}

	_, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "c", ResponseURI: "r"}})
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
}

func TestCreateVPTokenMap(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var matches []consent.Match
	for _, c := range creds {
		keys := make([]string, 0, 2)
		i := 0
		for k := range c.Claims {
			keys = append(keys, k)
			i++
			if i >= 2 {
				break
			}
		}
		matches = append(matches, consent.Match{
			QueryID:      "q_" + c.Format,
			CredentialID: c.ID,
			Format:       c.Format,
			SelectedKeys: keys,
		})
	}

	vpResult, err := w.createVPTokenMap(matches, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "nonce", ClientID: "client", ResponseURI: "response_uri"}})
	if err != nil {
		t.Fatalf("createVPTokenMap error: %v", err)
	}

	if len(vpResult.TokenMap) != len(matches) {
		t.Errorf("expected %d tokens, got %d", len(matches), len(vpResult.TokenMap))
	}

	for _, m := range matches {
		if _, ok := vpResult.TokenMap[m.QueryID]; !ok {
			t.Errorf("missing token for query ID %s", m.QueryID)
		}
	}
}

func TestBuildSessionTranscriptOID4VP(t *testing.T) {
	clientID := "https://verifier.example"
	nonce := "test-nonce"
	responseURI := "https://verifier.example/response"

	transcript, err := mdoc.OID4VPSessionTranscript(clientID, nonce, nil, responseURI)
	if err != nil {
		t.Fatalf("buildSessionTranscriptOID4VP error: %v", err)
	}

	var decoded []cbor.RawMessage
	if err := cbor.Unmarshal(transcript, &decoded); err != nil {
		t.Fatalf("decoding SessionTranscript: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(decoded))
	}

	for i := 0; i < 2; i++ {
		var v any
		if err := cbor.Unmarshal(decoded[i], &v); err != nil {
			t.Fatalf("decoding element %d: %v", i, err)
		}
		if v != nil {
			t.Errorf("element %d: expected null, got %v", i, v)
		}
	}

	var handover []cbor.RawMessage
	if err := cbor.Unmarshal(decoded[2], &handover); err != nil {
		t.Fatalf("decoding OID4VPHandover: %v", err)
	}
	if len(handover) != 2 {
		t.Fatalf("OID4VPHandover: expected 2 elements, got %d", len(handover))
	}

	var marker string
	if err := cbor.Unmarshal(handover[0], &marker); err != nil {
		t.Fatalf("decoding handover marker: %v", err)
	}
	if marker != "OpenID4VPHandover" {
		t.Errorf("expected 'OpenID4VPHandover', got %q", marker)
	}

	var hashBytes []byte
	if err := cbor.Unmarshal(handover[1], &hashBytes); err != nil {
		t.Fatalf("decoding handover hash: %v", err)
	}

	handoverInfo, _ := cbor.Marshal([]any{clientID, nonce, nil, responseURI})
	expectedHash := sha256.Sum256(handoverInfo)
	if string(hashBytes) != string(expectedHash[:]) {
		t.Error("handover hash does not match expected SHA256(CBOR(HandoverInfo))")
	}
}

func TestBuildSessionTranscriptOID4VPDCAPI(t *testing.T) {
	origin := "https://demo.certification.openid.net"
	nonce := "test-nonce"

	transcript, err := mdoc.OID4VPDCAPISessionTranscript(origin, nonce, nil)
	if err != nil {
		t.Fatalf("buildSessionTranscriptOID4VPDCAPI error: %v", err)
	}

	var decoded []cbor.RawMessage
	if err := cbor.Unmarshal(transcript, &decoded); err != nil {
		t.Fatalf("decoding SessionTranscript: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(decoded))
	}

	var handover []cbor.RawMessage
	if err := cbor.Unmarshal(decoded[2], &handover); err != nil {
		t.Fatalf("decoding OpenID4VPDCAPIHandover: %v", err)
	}
	if len(handover) != 2 {
		t.Fatalf("OpenID4VPDCAPIHandover: expected 2 elements, got %d", len(handover))
	}

	var marker string
	if err := cbor.Unmarshal(handover[0], &marker); err != nil {
		t.Fatalf("decoding handover marker: %v", err)
	}
	if marker != "OpenID4VPDCAPIHandover" {
		t.Errorf("expected 'OpenID4VPDCAPIHandover', got %q", marker)
	}

	var hashBytes []byte
	if err := cbor.Unmarshal(handover[1], &hashBytes); err != nil {
		t.Fatalf("decoding handover hash: %v", err)
	}

	handoverInfo, _ := cbor.Marshal([]any{origin, nonce, nil})
	expectedHash := sha256.Sum256(handoverInfo)
	if string(hashBytes) != string(expectedHash[:]) {
		t.Error("handover hash does not match expected SHA256(CBOR(DCAPIHandoverInfo))")
	}
}

func TestSignJWT(t *testing.T) {
	key, _ := mock.GenerateKey()

	header := map[string]any{"alg": "ES256", "typ": "test+jwt"}
	payload := map[string]any{"sub": "test", "iat": time.Now().Unix()}

	jwt, err := signJWT(header, payload, key)
	if err != nil {
		t.Fatalf("signJWT error: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	for i, p := range parts {
		if p == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

func TestCreateVPToken_ImportedSDJWT_PreservesDisclosures(t *testing.T) {
	w := generateTestWallet(t)

	externalKey, _ := mock.GenerateKey()
	rawSDJWT, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://external-issuer.example",
		VCT:       "urn:test:user_binding",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"user_id": "abc123", "role": "admin", "department": "engineering"},
		Key:       externalKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("generating external SD-JWT: %v", err)
	}

	if _, err := w.ImportCredential(rawSDJWT); err != nil {
		t.Fatalf("importing SD-JWT: %v", err)
	}

	cred := w.GetCredentials()[0]
	if cred.Format != "dc+sd-jwt" {
		t.Fatalf("expected dc+sd-jwt format, got %s", cred.Format)
	}
	if len(cred.Disclosures) == 0 {
		t.Fatal("expected disclosures after import")
	}

	cred.Disclosures = nil
	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	w.mu.Lock()
	w.Credentials[0] = cred
	w.mu.Unlock()

	match := consent.Match{
		QueryID:      "test",
		CredentialID: cred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"user_id"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/callback"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	foundUserID := false
	for _, d := range parsed.Disclosures {
		if d.Name == "user_id" {
			foundUserID = true
			if d.Value != "abc123" {
				t.Errorf("expected user_id value abc123, got %v", d.Value)
			}
		}
	}
	if !foundUserID {
		t.Error("user_id disclosure missing from VP token, disclosures were stripped during import/persist/present")
	}

	if parsed.ResolvedClaims["user_id"] != "abc123" {
		t.Errorf("expected user_id in resolved claims, got %v", parsed.ResolvedClaims["user_id"])
	}
}

func TestEncryptResponse_UsesEncryptedResponseEncValuesSupported(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
				"encrypted_response_enc_values_supported": []any{"A256GCM", "A128GCM"},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	jweStr, _, err := w.encryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE parts, got %d", len(parts))
	}
	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["enc"] != "A256GCM" {
		t.Errorf("expected enc=A256GCM (first supported value), got %v", header["enc"])
	}
}

func TestEncryptResponse_DefaultsToA128GCMWhenNoEncValues(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	jweStr, _, err := w.encryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["enc"] != "A128GCM" {
		t.Errorf("expected default enc=A128GCM, got %v", header["enc"])
	}
}

func TestEncryptResponse_TopLevelJWKSNotUsed(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	// The encryption key is read from client_metadata.jwks only, so a top-level
	// jwks does not count.
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"encrypted_response_enc_values_supported": []any{"A256GCM"},
			},
			"jwks": map[string]any{
				"keys": []any{jwk},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	_, _, err := w.encryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err == nil {
		t.Fatal("expected error when JWK is only in top-level jwks (not client_metadata.jwks)")
	}
}

func TestEncryptResponse_LegacyFieldNamesIgnored(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	// Earlier draft field names do not select an algorithm. The default is A128GCM.
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"authorization_encrypted_response_alg": "ECDH-ES",
				"authorization_encrypted_response_enc": "A256GCM",
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	jweStr, _, err := w.encryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["enc"] != "A128GCM" {
		t.Errorf("expected default enc=A128GCM (legacy fields ignored), got %v", header["enc"])
	}
}

func TestCreateVPToken_SDJWT_SurvivesPersistReload(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var sdCred StoredCredential
	for _, c := range creds {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	originalDisclosureCount := len(sdCred.Disclosures)
	if originalDisclosureCount == 0 {
		t.Fatal("expected disclosures in original credential")
	}

	// Persistence omits fields tagged json:"-".
	sdCred.Disclosures = nil
	sdCred.NameSpaces = nil

	if err := sdCred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if len(sdCred.Disclosures) != originalDisclosureCount {
		t.Fatalf("expected %d disclosures after rehydrate, got %d", originalDisclosureCount, len(sdCred.Disclosures))
	}

	w.mu.Lock()
	for i, c := range w.Credentials {
		if c.ID == sdCred.ID {
			w.Credentials[i] = sdCred
			break
		}
	}
	w.mu.Unlock()

	match := consent.Match{
		QueryID:      "test",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name", "family_name"},
	}

	result, err := vpToken(w, match, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "client", ResponseURI: "response"}})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	var names []string
	for _, d := range parsed.Disclosures {
		if !d.IsArrayEntry {
			names = append(names, d.Name)
		}
	}
	if len(names) != 2 {
		t.Errorf("expected 2 disclosures after persist/reload round-trip, got %d: %v", len(names), names)
	}

	if parsed.KeyBindingJWT == nil {
		t.Error("expected KB-JWT in VP token after persist/reload round-trip")
	}
}

func TestSubmitPresentation_DirectPostJWT_NoEncryptionKey(t *testing.T) {
	w := generateTestWallet(t)

	vpResult := &VPTokenMapResult{
		TokenMap: map[string][]string{"q1": {"dummy-token"}},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "c", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{},
		},
	}}}

	_, err := w.submitPresentation(vpResult, "", "state", params.ResponseURI, params)
	if err == nil {
		t.Fatal("expected error when direct_post.jwt is used without encryption key")
	}
	if !strings.Contains(err.Error(), "no encryption key") {
		t.Errorf("expected 'no encryption key' in error, got: %v", err)
	}
}

func TestEncryptResponse_UsesAlgFromJWK(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	jweStr, _, err := w.encryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["alg"] != "ECDH-ES" {
		t.Errorf("expected alg=ECDH-ES from JWK, got %v", header["alg"])
	}
}

func TestEncryptResponse_ErrorWhenJWKMissingAlg(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()

	jwkJSON := mock.PublicKeyJWK(&key.PublicKey)
	var jwk map[string]any
	json.Unmarshal([]byte(jwkJSON), &jwk)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response", ResponseMode: "direct_post.jwt", RequestObject: reqObj}}

	_, _, err := w.encryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err == nil {
		t.Fatal("expected error when JWK is missing 'alg' field")
	}
	if !strings.Contains(err.Error(), "alg") {
		t.Errorf("expected error about missing 'alg', got: %v", err)
	}
}

func TestVPTokenMapResult_VPToken(t *testing.T) {
	r := &VPTokenMapResult{
		TokenMap: map[string][]string{
			"pid": {"token1"},
			"mdl": {"token2", "token3"},
		},
	}
	vp := r.VPToken()
	if len(vp) != 2 {
		t.Errorf("expected 2 entries, got %d", len(vp))
	}
	if len(vp["pid"]) != 1 || vp["pid"][0] != "token1" {
		t.Errorf("wrong pid token: %v", vp["pid"])
	}
	if len(vp["mdl"]) != 2 || vp["mdl"][0] != "token2" || vp["mdl"][1] != "token3" {
		t.Errorf("wrong mdl tokens: %v", vp["mdl"])
	}
	if n := r.PresentationCount(); n != 3 {
		t.Errorf("PresentationCount = %d, want 3", n)
	}
}

func TestVPTokenMapResult_VPToken_Empty(t *testing.T) {
	r := &VPTokenMapResult{
		TokenMap: map[string][]string{},
	}
	vp := r.VPToken()
	if len(vp) != 0 {
		t.Errorf("expected 0 entries, got %d", len(vp))
	}
}

func TestVPTokenMapResult_QueryIDs(t *testing.T) {
	r := &VPTokenMapResult{
		TokenMap: map[string][]string{"pid": {"t1"}, "mdl": {"t2"}},
	}
	ids := r.QueryIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["pid"] || !idSet["mdl"] {
		t.Errorf("expected pid and mdl in query IDs, got %v", ids)
	}
}

func TestVPTokenMapResult_QueryIDs_Empty(t *testing.T) {
	r := &VPTokenMapResult{
		TokenMap: map[string][]string{},
	}
	ids := r.QueryIDs()
	if len(ids) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids))
	}
}

func TestEncryptJWE_A128CBCHS256(t *testing.T) {
	key, _ := mock.GenerateKey()
	payload := []byte(`{"vp_token":"test","state":"s"}`)

	jweStr, cek, err := jwe.EncryptECDHES(payload, &key.PublicKey, "kid1", "A128CBC-HS256", "", nil, nil)
	if err != nil {
		t.Fatalf("EncryptJWE error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE parts, got %d", len(parts))
	}

	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["enc"] != "A128CBC-HS256" {
		t.Errorf("expected enc=A128CBC-HS256, got %v", header["enc"])
	}
	if header["alg"] != "ECDH-ES" {
		t.Errorf("expected alg=ECDH-ES, got %v", header["alg"])
	}

	// The 256-bit CEK contains a 128-bit MAC key and a 128-bit encryption key.
	if len(cek) != 32 {
		t.Errorf("expected 32-byte CEK, got %d bytes", len(cek))
	}

	// ECDH-ES uses direct key agreement, so the encrypted key part is empty.
	if parts[1] != "" {
		t.Errorf("expected empty encrypted key for ECDH-ES, got %q", parts[1])
	}

	// AES-CBC uses a 128-bit IV.
	ivBytes, _ := format.DecodeBase64URL(parts[2])
	if len(ivBytes) != 16 {
		t.Errorf("expected 16-byte IV, got %d bytes", len(ivBytes))
	}

	// A128CBC-HS256 truncates the HMAC tag to 128 bits.
	tagBytes, _ := format.DecodeBase64URL(parts[4])
	if len(tagBytes) != 16 {
		t.Errorf("expected 16-byte tag, got %d bytes", len(tagBytes))
	}
}

// vpToken builds one presentation with its own mdoc generated nonce.
func vpToken(w *Wallet, match consent.Match, params *oid4vp.Request) (VPTokenResult, error) {
	return w.createVPToken(match, params, "")
}
