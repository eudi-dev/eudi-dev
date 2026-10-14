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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

// resignCredential signs the issuer JWT of an SD-JWT again with the issuer
// key after edit changes its payload. The disclosures stay as they are.
func resignCredential(t *testing.T, d *DemoRP, credential string, edit func(payload map[string]any)) string {
	t.Helper()
	jwt, disclosures, _ := strings.Cut(credential, "~")
	parts := strings.Split(jwt, ".")
	var header, payload map[string]any
	for i, target := range []*map[string]any{&header, &payload} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
	}
	edit(payload)
	return signES256(t, d.wallet.IssuerKey, header, payload) + "~" + disclosures
}

// RFC 9901 §7.3 and OpenID4VP 1.0 §B.3.6: a presentation of a holder-bound
// credential carries a key binding JWT of type kb+jwt, signed with the
// cnf.jwk key. Its sd_hash covers the presentation.
func TestVerifierChecksTheKeyBinding(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	req := &requestState{id: "req", clientID: "x509_hash:verifier", nonce: "the-nonce"}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, chain, err := d.wallet.Signer().Default()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       TicketVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"event": "Demo"},
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(credential, "~") {
		credential += "~"
	}
	// kbJWT signs a key binding JWT over prefix after edit changes it.
	kbJWT := func(prefix string, edit func(header, payload map[string]any)) string {
		digest := sha256.Sum256([]byte(prefix))
		header := map[string]any{"alg": "ES256", "typ": "kb+jwt"}
		payload := map[string]any{
			"iat":     time.Now().Unix(),
			"aud":     req.clientID,
			"nonce":   req.nonce,
			"sd_hash": base64.RawURLEncoding.EncodeToString(digest[:]),
		}
		if edit != nil {
			edit(header, payload)
		}
		return signES256(t, holderKey, header, payload)
	}
	present := func(credential string, edit func(header, payload map[string]any)) string {
		return credential + kbJWT(credential, edit)
	}
	withCNF := func(cnf any) string {
		return resignCredential(t, d, credential, func(payload map[string]any) {
			if cnf == nil {
				delete(payload, "cnf")
			} else {
				payload["cnf"] = cnf
			}
		})
	}

	for _, tc := range []struct {
		name         string
		presentation string
		failedCheck  string
	}{
		{"a complete presentation", present(credential, nil), ""},
		{"no key binding JWT", credential, "key binding JWT present"},
		{"no cnf", present(withCNF(nil), nil), "credential is holder bound (cnf.jwk)"},
		{"a cnf.jwk that is no key", present(withCNF(map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}}), nil), "cnf.jwk parses"},
		// RFC 9901 §4.3: the typ kb+jwt tells a KB-JWT apart from a
		// Disclosure, so a trailing component without it is a Disclosure.
		{"a key binding JWT that does not parse", credential + "a.b.c", "presentation parses as SD-JWT"},
		{"another typ", present(credential, func(h, _ map[string]any) { h["typ"] = "JWT" }), "presentation parses as SD-JWT"},
		{"a signature by another key", credential + signES256(t, otherKey, map[string]any{"alg": "ES256", "typ": "kb+jwt"}, map[string]any{}), "key binding signature verifies with cnf key"},
		{"an sd_hash of another presentation", present(credential, func(_, p map[string]any) { p["sd_hash"] = "AAAA" }), "sd_hash matches the presentation"},
		{"an _sd_alg this verifier does not compute", present(resignCredential(t, d, credential, func(p map[string]any) { p["_sd_alg"] = "sha-1" }), nil), "presentation parses as SD-JWT"},
		{"another nonce", present(credential, func(_, p map[string]any) { p["nonce"] = "another" }), "nonce matches the request"},
		{"another audience", present(credential, func(_, p map[string]any) { p["aud"] = "another" }), "audience is this verifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &checklist{}
			_, err := d.verifySDJWTEntry(req, tc.presentation, credentialQuery{vct: TicketVCT}, "", d.credentialTrust(), log)
			if tc.failedCheck == "" {
				if err != nil {
					t.Fatalf("refused: %v (checks %v)", err, log.entries)
				}
				return
			}
			last := log.entries[len(log.entries)-1]
			if err == nil || last["name"] != tc.failedCheck || last["ok"] != false {
				t.Errorf("error %v, last check %v, want the failed check %q", err, last, tc.failedCheck)
			}
		})
	}
}

// Each vp_token presentation answers one credential query (OpenID4VP 1.0
// §8.1). The verifier reads one document, so a DeviceResponse with a second
// document is refused.
func TestVerifierRefusesADeviceResponseWithTwoDocuments(t *testing.T) {
	d, _, _ := newDemoRP(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{DocType: PIDDocType, Namespace: PIDDocType, Claims: map[string]any{"given_name": "Erika"}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	data, err := format.DecodeHexOrBase64URL(raw)
	if err != nil {
		t.Fatal(err)
	}
	var issuerSigned map[any]any
	if err := cbor.Unmarshal(data, &issuerSigned); err != nil {
		t.Fatal(err)
	}
	document := map[any]any{"docType": PIDDocType, "issuerSigned": issuerSigned}
	encoded, err := cbor.Marshal(map[any]any{"version": "1.0", "status": 0, "documents": []any{document, document}})
	if err != nil {
		t.Fatal(err)
	}

	log := &checklist{}
	_, err = d.verifyMDOCPresentation(&requestState{}, format.EncodeBase64URL(encoded), credentialQuery{docType: PIDDocType}, "", d.credentialTrust(), log)
	last := log.entries[len(log.entries)-1]
	if err == nil || last["name"] != "DeviceResponse holds one document" || last["ok"] != false {
		t.Errorf("error %v, last check %v, want the failed document count check", err, last)
	}
}

// ADR-0022: under --arf a PID chains to a PID provider list (ARF ISSU_07).
// Without --arf every credential provider list anchors every credential.
func TestUnderARFAPIDChainsToThePIDProviderList(t *testing.T) {
	for _, tc := range []struct {
		name     string
		arf      bool
		category string
		verified bool
	}{
		{"a PID signer under --arf", true, "pid", true},
		{"an EAA signer under --arf", true, "eaa", false},
		{"an EAA signer without --arf", false, "eaa", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, holderKey := newDemoRP(t)
			d.wallet.RequireARF = tc.arf
			h := d.VerifierHandler()
			id, params := startVerificationWith(t, h, `{"type":"pid","format":"sd-jwt"}`)

			key, chain, err := d.wallet.Signer().ForList(provider.CategoryList(tc.category), "")
			if err != nil {
				t.Fatal(err)
			}
			pid, err := mock.GenerateSDJWT(mock.SDJWTConfig{
				Issuer:    d.issuerID(),
				VCT:       PIDVCT,
				ExpiresIn: time.Hour,
				Claims:    templateClaims("pid-sdjwt"),
				Key:       key,
				HolderKey: &holderKey.PublicKey,
				CertChain: chain,
			})
			if err != nil {
				t.Fatal(err)
			}
			postPresentation(t, h, id, "pid", presentCredential(t, holderKey, pid, params.Get("client_id"), params.Get("nonce")))

			_, status := requestStatus(t, d, id)
			if verified := status["status"] == "verified"; verified != tc.verified {
				t.Errorf("status = %v, want verified %v (error: %v)", status["status"], tc.verified, status["error"])
			}
			if errText, _ := status["error"].(string); !tc.verified && !strings.HasPrefix(errText, "signature") {
				t.Errorf("error = %q, want the signature check to refuse the PID", errText)
			}
		})
	}
}
