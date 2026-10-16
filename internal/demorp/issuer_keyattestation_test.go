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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// keyAttestation signs a key attestation (OpenID4VCI 1.0 Appendix D.1) of the
// keys. edit changes the payload before signing.
func (p walletProvider) keyAttestation(t *testing.T, d *DemoRP, keys []*ecdsa.PrivateKey, edit func(payload map[string]any)) string {
	t.Helper()
	attested := make([]any, 0, len(keys))
	for _, key := range keys {
		attested = append(attested, holderJWK(t, key))
	}
	payload := map[string]any{
		"iat":                 time.Now().Unix(),
		"exp":                 time.Now().Add(time.Hour).Unix(),
		"attested_keys":       attested,
		"key_storage":         []any{"iso_18045_high"},
		"user_authentication": []any{"iso_18045_high"},
		"nonce":               issuedNonce(t, d),
	}
	if edit != nil {
		edit(payload)
	}
	return signJWT(t, p.key, map[string]any{
		"typ": "key-attestation+jwt",
		"x5c": []any{base64.StdEncoding.EncodeToString(p.leaf.Raw)},
	}, payload)
}

func generateKeys(t *testing.T, n int) []*ecdsa.PrivateKey {
	t.Helper()
	keys := make([]*ecdsa.PrivateKey, n)
	for i := range keys {
		key, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
	}
	return keys
}

// attestedProof is a jwt proof signed by signer that carries the key
// attestation in its key_attestation header.
func attestedProof(t *testing.T, d *DemoRP, signer *ecdsa.PrivateKey, attestation string) string {
	t.Helper()
	return signJWT(t, signer,
		map[string]any{"typ": "openid4vci-proof+jwt", "key_attestation": attestation},
		map[string]any{"aud": d.issuerID(), "iat": time.Now().Unix(), "nonce": issuedNonce(t, d)})
}

func sendProofs(t *testing.T, d *DemoRP, offerQuery, proofType string, proofs ...string) (int, map[string]any) {
	t.Helper()
	tokenDoc := redeemPreAuthOffer(t, d, offerQuery, nil)
	configID := "demo-ticket"
	if _, id, ok := strings.Cut(offerQuery, "credential="); ok {
		configID = id
	}
	encoded, err := json.Marshal(proofs)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{%q:%s}}`, configID, proofType, encoded)
	return doJSON(t, d.IssuerHandler(), "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + tokenDoc["access_token"].(string),
		"Content-Type":  "application/json",
	})
}

// boundCredentialKeys reads the cnf key of each SD-JWT VC in a credential
// response.
func boundCredentialKeys(t *testing.T, doc map[string]any) []*ecdsa.PublicKey {
	t.Helper()
	entries, _ := doc["credentials"].([]any)
	var keys []*ecdsa.PublicKey
	for _, entry := range entries {
		token, err := sdjwt.Parse(entry.(map[string]any)["credential"].(string))
		if err != nil {
			t.Fatal(err)
		}
		cnf, _ := token.Payload["cnf"].(map[string]any)
		key, err := holderKeyFromJWK(cnf["jwk"].(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	return keys
}

func TestTheMetadataOffersTheAttestationProofType(t *testing.T) {
	d, w, _ := newDemoRP(t)
	proofTypes := func() map[string]any {
		_, metadata := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
		configs := metadata["credential_configurations_supported"].(map[string]any)
		return configs["pid-sdjwt"].(map[string]any)["proof_types_supported"].(map[string]any)
	}

	t.Run("optional", func(t *testing.T) {
		types := proofTypes()
		jwtProof := types["jwt"].(map[string]any)
		if _, required := jwtProof["key_attestations_required"]; required {
			t.Error("the jwt proof type requires a key attestation, so wallets without one cannot collect credentials")
		}
		attestation, ok := types["attestation"].(map[string]any)
		if !ok {
			t.Fatalf("proof_types_supported = %v, want the attestation proof type (CIR (EU) 2024/2979 Annex Ib TR_KA-4)", types)
		}
		if _, ok := attestation["key_attestations_required"].(map[string]any); !ok {
			t.Errorf("attestation proof type = %v, want key_attestations_required", attestation)
		}
		for _, proof := range []map[string]any{jwtProof, attestation} {
			if got := fmt.Sprint(proof["proof_signing_alg_values_supported"]); got != "[ES256 ES384 ES512]" {
				t.Errorf("proof_signing_alg_values_supported = %s, want every SA-1 algorithm", got)
			}
		}
	})

	t.Run("required with ARF", func(t *testing.T) {
		d.SetKeyAttestationMode(KeyAttestationRequired)
		w.RequireARF = true
		t.Cleanup(func() { d.SetKeyAttestationMode(KeyAttestationOptional); w.RequireARF = false })
		types := proofTypes()
		for _, name := range []string{"jwt", "attestation"} {
			requirement, _ := types[name].(map[string]any)["key_attestations_required"].(map[string]any)
			if got := fmt.Sprint(requirement["key_storage"]); got != "[iso_18045_high]" {
				t.Errorf("%s key_attestations_required = %v, want key_storage iso_18045_high for a PID (TR_KA-8)", name, requirement)
			}
		}
	})
}

// ETSI TS 119 472-3 V1.1.1 CRED-REQ-PROC-4.6.2.1-04: "as many PIDs/EAAs as
// elements present in the attested_keys array", each bound to one of them.
func TestAJWTProofWithAKeyAttestationIssuesOneCredentialPerAttestedKey(t *testing.T) {
	d, _, _ := newDemoRP(t)
	keys := generateKeys(t, 3)
	attestation := foreignWalletProvider(t).keyAttestation(t, d, keys, nil)

	code, doc := sendProofs(t, d, "credential=pid-sdjwt", "jwt", attestedProof(t, d, keys[0], attestation))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", code, doc)
	}
	bound := boundCredentialKeys(t, doc)
	if len(bound) != len(keys) {
		t.Fatalf("issued %d credentials, want one per attested key (%d)", len(bound), len(keys))
	}
	for i, key := range keys {
		if !bound[i].Equal(&key.PublicKey) {
			t.Errorf("credential %d is not bound to attested key %d", i, i)
		}
	}
}

func TestAnAttestationProofIssuesOneCredentialPerAttestedKey(t *testing.T) {
	d, _, _ := newDemoRP(t)
	keys := generateKeys(t, 2)
	attestation := foreignWalletProvider(t).keyAttestation(t, d, keys, func(p map[string]any) { delete(p, "exp") })

	code, doc := sendProofs(t, d, "credential=pid-sdjwt", "attestation", attestation)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", code, doc)
	}
	if bound := boundCredentialKeys(t, doc); len(bound) != 2 {
		t.Errorf("issued %d credentials, want 2", len(bound))
	}
}

func TestAKeyAttestationIsVerified(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	keys := generateKeys(t, 2)
	other := generateKeys(t, 1)[0]

	for _, tc := range []struct {
		name  string
		proof func() string
		want  string
	}{
		{"a proof signed by the second attested key", func() string {
			return attestedProof(t, d, keys[1], provider.keyAttestation(t, d, keys, nil))
		}, "first attested key"},
		{"a jwk that is not the first attested key", func() string {
			return signJWT(t, keys[0],
				map[string]any{"typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, other), "key_attestation": provider.keyAttestation(t, d, keys, nil)},
				map[string]any{"aud": d.issuerID(), "iat": time.Now().Unix(), "nonce": issuedNonce(t, d)})
		}, "first attested key"},
		{"a key attestation signed by another key", func() string {
			forged := provider.keyAttestation(t, d, keys, nil)
			resigned := walletProvider{key: other, leaf: provider.leaf}.keyAttestation(t, d, keys, nil)
			parts := strings.Split(forged, ".")
			return attestedProof(t, d, keys[0], parts[0]+"."+parts[1]+"."+strings.Split(resigned, ".")[2])
		}, "signature"},
		{"no exp next to a jwt proof", func() string {
			return attestedProof(t, d, keys[0], provider.keyAttestation(t, d, keys, func(p map[string]any) { delete(p, "exp") }))
		}, "exp"},
		{"no nonce", func() string {
			return attestedProof(t, d, keys[0], provider.keyAttestation(t, d, keys, func(p map[string]any) { delete(p, "nonce") }))
		}, "nonce"},
		{"no attested keys", func() string {
			return attestedProof(t, d, keys[0], provider.keyAttestation(t, d, keys, func(p map[string]any) { p["attested_keys"] = []any{} }))
		}, "attested_keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc := sendProofs(t, d, "credential=pid-sdjwt", "jwt", tc.proof())
			if code != http.StatusBadRequest || doc["error"] != "invalid_proof" {
				t.Fatalf("status = %d %v, want 400 invalid_proof", code, doc)
			}
			if !strings.Contains(fmt.Sprint(doc["error_description"]), tc.want) {
				t.Errorf("error_description = %q, want it to name %q", doc["error_description"], tc.want)
			}
		})
	}

	t.Run("a nonce not issued by this issuer", func(t *testing.T) {
		attestation := provider.keyAttestation(t, d, keys, func(p map[string]any) { p["nonce"] = "invented" })
		code, doc := sendProofs(t, d, "credential=pid-sdjwt", "attestation", attestation)
		if code != http.StatusBadRequest || doc["error"] != "invalid_nonce" {
			t.Errorf("status = %d %v, want 400 invalid_nonce", code, doc)
		}
	})
}

// CIR (EU) 2024/2979 Annex Ib TR_KA-8 binds a PID to a key in a WSCD. C_KA-1
// sets key_storage and user_authentication to iso_18045_high in a key
// attestation for a WSCD. With --arf, required mode refuses a PID proof
// without such a key attestation, and optional mode accepts it.
func TestAPIDProofWithoutAWSCDKeyIsRefusedOnlyInRequiredMode(t *testing.T) {
	d, w, _ := newDemoRP(t)
	w.RequireARF = true
	provider := foreignWalletProvider(t)
	keys := generateKeys(t, 1)

	for _, tc := range []struct {
		name  string
		proof func() (proofType, proof string)
		want  string
	}{
		{"no key attestation", func() (string, string) {
			return "jwt", proofJWTForKey(t, d, keys[0], proofOptions{nonce: issuedNonce(t, d)})
		}, "key attestation"},
		{"key_storage below iso_18045_high", func() (string, string) {
			return "attestation", provider.keyAttestation(t, d, keys, func(p map[string]any) { p["key_storage"] = []any{"iso_18045_moderate"} })
		}, "key_storage"},
		{"user_authentication below iso_18045_high", func() (string, string) {
			return "attestation", provider.keyAttestation(t, d, keys, func(p map[string]any) { p["user_authentication"] = []any{"iso_18045_moderate"} })
		}, "user_authentication"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.SetKeyAttestationMode(KeyAttestationOptional)
			proofType, proof := tc.proof()
			if code, doc := sendProofs(t, d, "credential=pid-sdjwt", proofType, proof); code != http.StatusOK {
				t.Errorf("optional mode: status = %d %v, want 200", code, doc)
			}
			d.SetKeyAttestationMode(KeyAttestationRequired)
			proofType, proof = tc.proof()
			code, doc := sendProofs(t, d, "credential=pid-sdjwt", proofType, proof)
			if code != http.StatusBadRequest || doc["error"] != "invalid_proof" || !strings.Contains(fmt.Sprint(doc["error_description"]), tc.want) {
				t.Errorf("required mode: status = %d %v, want invalid_proof naming %q", code, doc, tc.want)
			}
		})
	}
}

// The wallet picks the attestation proof type when the jwt proof type requires
// a key attestation. It attests as many keys as batch_size allows (CIR (EU)
// 2024/2979 Annex Ib TR_KA-2.2), and the issuer binds a credential to each,
// also for an offer of a single credential.
func TestTheWalletCollectsACredentialPerAttestedKeyUnderRequiredKeyAttestation(t *testing.T) {
	w := newIssuanceWallet(t)
	d, ts := serveDemoStack(t, w)
	d.SetKeyAttestationMode(KeyAttestationRequired)

	redeemDemoTicket(t, w, ts, "")
	count := 0
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			count++
		}
	}
	if count != demoBatchSize {
		t.Fatalf("the wallet stored %d tickets, want one per attested key (%d)", count, demoBatchSize)
	}
}

func TestTheRequiredModeRefusesAProofWithoutKeyAttestation(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.SetKeyAttestationMode(KeyAttestationRequired)
	key := generateKeys(t, 1)[0]

	code, doc := sendProofs(t, d, "credential=pid-sdjwt", "jwt", proofJWTForKey(t, d, key, proofOptions{nonce: issuedNonce(t, d)}))
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(doc["error_description"]), "key attestation") {
		t.Errorf("status = %d %v, want a refusal asking for a key attestation", code, doc)
	}
}
