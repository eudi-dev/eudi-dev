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
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func walletInstanceAttestation(t *testing.T, w *Wallet, auth *ClientAuthentication) map[string]any {
	t.Helper()
	key := w.clientKey(CredentialRenewal{AuthorizationServer: auth.Audience})
	headers, err := createClientAttestationHeaders(w, auth, "wallet-client", "", key)
	if err != nil {
		t.Fatalf("createClientAttestationHeaders: %v", err)
	}
	return decodeJWTPart(t, headers["OAuth-Client-Attestation"], 1)
}

// maintainedStatusOf reads a client_status or key_storage_status claim.
func maintainedStatusOf(t *testing.T, claims map[string]any, claim string) (idx float64, uri string, exp time.Time) {
	t.Helper()
	status, _ := claims[claim].(map[string]any)
	reference, _ := status["status"].(map[string]any)
	entry, _ := reference["status_list"].(map[string]any)
	idx, okIdx := entry["idx"].(float64)
	uri, _ = entry["uri"].(string)
	seconds, okExp := status["exp"].(float64)
	if !okIdx || uri == "" || !okExp {
		t.Fatalf("%s = %v, want a status list reference and exp", claim, claims[claim])
	}
	return idx, uri, time.Unix(int64(seconds), 0)
}

// CIR (EU) 2024/2979 Annex Ib C_WIA-1 and C_WIA-2: a WIA names the wallet
// solution, its version, its certification and the status of the wallet
// instance, and should link further information.
func TestWalletInstanceAttestationClaims(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"

	claims := walletInstanceAttestation(t, w, &ClientAuthentication{Method: ClientAuthAttestation, Audience: "https://as-one.example"})
	if claims["wallet_name"] != config.WalletName {
		t.Errorf("wallet_name = %v, want %q, the service name on the wallet provider list", claims["wallet_name"], config.WalletName)
	}
	if claims["wallet_version"] != solutionVersion {
		t.Errorf("wallet_version = %v, want %q", claims["wallet_version"], solutionVersion)
	}
	if claims["wallet_link"] != walletLink {
		t.Errorf("wallet_link = %v, want %q", claims["wallet_link"], walletLink)
	}
	if certification, ok := claims["wallet_solution_certification_information"].(map[string]any); !ok || certification["certification_number"] != "TEST-UNCERTIFIED" {
		t.Errorf("wallet_solution_certification_information = %v, want the test object", claims["wallet_solution_certification_information"])
	}
	_, uri, exp := maintainedStatusOf(t, claims, "client_status")
	if uri != w.StatusListURL() {
		t.Errorf("client_status uri = %q, want the wallet's status list %q", uri, w.StatusListURL())
	}
	// LC_GEN-1: at least 31 days at presentation.
	if remaining := time.Until(exp); remaining < 31*24*time.Hour {
		t.Errorf("client_status.exp is %v away, want at least 31 days", remaining)
	}
}

// R_WIA-1.1 under the per-issuer reuse option: the WIAs sent to one
// authorization server keep the index. R_WIA-1.3: another authorization
// server gets another one. ARF ISSU_35a b): the WIA public key differs
// between providers too, and none is the holder key.
func TestWalletInstanceIsScopedToTheAuthorizationServer(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	one := &ClientAuthentication{Method: ClientAuthAttestation, Audience: "https://as-one.example"}
	two := &ClientAuthentication{Method: ClientAuthAttestation, Audience: "https://as-two.example"}

	first := walletInstanceAttestation(t, w, one)
	again := walletInstanceAttestation(t, w, one)
	other := walletInstanceAttestation(t, w, two)

	firstIdx, _, _ := maintainedStatusOf(t, first, "client_status")
	againIdx, _, _ := maintainedStatusOf(t, again, "client_status")
	otherIdx, _, _ := maintainedStatusOf(t, other, "client_status")
	if firstIdx != againIdx {
		t.Errorf("two WIAs for one authorization server carry indices %v and %v, want one", firstIdx, againIdx)
	}
	if firstIdx == otherIdx {
		t.Errorf("the WIAs for two authorization servers share index %v", firstIdx)
	}

	cnfX := func(claims map[string]any) any {
		cnf, _ := claims["cnf"].(map[string]any)
		jwk, _ := cnf["jwk"].(map[string]any)
		return jwk["x"]
	}
	holderX := mock.SigningJWKMap(&w.HolderKey.PublicKey)["x"]
	if cnfX(first) != cnfX(again) {
		t.Error("two WIAs for one authorization server attest different keys")
	}
	if cnfX(first) == cnfX(other) {
		t.Error("the WIAs for two authorization servers attest the same key")
	}
	if cnfX(first) == holderX || cnfX(other) == holderX {
		t.Error("a WIA attests the wallet's holder key")
	}
}

// The DPoP key is the key the WIA attests, because draft-10 §5.2 takes the
// DPoP proof as the attestation's possession proof. A renewal stored without
// an authorization server keeps the holder key its tokens are bound to.
func TestDPoPKeyIsTheWalletInstanceKey(t *testing.T) {
	w := generateTestWallet(t)
	renewal := CredentialRenewal{UseDPoP: true, AuthorizationServer: "https://as-one.example"}
	if got, want := w.dpopKeyForRenewal(renewal), w.walletInstanceKey("https://as-one.example"); !got.Equal(want) {
		t.Error("the DPoP key is not the wallet instance key of the authorization server")
	}
	if w.dpopKeyForRenewal(renewal).Equal(w.HolderKey) {
		t.Error("the DPoP key is the wallet's holder key")
	}
	if !w.dpopKeyForRenewal(CredentialRenewal{UseDPoP: true}).Equal(w.HolderKey) {
		t.Error("a renewal without an authorization server must keep the holder key")
	}
}

// LC_WIA-1 and LC_GEN_2.2: an issuer's preferred_client_status_period sets
// the remaining status maintenance period of the WIA.
func TestWalletInstanceAttestationFollowsPreferredStatusPeriod(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	auth := w.attestationClientAuth(clientAuthContext{
		oauthMeta:      map[string]any{"issuer": "https://as-one.example"},
		issuerMetadata: map[string]any{"preferred_client_status_period": float64(90 * 24 * 3600)},
	})
	claims := walletInstanceAttestation(t, w, auth)
	_, _, exp := maintainedStatusOf(t, claims, "client_status")
	if remaining := time.Until(exp); remaining < 89*24*time.Hour || remaining > 90*24*time.Hour {
		t.Errorf("client_status.exp is %v away, want the preferred 90 days", remaining)
	}
}

// C_KA-1: a KA names the certification of the key storage and its status
// (R_KA_1 option 1, one index for the key storage type). With --arf and no
// requirement of the issuer it describes a WSCD.
func TestKeyAttestationStorageClaims(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	w.RequireARF = true
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"pid": map[string]any{
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{"key_attestations_required": map[string]any{
						// LC_KA-1.1 places the preference in key_attestations_required.
						"preferred_key_storage_status_period": float64(60 * 24 * 3600),
					}},
				},
			},
		},
	}
	attest := func() map[string]any {
		keys, err := issuanceProofKeys(metadata)
		if err != nil {
			t.Fatalf("issuanceProofKeys: %v", err)
		}
		attestation, err := createKeyAttestation(w, metadata, "pid", "nonce", keys)
		if err != nil {
			t.Fatalf("createKeyAttestation: %v", err)
		}
		return decodeJWTPart(t, attestation, 1)
	}
	first, second := attest(), attest()

	if first["certification"] != testCertificationURI {
		t.Errorf("certification = %v, want %q", first["certification"], testCertificationURI)
	}
	for _, claim := range keyAttestationClaimNames {
		if values, _ := first[claim].([]any); len(values) != 1 || values[0] != wscdAttestationLevel {
			t.Errorf("%s = %v, want [%s]", claim, first[claim], wscdAttestationLevel)
		}
	}
	firstIdx, _, exp := maintainedStatusOf(t, first, "key_storage_status")
	secondIdx, _, _ := maintainedStatusOf(t, second, "key_storage_status")
	if firstIdx != secondIdx {
		t.Errorf("two KAs of one key storage carry indices %v and %v, want the type-shared one", firstIdx, secondIdx)
	}
	if remaining := time.Until(exp); remaining < 59*24*time.Hour || remaining > 60*24*time.Hour {
		t.Errorf("key_storage_status.exp is %v away, want the preferred 60 days", remaining)
	}
}
