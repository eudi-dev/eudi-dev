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

package mock

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func generateForTest(t *testing.T, cfg SDJWTConfig) string {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg.Key = key
	if cfg.VCT == "" {
		cfg.VCT = "urn:eudi:pid:1"
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "https://issuer.example"
	}
	if cfg.ExpiresIn == 0 {
		cfg.ExpiresIn = time.Hour
	}
	raw, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	return raw
}

// SD-JWT VC §2.2.2.5: "An SD-JWT VC MAY have no selectively disclosable
// claims. In that case, the SD-JWT VC MUST NOT contain the _sd claim in the
// JWT body. It also MUST NOT have any Disclosures." RFC 9901 §4's ABNF
// permits no empty component, so the serialization ends in a single tilde.
func TestGenerateSDJWT_WithoutDisclosures(t *testing.T) {
	raw := generateForTest(t, SDJWTConfig{
		VCT:             "urn:example:vc",
		Claims:          map[string]any{"given_name": "Erika", "family_name": "Mustermann"},
		AlwaysDisclosed: []string{"given_name", "family_name"},
	})

	if strings.Contains(raw, "~~") {
		t.Errorf("serialization carries an empty component: %s", raw)
	}
	if !strings.HasSuffix(raw, "~") {
		t.Errorf("serialization does not end in a tilde: %s", raw)
	}

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	if len(token.Disclosures) != 0 {
		t.Errorf("got %d disclosures, want 0", len(token.Disclosures))
	}
	if _, present := token.Payload["_sd"]; present {
		t.Errorf("payload carries _sd = %#v, want the key omitted", token.Payload["_sd"])
	}
	if token.ResolvedClaims["given_name"] != "Erika" {
		t.Errorf("resolved given_name = %v, want Erika", token.ResolvedClaims["given_name"])
	}
}

// SD-JWT VC §2.2.2.3: iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts and
// status "MUST NOT be included in the Disclosures, i.e., cannot be
// selectively disclosed". Outside a PID, iat stays in the payload too.
func TestGenerateSDJWT_ReservedClaimsStayInThePayload(t *testing.T) {
	raw := generateForTest(t, SDJWTConfig{
		VCT: "urn:example:vc",
		Claims: map[string]any{
			"given_name": "Erika",
			"vct":        "urn:attacker:admin",
			"status":     map[string]any{"note": "not disclosable"},
			"iat":        1700000000,
		},
	})

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	for _, d := range token.Disclosures {
		switch d.Name {
		case "vct", "status", "iat":
			t.Errorf("claim %q became a disclosure", d.Name)
		}
	}
	if token.Payload["vct"] != "urn:attacker:admin" {
		t.Errorf("payload vct = %v, want the claim to be embedded plainly", token.Payload["vct"])
	}
	if token.ResolvedClaims["given_name"] != "Erika" {
		t.Errorf("resolved given_name = %v, want Erika", token.ResolvedClaims["given_name"])
	}
}

// CIR (EU) 2024/2977 Annex section 4.2, as replaced by CIR (EU) 2026/1731,
// and ARF PID_21: a PID must disclose each claim selectively, except the
// claims SD-JWT VC keeps in plain text. iat is not one of them (SD-JWT VC
// §3.2.2.2). nbf stays in the payload.
func TestGenerateSDJWT_PIDIssuanceTimeIsSelectivelyDisclosable(t *testing.T) {
	issuedAt := time.Now().Add(-time.Hour).Truncate(time.Hour)
	raw := generateForTest(t, SDJWTConfig{VCT: "urn:example:national-id:1", IsPID: true, IssuedAt: &issuedAt, Claims: map[string]any{"given_name": "Erika", "iat": 1700000000}})

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	if iat, plain := token.Payload["iat"]; plain {
		t.Errorf("payload carries iat = %v in plain text", iat)
	}
	if token.ResolvedClaims["iat"] != float64(1700000000) {
		t.Errorf("disclosed iat = %v, want the claimed issuance time", token.ResolvedClaims["iat"])
	}
	if token.Payload["nbf"] != float64(issuedAt.Unix()) {
		t.Errorf("nbf = %v, want %d in the payload", token.Payload["nbf"], issuedAt.Unix())
	}
}

// RFC 9901 §4.2.1: a claim name "MUST NOT be _sd, ..., or a claim name
// existing in the object as a permanently disclosed claim", and §4.1.1
// reserves _sd_alg for the top level of the payload.
func TestGenerateSDJWT_RejectsReservedClaimNames(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	for _, name := range []string{"_sd", "_sd_alg", "..."} {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateSDJWT(SDJWTConfig{
				Issuer:    "https://issuer.example",
				VCT:       "urn:eudi:pid:1",
				ExpiresIn: time.Hour,
				Claims:    map[string]any{name: "value"},
				Key:       key,
			}); err == nil {
				t.Fatalf("GenerateSDJWT accepted a claim named %q", name)
			}
		})

		t.Run("nested "+name, func(t *testing.T) {
			if _, err := GenerateSDJWT(SDJWTConfig{
				Issuer:    "https://issuer.example",
				VCT:       "urn:eudi:pid:1",
				ExpiresIn: time.Hour,
				Claims:    map[string]any{"address": map[string]any{name: "value"}},
				Key:       key,
			}); err == nil {
				t.Fatalf("GenerateSDJWT accepted a nested claim named %q", name)
			}
		})
	}
}

// RFC 9901 §4.2.4.1: "The Issuer MUST hide the original order of the claims in
// the array. To ensure this, it is RECOMMENDED to shuffle the array of hashes,
// e.g., by sorting it alphanumerically or randomly, after potentially adding
// decoy digests".
func TestGenerateSDJWT_SDArrayHidesClaimOrder(t *testing.T) {
	raw := generateForTest(t, SDJWTConfig{
		Claims: map[string]any{
			"given_name":  "Erika",
			"family_name": "Mustermann",
			"birthdate":   "1964-08-12",
			"nationality": "DE",
			"address":     map[string]any{"locality": "Berlin", "country": "DE", "street": "Schulstr. 12"},
		},
	})

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	assertSorted(t, "payload", token.Payload["_sd"])
	for _, d := range token.Disclosures {
		if obj, ok := d.Value.(map[string]any); ok {
			if _, present := obj["_sd"]; present {
				assertSorted(t, "disclosure "+d.Name, obj["_sd"])
			}
		}
	}
}

func assertSorted(t *testing.T, where string, raw any) {
	t.Helper()
	entries, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s: _sd = %T, want an array", where, raw)
	}
	digests := make([]string, 0, len(entries))
	for _, entry := range entries {
		digest, ok := entry.(string)
		if !ok {
			t.Fatalf("%s: _sd entry = %T, want a string", where, entry)
		}
		digests = append(digests, digest)
	}
	if !sort.StringsAreSorted(digests) {
		t.Errorf("%s: _sd digests are in claim order rather than hidden: %v", where, digests)
	}
}

// The caller decides whether a credential is a PID. A PID vct alone does
// not make the generator disclose iat.
func TestGenerateSDJWT_KeepsIssuanceTimePlainWithoutPIDFlag(t *testing.T) {
	token, err := sdjwt.Parse(generateForTest(t, SDJWTConfig{VCT: "urn:eudi:pid:de:1", Claims: map[string]any{"given_name": "Erika"}}))
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	if _, plain := token.Payload["iat"]; !plain {
		t.Error("payload has no plain iat")
	}
}

// A template nbf is kept. Without one, NotBefore and then the issuance time
// set nbf.
func TestGenerateSDJWT_NotBefore(t *testing.T) {
	issuedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	configured := issuedAt.Add(time.Minute)
	for _, tc := range []struct {
		name string
		cfg  SDJWTConfig
		want int64
	}{
		{"template nbf", SDJWTConfig{IssuedAt: &issuedAt, NotBefore: &configured, Claims: map[string]any{"nbf": 1700000000}}, 1700000000},
		{"configured nbf", SDJWTConfig{IssuedAt: &issuedAt, NotBefore: &configured}, configured.Unix()},
		{"issuance time", SDJWTConfig{IssuedAt: &issuedAt}, issuedAt.Unix()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := sdjwt.Parse(generateForTest(t, tc.cfg))
			if err != nil {
				t.Fatalf("sdjwt.Parse: %v", err)
			}
			if token.Payload["nbf"] != float64(tc.want) {
				t.Errorf("nbf = %v, want %d", token.Payload["nbf"], tc.want)
			}
		})
	}
}
