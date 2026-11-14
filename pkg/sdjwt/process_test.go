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

package sdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func disclosureOf(t *testing.T, elements ...any) (raw string, digest string) {
	t.Helper()
	encoded, err := json.Marshal(elements)
	if err != nil {
		t.Fatalf("marshaling disclosure: %v", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(encoded)
	sum := sha256.Sum256([]byte(raw))
	return raw, base64.RawURLEncoding.EncodeToString(sum[:])
}

// assembleSDJWT serializes the credential by hand, so tests can supply malformed payloads.
func assembleSDJWT(t *testing.T, payload map[string]any, disclosures ...string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": TypeSDJWTVC})
	if err != nil {
		t.Fatalf("marshaling header: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".fakesig~"
	for _, d := range disclosures {
		raw += d + "~"
	}
	return raw
}

func mustParse(t *testing.T, raw string) *Token {
	t.Helper()
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	return token
}

func parseError(t *testing.T, raw string, want string) {
	t.Helper()
	_, err := Parse(raw)
	if err == nil {
		t.Fatalf("Parse() accepted the credential, want rejection mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Parse() error = %v, want it to mention %q", err, want)
	}
}

// RFC 9901 §7.1 step 3.c.ii.2: "If the claim name is _sd or ..., the SD-JWT
// MUST be rejected."
func TestParse_RejectsDisclosureNamedSD(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "_sd", []any{"injected"})
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, `"_sd"`)
}

func TestParse_RejectsDisclosureNamedEllipsis(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "...", "injected")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, `"..."`)
}

// RFC 9901 §7.1 step 3.c.ii.3: "If the claim name already exists at the level
// of the _sd key, the SD-JWT MUST be rejected." A Disclosure named vct must
// not shadow the signed vct.
func TestParse_RejectsDisclosureShadowingSignedVCT(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "vct", "urn:attacker:admin")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"vct": "urn:eudi:pid:1",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, "vct")
}

func TestParse_RejectsTwoDisclosuresForOneClaimName(t *testing.T) {
	first, firstDigest := disclosureOf(t, "salt1", "given_name", "Erika")
	second, secondDigest := disclosureOf(t, "salt2", "given_name", "Max")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{firstDigest, secondDigest},
	}, first, second)

	parseError(t, raw, "given_name")
}

// RFC 9901 §7.1 step 3.d: "Remove all array elements for which the digest was
// not found in the previous step."
func TestParse_RemovesUndisclosedArrayElements(t *testing.T) {
	disclosed, disclosedDigest := disclosureOf(t, "salt1", "FR")
	_, withheldDigest := disclosureOf(t, "salt2", "US")

	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"nationalities": []any{
			"DE",
			map[string]any{"...": disclosedDigest},
			map[string]any{"...": withheldDigest},
		},
	}, disclosed)

	token := mustParse(t, raw)
	got, ok := token.ResolvedClaims["nationalities"].([]any)
	if !ok {
		t.Fatalf("nationalities = %T, want an array", token.ResolvedClaims["nationalities"])
	}
	want := []any{"DE", "FR"}
	if len(got) != len(want) {
		t.Fatalf("nationalities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nationalities = %v, want %v", got, want)
		}
	}
}

// RFC 9901 §4.1: "The same digest value MUST NOT appear more than once in the
// SD-JWT", enforced by §7.1 step 4.
func TestParse_RejectsDuplicateDigestInSDArray(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest, digest},
	}, disc)

	parseError(t, raw, "more than once")
}

func TestParse_RejectsDigestReusedAcrossLevels(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss":     "https://issuer.example",
		"_sd":     []any{digest},
		"address": map[string]any{"_sd": []any{digest}},
	}, disc)

	parseError(t, raw, "more than once")
}

// RFC 9901 §4.2.4.2: "There MUST NOT be any other keys in the object."
func TestParse_RejectsArrayPlaceholderWithExtraKeys(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "FR")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"nationalities": []any{
			map[string]any{"...": digest, "hint": "FR"},
		},
	}, disc)

	parseError(t, raw, `"..."`)
}

func TestParse_RejectsArrayPlaceholderWithNonStringDigest(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{
		"iss":           "https://issuer.example",
		"nationalities": []any{map[string]any{"...": 42}},
	})

	parseError(t, raw, `"..."`)
}

// RFC 9901 §7.1 step 3.c.ii.1: a Disclosure referenced from an _sd array must
// have three elements.
func TestParse_RejectsArrayElementDisclosureReferencedFromSD(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "orphan-value")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, "two elements")
}

// RFC 9901 §7.1 step 3.c.iii.1: a Disclosure referenced from an array element
// must have two elements.
func TestParse_RejectsObjectDisclosureReferencedFromArray(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss":           "https://issuer.example",
		"nationalities": []any{map[string]any{"...": digest}},
	}, disc)

	parseError(t, raw, "three elements")
}

// RFC 9901 §7.1 step 5: "If any Disclosure was not referenced by digest value
// in the Issuer-signed JWT ... the SD-JWT MUST be rejected."
func TestParse_RejectsUnreferencedDisclosure(t *testing.T) {
	referenced, digest := disclosureOf(t, "salt1", "given_name", "Erika")
	stray, _ := disclosureOf(t, "salt2", "role", "admin")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, referenced, stray)

	parseError(t, raw, "not referenced")
}

func TestParse_RejectsUnreferencedNestedDisclosure(t *testing.T) {
	// Only the parent's value references the child, and the presentation omits
	// the parent.
	child, childDigest := disclosureOf(t, "salt1", "locality", "Berlin")
	_, parentDigest := disclosureOf(t, "salt2", "address", map[string]any{"_sd": []any{childDigest}})
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{parentDigest},
	}, child)

	parseError(t, raw, "not referenced")
}

func TestParse_RejectsDuplicateDisclosure(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc, disc)

	parseError(t, raw, "more than once")
}

// RFC 9901 §4.1.1: "This claim value is a case-sensitive string with the hash
// algorithm identifier."
func TestParse_SDAlgIsCaseSensitive(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss":     "https://issuer.example",
		"_sd_alg": "SHA-256",
		"_sd":     []any{digest},
	}, disc)

	parseError(t, raw, "_sd_alg")
}

// RFC 9901 §4.1.1: the _sd_alg claim "MUST NOT be used in any object nested
// within the payload."
func TestParse_RejectsNestedSDAlg(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{
		"iss":     "https://issuer.example",
		"_sd_alg": "sha-256",
		"address": map[string]any{"_sd_alg": "sha-256", "locality": "Berlin"},
	})

	parseError(t, raw, "_sd_alg")
}

func TestParse_RejectsNestedSDAlgInsideDisclosure(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", "address", map[string]any{"_sd_alg": "sha-512"})
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, "_sd_alg")
}

func TestParse_RejectsNonStringSDAlg(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{
		"iss":     "https://issuer.example",
		"_sd_alg": 256,
	})

	parseError(t, raw, "_sd_alg")
}

// RFC 9901 §4.2.1 requires a string salt and a string claim name.
func TestParse_RejectsNonStringSalt(t *testing.T) {
	disc, digest := disclosureOf(t, 12345, "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, "salt")
}

func TestParse_RejectsNonStringClaimName(t *testing.T) {
	disc, digest := disclosureOf(t, "salt", 7, "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	parseError(t, raw, "claim name")
}

// RFC 9901 §4.2.4.1: "The _sd key MUST refer to an array of strings".
func TestParse_RejectsNonArraySD(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": nil,
	})

	parseError(t, raw, `"_sd"`)
}

func TestParse_RejectsNonStringSDEntry(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{42},
	})

	parseError(t, raw, `"_sd"`)
}

// RFC 9901 §4 ABNF: SD-JWT = JWT "~" *(DISCLOSURE "~") with DISCLOSURE being
// one or more base64url characters, so no component may be empty.
func TestParse_RejectsEmptyDisclosureComponent(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{"iss": "https://issuer.example"})
	// assembleSDJWT already ends in a tilde, so this is jwt~~.
	parseError(t, raw+"~", "empty")
}

func TestParse_AcceptsCredentialWithoutDisclosures(t *testing.T) {
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"vct": "urn:eudi:pid:1",
	})

	token := mustParse(t, raw)
	if len(token.Disclosures) != 0 {
		t.Fatalf("got %d disclosures, want 0", len(token.Disclosures))
	}
	if token.ResolvedClaims["vct"] != "urn:eudi:pid:1" {
		t.Fatalf("resolved vct = %v, want urn:eudi:pid:1", token.ResolvedClaims["vct"])
	}
}

// RFC 9901 §7.1 step 3.c.i: "If no such Disclosure can be found, the digest
// MUST be ignored". Decoy digests (§4.2.5) rely on this rule.
func TestParse_IgnoresUnmatchedDigest(t *testing.T) {
	_, decoy := disclosureOf(t, "salt", "role", "admin")
	disc, digest := disclosureOf(t, "salt2", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{decoy, digest},
	}, disc)

	token := mustParse(t, raw)
	if token.ResolvedClaims["given_name"] != "Erika" {
		t.Fatalf("resolved given_name = %v, want Erika", token.ResolvedClaims["given_name"])
	}
	if _, present := token.ResolvedClaims["role"]; present {
		t.Fatal("a digest without a disclosure produced a claim")
	}
	if _, present := token.ResolvedClaims["_sd"]; present {
		t.Fatal("_sd survived into the processed payload")
	}
}

func TestParse_ResolvesRecursiveDisclosuresAndArrays(t *testing.T) {
	locality, localityDigest := disclosureOf(t, "salt1", "locality", "Berlin")
	nationality, nationalityDigest := disclosureOf(t, "salt2", "FR")
	address, addressDigest := disclosureOf(t, "salt3", "address", map[string]any{
		"country": "DE",
		"_sd":     []any{localityDigest},
	})
	nationalities, nationalitiesDigest := disclosureOf(t, "salt4", "nationalities", []any{
		"DE",
		map[string]any{"...": nationalityDigest},
	})

	raw := assembleSDJWT(t, map[string]any{
		"iss":     "https://issuer.example",
		"_sd_alg": "sha-256",
		"_sd":     []any{addressDigest, nationalitiesDigest},
	}, locality, nationality, address, nationalities)

	token := mustParse(t, raw)
	if _, present := token.ResolvedClaims["_sd_alg"]; present {
		t.Error("_sd_alg survived into the processed payload")
	}
	addressClaim, ok := token.ResolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatalf("address = %T, want an object", token.ResolvedClaims["address"])
	}
	if addressClaim["locality"] != "Berlin" || addressClaim["country"] != "DE" {
		t.Errorf("address = %v, want locality Berlin and country DE", addressClaim)
	}
	if _, present := addressClaim["_sd"]; present {
		t.Error("_sd survived inside a disclosed object")
	}
	list, ok := token.ResolvedClaims["nationalities"].([]any)
	if !ok || len(list) != 2 || list[0] != "DE" || list[1] != "FR" {
		t.Errorf("nationalities = %v, want [DE FR]", token.ResolvedClaims["nationalities"])
	}
}

// RFC 7515 §4.1.9 makes the media type case insensitive and lets the
// application/ prefix be omitted.
func TestParse_KeyBindingJWT(t *testing.T) {
	for _, typ := range []string{"kb+jwt", "application/kb+jwt", "KB+JWT"} {
		t.Run(typ, func(t *testing.T) { testKeyBindingJWT(t, typ) })
	}
}

func testKeyBindingJWT(t *testing.T, typ string) {
	disc, digest := disclosureOf(t, "salt", "given_name", "Erika")
	raw := assembleSDJWT(t, map[string]any{
		"iss": "https://issuer.example",
		"_sd": []any{digest},
	}, disc)

	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": typ})
	payload, _ := json.Marshal(map[string]any{"nonce": "n-1", "aud": "https://verifier.example"})
	kb := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"

	token := mustParse(t, raw+kb)
	if token.KeyBindingJWT == nil {
		t.Fatal("expected a key binding JWT")
	}
	if len(token.Disclosures) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(token.Disclosures))
	}
	if token.ResolvedClaims["given_name"] != "Erika" {
		t.Fatalf("resolved given_name = %v, want Erika", token.ResolvedClaims["given_name"])
	}
}

func TestArrayElementDigest(t *testing.T) {
	digest, isPlaceholder, err := arrayElementDigest(map[string]any{"...": "abc"})
	if err != nil || !isPlaceholder || digest != "abc" {
		t.Fatalf("arrayElementDigest = (%q, %v, %v), want (abc, true, nil)", digest, isPlaceholder, err)
	}

	if _, isPlaceholder, err := arrayElementDigest("plain"); err != nil || isPlaceholder {
		t.Fatalf("a plain value is not a placeholder: (%v, %v)", isPlaceholder, err)
	}

	if _, _, err := arrayElementDigest(map[string]any{"...": "abc", "extra": 1}); err == nil {
		t.Fatal("expected an error for a placeholder carrying a second key")
	}
}

// Each level of this chain references the next disclosure twice. Resolving
// every reference would build 2^40 objects.
func TestParseLenient_DuplicatedDigestChainStaysLinear(t *testing.T) {
	const levels = 40
	t.Run("object", func(t *testing.T) {
		disc, digest := disclosureOf(t, "salt", "leaf", "value")
		disclosures := []string{disc}
		for i := 0; i < levels; i++ {
			disc, digest = disclosureOf(t, "salt", "level", map[string]any{
				"a": map[string]any{"_sd": []any{digest}},
				"b": map[string]any{"_sd": []any{digest}},
			})
			disclosures = append(disclosures, disc)
		}
		assertFinishesWithRepeatedDigest(t, assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{digest}}, disclosures...))
	})
	t.Run("array", func(t *testing.T) {
		disc, digest := disclosureOf(t, "salt", "leaf")
		disclosures := []string{disc}
		for i := 0; i < levels; i++ {
			disc, digest = disclosureOf(t, "salt", []any{
				map[string]any{"...": digest},
				map[string]any{"...": digest},
			})
			disclosures = append(disclosures, disc)
		}
		assertFinishesWithRepeatedDigest(t, assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "levels": []any{map[string]any{"...": digest}}}, disclosures...))
	})
}

func assertFinishesWithRepeatedDigest(t *testing.T, raw string) {
	t.Helper()
	done := make(chan []string, 1)
	go func() {
		token, err := ParseLenient(raw)
		if err != nil {
			t.Errorf("ParseLenient: %v", err)
			done <- nil
			return
		}
		done <- token.Deviations
	}()
	select {
	case deviations := <-done:
		if !strings.Contains(strings.Join(deviations, "\n"), "more than once") {
			t.Fatalf("deviations = %v, want a repeated digest finding", deviations)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ParseLenient did not finish within 5s")
	}
	parseError(t, raw, "more than once")
}
