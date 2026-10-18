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
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// Parse splits and decodes an SD-JWT and processes its Disclosures per RFC
// 9901 §7.1, where every MUST-reject condition is an error: "If any step
// fails, the SD-JWT is not valid, and processing MUST be aborted."
//
// It covers steps 3 to 5. These steps turn Disclosures into claims. Verify
// checks the Issuer-signed JWT signature.
func Parse(raw string) (*Token, error) {
	token, err := ParseLenient(raw)
	if err != nil {
		return nil, err
	}
	// RFC 9901 §7.1 aborts processing when any step fails, so every deviation is an error.
	if len(token.Deviations) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(token.Deviations, ". "))
	}
	return token, nil
}

// ParseLenient records recoverable RFC 9901 violations in token.Deviations while
// resolving claims, such as a nested _sd_alg or a repeated digest. Errors that
// prevent claim resolution still fail. Inspection and debug mode use it. Strict
// validation uses Parse.
func ParseLenient(raw string) (*Token, error) {
	token, err := parseStructure(raw)
	if err != nil {
		return nil, err
	}

	// RFC 9901 §7.1 steps 3 to 5.
	resolved, deviations, err := processPayload(token.Payload, token.Disclosures)
	if err != nil {
		return nil, err
	}
	token.ResolvedClaims = resolved
	token.Deviations = append(token.Deviations, deviations...)

	token.Warnings = append(token.Warnings, checkFullyUndisclosedChildren(token.Disclosures)...)

	return token, nil
}

// splitComponents assigns the tilde-separated components after the
// Issuer-signed JWT to Disclosures and to the optional Key Binding JWT.
//
// RFC 9901 §4 gives SD-JWT = JWT "~" *(DISCLOSURE "~"). So a component
// between two tildes is never empty, and the slot after the final tilde holds
// the KB-JWT: "In the case that there is no Key Binding JWT, the last element MUST
// be an empty string and the last separating tilde character MUST NOT be
// omitted."
//
// A single non-empty trailing component that is not a KB-JWT is read as a
// Disclosure without its trailing tilde. A warning reports the deviation.
func splitComponents(components []string) ([]string, *JWT, string, error) {
	if len(components) == 0 {
		return nil, nil, "", nil
	}

	discParts := components
	var kbJWT *JWT
	var warning string
	last := strings.TrimSpace(components[len(components)-1])
	if last == "" {
		discParts = components[:len(components)-1]
	} else if jwt := parseKeyBindingJWT(last); jwt != nil {
		discParts = components[:len(components)-1]
		kbJWT = jwt
	} else {
		// The last component is a Disclosure, so the final tilde is missing. RFC 9901
		// §4 requires it.
		warning = "the SD-JWT omits the tilde that RFC 9901 requires after the last disclosure"
	}

	for i, d := range discParts {
		if strings.TrimSpace(d) == "" {
			return nil, nil, "", fmt.Errorf("invalid SD-JWT: component %d between two tildes is empty", i+1)
		}
	}
	return discParts, kbJWT, warning, nil
}

// parseKeyBindingJWT decodes a trailing component as a Key Binding JWT.
// RFC 9901 §4.3 requires the typ header parameter of a KB-JWT to be kb+jwt.
// That typ tells a KB-JWT apart from a Disclosure.
func parseKeyBindingJWT(component string) *JWT {
	if strings.Count(component, ".") != 2 {
		return nil
	}
	jwt, err := parseJWT(component)
	if err != nil {
		return nil
	}
	if typ, ok := jwt.Header["typ"].(string); !ok || !format.JOSETypeIs(typ, TypeKeyBinding) {
		return nil
	}
	return jwt
}

// checkFullyUndisclosedChildren warns about a disclosed object or array whose
// children are all undisclosed.
func checkFullyUndisclosedChildren(disclosures []Disclosure) []string {
	digestMap := make(map[string]bool)
	for _, d := range disclosures {
		digestMap[d.Digest] = true
	}

	var warnings []string
	for _, d := range disclosures {
		if d.IsArrayEntry {
			continue
		}
		switch val := d.Value.(type) {
		case []any:
			if len(val) == 0 {
				continue
			}
			allUndisclosed := true
			for _, item := range val {
				ds, isPlaceholder, err := arrayElementDigest(item)
				if err != nil || !isPlaceholder || digestMap[ds] {
					allUndisclosed = false
					break
				}
			}
			if allUndisclosed {
				warnings = append(warnings, fmt.Sprintf("%s is disclosed but all %d array elements are undisclosed", d.Name, len(val)))
			}
		case map[string]any:
			sdArr, ok := val["_sd"].([]any)
			if !ok || len(sdArr) == 0 {
				continue
			}
			hasVisibleClaims := false
			for k := range val {
				if k != "_sd" && k != "_sd_alg" {
					hasVisibleClaims = true
					break
				}
			}
			if !hasVisibleClaims {
				hasResolved := false
				for _, item := range sdArr {
					if ds, ok := item.(string); ok && digestMap[ds] {
						hasResolved = true
						break
					}
				}
				if !hasResolved {
					warnings = append(warnings, fmt.Sprintf("%s is disclosed but all %d sub-claims are undisclosed", d.Name, len(sdArr)))
				}
			}
		}
	}
	return warnings
}

func parseJWT(raw string) (*JWT, error) {
	header, payload, sig, err := format.ParseJWTParts(raw)
	if err != nil {
		return nil, err
	}
	return &JWT{
		Raw:       raw,
		Header:    header,
		Payload:   payload,
		Signature: sig,
	}, nil
}

func parseDisclosure(raw string, sdAlg string) (*Disclosure, error) {
	decoded, err := format.DecodeBase64URL(raw)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}

	var arr []any
	if err := json.Unmarshal(decoded, &arr); err != nil {
		return nil, fmt.Errorf("JSON decode: %w", err)
	}

	disc := &Disclosure{
		Raw:     raw,
		Decoded: string(decoded),
	}

	digest, err := computeDigest(raw, sdAlg)
	if err != nil {
		return nil, err
	}
	disc.Digest = digest

	// RFC 9901 §4.2.1 requires the salt to be a string and says of the claim
	// name: "It MUST be a string and MUST NOT be _sd, ..., or a claim name
	// existing in the object as a permanently disclosed claim." §4.2.2
	// requires the same salt type for an array element Disclosure.
	switch len(arr) {
	case 3:
		// [salt, name, value]
		salt, ok := arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("salt is not a string")
		}
		name, ok := arr[1].(string)
		if !ok {
			return nil, fmt.Errorf("claim name is not a string")
		}
		disc.Salt = salt
		disc.Name = name
		disc.Value = arr[2]
	case 2:
		// [salt, value] for an array element
		salt, ok := arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("salt is not a string")
		}
		disc.Salt = salt
		disc.Value = arr[1]
		disc.IsArrayEntry = true
	default:
		return nil, fmt.Errorf("unexpected disclosure array length: %d", len(arr))
	}

	return disc, nil
}

// defaultSDAlg applies when the payload carries no _sd_alg. RFC 9901 §4.1.1:
// "If the _sd_alg claim is not present at the top level, a default value of
// sha-256 MUST be used."
const defaultSDAlg = "sha-256"

// hashForSDAlg maps an _sd_alg value to its hash. RFC 9901 §4.1.1: "This claim
// value is a case-sensitive string with the hash algorithm identifier". The
// Named Information Hash Algorithm Registry spells the identifiers in lower case.
func hashForSDAlg(sdAlg string) (func() hash.Hash, error) {
	switch sdAlg {
	case "sha-256":
		return sha256.New, nil
	case "sha-384":
		return sha512.New384, nil
	case "sha-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported _sd_alg: %q", sdAlg)
	}
}

// SDAlg returns the payload's _sd_alg. The default is sha-256 per RFC 9901 §4.1.1.
func (t *Token) SDAlg() string {
	return SDAlgFromPayload(t.Payload)
}

// SDAlgFromPayload returns the _sd_alg of an issuer-signed JWT payload. The
// default is sha-256 per RFC 9901 §4.1.1.
func SDAlgFromPayload(payload map[string]any) string {
	if alg, ok := payload["_sd_alg"].(string); ok && alg != "" {
		return alg
	}
	return defaultSDAlg
}

// SDHash returns the base64url digest of data under sdAlg. A KB-JWT's sd_hash
// uses the same algorithm as the credential's disclosures (RFC 9901 §4.3).
func SDHash(data, sdAlg string) (string, error) {
	return computeDigest(data, sdAlg)
}

func computeDigest(raw string, sdAlg string) (string, error) {
	newHash, err := hashForSDAlg(sdAlg)
	if err != nil {
		return "", err
	}
	h := newHash()
	h.Write([]byte(raw))
	return format.EncodeBase64URL(h.Sum(nil)), nil
}

// ReferencedDigests returns the digests in the credential: the entries of its
// "_sd" arrays and the array elements {"...": digest}. A disclosure with a
// digest outside this set belongs to another credential.
func ReferencedDigests(token *Token) map[string]bool {
	out := make(map[string]bool)
	if token == nil {
		return out
	}
	collectDigests(token.Payload, out)
	for _, d := range token.Disclosures {
		// A nested disclosure's digest lives inside its parent's value.
		collectDigests(d.Value, out)
	}
	return out
}

func collectDigests(value any, out map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		if digest, isPlaceholder, err := arrayElementDigest(v); err == nil && isPlaceholder {
			out[digest] = true
			return
		}
		for key, val := range v {
			if key == "_sd" {
				if arr, ok := val.([]any); ok {
					for _, entry := range arr {
						if digest, ok := entry.(string); ok {
							out[digest] = true
						}
					}
				}
				continue
			}
			collectDigests(val, out)
		}
	case []any:
		for _, item := range v {
			collectDigests(item, out)
		}
	}
}

// Inspect decodes malformed credentials for display and records violations. It fails
// only if the JWT cannot decode. Its result never establishes validity or trust.
func Inspect(raw string) (*Token, error) {
	return ParseLenient(raw)
}

// parseStructure decodes the SD-JWT components for Parse and Inspect. It does
// no validation.
func parseStructure(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, "~")

	if len(parts) < 1 || parts[0] == "" {
		return nil, fmt.Errorf("invalid SD-JWT: no JWT part found")
	}

	jwt, err := parseJWT(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	token := &Token{
		Raw:       raw,
		Header:    jwt.Header,
		Payload:   jwt.Payload,
		Signature: jwt.Signature,
	}

	// RFC 9901 §4.1.1 makes _sd_alg a string with the hash algorithm. A
	// non-string or unknown value leaves the disclosures unmatchable. It is
	// recorded, and the default still decodes them.
	sdAlg := defaultSDAlg
	if rawAlg, present := token.Payload["_sd_alg"]; present {
		if alg, ok := rawAlg.(string); !ok {
			token.Deviations = append(token.Deviations, "_sd_alg is not a string, which RFC 9901 §4.1.1 requires, so its disclosures cannot be matched")
		} else if _, err := hashForSDAlg(alg); err != nil {
			token.Deviations = append(token.Deviations, fmt.Sprintf("_sd_alg %q is not a supported hash algorithm, so its disclosures cannot be matched", alg))
		} else {
			sdAlg = alg
		}
	}

	discParts, kbJWT, warning, err := splitComponents(parts[1:])
	if err != nil {
		return nil, err
	}
	token.KeyBindingJWT = kbJWT
	if warning != "" {
		token.Warnings = append(token.Warnings, warning)
	}

	for i, d := range discParts {
		disc, err := parseDisclosure(d, sdAlg)
		if err != nil {
			// An unparsable disclosure is dropped, so the rest of the credential
			// still reads.
			token.Deviations = append(token.Deviations, fmt.Sprintf("disclosure %d could not be parsed (%s), so it is dropped", i+1, err))
			continue
		}
		token.Disclosures = append(token.Disclosures, *disc)
	}

	return token, nil
}
