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
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// The typ values of draft-ietf-oauth-delegate-sd-jwt-00 §5.1.4. A KB-SD-JWT+KB
// has a Delegate Payload with a cnf claim. A Key Binding JWT or another
// KB-SD-JWT can follow it.
const (
	TypeKBSDJWT   = "kb+sd-jwt"
	TypeKBSDJWTKB = "kb-sd-jwt+kb"
)

// The format values of the delegate transaction data type (§7.1).
const (
	FormatDelegate   = "dSD-JWT"
	FormatDelegateKB = "dSD-JWT+KB"
)

// Delegation is a dSD-JWT or dSD-JWT+KB in Compact Serialization (§5.1.1).
type Delegation struct {
	// Credential is the initial SD-JWT with its Disclosures.
	Credential *Token
	// Links are the KB-SD-JWTs in chain order.
	Links []*DelegationLink
	// KeyBindingJWT is the delegate KB-JWT of a dSD-JWT+KB.
	KeyBindingJWT *JWT
}

// DelegationLink is one KB-SD-JWT with its Disclosures.
type DelegationLink struct {
	// Token holds the KB-SD-JWT header and payload and the Disclosures after it.
	Token *Token
	// Payload is the processed Delegate Payload. It is nil unless
	// delegate_payload has exactly 1 disclosed element and that element is a
	// JSON object.
	Payload map[string]any
}

// Format is dSD-JWT+KB when a delegate KB-JWT ends the chain, else dSD-JWT.
func (d *Delegation) Format() string {
	if d.KeyBindingJWT != nil {
		return FormatDelegateKB
	}
	return FormatDelegate
}

// IsDelegation reports whether raw has the empty component of §5.1.1. An
// SD-JWT has none (RFC 9901 §4).
func IsDelegation(raw string) bool {
	return strings.Contains(strings.TrimSpace(raw), "~~")
}

// ParseDelegation splits a dSD-JWT or dSD-JWT+KB and decodes its components
// (§6 step 1). It checks no signature and no hash.
func ParseDelegation(raw string) (*Delegation, error) {
	components := strings.Split(strings.TrimSpace(raw), "~")
	// §5.1.1: "dSD-JWT+KB and dSD-JWT formats are differentiated by a trailing
	// ~ for dSD-JWT."
	last := components[len(components)-1]
	segments, err := delegationSegments(components[:len(components)-1])
	if err != nil {
		return nil, err
	}
	d := &Delegation{}
	if last != "" {
		d.KeyBindingJWT, err = parseJWT(last)
		if err != nil {
			return nil, fmt.Errorf("the component after the last tilde is not a Key Binding JWT: %w", err)
		}
	}
	d.Credential, err = ParseLenient(segments[0])
	if err != nil {
		return nil, fmt.Errorf("SD-JWT: %w", err)
	}
	for i, segment := range segments[1:] {
		token, err := ParseLenient(segment)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", linkLabel(i), err)
		}
		d.Links = append(d.Links, NewDelegationLink(token))
	}
	return d, nil
}

// delegationSegments groups the components before the last tilde into the
// SD-JWT and the KB-SD-JWTs. Each segment keeps its trailing tilde. sd_hash
// covers the segment with that tilde (RFC 9901 §4.3.1).
//
// §5.1.1: "The resulting array of components MUST have exactly one empty
// component between the last component of each SD-JWT or KB-SD-JWT and the
// following KB-SD-JWT."
func delegationSegments(components []string) ([]string, error) {
	var segments []string
	var current []string
	for _, component := range components {
		if component != "" {
			current = append(current, component)
			continue
		}
		if len(current) == 0 {
			return nil, fmt.Errorf("invalid Delegate SD-JWT: more than one empty component separates two parts of the chain")
		}
		segments = append(segments, strings.Join(current, "~")+"~")
		current = nil
	}
	if len(current) == 0 {
		return nil, fmt.Errorf("invalid Delegate SD-JWT: no KB-SD-JWT follows the last empty component")
	}
	segments = append(segments, strings.Join(current, "~")+"~")
	if len(segments) < 2 {
		return nil, fmt.Errorf("invalid Delegate SD-JWT: no empty component separates the SD-JWT from a KB-SD-JWT")
	}
	return segments, nil
}

func linkLabel(index int) string {
	return fmt.Sprintf("KB-SD-JWT %d", index+1)
}

// NewDelegationLink reads the Delegate Payload of a parsed KB-SD-JWT.
func NewDelegationLink(token *Token) *DelegationLink {
	return &DelegationLink{Token: token, Payload: disclosedDelegatePayload(token)}
}

func disclosedDelegatePayload(token *Token) map[string]any {
	disclosed, _ := token.ResolvedClaims["delegate_payload"].([]any)
	if len(disclosed) != 1 {
		return nil
	}
	payload, _ := disclosed[0].(map[string]any)
	return payload
}

// DelegationOptions are the expectations of the verifier.
type DelegationOptions struct {
	// Now is the verification time. The zero value means the current time.
	Now time.Time
	// Audience and Nonce are compared with the last signed component when set.
	// That is the delegate KB-JWT of a dSD-JWT+KB and the final KB-SD-JWT of a
	// dSD-JWT.
	Audience string
	Nonce    string
	// RequireKeyBinding rejects a dSD-JWT (§6 step 5.1).
	RequireKeyBinding bool
}

// VerifyDelegation runs the steps of §6 on a dSD-JWT or dSD-JWT+KB. issuerKey
// verifies the Issuer-signed JWT. The caller decides whether it trusts that
// key.
func VerifyDelegation(raw string, issuerKey crypto.PublicKey, opts DelegationOptions) (*Delegation, error) {
	d, err := ParseDelegation(raw)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(d.Credential, issuerKey); err != nil {
		return nil, fmt.Errorf("SD-JWT: %w", err)
	}
	if err := d.VerifyChain(opts); err != nil {
		return nil, err
	}
	return d, nil
}

// VerifyChain runs §6 steps 3 to 5. Of step 2 it covers the Disclosures and
// the validity period. VerifyDelegation also verifies the signature of the
// Issuer-signed JWT.
func (d *Delegation) VerifyChain(opts DelegationOptions) error {
	// §6 step 5.1: "If the credential is a dSD-JWT (without Key Binding), the
	// Verifier MUST reject the presentation".
	if opts.RequireKeyBinding && d.KeyBindingJWT == nil {
		return fmt.Errorf("the presentation is a dSD-JWT, but Key Binding is required")
	}
	return d.Inspect(opts).Err()
}

// DelegationReport is the result of each component of a chain.
// Delegation.Inspect returns it.
type DelegationReport struct {
	// Credential is the first error of the checks of the Disclosures and the
	// validity period of the SD-JWT.
	Credential error
	// Links has one DelegationStep for each KB-SD-JWT, in chain order.
	Links []DelegationStep
	// KeyBinding is the DelegationStep of the Key Binding JWT of the Delegate
	// Holder. It is nil for a dSD-JWT.
	KeyBinding *DelegationStep
}

// DelegationStep is the result of one KB-SD-JWT or Key Binding JWT. Each
// error is nil when its check passes.
type DelegationStep struct {
	// Signature reports the signature with the cnf key of the preceding
	// component (§6 step 3.1).
	Signature error
	// Binding reports the sd_hash or issuer_jwt_hash over the preceding
	// component (§6 steps 3.3 and 3.4).
	Binding error
	// Other is the first error of the other checks, such as the typ and the
	// claims.
	Other error
	// first is the error that VerifyChain reports for the step.
	first error
}

func (s *DelegationStep) record(field *error, err error) {
	if err == nil {
		return
	}
	if *field == nil {
		*field = err
	}
	if s.first == nil {
		s.first = err
	}
}

// Failed reports whether a check of the step failed.
func (s DelegationStep) Failed() bool {
	return s.first != nil
}

// Err is the first error in chain order, the error that VerifyChain returns.
func (r DelegationReport) Err() error {
	if r.Credential != nil {
		return fmt.Errorf("SD-JWT: %w", r.Credential)
	}
	for i, step := range r.Links {
		if step.first != nil {
			return fmt.Errorf("%s: %w", linkLabel(i), step.first)
		}
	}
	if r.KeyBinding != nil && r.KeyBinding.first != nil {
		return fmt.Errorf("the Key Binding JWT of the Delegate Holder: %w", r.KeyBinding.first)
	}
	return nil
}

// Inspect runs the checks of VerifyChain and reports each component on its
// own. A step after a failing step is still checked.
func (d *Delegation) Inspect(opts DelegationOptions) DelegationReport {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := DelegationReport{Credential: processedError(d.Credential, d.Credential.ResolvedClaims, now)}
	preceding, precedingClaims := d.Credential, d.Credential.ResolvedClaims
	for i, link := range d.Links {
		// §6 steps 3.5 and 4.2 allow the typ kb+sd-jwt only for the final
		// KB-SD-JWT of a dSD-JWT.
		final := i == len(d.Links)-1 && d.KeyBindingJWT == nil
		step := link.check(preceding, precedingClaims, final, now)
		if final {
			step.record(&step.Other, bindingError(link.Token.Payload, opts))
		}
		r.Links = append(r.Links, step)
		preceding, precedingClaims = link.Token, link.Payload
	}
	if d.KeyBindingJWT != nil {
		step := d.checkKeyBinding(preceding, precedingClaims, opts)
		r.KeyBinding = &step
	}
	return r
}

// check runs §6 steps 3.1 to 3.5 on one KB-SD-JWT. preceding is the SD-JWT or
// KB-SD-JWT before it, and precedingClaims are its processed claims.
func (l *DelegationLink) check(preceding *Token, precedingClaims map[string]any, final bool, now time.Time) DelegationStep {
	var s DelegationStep
	typ, _ := l.Token.Header["typ"].(string)
	withKeyBinding := format.JOSETypeIs(typ, TypeKBSDJWTKB)
	switch {
	case withKeyBinding:
	case !final:
		s.record(&s.Other, fmt.Errorf("typ is %q. A KB-SD-JWT followed by another component needs %q", typ, TypeKBSDJWTKB))
	case !format.JOSETypeIs(typ, TypeKBSDJWT):
		s.record(&s.Other, fmt.Errorf("typ is %q, expected %q or %q", typ, TypeKBSDJWT, TypeKBSDJWTKB))
	}
	// §6 step 3.1: "The cnf claim of the preceding component is used as the
	// Issuer public key."
	if key, err := confirmationKey(precedingClaims); err != nil {
		s.record(&s.Signature, fmt.Errorf("the preceding component %w", err))
	} else {
		s.record(&s.Signature, verifySignature(l.Token, key))
	}
	// §5.1.4: "KB-SD-JWTs MUST conform to all the requirements of a KB-JWT".
	s.record(&s.Other, keyBindingClaimsError(l.Token.Payload))
	s.record(&s.Other, l.delegatePayloadError())
	s.record(&s.Other, processedError(l.Token, l.Payload, now))
	s.record(&s.Binding, precedingHashError(l.Token.Payload, preceding))
	// §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate Payload MUST
	// include a cnf claim."
	if withKeyBinding {
		if _, err := confirmationKey(l.Payload); err != nil {
			s.record(&s.Other, fmt.Errorf("the typ is %q, but the Delegate Payload %w", TypeKBSDJWTKB, err))
		}
	}
	return s
}

// delegatePayloadError checks delegate_payload against §5.1.4 and §6 step 3.2.
func (l *DelegationLink) delegatePayloadError() error {
	elements, ok := l.Token.Payload["delegate_payload"].([]any)
	if !ok || len(elements) == 0 {
		return fmt.Errorf("delegate_payload must be a non-empty array")
	}
	// §5.1.4: "If it contains more than one element then they MUST all be
	// replaced with disclosures."
	if len(elements) > 1 {
		for i, element := range elements {
			if _, isPlaceholder, err := arrayElementDigest(element); err != nil || !isPlaceholder {
				return fmt.Errorf("delegate_payload has %d elements, but element %d is not a digest of a Disclosure", len(elements), i)
			}
		}
	}
	// §6 step 3.2: "Verify that there is exactly one disclosed element in the
	// delegate_payload array."
	disclosed, _ := l.Token.ResolvedClaims["delegate_payload"].([]any)
	if len(disclosed) != 1 {
		return fmt.Errorf("delegate_payload has %d disclosed elements, expected exactly 1", len(disclosed))
	}
	if l.Payload == nil {
		return fmt.Errorf("the disclosed element of delegate_payload is not a JSON object")
	}
	return nil
}

// processedError reports what RFC 9901 §7.1 rejects in a processed SD-JWT or
// KB-SD-JWT: a deviation in its Disclosures and a validity claim outside now.
func processedError(token *Token, claims map[string]any, now time.Time) error {
	if len(token.Deviations) > 0 {
		return fmt.Errorf("%s", strings.Join(token.Deviations, ". "))
	}
	if exp, ok := jsonutil.GetFloat64(claims, "exp"); ok {
		t := time.Unix(int64(exp), 0)
		if validity.Expired(&t, now) {
			return fmt.Errorf("expired at %s", t.UTC().Format(time.RFC3339))
		}
	}
	if nbf, ok := jsonutil.GetFloat64(claims, "nbf"); ok {
		t := time.Unix(int64(nbf), 0)
		if validity.NotYet(&t, now) {
			return fmt.Errorf("not valid before %s", t.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// precedingHashError checks the binding of a KB-SD-JWT to the component
// before it (§6 steps 3.3 and 3.4). §5.1.4: "Both sd_hash and issuer_jwt_hash
// use the hash algorithm of the preceding Issuer-signed JWT or KB-SD-JWT+KB".
func precedingHashError(payload map[string]any, preceding *Token) error {
	claim, input := "sd_hash", preceding.Raw
	if _, present := payload["sd_hash"]; !present {
		// §5.1.4: issuer_jwt_hash "hashes over only the preceding Issuer-signed
		// jwt or KB-SD-JWT+KB and not any disclosures".
		claim, input = "issuer_jwt_hash", signedJWT(preceding)
		if _, present := payload[claim]; !present {
			return fmt.Errorf("neither sd_hash nor issuer_jwt_hash is present")
		}
	}
	want, err := SDHash(input, preceding.SDAlg())
	if err != nil {
		return err
	}
	if got, _ := payload[claim].(string); got != want {
		return fmt.Errorf("%s does not match the preceding component", claim)
	}
	return nil
}

// checkKeyBinding checks the Key Binding JWT of the Delegate Holder (§6 steps
// 5.2 and 5.3). last is the final KB-SD-JWT and delegatePayload its Delegate
// Payload.
func (d *Delegation) checkKeyBinding(last *Token, delegatePayload map[string]any, opts DelegationOptions) DelegationStep {
	var s DelegationStep
	kb := d.KeyBindingJWT
	if typ, _ := kb.Header["typ"].(string); !format.JOSETypeIs(typ, TypeKeyBinding) {
		s.record(&s.Other, fmt.Errorf("typ is %q, expected %q", typ, TypeKeyBinding))
	}
	if key, err := confirmationKey(delegatePayload); err != nil {
		s.record(&s.Signature, fmt.Errorf("the final Delegate Payload %w", err))
	} else {
		s.record(&s.Signature, verifySignature(&Token{Raw: kb.Raw, Header: kb.Header}, key))
	}
	s.record(&s.Other, keyBindingClaimsError(kb.Payload))
	// §5.1.3: "the REQUIRED sd_hash is calculated over the preceding KB-SD-JWT
	// and its associated disclosures."
	if want, err := SDHash(last.Raw, last.SDAlg()); err != nil {
		s.record(&s.Binding, err)
	} else if got, _ := kb.Payload["sd_hash"].(string); got != want {
		s.record(&s.Binding, fmt.Errorf("sd_hash does not match the final KB-SD-JWT and its Disclosures"))
	}
	s.record(&s.Other, bindingError(kb.Payload, opts))
	return s
}

// keyBindingClaimsError checks the claims that RFC 9901 §4.3 requires in a
// KB-JWT besides sd_hash.
func keyBindingClaimsError(payload map[string]any) error {
	if _, ok := jsonutil.GetFloat64(payload, "iat"); !ok {
		return fmt.Errorf("iat is missing or not a number")
	}
	for _, name := range []string{"aud", "nonce"} {
		if value, _ := payload[name].(string); value == "" {
			return fmt.Errorf("%s is missing or not a string", name)
		}
	}
	return nil
}

func bindingError(payload map[string]any, opts DelegationOptions) error {
	if aud, _ := payload["aud"].(string); opts.Audience != "" && aud != opts.Audience {
		return fmt.Errorf("aud is %q, expected %q", aud, opts.Audience)
	}
	if nonce, _ := payload["nonce"].(string); opts.Nonce != "" && nonce != opts.Nonce {
		return fmt.Errorf("nonce is %q, expected %q", nonce, opts.Nonce)
	}
	return nil
}

// confirmationKey reads cnf.jwk (RFC 7800 §3.2) from processed claims.
func confirmationKey(claims map[string]any) (crypto.PublicKey, error) {
	jwk := jsonutil.GetMap(jsonutil.GetMap(claims, "cnf"), "jwk")
	if jwk == nil {
		return nil, fmt.Errorf("has no cnf claim with a jwk")
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	key, err := keys.ParseJWK(encoded)
	if err != nil {
		return nil, fmt.Errorf("has an unreadable cnf key: %w", err)
	}
	return key, nil
}

func signedJWT(token *Token) string {
	return strings.SplitN(token.Raw, "~", 2)[0]
}

func verifySignature(token *Token, key crypto.PublicKey) error {
	alg := jsonutil.GetString(token.Header, "alg")
	if !isSupportedAlgorithm(alg) {
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
	if !jws.Valid(signedJWT(token), key) {
		return fmt.Errorf("%s", ErrSignatureInvalid)
	}
	return nil
}

// DelegatedPayload is one Delegate Payload Disclosure with the Disclosures of
// its selectively disclosable claims.
type DelegatedPayload struct {
	// Disclosure is the base64url encoding of [salt, Delegate Payload] (§5.1.3).
	Disclosure  string
	Disclosures []string
}

// KBSDJWT describes the KB-SD-JWT of a new delegation.
type KBSDJWT struct {
	// Type is TypeKBSDJWT or TypeKBSDJWTKB.
	Type string
	// SDAlg is the _sd_alg of the KB-SD-JWT. It hashes the Delegate Payload
	// Disclosures. Empty means sha-256.
	SDAlg string
	// IssuerJWTHash binds the KB-SD-JWT with issuer_jwt_hash. Without it,
	// sd_hash binds the KB-SD-JWT.
	IssuerJWTHash bool
	// Payloads become the elements of delegate_payload, one digest each.
	Payloads []DelegatedPayload
	// Claims are the other claims of the KB-SD-JWT, such as iat, aud and nonce.
	Claims map[string]any
}

// Delegate appends a KB-SD-JWT signed with key to preceding and returns the
// dSD-JWT (§5.1.1). preceding is an SD-JWT or dSD-JWT with its Disclosures and
// its trailing tilde. key is the cnf key of its last component.
func Delegate(preceding string, kb KBSDJWT, key *ecdsa.PrivateKey) (string, error) {
	if kb.Type != TypeKBSDJWT && kb.Type != TypeKBSDJWTKB {
		return "", fmt.Errorf("the KB-SD-JWT typ must be %q or %q", TypeKBSDJWT, TypeKBSDJWTKB)
	}
	if len(kb.Payloads) == 0 {
		return "", fmt.Errorf("a KB-SD-JWT needs a Delegate Payload Disclosure")
	}
	if !strings.HasSuffix(preceding, "~") || strings.HasSuffix(preceding, "~~") {
		return "", fmt.Errorf("preceding must end with exactly one tilde")
	}
	// The hash covers the last SD-JWT or KB-SD-JWT of preceding (§5.1.4).
	last := preceding[strings.LastIndex(preceding, "~~")+1:]
	last = strings.TrimPrefix(last, "~")
	lastJWT, err := parseJWT(strings.SplitN(last, "~", 2)[0])
	if err != nil {
		return "", fmt.Errorf("parsing the preceding JWT: %w", err)
	}
	claim, input := "sd_hash", last
	if kb.IssuerJWTHash {
		claim, input = "issuer_jwt_hash", lastJWT.Raw
	}
	hash, err := SDHash(input, SDAlgFromPayload(lastJWT.Payload))
	if err != nil {
		return "", err
	}

	sdAlg := kb.SDAlg
	if sdAlg == "" {
		sdAlg = defaultSDAlg
	}
	payload := maps.Clone(kb.Claims)
	if payload == nil {
		payload = map[string]any{}
	}
	payload[claim] = hash
	payload["_sd_alg"] = sdAlg
	digests := make([]any, 0, len(kb.Payloads))
	components := make([]string, 0, len(kb.Payloads))
	for _, delegated := range kb.Payloads {
		digest, err := computeDigest(delegated.Disclosure, sdAlg)
		if err != nil {
			return "", err
		}
		digests = append(digests, map[string]any{"...": digest})
		components = append(components, delegated.Disclosure)
		components = append(components, delegated.Disclosures...)
	}
	payload["delegate_payload"] = digests

	jwt, err := jws.Sign(map[string]any{"typ": kb.Type, "alg": jws.AlgES256}, payload, key)
	if err != nil {
		return "", fmt.Errorf("signing the KB-SD-JWT: %w", err)
	}
	return preceding + "~" + jwt + "~" + strings.Join(components, "~") + "~", nil
}

// DelegatePayloadInspection is the result of InspectDelegatePayload.
type DelegatePayloadInspection struct {
	// Claims is the Delegate Payload with its Disclosures applied.
	Claims map[string]any
	// MissingDigests are the digests in the Delegate Payload without a
	// Disclosure.
	MissingDigests []string
	// Unreferenced are the positions of the Disclosures without a digest in
	// the Delegate Payload.
	Unreferenced []int
}

// InspectDelegatePayload decodes a Delegate Payload Disclosure and matches it
// with disclosures under sdAlg. §5.1.3: "The delegate payload disclosure is an
// Array disclosure, which is the base64url encoding of [salt, JSON Object
// Payload]."
func InspectDelegatePayload(payloadDisclosure string, disclosures []string, sdAlg string) (*DelegatePayloadInspection, error) {
	disclosure, err := parseDisclosure(payloadDisclosure, sdAlg)
	if err != nil {
		return nil, fmt.Errorf("the delegate payload disclosure does not decode: %w", err)
	}
	payload, isObject := disclosure.Value.(map[string]any)
	if !disclosure.IsArrayEntry || !isObject {
		return nil, fmt.Errorf("the delegate payload disclosure must decode to [salt, JSON object]")
	}
	parsed := make([]Disclosure, 0, len(disclosures))
	referenced := map[string]bool{}
	collectDigests(payload, referenced)
	for i, raw := range disclosures {
		d, err := parseDisclosure(raw, sdAlg)
		if err != nil {
			return nil, fmt.Errorf("disclosure %d of the delegate payload does not decode: %w", i, err)
		}
		parsed = append(parsed, *d)
		collectDigests(d.Value, referenced)
	}
	inspection := &DelegatePayloadInspection{}
	for i, d := range parsed {
		if !referenced[d.Digest] {
			inspection.Unreferenced = append(inspection.Unreferenced, i)
		}
		delete(referenced, d.Digest)
	}
	inspection.MissingDigests = slices.Sorted(maps.Keys(referenced))
	inspection.Claims, _, err = processPayload(payload, parsed)
	return inspection, err
}
