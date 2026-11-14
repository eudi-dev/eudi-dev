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

// Package delegate reads, verifies and creates a Delegate SD-JWT.
//
// It implements draft-ietf-oauth-delegate-sd-jwt-00. The draft is not final.
// The package follows later drafts. Its API can change in a minor release
// until the draft is final. Section numbers without a document name refer to
// the draft.
//
// Parse splits a dSD-JWT or dSD-JWT+KB. Verify runs the verifier steps of §6.
// Chain.VerifyWithoutBinding runs them without the binding to a request.
// Append adds a KB-SD-JWT to an SD-JWT or a dSD-JWT.
package delegate

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

// The typ values of §5.1.4.
const (
	// TypeKBSDJWT is the typ of a KB-SD-JWT that ends the chain.
	TypeKBSDJWT = "kb+sd-jwt"
	// TypeKBSDJWTKB is the typ of a KB-SD-JWT with a cnf claim in its Delegate
	// Payload. A Key Binding JWT or another KB-SD-JWT can follow it.
	TypeKBSDJWTKB = "kb-sd-jwt+kb"
)

// The format values of the delegate transaction data type (§7.1).
const (
	// FormatDSDJWT is a chain without a Key Binding JWT.
	FormatDSDJWT = "dSD-JWT"
	// FormatDSDJWTKB is a chain that ends with a Key Binding JWT.
	FormatDSDJWTKB = "dSD-JWT+KB"
)

// MaxLinks is the largest number of KB-SD-JWTs that Parse accepts. Each one
// costs a signature verification.
const MaxLinks = 4

// ErrOptionUnset reports Options without Audience, Nonce or MaxAge.
var ErrOptionUnset = errors.New("required option is not set")

// Chain is a dSD-JWT or dSD-JWT+KB in Compact Serialization (§5.1.1).
type Chain struct {
	// Credential is the initial SD-JWT with its Disclosures.
	Credential *sdjwt.Token
	// Links are the KB-SD-JWTs in chain order.
	Links []*Link
	// KeyBindingJWT is the Key Binding JWT of the Delegate Holder in a dSD-JWT+KB.
	// It is nil for a dSD-JWT.
	KeyBindingJWT *sdjwt.JWT
}

// Link is one KB-SD-JWT with its Disclosures.
type Link struct {
	// Token holds the KB-SD-JWT header and payload and the Disclosures after it.
	Token *sdjwt.Token
	// Payload is the processed Delegate Payload. It is nil unless
	// delegate_payload has exactly 1 disclosed element and that element is a
	// JSON object.
	Payload map[string]any
}

// Format is FormatDSDJWTKB when a Key Binding JWT of the Delegate Holder ends
// the chain, else FormatDSDJWT.
func (c *Chain) Format() string {
	if c.KeyBindingJWT != nil {
		return FormatDSDJWTKB
	}
	return FormatDSDJWT
}

// IsChain reports whether raw is a Delegate SD-JWT: the first component after
// an empty component is a JWT with the typ of a KB-SD-JWT (§5.1.4). An SD-JWT
// has no empty component (RFC 9901 §4), so a malformed SD-JWT with one is not
// a chain.
func IsChain(raw string) bool {
	_, rest, found := strings.Cut(strings.TrimSpace(raw), "~~")
	if !found {
		return false
	}
	link, _, _ := strings.Cut(strings.TrimLeft(rest, "~"), "~")
	header, _, _, err := format.ParseJWTParts(link)
	if err != nil {
		return false
	}
	typ, _ := header["typ"].(string)
	return typ == TypeKBSDJWT || typ == TypeKBSDJWTKB
}

// Parse splits a dSD-JWT or dSD-JWT+KB and decodes its components (§6 step 1).
// It checks no signature and no hash. It rejects a chain with more than
// MaxLinks KB-SD-JWTs.
func Parse(raw string) (*Chain, error) {
	components := strings.Split(strings.TrimSpace(raw), "~")
	// §5.1.1: "dSD-JWT+KB and dSD-JWT formats are differentiated by a trailing
	// ~ for dSD-JWT."
	last := components[len(components)-1]
	segments, err := chainSegments(components[:len(components)-1])
	if err != nil {
		return nil, err
	}
	if links := len(segments) - 1; links > MaxLinks {
		return nil, fmt.Errorf("invalid Delegate SD-JWT: it has %d KB-SD-JWTs, but at most %d are accepted", links, MaxLinks)
	}
	c := &Chain{}
	if last != "" {
		header, payload, signature, err := format.ParseJWTParts(last)
		if err != nil {
			return nil, fmt.Errorf("the component after the last tilde is not a Key Binding JWT: %w", err)
		}
		c.KeyBindingJWT = &sdjwt.JWT{Raw: last, Header: header, Payload: payload, Signature: signature}
	}
	c.Credential, err = sdjwt.ParseLenient(segments[0])
	if err != nil {
		return nil, fmt.Errorf("SD-JWT: %w", err)
	}
	for i, segment := range segments[1:] {
		token, err := sdjwt.ParseLenient(segment)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", linkLabel(i), err)
		}
		c.Links = append(c.Links, NewLink(token))
	}
	return c, nil
}

// chainSegments groups the components before the last tilde into the SD-JWT
// and the KB-SD-JWTs. Each segment keeps its trailing tilde. sd_hash covers
// the segment with that tilde (RFC 9901 §4.3.1).
//
// §5.1.1: "The resulting array of components MUST have exactly one empty
// component between the last component of each SD-JWT or KB-SD-JWT and the
// following KB-SD-JWT."
func chainSegments(components []string) ([]string, error) {
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

// NewLink reads the Delegate Payload of a parsed KB-SD-JWT.
func NewLink(token *sdjwt.Token) *Link {
	return &Link{Token: token, Payload: disclosedDelegatePayload(token)}
}

func disclosedDelegatePayload(token *sdjwt.Token) map[string]any {
	disclosed, _ := token.ResolvedClaims["delegate_payload"].([]any)
	if len(disclosed) != 1 {
		return nil
	}
	payload, _ := disclosed[0].(map[string]any)
	return payload
}

// Options are the expectations of the verifier. Audience, Nonce and MaxAge
// bind the last signed component to a request (RFC 9901 §7.3 steps 5.e and
// 5.f). That component is the Key Binding JWT of the Delegate Holder in a
// dSD-JWT+KB and the final KB-SD-JWT of a dSD-JWT. Verify fails with
// ErrOptionUnset when one of them is not set.
type Options struct {
	// Now is the verification time. The zero value means the current time.
	Now time.Time
	// Audience is the expected aud claim. It is required.
	Audience string
	// Nonce is the nonce of the verifier's request. It is required.
	Nonce string
	// MaxAge is the maximum age, measured from the iat claim. It is required. A
	// clock skew of 1 minute is added on both sides.
	MaxAge time.Duration
	// RequireKeyBinding rejects a dSD-JWT (§6 step 5.1).
	RequireKeyBinding bool
}

// Verify runs steps 1 to 5 of §6 on a dSD-JWT or dSD-JWT+KB. issuerKey
// verifies the Issuer-signed JWT. The caller decides whether it trusts that
// key. Step 5.1 runs only when opts.RequireKeyBinding is set. Steps 5.2 and
// 5.3 run for every dSD-JWT+KB.
func Verify(raw string, issuerKey crypto.PublicKey, opts Options) (*Chain, error) {
	if err := opts.bindingSet(); err != nil {
		return nil, err
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := sdjwt.Verify(c.Credential, issuerKey); err != nil {
		return nil, fmt.Errorf("SD-JWT: %w", err)
	}
	if err := c.Verify(opts); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify runs steps 3 to 5 of §6. It also runs part of step 2: the checks of
// the Disclosures and of the validity period of the initial SD-JWT (RFC 9901
// §7.1 steps 3 to 6). It does not verify the signature of the Issuer-signed
// JWT. The cnf keys of the chain are authentic only when the caller verified
// that signature.
func (c *Chain) Verify(opts Options) error {
	if err := opts.bindingSet(); err != nil {
		return err
	}
	return c.verify(opts, true)
}

// VerifyWithoutBinding runs the checks of Verify except the binding to a
// request. It ignores opts.Audience, opts.Nonce and opts.MaxAge. A tool that
// inspects a chain outside a presentation uses it. A verifier uses Verify.
func (c *Chain) VerifyWithoutBinding(opts Options) error {
	return c.verify(opts, false)
}

func (opts Options) bindingSet() error {
	for _, option := range []struct {
		name string
		set  bool
	}{
		{"Audience", opts.Audience != ""},
		{"Nonce", opts.Nonce != ""},
		{"MaxAge", opts.MaxAge > 0},
	} {
		if !option.set {
			return fmt.Errorf("%w: %s", ErrOptionUnset, option.name)
		}
	}
	return nil
}

func (c *Chain) verify(opts Options, bound bool) error {
	// §6 step 5.1: "If the credential is a dSD-JWT (without Key Binding), the
	// Verifier MUST reject the presentation".
	if opts.RequireKeyBinding && c.KeyBindingJWT == nil {
		return fmt.Errorf("the presentation is a dSD-JWT, but Key Binding is required")
	}
	return c.report(opts, bound).Err()
}

// Report is the result of each component of a chain. Chain.Inspect returns
// it.
type Report struct {
	// Credential is the first error of the checks of the Disclosures and the
	// validity period of the SD-JWT.
	Credential error
	// Links has one Step for each KB-SD-JWT, in chain order.
	Links []Step
	// KeyBinding is the Step of the Key Binding JWT of the Delegate Holder. It
	// is nil for a dSD-JWT.
	KeyBinding *Step
}

// Step is the result of one KB-SD-JWT or Key Binding JWT. Each error is nil
// when its check passes.
type Step struct {
	// Signature reports the signature with the cnf key of the preceding
	// component (§6 step 3.1).
	Signature error
	// Binding reports the sd_hash or issuer_jwt_hash over the preceding
	// component (§6 steps 3.3 and 3.4).
	Binding error
	// Other is the first error of the other checks, such as the typ and the
	// claims.
	Other error
	// first is the error that Verify reports for the step.
	first error
}

func (s *Step) record(field *error, err error) {
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
func (s Step) Failed() bool {
	return s.first != nil
}

// Err is the first error in chain order, the error that VerifyWithoutBinding
// returns.
func (r Report) Err() error {
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

// Inspect runs the checks of VerifyWithoutBinding and reports each component
// on its own. A step after a failing step is still checked.
func (c *Chain) Inspect(opts Options) Report {
	return c.report(opts, false)
}

func (c *Chain) report(opts Options, bound bool) Report {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := Report{Credential: processedError(c.Credential, c.Credential.ResolvedClaims, now)}
	preceding, precedingClaims := c.Credential, c.Credential.ResolvedClaims
	for i, link := range c.Links {
		// §6 steps 3.5 and 4.2 allow the typ kb+sd-jwt only for the final
		// KB-SD-JWT of a dSD-JWT.
		final := i == len(c.Links)-1 && c.KeyBindingJWT == nil
		step := link.check(preceding, precedingClaims, final, now)
		if final {
			step.record(&step.Other, lastComponentError(link.Token.Payload, opts, bound, now))
		}
		r.Links = append(r.Links, step)
		preceding, precedingClaims = link.Token, link.Payload
	}
	if c.KeyBindingJWT != nil {
		step := c.checkKeyBinding(preceding, precedingClaims, opts, bound, now)
		r.KeyBinding = &step
	}
	return r
}

// check runs §6 steps 3.1 to 3.5 on one KB-SD-JWT. preceding is the SD-JWT or
// KB-SD-JWT before it, and precedingClaims are its processed claims.
func (l *Link) check(preceding *sdjwt.Token, precedingClaims map[string]any, final bool, now time.Time) Step {
	var s Step
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
		s.record(&s.Signature, fmt.Errorf("the preceding component has %w", err))
	} else {
		s.record(&s.Signature, sdjwt.Verify(l.Token, key))
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
			s.record(&s.Other, fmt.Errorf("the typ is %q, but the Delegate Payload has %w", TypeKBSDJWTKB, err))
		}
	}
	return s
}

// delegatePayloadError checks delegate_payload against §5.1.4 and §6 step 3.2.
func (l *Link) delegatePayloadError() error {
	elements, ok := l.Token.Payload["delegate_payload"].([]any)
	if !ok || len(elements) == 0 {
		return fmt.Errorf("delegate_payload must be a non-empty array")
	}
	// §5.1.4: "If it contains more than one element then they MUST all be
	// replaced with disclosures."
	if len(elements) > 1 {
		for i, element := range elements {
			if !isDigestPlaceholder(element) {
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

// isDigestPlaceholder reports whether an array element has the form
// {"...": "<digest>"} of RFC 9901 §4.2.4.2.
func isDigestPlaceholder(element any) bool {
	object, _ := element.(map[string]any)
	_, isString := object["..."].(string)
	return isString && len(object) == 1
}

// processedError reports what RFC 9901 §7.1 rejects in a processed SD-JWT or
// KB-SD-JWT: a deviation in its Disclosures and a time claim that makes it
// invalid now. claims is separate from token because §6 step 3.1 takes the
// claims of a KB-SD-JWT from its Delegate Payload.
func processedError(token *sdjwt.Token, claims map[string]any, now time.Time) error {
	if len(token.Deviations) > 0 {
		return fmt.Errorf("%s", strings.Join(token.Deviations, ". "))
	}
	return (&sdjwt.Token{ResolvedClaims: claims}).ValidAt(now)
}

// confirmationKey reads the cnf key of processed claims.
func confirmationKey(claims map[string]any) (crypto.PublicKey, error) {
	return (&sdjwt.Token{ResolvedClaims: claims}).ConfirmationKey()
}

func signedJWT(token *sdjwt.Token) string {
	jwt, _, _ := strings.Cut(token.Raw, "~")
	return jwt
}

// precedingHashError checks the binding of a KB-SD-JWT to the component
// before it (§6 steps 3.3 and 3.4). §5.1.4: "Both sd_hash and issuer_jwt_hash
// use the hash algorithm of the preceding Issuer-signed JWT or KB-SD-JWT+KB".
func precedingHashError(payload map[string]any, preceding *sdjwt.Token) error {
	claim, input := "sd_hash", preceding.Raw
	if _, present := payload["sd_hash"]; !present {
		// §5.1.4: issuer_jwt_hash "hashes over only the preceding Issuer-signed
		// jwt or KB-SD-JWT+KB and not any disclosures".
		claim, input = "issuer_jwt_hash", signedJWT(preceding)
		if _, present := payload[claim]; !present {
			return fmt.Errorf("neither sd_hash nor issuer_jwt_hash is present")
		}
	}
	want, err := sdjwt.SDHash(input, preceding.SDAlg())
	if err != nil {
		return err
	}
	got, _ := payload[claim].(string)
	switch {
	case got == want:
		return nil
	case claim == "sd_hash":
		return fmt.Errorf("%w the preceding component", sdjwt.ErrSDHash)
	default:
		return fmt.Errorf("%s does not match the preceding component", claim)
	}
}

// checkKeyBinding checks the Key Binding JWT of the Delegate Holder (§6 steps
// 5.2 and 5.3). last is the final KB-SD-JWT and delegatePayload its Delegate
// Payload.
func (c *Chain) checkKeyBinding(last *sdjwt.Token, delegatePayload map[string]any, opts Options, bound bool, now time.Time) Step {
	var s Step
	kb := c.KeyBindingJWT
	if typ, _ := kb.Header["typ"].(string); !format.JOSETypeIs(typ, sdjwt.TypeKeyBinding) {
		s.record(&s.Other, fmt.Errorf("typ is %q, expected %q", typ, sdjwt.TypeKeyBinding))
	}
	if key, err := confirmationKey(delegatePayload); err != nil {
		s.record(&s.Signature, fmt.Errorf("the final Delegate Payload has %w", err))
	} else {
		s.record(&s.Signature, sdjwt.Verify(&sdjwt.Token{Raw: kb.Raw, Header: kb.Header}, key))
	}
	s.record(&s.Other, keyBindingClaimsError(kb.Payload))
	// §5.1.3: "the REQUIRED sd_hash is calculated over the preceding KB-SD-JWT
	// and its associated disclosures."
	if want, err := sdjwt.SDHash(last.Raw, last.SDAlg()); err != nil {
		s.record(&s.Binding, err)
	} else if got, _ := kb.Payload["sd_hash"].(string); got != want {
		s.record(&s.Binding, fmt.Errorf("%w the final KB-SD-JWT and its Disclosures", sdjwt.ErrSDHash))
	}
	s.record(&s.Other, lastComponentError(kb.Payload, opts, bound, now))
	return s
}

// lastComponentError checks the last signed component. bound adds the
// binding to the request in opts.
func lastComponentError(payload map[string]any, opts Options, bound bool, now time.Time) error {
	if bound {
		if err := bindingError(payload, opts, now); err != nil {
			return err
		}
	}
	// RFC 9901 §7.3 step 5.h.
	return (&sdjwt.Token{ResolvedClaims: payload}).ValidAt(now)
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

// bindingError compares the last signed component with the expectations in
// opts.
func bindingError(payload map[string]any, opts Options, now time.Time) error {
	seconds, _ := jsonutil.GetFloat64(payload, "iat")
	if seconds < 0 || seconds > delegatepayload.MaxNumericDate {
		return fmt.Errorf("iat is not a NumericDate")
	}
	iat := time.Unix(int64(seconds), 0)
	if validity.NotYet(&iat, now) {
		return fmt.Errorf("iat %s is in the future", iat.UTC().Format(time.RFC3339))
	}
	if oldest := iat.Add(opts.MaxAge); validity.Expired(&oldest, now) {
		return fmt.Errorf("iat %s is older than %s", iat.UTC().Format(time.RFC3339), opts.MaxAge)
	}
	if aud, _ := payload["aud"].(string); aud != opts.Audience {
		return fmt.Errorf("%w: got %q, expected %q", sdjwt.ErrAudience, aud, opts.Audience)
	}
	if nonce, _ := payload["nonce"].(string); nonce != opts.Nonce {
		return fmt.Errorf("%w: got %q, expected %q", sdjwt.ErrNonce, nonce, opts.Nonce)
	}
	return nil
}

// PayloadDisclosure is one Delegate Payload Disclosure with the Disclosures of
// its selectively disclosable claims.
type PayloadDisclosure struct {
	// Disclosure is the base64url encoding of [salt, Delegate Payload] (§5.1.3).
	Disclosure string
	// Disclosures are the Disclosures of the claims inside the Delegate Payload.
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
	Payloads []PayloadDisclosure
	// Claims are the other claims of the KB-SD-JWT, such as iat, aud and nonce.
	Claims map[string]any
}

// Append adds a KB-SD-JWT signed with key to preceding and returns the dSD-JWT
// (§5.1.1). preceding is an SD-JWT or dSD-JWT with its Disclosures and its
// trailing tilde. key is the private key that matches the cnf key in the last
// component of preceding.
func Append(preceding string, kb KBSDJWT, key *ecdsa.PrivateKey) (string, error) {
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
	lastJWT, _, _ := strings.Cut(last, "~")
	_, lastPayload, _, err := format.ParseJWTParts(lastJWT)
	if err != nil {
		return "", fmt.Errorf("parsing the preceding JWT: %w", err)
	}
	claim, input := "sd_hash", last
	if kb.IssuerJWTHash {
		claim, input = "issuer_jwt_hash", lastJWT
	}
	hash, err := sdjwt.SDHash(input, sdjwt.SDAlgFromPayload(lastPayload))
	if err != nil {
		return "", err
	}

	sdAlg := kb.SDAlg
	if sdAlg == "" {
		sdAlg = sdjwt.SDAlgFromPayload(nil)
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
		digest, err := sdjwt.SDHash(delegated.Disclosure, sdAlg)
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
