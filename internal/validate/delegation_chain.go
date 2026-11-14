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

package validate

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

// The kinds of a ChainPart.
const (
	PartSDJWT   = "sd-jwt"
	PartKBSDJWT = "kb-sd-jwt"
	PartKBJWT   = "kb-jwt"
)

// FormatKBSDJWT is the Chain format of a KB-SD-JWT on its own.
const FormatKBSDJWT = "KB-SD-JWT"

// Chain is the result of each part of a Delegate SD-JWT
// (draft-ietf-oauth-delegate-sd-jwt-00) or of a KB-SD-JWT on its own.
type Chain struct {
	// Format is delegate.FormatDSDJWT, delegate.FormatDSDJWTKB or
	// FormatKBSDJWT.
	Format string
	// Parts are the signed parts in chain order.
	Parts []ChainPart
}

// Failed reports whether a part of the chain failed.
func (c *Chain) Failed() bool {
	for _, part := range c.Parts {
		if part.Failed() {
			return true
		}
	}
	return false
}

// ChainPart is one signed part of a Chain.
type ChainPart struct {
	// Kind is PartSDJWT, PartKBSDJWT or PartKBJWT.
	Kind  string
	Label string
	// Raw is the part as it appears in the chain, with the trailing tilde of
	// an SD-JWT or KB-SD-JWT.
	Raw string
	Typ string
	// Signer is the key the part must be signed with. It is nil for the
	// SD-JWT, which the issuer signs, and for a KB-SD-JWT without the part
	// before it.
	Signer *ChainKey
	// Delegate is the cnf key of the part. It is nil for the last part.
	Delegate *ChainKey
	// Expiry is the exp of the part. For a KB-SD-JWT it is the exp of the
	// Delegate Payload.
	Expiry *time.Time
	// Limits are the type of the SD-JWT, the Delegate Payload of a KB-SD-JWT
	// or the request of the Key Binding JWT.
	Limits    []delegatepayload.Limit
	Signature PartCheck
	// Binding is the hash over the part before. It is nil for the SD-JWT.
	Binding *PartCheck
	// Problem is the first failing check besides Signature and Binding.
	Problem string
	// Trusted is false from the first failing part on.
	Trusted bool
	// TrustDetail says which earlier part fails when the part is not trusted.
	TrustDetail string
}

// Failed reports whether a check of the part failed.
func (p ChainPart) Failed() bool {
	return p.Signature.Status == Fail || (p.Binding != nil && p.Binding.Status == Fail) || p.Problem != ""
}

// ChainKey is a cnf key of the chain. Letter is A for the first key that
// appears in the chain, B for the next and so on.
type ChainKey struct {
	Letter     string
	Thumbprint string
}

// PartCheck is one check of a ChainPart. Status is Pass, Fail or Skipped.
type PartCheck struct {
	Status string
	Detail string
}

// chainKeys gives each thumbprint its letter.
type chainKeys map[string]string

func (k chainKeys) key(thumbprint string) *ChainKey {
	if thumbprint == "" {
		return nil
	}
	letter, ok := k[thumbprint]
	if !ok {
		letter = string(rune('A' + len(k)))
		k[thumbprint] = letter
	}
	return &ChainKey{Letter: letter, Thumbprint: thumbprint}
}

// delegationChain builds the Chain of a Delegate SD-JWT. r is the result of
// its SD-JWT. report holds the results of the KB-SD-JWTs and the Key Binding
// JWT.
func delegationChain(c *delegate.Chain, report delegate.Report, r *Result) *Chain {
	keys := chainKeys{}
	credential := ChainPart{
		Kind:      PartSDJWT,
		Label:     "SD-JWT",
		Raw:       c.Credential.Raw,
		Typ:       headerTyp(c.Credential.Header),
		Delegate:  keys.key(delegatepayload.KeyThumbprint(c.Credential.ResolvedClaims)),
		Expiry:    expiry(c.Credential.ResolvedClaims),
		Signature: credentialSignature(r),
	}
	if vct, ok := c.Credential.ResolvedClaims["vct"].(string); ok {
		credential.Limits = []delegatepayload.Limit{{Name: "vct", Value: vct}}
	}
	if report.Credential != nil {
		credential.Problem = sentence(report.Credential.Error())
	}
	parts := []ChainPart{credential}
	for i, link := range c.Links {
		preceding := parts[len(parts)-1]
		part := ChainPart{
			Kind:     PartKBSDJWT,
			Label:    fmt.Sprintf("KB-SD-JWT %d", i+1),
			Raw:      link.Token.Raw,
			Typ:      headerTyp(link.Token.Header),
			Signer:   preceding.Delegate,
			Delegate: keys.key(delegatepayload.KeyThumbprint(link.Payload)),
			Expiry:   expiry(link.Payload),
			Limits:   delegatepayload.Limits(link.Payload),
		}
		part.setStep(report.Links[i], preceding, bindingClaim(link.Token.Payload))
		parts = append(parts, part)
	}
	if kb := c.KeyBindingJWT; kb != nil {
		preceding := parts[len(parts)-1]
		part := ChainPart{
			Kind:   PartKBJWT,
			Label:  "Key Binding JWT",
			Raw:    kb.Raw,
			Typ:    headerTyp(kb.Header),
			Signer: preceding.Delegate,
			Expiry: expiry(kb.Payload),
		}
		for _, name := range []string{"aud", "nonce"} {
			if value, ok := kb.Payload[name].(string); ok {
				part.Limits = append(part.Limits, delegatepayload.Limit{Name: name, Value: value})
			}
		}
		part.setStep(*report.KeyBinding, preceding, "sd_hash")
		parts = append(parts, part)
	}
	setTrust(parts)
	return &Chain{Format: c.Format(), Parts: parts}
}

// setStep fills the checks of a KB-SD-JWT or Key Binding JWT from its step.
// claim is the hash claim that binds the part to preceding.
func (p *ChainPart) setStep(step delegate.Step, preceding ChainPart, claim string) {
	p.Signature = PartCheck{Status: Pass, Detail: fmt.Sprintf("Signed with the %s of %s.", keyRole(preceding), partName(preceding))}
	if step.Signature != nil {
		p.Signature = PartCheck{Status: Fail, Detail: signatureFailure(step.Signature, preceding)}
	}
	p.Binding = &PartCheck{Status: Pass, Detail: fmt.Sprintf("The %s matches %s.", claim, partName(preceding))}
	if step.Binding != nil {
		p.Binding = &PartCheck{Status: Fail, Detail: sentence(step.Binding.Error())}
	}
	if step.Other != nil {
		p.Problem = sentence(step.Other.Error())
	}
}

// partName is the label of a part as it reads inside a sentence.
func partName(part ChainPart) string {
	if part.Kind == PartSDJWT {
		return "the SD-JWT"
	}
	return part.Label
}

func keyRole(part ChainPart) string {
	if part.Kind == PartSDJWT {
		return "holder key"
	}
	return "delegate key"
}

// signatureFailure explains a failed signature with the key the part before
// delegates to.
func signatureFailure(err error, preceding ChainPart) string {
	if preceding.Delegate == nil {
		return sentence(err.Error())
	}
	letter := preceding.Delegate.Letter
	return fmt.Sprintf("The signature does not match key %s. %s delegates to key %s.", letter, sentenceStart(partName(preceding)), letter)
}

// setTrust marks every part from the first failing part on as untrusted.
func setTrust(parts []ChainPart) {
	failing := ""
	for i := range parts {
		part := &parts[i]
		part.Trusted = failing == ""
		if failing != "" {
			part.TrustDetail = fmt.Sprintf("Not trusted because %s fails.", failing)
		}
		if failing == "" && part.Failed() {
			failing = partName(*part)
		}
	}
}

// credentialSignature takes the signature of the SD-JWT from the signature
// check of its result.
func credentialSignature(r *Result) PartCheck {
	check, ok := r.Find(CheckSignature)
	if !ok {
		return PartCheck{Status: Skipped}
	}
	status := check.Status
	if status != Pass && status != Fail {
		status = Skipped
	}
	return PartCheck{Status: status, Detail: sentence(check.Detail)}
}

// kbSDJWTChain is the Chain of a KB-SD-JWT on its own. Its signer and the
// hash over the part before it are in the part before it.
func kbSDJWTChain(token *sdjwt.Token) *Chain {
	payload := delegate.NewLink(token).Payload
	keys := chainKeys{}
	notChecked := PartCheck{Status: Skipped, Detail: "Checked with the whole chain."}
	part := ChainPart{
		Kind:      PartKBSDJWT,
		Label:     "KB-SD-JWT",
		Raw:       token.Raw,
		Typ:       headerTyp(token.Header),
		Delegate:  keys.key(delegatepayload.KeyThumbprint(payload)),
		Expiry:    expiry(payload),
		Limits:    delegatepayload.Limits(payload),
		Signature: notChecked,
		Binding:   &notChecked,
		Trusted:   true,
	}
	return &Chain{Format: FormatKBSDJWT, Parts: []ChainPart{part}}
}

func bindingClaim(payload map[string]any) string {
	if _, present := payload["sd_hash"]; present {
		return "sd_hash"
	}
	return "issuer_jwt_hash"
}

func headerTyp(header map[string]any) string {
	typ, _ := header["typ"].(string)
	return typ
}

func expiry(claims map[string]any) *time.Time {
	exp, ok := delegatepayload.Expiry(claims)
	if !ok {
		return nil
	}
	return &exp
}

func sentenceStart(text string) string {
	first, size := utf8.DecodeRuneInString(text)
	return string(unicode.ToUpper(first)) + text[size:]
}

// sentence starts an error text with a capital letter and ends it with a
// period.
func sentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return text
	}
	text = sentenceStart(text)
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	return text
}
