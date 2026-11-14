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

package delegate

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

var delegationNow = time.Unix(1794571200, 0)

// delegationFixture builds the parts of a chain: an Issuer, a Holder, an
// agent as first Delegate Holder and a sub-agent as second.
type delegationFixture struct {
	t                              *testing.T
	issuer, holder, agent, subject *ecdsa.PrivateKey
	salts                          int
}

func newDelegationFixture(t *testing.T) *delegationFixture {
	t.Helper()
	f := &delegationFixture{t: t}
	for _, key := range []**ecdsa.PrivateKey{&f.issuer, &f.holder, &f.agent, &f.subject} {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		*key = generated
	}
	return f
}

func (f *delegationFixture) disclosure(parts ...any) string {
	f.t.Helper()
	f.salts++
	encoded, err := json.Marshal(append([]any{fmt.Sprintf("salt-%d", f.salts)}, parts...))
	if err != nil {
		f.t.Fatal(err)
	}
	return format.EncodeBase64URL(encoded)
}

func (f *delegationFixture) digest(disclosure, sdAlg string) string {
	f.t.Helper()
	digest, err := sdjwt.SDHash(disclosure, sdAlg)
	if err != nil {
		f.t.Fatal(err)
	}
	return digest
}

func (f *delegationFixture) cnf(key *ecdsa.PrivateKey) map[string]any {
	f.t.Helper()
	jwk, err := keys.PublicJWK(&key.PublicKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return map[string]any{"jwk": jwk}
}

func (f *delegationFixture) sign(typ string, payload map[string]any, key *ecdsa.PrivateKey) string {
	f.t.Helper()
	jwt, err := jws.Sign(map[string]any{"typ": typ, "alg": jws.AlgES256}, payload, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return jwt
}

// credential is an SD-JWT VC bound to the Holder key with one disclosed claim.
// It ends with a tilde. change edits the payload before signing.
func (f *delegationFixture) credential(sdAlg string, change func(payload map[string]any)) string {
	f.t.Helper()
	name := f.disclosure("given_name", "Erika")
	payload := map[string]any{
		"iss": "https://issuer.example", "vct": "urn:example:authority:1", "_sd_alg": sdAlg,
		"exp": delegationNow.Add(time.Hour).Unix(), "cnf": f.cnf(f.holder),
		"_sd": []any{f.digest(name, sdAlg)},
	}
	if change != nil {
		change(payload)
	}
	return f.sign("dc+sd-jwt", payload, f.issuer) + "~" + name + "~"
}

// linkSpec describes one KB-SD-JWT of a test chain.
type linkSpec struct {
	typ    string
	sdAlg  string
	signer *ecdsa.PrivateKey
	// delegate is the key in the cnf of the Delegate Payload. Nil leaves cnf out.
	delegate *ecdsa.PrivateKey
	// changePayload edits the Delegate Payload before it is disclosed.
	changePayload func(payload map[string]any)
	// change edits the KB-SD-JWT payload before signing. disclosures are the
	// components after the JWT.
	change func(payload map[string]any, disclosures *[]string)
}

// link is a KB-SD-JWT over preceding with one Delegate Payload and one
// selectively disclosable audience. It ends with a tilde.
func (f *delegationFixture) link(preceding string, spec linkSpec) string {
	f.t.Helper()
	if spec.sdAlg == "" {
		spec.sdAlg = "sha-256"
	}
	audience := f.disclosure("https://verifier.example")
	delegatePayload := map[string]any{
		"vct": "urn:example:mandate:1", "exp": delegationNow.Add(time.Hour).Unix(),
		"audiences": []any{map[string]any{"...": f.digest(audience, spec.sdAlg)}},
	}
	if spec.delegate != nil {
		delegatePayload["cnf"] = f.cnf(spec.delegate)
	}
	if spec.changePayload != nil {
		spec.changePayload(delegatePayload)
	}
	payloadDisclosure := f.disclosure(delegatePayload)
	token, err := sdjwt.ParseLenient(preceding)
	if err != nil {
		f.t.Fatal(err)
	}
	payload := map[string]any{
		"iat": delegationNow.Unix(), "aud": "https://agent.example", "nonce": "n-1",
		"sd_hash": f.digest(preceding, token.SDAlg()), "_sd_alg": spec.sdAlg,
		"delegate_payload": []any{map[string]any{"...": f.digest(payloadDisclosure, spec.sdAlg)}},
	}
	disclosures := []string{payloadDisclosure, audience}
	if spec.change != nil {
		spec.change(payload, &disclosures)
	}
	return f.sign(spec.typ, payload, spec.signer) + "~" + strings.Join(disclosures, "~") + "~"
}

// keyBinding is the Key Binding JWT of the Delegate Holder over link.
func (f *delegationFixture) keyBinding(link string, key *ecdsa.PrivateKey, change func(payload map[string]any)) string {
	f.t.Helper()
	token, err := sdjwt.ParseLenient(link)
	if err != nil {
		f.t.Fatal(err)
	}
	payload := map[string]any{
		"iat": delegationNow.Unix(), "aud": "https://verifier.example", "nonce": "n-2",
		"sd_hash": f.digest(link, token.SDAlg()),
	}
	if change != nil {
		change(payload)
	}
	return f.sign(sdjwt.TypeKeyBinding, payload, key)
}

// chain joins the SD-JWT, the KB-SD-JWTs and the optional KB-JWT (§5.1.1).
func chain(kbJWT string, segments ...string) string {
	return strings.Join(segments, "~") + kbJWT
}

// bound fills each unset option in opts with the audience and nonce of raw and
// a MaxAge of 5 minutes. It always sets Now. The final KB-SD-JWT of a dSD-JWT
// is for the agent, and the Key Binding JWT of the Delegate Holder in a
// dSD-JWT+KB is for the verifier.
func bound(raw string, opts Options) Options {
	audience, nonce := "https://verifier.example", "n-2"
	if strings.HasSuffix(raw, "~") {
		audience, nonce = "https://agent.example", "n-1"
	}
	opts.Now = delegationNow
	opts.Audience = cmp.Or(opts.Audience, audience)
	opts.Nonce = cmp.Or(opts.Nonce, nonce)
	opts.MaxAge = cmp.Or(opts.MaxAge, 5*time.Minute)
	return opts
}

func TestVerifyAcceptsValidChains(t *testing.T) {
	tests := []struct {
		name      string
		build     func(f *delegationFixture) string
		opts      Options
		wantLinks int
		wantKB    bool
	}{
		{
			name: "dSD-JWT with typ kb+sd-jwt",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				return chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder}))
			},
			wantLinks: 1,
		},
		{
			name: "dSD-JWT with typ kb-sd-jwt+kb",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				return chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent}))
			},
			wantLinks: 1,
		},
		{
			name: "dSD-JWT+KB",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
				return chain(f.keyBinding(link, f.agent, nil), credential, link)
			},
			opts:      Options{RequireKeyBinding: true},
			wantLinks: 1,
			wantKB:    true,
		},
		{
			name: "dSD-JWT+KB with two delegations",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				first := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
				second := f.link(first, linkSpec{typ: TypeKBSDJWTKB, signer: f.agent, delegate: f.subject})
				return chain(f.keyBinding(second, f.subject, nil), credential, first, second)
			},
			opts:      Options{RequireKeyBinding: true},
			wantLinks: 2,
			wantKB:    true,
		},
		{
			// §5.1.4: sd_hash uses the hash algorithm of the preceding component.
			name: "each component with its own _sd_alg",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-384", nil)
				link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, sdAlg: "sha-512", signer: f.holder, delegate: f.agent})
				return chain(f.keyBinding(link, f.agent, nil), credential, link)
			},
			wantLinks: 1,
			wantKB:    true,
		},
		{
			name: "issuer_jwt_hash instead of sd_hash",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-384", nil)
				link := f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder, change: func(payload map[string]any, _ *[]string) {
					delete(payload, "sd_hash")
					payload["issuer_jwt_hash"] = f.digest(strings.SplitN(credential, "~", 2)[0], "sha-384")
				}})
				return chain("", credential, link)
			},
			wantLinks: 1,
		},
		{
			// §5.1.4 requires Disclosures only for more than one element.
			name: "single Delegate Payload in the clear",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				link := f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder, change: func(payload map[string]any, disclosures *[]string) {
					payload["delegate_payload"] = []any{map[string]any{"vct": "urn:example:mandate:1"}}
					*disclosures = nil
				}})
				return chain("", credential, strings.TrimSuffix(link, "~"))
			},
			wantLinks: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newDelegationFixture(t)
			raw := tt.build(f)
			d, err := Verify(raw, &f.issuer.PublicKey, bound(raw, tt.opts))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(d.Links) != tt.wantLinks || (d.KeyBindingJWT != nil) != tt.wantKB {
				t.Fatalf("got %d links and KB-JWT %t, want %d and %t", len(d.Links), d.KeyBindingJWT != nil, tt.wantLinks, tt.wantKB)
			}
			if got := d.Credential.ResolvedClaims["given_name"]; got != "Erika" {
				t.Errorf("credential given_name = %v, want Erika", got)
			}
			for i, link := range d.Links {
				if got := link.Payload["vct"]; got != "urn:example:mandate:1" {
					t.Errorf("delegate payload %d vct = %v", i, got)
				}
			}
		})
	}
}

func TestVerifyReturnsProcessedPayloads(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
	raw := chain(f.keyBinding(link, f.agent, nil), credential, link)
	d, err := Verify(raw, &f.issuer.PublicKey, bound(raw, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Format() != FormatDSDJWTKB {
		t.Errorf("Format() = %q, want %q", d.Format(), FormatDSDJWTKB)
	}
	payload := d.Links[0].Payload
	if got, want := payload["audiences"], []any{"https://verifier.example"}; !reflect.DeepEqual(got, want) {
		t.Errorf("audiences = %v, want %v", got, want)
	}
	if got, want := payload["cnf"], f.cnf(f.agent); !reflect.DeepEqual(got, want) {
		t.Errorf("cnf = %v, want %v", got, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	// base builds a valid single-hop chain from its three parts.
	type parts struct {
		credential, link, kbJWT string
	}
	valid := func(f *delegationFixture) parts {
		credential := f.credential("sha-256", nil)
		link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
		return parts{credential, link, f.keyBinding(link, f.agent, nil)}
	}
	withLink := func(spec linkSpec, withKB bool) func(f *delegationFixture) string {
		return func(f *delegationFixture) string {
			credential := f.credential("sha-256", nil)
			if spec.signer == nil {
				spec.signer = f.holder
			}
			if spec.typ == "" {
				spec.typ = TypeKBSDJWTKB
				spec.delegate = f.agent
			}
			link := f.link(credential, spec)
			if !withKB {
				return chain("", credential, link)
			}
			return chain(f.keyBinding(link, f.agent, nil), credential, link)
		}
	}
	tests := []struct {
		name    string
		build   func(f *delegationFixture) string
		opts    Options
		wantErr string
		wantIs  error
	}{
		// §6 step 1 and §5.1.1.
		{
			name: "two empty components between SD-JWT and KB-SD-JWT",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return p.credential + "~~" + p.link
			},
			wantErr: "more than one empty component",
		},
		{
			name: "no empty component",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return p.credential + p.link
			},
			wantErr: "no empty component separates",
		},
		{
			name: "empty component before the Key Binding JWT of the Delegate Holder",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return p.credential + "~" + p.link + "~" + p.kbJWT
			},
			wantErr: "no KB-SD-JWT follows the last empty component",
		},
		{
			name: "last component is not a JWT",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return strings.TrimSuffix(chain("", p.credential, p.link), "~")
			},
			wantErr: "not a Key Binding JWT",
		},
		// §6 step 2.
		{
			name: "Issuer-signed JWT signed with another key",
			build: func(f *delegationFixture) string {
				p := valid(f)
				f.issuer = f.subject
				return chain(p.kbJWT, p.credential, p.link)
			},
			wantErr: "SD-JWT: " + sdjwt.ErrSignature.Error(),
		},
		{
			name: "expired credential",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", func(payload map[string]any) { payload["exp"] = delegationNow.Add(-time.Hour).Unix() })
				return chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder}))
			},
			wantErr: "SD-JWT: expired",
		},
		{
			name: "credential Disclosure without a digest",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil) + f.disclosure("family_name", "Mustermann") + "~"
				return chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder}))
			},
			wantErr: "not referenced by any digest",
		},
		// §6 step 3.1.
		{
			name:    "KB-SD-JWT signed with a key other than the cnf key",
			build:   func(f *delegationFixture) string { return withLink(linkSpec{signer: f.agent}, true)(f) },
			wantErr: "KB-SD-JWT 1: " + sdjwt.ErrSignature.Error(),
		},
		{
			name: "credential without cnf",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", func(payload map[string]any) { delete(payload, "cnf") })
				return chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder}))
			},
			wantErr: "the preceding component has no cnf claim",
		},
		{
			name: "delegate Disclosure without a digest",
			build: withLink(linkSpec{change: func(_ map[string]any, disclosures *[]string) {
				*disclosures = append(*disclosures, format.EncodeBase64URL([]byte(`["s","extra"]`)))
			}}, true),
			wantErr: "not referenced by any digest",
		},
		{
			name:    "KB-SD-JWT without nonce",
			build:   withLink(linkSpec{change: func(payload map[string]any, _ *[]string) { delete(payload, "nonce") }}, true),
			wantErr: "nonce is missing",
		},
		{
			name:    "KB-SD-JWT without iat",
			build:   withLink(linkSpec{change: func(payload map[string]any, _ *[]string) { delete(payload, "iat") }}, true),
			wantErr: "iat is missing",
		},
		{
			name: "expired Delegate Payload",
			build: withLink(linkSpec{changePayload: func(payload map[string]any) {
				payload["exp"] = delegationNow.Add(-time.Hour).Unix()
			}}, true),
			wantErr: "KB-SD-JWT 1: expired",
		},
		// §6 step 3.2 and §5.1.4.
		{
			name: "two disclosed Delegate Payloads",
			build: func(f *delegationFixture) string {
				second := f.disclosure(map[string]any{"vct": "urn:example:mandate:2", "cnf": f.cnf(f.agent)})
				return withLink(linkSpec{change: func(payload map[string]any, disclosures *[]string) {
					payload["delegate_payload"] = append(payload["delegate_payload"].([]any), map[string]any{"...": f.digest(second, "sha-256")})
					*disclosures = append(*disclosures, second)
				}}, true)(f)
			},
			wantErr: "delegate_payload has 2 disclosed elements",
		},
		{
			name: "no disclosed Delegate Payload",
			build: withLink(linkSpec{change: func(payload map[string]any, _ *[]string) {
				payload["delegate_payload"] = []any{map[string]any{"...": "ZGVjb3k"}}
			}}, true),
			wantErr: "delegate_payload has 0 disclosed elements",
		},
		{
			name: "two elements and one in the clear",
			build: withLink(linkSpec{change: func(payload map[string]any, _ *[]string) {
				payload["delegate_payload"] = append(payload["delegate_payload"].([]any), map[string]any{"vct": "urn:example:mandate:2"})
			}}, true),
			wantErr: "element 1 is not a digest of a Disclosure",
		},
		{
			name: "Delegate Payload is not an object",
			build: func(f *delegationFixture) string {
				text := f.disclosure("mandate")
				return withLink(linkSpec{typ: TypeKBSDJWT, change: func(payload map[string]any, disclosures *[]string) {
					payload["delegate_payload"] = []any{map[string]any{"...": f.digest(text, "sha-256")}}
					*disclosures = []string{text}
				}}, false)(f)
			},
			wantErr: "not a JSON object",
		},
		// §6 steps 3.3 and 3.4, §8.1.
		{
			// §8.1: "a malicious Delegate Holder may mis-match parts of the
			// chain if the Holder cnf is reused."
			name: "KB-SD-JWT of another credential with the same cnf key",
			build: func(f *delegationFixture) string {
				p := valid(f)
				other := f.credential("sha-256", func(payload map[string]any) { payload["vct"] = "urn:example:other:1" })
				return chain(p.kbJWT, other, p.link)
			},
			wantErr: "sd_hash does not match the preceding component",
		},
		{
			name: "credential Disclosure withheld after delegation",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return chain(p.kbJWT, strings.SplitN(p.credential, "~", 2)[0]+"~", p.link)
			},
			wantErr: "sd_hash does not match the preceding component",
		},
		{
			name: "issuer_jwt_hash of another JWT",
			build: withLink(linkSpec{change: func(payload map[string]any, _ *[]string) {
				delete(payload, "sd_hash")
				payload["issuer_jwt_hash"] = "bm90IHRoZSBoYXNo"
			}}, true),
			wantErr: "issuer_jwt_hash does not match the preceding component",
		},
		{
			name:    "neither sd_hash nor issuer_jwt_hash",
			build:   withLink(linkSpec{change: func(payload map[string]any, _ *[]string) { delete(payload, "sd_hash") }}, true),
			wantErr: "neither sd_hash nor issuer_jwt_hash is present",
		},
		// §6 steps 3.5 and 4.2, §5.1.4.
		{
			name: "typ kb+sd-jwt before another KB-SD-JWT",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				first := f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder, delegate: f.agent})
				second := f.link(first, linkSpec{typ: TypeKBSDJWT, signer: f.agent})
				return chain("", credential, first, second)
			},
			wantErr: `KB-SD-JWT 1: typ is "kb+sd-jwt"`,
		},
		{
			name: "typ kb+sd-jwt before the Key Binding JWT of the Delegate Holder",
			build: func(f *delegationFixture) string {
				return withLink(linkSpec{typ: TypeKBSDJWT, delegate: f.agent}, true)(f)
			},
			wantErr: `KB-SD-JWT 1: typ is "kb+sd-jwt"`,
		},
		{
			name:    "KB-SD-JWT with typ kb+jwt",
			build:   withLink(linkSpec{typ: sdjwt.TypeKeyBinding}, false),
			wantErr: `typ is "kb+jwt", expected "kb+sd-jwt" or "kb-sd-jwt+kb"`,
		},
		{
			name: "typ kb-sd-jwt+kb without cnf in the Delegate Payload",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				return chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder}))
			},
			wantErr: "the Delegate Payload has no cnf claim",
		},
		// §6 step 5.
		{
			name: "dSD-JWT where Key Binding is required",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return chain("", p.credential, p.link)
			},
			opts:    Options{RequireKeyBinding: true},
			wantErr: "Key Binding is required",
		},
		{
			name: "Key Binding JWT of the Delegate Holder signed with a key other than the delegate cnf key",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return chain(f.keyBinding(p.link, f.holder, nil), p.credential, p.link)
			},
			wantErr: "the Key Binding JWT of the Delegate Holder: " + sdjwt.ErrSignature.Error(),
		},
		{
			name: "Key Binding JWT of the Delegate Holder with typ kb+sd-jwt",
			build: func(f *delegationFixture) string {
				p := valid(f)
				payload := map[string]any{"iat": delegationNow.Unix(), "aud": "a", "nonce": "n", "sd_hash": f.digest(p.link, "sha-256")}
				return chain(f.sign(TypeKBSDJWT, payload, f.agent), p.credential, p.link)
			},
			wantErr: `the Key Binding JWT of the Delegate Holder: typ is "kb+sd-jwt"`,
		},
		{
			name: "Key Binding JWT of the Delegate Holder sd_hash over the credential",
			build: func(f *delegationFixture) string {
				p := valid(f)
				kbJWT := f.keyBinding(p.link, f.agent, func(payload map[string]any) { payload["sd_hash"] = f.digest(p.credential, "sha-256") })
				return chain(kbJWT, p.credential, p.link)
			},
			wantErr: "sd_hash does not match the final KB-SD-JWT",
			wantIs:  sdjwt.ErrSDHash,
		},
		{
			name: "delegate Disclosure withheld after the KB-JWT was signed",
			build: func(f *delegationFixture) string {
				p := valid(f)
				components := strings.Split(strings.TrimSuffix(p.link, "~"), "~")
				return chain(p.kbJWT, p.credential, strings.Join(components[:2], "~")+"~")
			},
			wantErr: "sd_hash does not match the final KB-SD-JWT",
		},
		{
			name: "Key Binding JWT of the Delegate Holder for another audience",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return chain(p.kbJWT, p.credential, p.link)
			},
			opts:    Options{Audience: "https://other.example"},
			wantErr: `aud does not match: got "https://verifier.example"`,
			wantIs:  sdjwt.ErrAudience,
		},
		{
			name: "Key Binding JWT of the Delegate Holder with another nonce",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return chain(p.kbJWT, p.credential, p.link)
			},
			opts:    Options{Nonce: "other"},
			wantErr: `nonce does not match: got "n-2"`,
			wantIs:  sdjwt.ErrNonce,
		},
		{
			name: "dSD-JWT for another audience",
			build: func(f *delegationFixture) string {
				p := valid(f)
				return chain("", p.credential, p.link)
			},
			opts:    Options{Audience: "https://other.example"},
			wantErr: `KB-SD-JWT 1: aud does not match: got "https://agent.example"`,
			wantIs:  sdjwt.ErrAudience,
		},
		{
			name: "Key Binding JWT of the Delegate Holder older than MaxAge",
			build: func(f *delegationFixture) string {
				p := valid(f)
				kbJWT := f.keyBinding(p.link, f.agent, func(payload map[string]any) { payload["iat"] = delegationNow.Add(-7 * time.Minute).Unix() })
				return chain(kbJWT, p.credential, p.link)
			},
			opts:    Options{MaxAge: 5 * time.Minute},
			wantErr: "the Key Binding JWT of the Delegate Holder: iat 2026-11-13T11:53:00Z is older than 5m0s",
		},
		{
			name: "Key Binding JWT of the Delegate Holder from the future",
			build: func(f *delegationFixture) string {
				p := valid(f)
				kbJWT := f.keyBinding(p.link, f.agent, func(payload map[string]any) { payload["iat"] = delegationNow.Add(2 * time.Minute).Unix() })
				return chain(kbJWT, p.credential, p.link)
			},
			opts:    Options{MaxAge: 5 * time.Minute},
			wantErr: "the Key Binding JWT of the Delegate Holder: iat 2026-11-13T12:02:00Z is in the future",
		},
		{
			name: "expired Key Binding JWT of the Delegate Holder",
			build: func(f *delegationFixture) string {
				p := valid(f)
				kbJWT := f.keyBinding(p.link, f.agent, func(payload map[string]any) { payload["exp"] = delegationNow.Add(-2 * time.Minute).Unix() })
				return chain(kbJWT, p.credential, p.link)
			},
			wantErr: "the Key Binding JWT of the Delegate Holder: expired",
			wantIs:  sdjwt.ErrExpired,
		},
		{
			name:    "expired final KB-SD-JWT of a dSD-JWT",
			build:   withLink(linkSpec{typ: TypeKBSDJWT, change: func(payload map[string]any, _ *[]string) { payload["exp"] = delegationNow.Add(-2 * time.Minute).Unix() }}, false),
			wantErr: "KB-SD-JWT 1: expired",
			wantIs:  sdjwt.ErrExpired,
		},
		{
			name:    "final KB-SD-JWT of a dSD-JWT before its nbf",
			build:   withLink(linkSpec{typ: TypeKBSDJWT, change: func(payload map[string]any, _ *[]string) { payload["nbf"] = delegationNow.Add(2 * time.Minute).Unix() }}, false),
			wantErr: "KB-SD-JWT 1: not valid before",
			wantIs:  sdjwt.ErrNotYetValid,
		},
		{
			name: "more than MaxLinks KB-SD-JWTs",
			build: func(f *delegationFixture) string {
				credential := f.credential("sha-256", nil)
				link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
				links := []string{credential}
				for range MaxLinks + 1 {
					links = append(links, link)
				}
				return chain("", links...)
			},
			wantErr: "it has 5 KB-SD-JWTs, but at most 4 are accepted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newDelegationFixture(t)
			raw := tt.build(f)
			_, err := Verify(raw, &f.issuer.PublicKey, bound(raw, tt.opts))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Verify error = %v, want it to contain %q", err, tt.wantErr)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Verify error = %v, want it to match %v", err, tt.wantIs)
			}
		})
	}
}

func TestAppendBuildsVerifiableChain(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-384", nil)
	audience := f.disclosure("https://verifier.example")
	mandate := f.disclosure(map[string]any{
		"vct": "urn:example:mandate:1", "cnf": f.cnf(f.agent),
		"audiences": []any{map[string]any{"...": f.digest(audience, "sha-256")}},
	})
	other := f.disclosure(map[string]any{"vct": "urn:example:mandate:2", "cnf": f.cnf(f.subject)})
	claims := map[string]any{"iat": delegationNow.Unix(), "aud": "https://agent.example", "nonce": "n-1"}

	delegated, err := Append(credential, KBSDJWT{
		Type:     TypeKBSDJWTKB,
		Payloads: []PayloadDisclosure{{Disclosure: mandate, Disclosures: []string{audience}}, {Disclosure: other}},
		Claims:   claims,
	}, f.holder)
	if err != nil {
		t.Fatal(err)
	}
	if _, set := claims["sd_hash"]; set {
		t.Error("Append changed the caller's claims")
	}
	parsed, err := Parse(delegated)
	if err != nil {
		t.Fatal(err)
	}
	kb := parsed.Links[0].Token
	if got := kb.Header["typ"]; got != TypeKBSDJWTKB {
		t.Errorf("typ = %v", got)
	}
	if got, want := kb.Payload["sd_hash"], f.digest(credential, "sha-384"); got != want {
		t.Errorf("sd_hash = %v, want the sha-384 digest %v of the SD-JWT", got, want)
	}
	wantDigests := []any{map[string]any{"...": f.digest(mandate, "sha-256")}, map[string]any{"...": f.digest(other, "sha-256")}}
	if got := kb.Payload["delegate_payload"]; !reflect.DeepEqual(got, wantDigests) {
		t.Errorf("delegate_payload = %v, want %v", got, wantDigests)
	}

	// The Delegate Holder keeps one Delegate Payload (§5.1.4) and delegates the
	// credential again, using issuer_jwt_hash.
	kbJWT := strings.SplitN(strings.TrimPrefix(delegated, credential+"~"), "~", 2)[0]
	first := kbJWT + "~" + mandate + "~" + audience + "~"
	second, err := Append(credential+"~"+first, KBSDJWT{
		Type: TypeKBSDJWT, SDAlg: "sha-512", IssuerJWTHash: true,
		Payloads: []PayloadDisclosure{{Disclosure: f.disclosure(map[string]any{"vct": "urn:example:mandate:3"})}},
		Claims:   maps.Clone(claims),
	}, f.agent)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Verify(second, &f.issuer.PublicKey, bound(second, Options{}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, want := d.Links[1].Token.Payload["issuer_jwt_hash"], f.digest(kbJWT, "sha-256"); got != want {
		t.Errorf("issuer_jwt_hash = %v, want the digest %v of the preceding KB-SD-JWT", got, want)
	}
	if got := d.Links[1].Payload["vct"]; got != "urn:example:mandate:3" {
		t.Errorf("second delegate payload vct = %v", got)
	}
}

func TestAppendRejectsInvalidInput(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	payloads := []PayloadDisclosure{{Disclosure: f.disclosure(map[string]any{"vct": "x"})}}
	tests := []struct {
		name      string
		preceding string
		kb        KBSDJWT
	}{
		{"typ kb+jwt", credential, KBSDJWT{Type: sdjwt.TypeKeyBinding, Payloads: payloads}},
		{"no Delegate Payload", credential, KBSDJWT{Type: TypeKBSDJWT}},
		{"SD-JWT without trailing tilde", strings.TrimSuffix(credential, "~"), KBSDJWT{Type: TypeKBSDJWT, Payloads: payloads}},
		{"unknown _sd_alg", credential, KBSDJWT{Type: TypeKBSDJWT, SDAlg: "md5", Payloads: payloads}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Append(tt.preceding, tt.kb, f.holder); err == nil {
				t.Fatal("Append succeeded")
			}
		})
	}
}

func TestIsChain(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	if IsChain(credential) {
		t.Error("an SD-JWT is reported as a delegation")
	}
	if !IsChain(chain("", credential, f.link(credential, linkSpec{typ: TypeKBSDJWT, signer: f.holder})) + "\n") {
		t.Error("a dSD-JWT is not reported as a delegation")
	}
}

// An SD-JWT with an empty component is malformed (RFC 9901 §4). It is a chain
// only when a KB-SD-JWT follows the empty component (§5.1.4).
func TestIsChainNeedsAKBSDJWTAfterTheEmptyComponent(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	issuerJWT, disclosures, _ := strings.Cut(credential, "~")
	disclosure, _, _ := strings.Cut(disclosures, "~")
	kbJWT := format.EncodeBase64URL([]byte(`{"alg":"ES256","typ":"kb+jwt"}`)) + "." + format.EncodeBase64URL([]byte(`{}`)) + ".c2ln"
	for name, raw := range map[string]string{
		"nothing after the empty component":   issuerJWT + "~~",
		"a disclosure and an empty component": issuerJWT + "~" + disclosure + "~~",
		"a Key Binding JWT after it":          issuerJWT + "~" + disclosure + "~~" + kbJWT,
		"an SD-JWT with a Key Binding JWT":    credential + "~" + kbJWT,
		"an Issuer-signed JWT after it":       issuerJWT + "~~" + issuerJWT + "~",
	} {
		if IsChain(raw) {
			t.Errorf("%s: reported as a delegation", name)
		}
	}
}

func TestVerifyAcceptsAKeyBindingWithinMaxAge(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
	kbJWT := f.keyBinding(link, f.agent, func(payload map[string]any) { payload["iat"] = delegationNow.Add(-4 * time.Minute).Unix() })
	opts := Options{Now: delegationNow, Audience: "https://verifier.example", Nonce: "n-2", MaxAge: 5 * time.Minute, RequireKeyBinding: true}
	if _, err := Verify(chain(kbJWT, credential, link), &f.issuer.PublicKey, opts); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyNeedsTheBindingOptions(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
	raw := chain(f.keyBinding(link, f.agent, nil), credential, link)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, unset := range map[string]func(*Options){
		"Audience": func(opts *Options) { opts.Audience = "" },
		"Nonce":    func(opts *Options) { opts.Nonce = "" },
		"MaxAge":   func(opts *Options) { opts.MaxAge = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			opts := bound(raw, Options{})
			unset(&opts)
			if _, err := Verify(raw, &f.issuer.PublicKey, opts); !errors.Is(err, ErrOptionUnset) || !strings.HasSuffix(err.Error(), name) {
				t.Errorf("Verify error = %v, want ErrOptionUnset for %s", err, name)
			}
			if err := parsed.Verify(opts); !errors.Is(err, ErrOptionUnset) {
				t.Errorf("Chain.Verify error = %v, want ErrOptionUnset", err)
			}
		})
	}
}

func TestVerifyWithoutBindingIgnoresTheRequest(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
	kbJWT := f.keyBinding(link, f.agent, func(payload map[string]any) { payload["iat"] = delegationNow.Add(-24 * time.Hour).Unix() })
	parsed, err := Parse(chain(kbJWT, credential, link))
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyWithoutBinding(Options{Now: delegationNow}); err != nil {
		t.Errorf("VerifyWithoutBinding: %v", err)
	}

	expired := f.keyBinding(link, f.agent, func(payload map[string]any) { payload["exp"] = delegationNow.Add(-2 * time.Minute).Unix() })
	if parsed, err = Parse(chain(expired, credential, link)); err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyWithoutBinding(Options{Now: delegationNow}); !errors.Is(err, sdjwt.ErrExpired) {
		t.Errorf("VerifyWithoutBinding error = %v, want ErrExpired", err)
	}
}

func TestParseAcceptsMaxLinks(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	link := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
	links := []string{credential}
	for range MaxLinks {
		links = append(links, link)
	}
	if _, err := Parse(chain("", links...)); err != nil {
		t.Errorf("Parse with %d KB-SD-JWTs: %v", MaxLinks, err)
	}
}

func TestInspectReportsEachStep(t *testing.T) {
	f := newDelegationFixture(t)
	credential := f.credential("sha-256", nil)
	first := f.link(credential, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.agent})
	// The cnf of the first Delegate Payload is the agent key, so the holder
	// key does not verify the second KB-SD-JWT.
	second := f.link(first, linkSpec{typ: TypeKBSDJWTKB, signer: f.holder, delegate: f.subject})
	third := f.link(second, linkSpec{typ: TypeKBSDJWTKB, signer: f.subject, delegate: f.agent, change: func(payload map[string]any, _ *[]string) {
		payload["sd_hash"] = "AAAA"
	}})
	raw := chain(f.keyBinding(third, f.agent, nil), credential, first, second, third)
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	report := c.Inspect(Options{Now: delegationNow})
	if report.Credential != nil {
		t.Errorf("Credential = %v, want nil", report.Credential)
	}
	if len(report.Links) != 3 {
		t.Fatalf("got %d link steps, want 3", len(report.Links))
	}
	if report.Links[0].Failed() {
		t.Errorf("link 1 failed: %+v", report.Links[0])
	}
	if step := report.Links[1]; step.Signature == nil || step.Binding != nil || step.Other != nil {
		t.Errorf("link 2 = %+v, want only a signature error", step)
	}
	if step := report.Links[2]; step.Signature != nil || !errors.Is(step.Binding, sdjwt.ErrSDHash) || step.Other != nil {
		t.Errorf("link 3 = %+v, want only a binding error", step)
	}
	if report.KeyBinding == nil || report.KeyBinding.Failed() {
		t.Errorf("KeyBinding = %+v, want a passing step", report.KeyBinding)
	}
	if err := report.Err(); err == nil || !strings.HasPrefix(err.Error(), "KB-SD-JWT 2: ") {
		t.Errorf("Err() = %v, want the error of KB-SD-JWT 2", err)
	}
	if got, want := report.Err().Error(), c.VerifyWithoutBinding(Options{Now: delegationNow}).Error(); got != want {
		t.Errorf("Err() = %q, VerifyWithoutBinding = %q", got, want)
	}
}
