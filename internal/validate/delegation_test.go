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
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

// delegated is a dSD-JWT (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1). The
// Holder key signs its KB-SD-JWT.
func delegated(t *testing.T, chain issuerChain, signer, holder *ecdsa.PrivateKey) string {
	t.Helper()
	credential := chain.sdjwt(t, mock.SDJWTConfig{HolderKey: &holder.PublicKey})
	payload, err := json.Marshal([]any{"salt", map[string]any{"vct": "urn:example:mandate:1", "exp": time.Now().Add(time.Hour).Unix()}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := delegate.Append(credential, delegate.KBSDJWT{
		Type:     delegate.TypeKBSDJWT,
		Payloads: []delegate.PayloadDisclosure{{Disclosure: format.EncodeBase64URL(payload)}},
		Claims:   map[string]any{"iat": time.Now().Unix(), "aud": "https://verifier.example", "nonce": "n"},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestADelegateSDJWTGetsTheChecksOfItsSDJWTAndADelegationCheck(t *testing.T) {
	chain := newIssuerChain(t)
	holder, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	result := validated(t, delegated(t, chain, holder, holder), Trust{}, Options{Offline: true})
	if result.Format != FormatSDJWT || result.SDJWT.ResolvedClaims["given_name"] != "Erika" {
		t.Errorf("format = %s, given_name = %v, want the SD-JWT of the chain", result.Format, result.SDJWT.ResolvedClaims["given_name"])
	}
	if c, _ := result.Find(CheckSignature); c.Status != Pass {
		t.Errorf("signature check = %+v, want pass", c)
	}
	if c, _ := result.Find(CheckDelegation); c.Status != Pass || c.Detail != "dSD-JWT with 1 KB-SD-JWT. The binding to a request was not checked." {
		t.Errorf("delegation check = %+v, want pass", c)
	}
	if got := result.Delegation.Links[0].Payload["vct"]; got != "urn:example:mandate:1" {
		t.Errorf("delegate payload vct = %v", got)
	}
}

func TestTheDelegationCheckCountsEveryKBSDJWT(t *testing.T) {
	chain := newIssuerChain(t)
	holder, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(&agent.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	link := func(preceding, typ string, payload map[string]any, signer *ecdsa.PrivateKey) string {
		t.Helper()
		payload["exp"] = time.Now().Add(time.Hour).Unix()
		disclosure, err := json.Marshal([]any{"salt", payload})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := delegate.Append(preceding, delegate.KBSDJWT{
			Type:     typ,
			Payloads: []delegate.PayloadDisclosure{{Disclosure: format.EncodeBase64URL(disclosure)}},
			Claims:   map[string]any{"iat": time.Now().Unix(), "aud": "https://verifier.example", "nonce": "n"},
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	credential := chain.sdjwt(t, mock.SDJWTConfig{HolderKey: &holder.PublicKey})
	first := link(credential, delegate.TypeKBSDJWTKB, map[string]any{"vct": "urn:example:mandate:1", "cnf": map[string]any{"jwk": jwk}}, holder)
	second := link(first, delegate.TypeKBSDJWT, map[string]any{"vct": "urn:example:mandate:2"}, agent)

	result := validated(t, second, Trust{}, Options{Offline: true})
	if c, _ := result.Find(CheckDelegation); c.Status != Pass || c.Detail != "dSD-JWT with 2 KB-SD-JWTs. The binding to a request was not checked." {
		t.Errorf("delegation check = %+v, want pass with 2 KB-SD-JWTs", c)
	}
}

// §5.1.1: "The resulting array of components MUST have exactly one empty
// component between the last component of each SD-JWT or KB-SD-JWT and the
// following KB-SD-JWT."
func TestAChainThatDoesNotParseStillShowsItsSDJWT(t *testing.T) {
	chain := newIssuerChain(t)
	holder, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(delegated(t, chain, holder, holder), "~~", "~~~", 1)
	result := validated(t, raw, Trust{}, Options{Offline: true})
	if result.SDJWT.ResolvedClaims["given_name"] != "Erika" {
		t.Errorf("given_name = %v, want the SD-JWT of the chain", result.SDJWT.ResolvedClaims["given_name"])
	}
	if c, _ := result.Find(CheckSignature); c.Status != Pass {
		t.Errorf("signature check = %+v, want pass", c)
	}
	want := "invalid Delegate SD-JWT: more than one empty component separates two parts of the chain"
	if c, _ := result.Find(CheckDelegation); c.Status != Fail || c.Detail != want {
		t.Errorf("delegation check = %+v, want the failure %q", c, want)
	}
}
