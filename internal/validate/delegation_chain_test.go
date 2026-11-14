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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureChain(t *testing.T, name string) (string, *Chain) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "e2e", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSpace(string(data))
	result := validated(t, raw, Trust{}, Options{Offline: true})
	if result.Chain == nil {
		t.Fatalf("%s has no chain", name)
	}
	return raw, result.Chain
}

// joined puts the parts back together: the SD-JWT, an empty component before
// each KB-SD-JWT and the Key Binding JWT (draft-ietf-oauth-delegate-sd-jwt-00
// §5.1.1).
func joined(c *Chain) string {
	var b strings.Builder
	for i, part := range c.Parts {
		if i > 0 && part.Kind == PartKBSDJWT {
			b.WriteString("~")
		}
		b.WriteString(part.Raw)
	}
	return b.String()
}

func TestAChainWithThreeKBSDJWTsHasAPartForEachComponent(t *testing.T) {
	raw, c := fixtureChain(t, "delegate-sd-jwt-3-links.txt")
	if c.Format != "dSD-JWT" || c.Failed() {
		t.Errorf("format = %s, failed = %t, want a passing dSD-JWT", c.Format, c.Failed())
	}
	if got := joined(c); got != raw {
		t.Errorf("the parts join to\n%s\nwant\n%s", got, raw)
	}
	wantLabels := []string{"SD-JWT", "KB-SD-JWT 1", "KB-SD-JWT 2", "KB-SD-JWT 3"}
	if len(c.Parts) != len(wantLabels) {
		t.Fatalf("got %d parts, want %d", len(c.Parts), len(wantLabels))
	}
	for i, part := range c.Parts {
		if part.Label != wantLabels[i] {
			t.Errorf("part %d label = %q, want %q", i, part.Label, wantLabels[i])
		}
		if i == 0 {
			if part.Signer != nil || part.Delegate.Letter != "A" {
				t.Errorf("SD-JWT signer = %v, holder key = %+v, want the issuer and key A", part.Signer, part.Delegate)
			}
			continue
		}
		if part.Signer == nil || *part.Signer != *c.Parts[i-1].Delegate {
			t.Errorf("%s is signed by %+v, want the delegate key of the part before it", part.Label, part.Signer)
		}
		if part.Signature.Status != Pass || part.Binding == nil || part.Binding.Status != Pass || !part.Trusted {
			t.Errorf("%s = %+v, want a passing and trusted part", part.Label, part)
		}
	}
	if got := []string{c.Parts[1].Delegate.Letter, c.Parts[2].Delegate.Letter}; got[0] != "B" || got[1] != "C" {
		t.Errorf("delegate keys = %v, want B and C", got)
	}
	if c.Parts[3].Delegate != nil {
		t.Errorf("KB-SD-JWT 3 delegates to %+v, want no key", c.Parts[3].Delegate)
	}
	if got := c.Parts[2].Signature.Detail; got != "Signed with the delegate key of KB-SD-JWT 1." {
		t.Errorf("signature detail = %q", got)
	}
}

func TestAFailingKBSDJWTMakesTheStepsAfterItUntrusted(t *testing.T) {
	raw, c := fixtureChain(t, "delegate-sd-jwt-broken.txt")
	if check, _ := validated(t, raw, Trust{}, Options{Offline: true}).Find(CheckDelegation); !c.Failed() || check.Status != Fail || !strings.HasPrefix(check.Detail, "KB-SD-JWT 2: ") {
		t.Errorf("chain failed = %t, delegation check = %+v, want a failure of KB-SD-JWT 2", c.Failed(), check)
	}
	failing := c.Parts[2]
	if failing.Signature.Status != Fail || failing.Signature.Detail != "The signature does not match key B. KB-SD-JWT 1 delegates to key B." {
		t.Errorf("KB-SD-JWT 2 signature = %+v", failing.Signature)
	}
	if !c.Parts[1].Trusted || c.Parts[1].Failed() {
		t.Errorf("KB-SD-JWT 1 = %+v, want a trusted part", c.Parts[1])
	}
	last := c.Parts[3]
	if last.Trusted || last.TrustDetail != "Not trusted because KB-SD-JWT 2 fails." {
		t.Errorf("KB-SD-JWT 3 trusted = %t, detail = %q", last.Trusted, last.TrustDetail)
	}
}

func TestAKeyBindingJWTIsTheLastPart(t *testing.T) {
	raw, c := fixtureChain(t, "delegate-sd-jwt-kb.txt")
	if c.Format != "dSD-JWT+KB" {
		t.Errorf("format = %s", c.Format)
	}
	if got := joined(c); got != raw {
		t.Errorf("the parts join to\n%s\nwant\n%s", got, raw)
	}
	kb := c.Parts[len(c.Parts)-1]
	if kb.Kind != PartKBJWT || kb.Signer == nil || kb.Signer.Letter != "B" || kb.Delegate != nil {
		t.Errorf("last part = %+v, want the Key Binding JWT signed with key B", kb)
	}
	if kb.Binding == nil || kb.Binding.Detail != "The sd_hash matches KB-SD-JWT 1." {
		t.Errorf("binding = %+v", kb.Binding)
	}
}

// draft-ietf-oauth-delegate-sd-jwt-00 §5.1.4: a KB-SD-JWT has the typ
// "kb+sd-jwt" or "kb-sd-jwt+kb". §6 step 3.1 reads exp from the Delegate
// Payload.
func TestAKBSDJWTOnItsOwnPassesTheTypeCheck(t *testing.T) {
	_, c := fixtureChain(t, "delegate-sd-jwt-3-links.txt")
	for _, part := range []ChainPart{c.Parts[1], c.Parts[3]} {
		t.Run(part.Typ, func(t *testing.T) {
			result := validated(t, part.Raw, Trust{}, Options{Offline: true})
			if result.Chain == nil || result.Chain.Format != FormatKBSDJWT || len(result.Chain.Parts) != 1 {
				t.Fatalf("chain = %+v, want one KB-SD-JWT", result.Chain)
			}
			if c, _ := result.Find(CheckType); c.Status != Pass || c.Detail != part.Typ {
				t.Errorf("type check = %+v, want a pass", c)
			}
			if c, _ := result.Find(CheckExpiry); c.Status != Pass || !strings.HasPrefix(c.Detail, "expires ") {
				t.Errorf("expiry check = %+v, want the exp of the Delegate Payload", c)
			}
			if c, _ := result.Find(CheckSignature); c.Status != Skipped || c.Detail != "Checked with the whole chain" {
				t.Errorf("signature check = %+v", c)
			}
			for _, name := range []string{CheckTrust, CheckStatus, CheckDelegation} {
				if c, found := result.Find(name); found {
					t.Errorf("%s check = %+v, want none", name, c)
				}
			}
		})
	}
}
