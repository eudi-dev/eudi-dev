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

package output

import (
	"slices"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

func brokenChain() *validate.Chain {
	keyA := &validate.ChainKey{Letter: "A", Thumbprint: "thumb-a"}
	keyB := &validate.ChainKey{Letter: "B", Thumbprint: "thumb-b"}
	keyC := &validate.ChainKey{Letter: "C", Thumbprint: "thumb-c"}
	exp := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	pass := func(detail string) *validate.PartCheck {
		return &validate.PartCheck{Status: validate.Pass, Detail: detail}
	}
	return &validate.Chain{Format: "dSD-JWT", Parts: []validate.ChainPart{
		{
			Kind: validate.PartSDJWT, Label: "SD-JWT", Raw: "cred~", Typ: "dc+sd-jwt", Delegate: keyA, Expiry: &exp,
			Limits:    []delegatepayload.Limit{{Name: "vct", Value: "urn:example:authority:1"}},
			Signature: validate.PartCheck{Status: validate.Skipped, Detail: "Offline."}, Trusted: true,
		},
		{
			Kind: validate.PartKBSDJWT, Label: "KB-SD-JWT 1", Raw: "link1~", Typ: "kb-sd-jwt+kb", Signer: keyA, Delegate: keyB, Expiry: &exp,
			Limits:    []delegatepayload.Limit{{Name: "budget", Value: `{"per_order":50}`, JSON: true}},
			Signature: *pass("Signed with the holder key of the SD-JWT."), Binding: pass("The sd_hash matches the SD-JWT."), Trusted: true,
		},
		{
			Kind: validate.PartKBSDJWT, Label: "KB-SD-JWT 2", Raw: "link2", Typ: "kb+sd-jwt", Signer: keyB, Delegate: keyC,
			Signature: validate.PartCheck{Status: validate.Fail, Detail: "The signature does not match key B. KB-SD-JWT 1 delegates to key B."},
			Binding:   pass("The sd_hash matches KB-SD-JWT 1."), Problem: "The Delegate Payload has expired.",
			TrustDetail: "Not trusted because KB-SD-JWT 1 fails.",
		},
	}}
}

func TestChainLinesShowTheChainJSON(t *testing.T) {
	want := []string{
		"┌ SD-JWT (dc+sd-jwt)",
		"  Signed by: Issuer key",
		"  Holder key: thumb-a (key A)",
		"  Until: 2099-01-01 00:00 UTC",
		"  vct: urn:example:authority:1",
		"  ○ Signature not checked: Offline.",
		"┌ KB-SD-JWT 1 (kb-sd-jwt+kb)",
		"  Signed by: thumb-a (key A)",
		"  Delegates to: thumb-b (key B)",
		"  Until: 2099-01-01 00:00 UTC",
		`  budget: {"per_order":50}`,
		"  ✓ Signature: Signed with the holder key of the SD-JWT.",
		"  ✓ Binding: The sd_hash matches the SD-JWT.",
		"┌ KB-SD-JWT 2 (kb+sd-jwt)",
		"  Expected signer: thumb-b (key B)",
		"  Delegates to: thumb-c (key C)",
		"  Until: No exp",
		"  ✗ Signature: The signature does not match key B. KB-SD-JWT 1 delegates to key B.",
		"  ✓ Binding: The sd_hash matches KB-SD-JWT 1.",
		"  ✗ The Delegate Payload has expired.",
		"  Not trusted because KB-SD-JWT 1 fails.",
	}
	out := BuildChainJSON(brokenChain())
	if out.Format != "dSD-JWT" || out.Status != "fail" || *out.Parts[0].Exp != 4070908800 || out.Parts[2].Exp != nil {
		t.Errorf("chain = %+v", out)
	}
	if got := ChainLines(out); !slices.Equal(got, want) {
		t.Errorf("ChainLines =\n%q\nwant\n%q", got, want)
	}
}

func TestChainLinesOfAKBSDJWTOnItsOwn(t *testing.T) {
	chain := &validate.Chain{Format: validate.FormatKBSDJWT, Parts: []validate.ChainPart{{
		Kind: validate.PartKBSDJWT, Label: "KB-SD-JWT", Typ: "kb+sd-jwt", Trusted: true,
		Signature: validate.PartCheck{Status: validate.Skipped, Detail: "Checked with the whole chain."},
	}}}
	lines := ChainLines(BuildChainJSON(chain))
	if lines[1] != "  Signed by: The delegate key of the part before it" || lines[2] != "  Delegates to: No one. The chain ends here." {
		t.Errorf("ChainLines = %q", lines)
	}
}
