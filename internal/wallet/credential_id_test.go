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

package wallet

import "testing"

// An ID prefix resolves only when it matches exactly one credential.
func TestGetCredential_ResolvesByPrefix(t *testing.T) {
	w := generateTestWallet(t)
	w.PutCredential(StoredCredential{ID: "abcd1234ef567890", VCT: "urn:example:one"})
	w.PutCredential(StoredCredential{ID: "ffee0011deadbeef", VCT: "urn:example:two"})

	if c, ok := w.GetCredential("abcd1234ef567890"); !ok || c.VCT != "urn:example:one" {
		t.Fatalf("full id did not resolve: %v %+v", ok, c)
	}
	if c, ok := w.GetCredential("abcd1234"); !ok || c.VCT != "urn:example:one" {
		t.Fatalf("unambiguous prefix did not resolve: %v %+v", ok, c)
	}
	if c, ok := w.GetCredential("ffee"); !ok || c.VCT != "urn:example:two" {
		t.Fatalf("second prefix did not resolve: %v %+v", ok, c)
	}
	if _, ok := w.GetCredential("nope"); ok {
		t.Error("an unknown prefix resolved a credential")
	}
}

func TestGetCredential_AmbiguousPrefixResolvesNothing(t *testing.T) {
	w := generateTestWallet(t)
	w.PutCredential(StoredCredential{ID: "aaaa1111", VCT: "urn:example:one"})
	w.PutCredential(StoredCredential{ID: "aaaa2222", VCT: "urn:example:two"})

	if _, ok := w.GetCredential("aaaa"); ok {
		t.Error("an ambiguous prefix resolved a credential")
	}
	if _, ok := w.GetCredential("aaaa1111"); !ok {
		t.Error("a full id did not resolve past the ambiguous shared prefix")
	}
}

func TestRemoveCredential_ResolvesByPrefix(t *testing.T) {
	w := generateTestWallet(t)
	w.PutCredential(StoredCredential{ID: "1234abcd5678ef90", VCT: "urn:example:one"})

	if !w.RemoveCredential("1234abcd") {
		t.Fatal("an unambiguous prefix did not remove the credential")
	}
	if _, ok := w.GetCredential("1234abcd5678ef90"); ok {
		t.Error("the credential is still present after removal by prefix")
	}
}

func TestNewCredentialID_ShortHex(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newCredentialID()
		if len(id) != 16 {
			t.Fatalf("id %q is %d chars, want 16", id, len(id))
		}
		for _, r := range id {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Fatalf("id %q is not lowercase hex", id)
			}
		}
		if seen[id] {
			t.Fatalf("id %q was minted twice", id)
		}
		seen[id] = true
	}
}
