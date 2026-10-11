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

package trustedlists

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

type testEnv struct {
	signer   *provider.Signer
	settings Settings
	base     string
}

func (e *testEnv) Signer() *provider.Signer                                 { return e.signer }
func (e *testEnv) IssuedAttestationSpecs() []provider.IssuedAttestationSpec { return nil }
func (e *testEnv) TemplateLocation() credtemplate.Location                  { return credtemplate.Location{} }
func (e *testEnv) IssuerURL() string                                        { return "https://wallet.example" }
func (e *testEnv) RegistrarBase() string                                    { return e.base }
func (e *testEnv) HTTPClient() *http.Client                                 { return http.DefaultClient }
func (e *testEnv) Strict() bool                                             { return false }
func (e *testEnv) Settings() Settings                                       { return e.settings }
func (e *testEnv) ListedProviderName() string                               { return "Provider" }

type testRoot struct{ root provider.Root }

func (r testRoot) Root() provider.Root { return r.root }

// newTestTrust has a wallet CA and no additions.
func newTestTrust(t *testing.T) (*Set, *testEnv) {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateRootCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := provider.NewKeys(storage.NewMemory(), "", nil)
	leaf, err := keys.Certificate(caKey, ca, &issuerKey.PublicKey, mock.LeafCertOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	root := provider.Root{IssuerKey: issuerKey, CAKey: caKey, Chain: []*x509.Certificate{leaf, ca}, IssuerURL: "https://wallet.example"}
	env := &testEnv{signer: provider.NewSigner(keys, testRoot{root}), base: "https://wallet.example"}
	return New(&sync.RWMutex{}, &Additions{}, &ListCache{}, env), env
}

// Any visitor can name a list URL, so the list cache stays bounded. The
// bound leaves room for the lists the wallet reads itself.
func TestTheTrustedListCacheIsBounded(t *testing.T) {
	tr, _ := newTestTrust(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("list"))
	}))
	defer srv.Close()
	tr.additions.AddedTrustedLists = []string{srv.URL + "/added"}
	bound := tr.cacheBound()
	if bound != 1+maxFollowedPointers+requestedListSlots {
		t.Fatalf("bound = %d with one added list", bound)
	}
	for i := range bound + 5 {
		if _, err := tr.rawList(fmt.Sprintf("%s/list-%d", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(tr.cache.lists); n > bound {
		t.Errorf("cached lists = %d, want at most %d", n, bound)
	}
}

// The wallet signs its own lists with its list operator key, so they verify
// against the wallet CA.
func TestTheWalletsOwnListVerifiesAgainstItsCA(t *testing.T) {
	tr, env := newTestTrust(t)
	raw, err := tr.SignedList("https://wallet.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyListSigner(raw, []*x509.Certificate{env.signer.TrustAnchor()}); err != nil {
		t.Fatal(err)
	}
	list, err := tr.ReadList(tr.OwnListURL(tr.DefaultGroup().ID))
	if err != nil {
		t.Fatal(err)
	}
	if got := list.Entities[0].Name; got != "Provider" {
		t.Errorf("the first entity is %q, want the listed provider", got)
	}
}

// The wallet builds its own lists in process for every spelling of its origin.
func TestOwnListIDMatchesTheOriginLikeSameURL(t *testing.T) {
	tr, env := newTestTrust(t)
	env.base = "https://wallet.example/prefix"
	for raw, want := range map[string]bool{
		"https://wallet.example/prefix/api/trustlists/pid":     true,
		"https://WALLET.example:443/prefix/api/trustlists/pid": true,
		"http://wallet.example/prefix/api/trustlists/pid":      false,
		"https://wallet.example/api/trustlists/pid":            false,
		"https://other.example/prefix/api/trustlists/pid":      false,
	} {
		if id, ok := tr.ownListID(raw); ok != want || (ok && id != "pid") {
			t.Errorf("%s: %q %t, want %t", raw, id, ok, want)
		}
	}
}
