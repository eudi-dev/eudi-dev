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

package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

type readAllCounter struct {
	storage.Store
	readAll int
}

func (c *readAllCounter) ReadAll(prefix string) (map[string]storage.Blob, error) {
	c.readAll++
	return c.Store.ReadAll(prefix)
}

// The stored next update is the one the list carries (ETSI TS 119 602 V1.1.1
// §6.3.15), and a new Pub-EAA providers list keeps the services of the list
// it replaces (Table H.1).
func TestATrustListBuildsOnTheListItReplaces(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	otherCA, err := mock.GenerateCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	backend := storage.NewMemory()
	s := NewKeys(backend, "", nil)
	other := base64.StdEncoding.EncodeToString(otherCA.Raw)
	opts := lote.Options{Issuer: "https://wallet.example", Path: "/list", Scheme: CategoryList(credtemplate.CategoryPubEAA).Scheme, Entities: []lote.Entity{{Name: "Other", Issuance: []string{other}}}}
	if _, err := s.TrustList(key, ca, opts); err != nil {
		t.Fatal(err)
	}
	opts.Entities = nil
	raw, err := s.TrustList(key, ca, opts)
	if err != nil {
		t.Fatal(err)
	}
	list, err := lote.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Entities) != 2 || list.Entities[1].Name != "Other" || list.Entities[1].Services[0].ServiceStatus != lote.PubEAAWithdrawnStatus {
		t.Errorf("%d entities, want the removed provider withdrawn after the own one", len(list.Entities))
	}
	data, err := backend.Read(path.Join(s.trustListDir(opts.Issuer, opts.Path), "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored storedTrustList
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if got := stored.NextUpdate.Format(time.RFC3339); got != list.SchemeInfo.NextUpdate {
		t.Errorf("stored next update %s, the list's %s", got, list.SchemeInfo.NextUpdate)
	}
}

// The history of a trusted list only grows. Serving the current list and a
// stored signing certificate reads one blob each, not the whole directory.
func TestSigningStoreReadsOnlyTheCurrentBlob(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	backend := &readAllCounter{Store: storage.NewMemory()}
	s := NewKeys(backend, "", nil)
	sign := func(sequence int, _ time.Time, _ string) (string, error) {
		return fmt.Sprintf("list-%d", sequence), nil
	}
	for range 3 {
		if _, err := s.sequencedList("trustlists/x", ca, []byte("content"), sign); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Certificate(caKey, ca, &caKey.PublicKey, mock.LeafCertOptions{}, false); err != nil {
			t.Fatal(err)
		}
	}
	if backend.readAll != 0 {
		t.Fatalf("the store read whole directories %d times", backend.readAll)
	}
}
