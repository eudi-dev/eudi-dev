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
	"fmt"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

type readAllCounter struct {
	storage.Store
	readAll int
}

func (c *readAllCounter) ReadAll(prefix string) (map[string]storage.Blob, error) {
	c.readAll++
	return c.Store.ReadAll(prefix)
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
	sign := func(sequence int) (string, error) { return fmt.Sprintf("list-%d", sequence), nil }
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
