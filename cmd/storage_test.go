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

package cmd

import (
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func TestOpenStore_FlagBeatsEnvironment(t *testing.T) {
	t.Setenv(storage.EnvVar, storage.KindMemory)
	walletDir = t.TempDir()
	storageSpec = ""
	t.Cleanup(func() { walletDir, storageSpec = "", "" })

	store, err := openStore()
	if err != nil || store.Backend().Kind() != storage.KindMemory {
		t.Fatalf("from the environment: %v, %v", store, err)
	}

	storageSpec = storage.KindFile
	store, err = openStore()
	if err != nil || store.Backend().Kind() != storage.KindFile {
		t.Fatalf("from the flag: %v, %v", store, err)
	}

	storageSpec = "h2"
	if _, err := openStore(); err == nil {
		t.Fatal("unknown --storage accepted")
	}
}

// Wallet commands find a running server by the wallet directory. That key
// must be the same on every backend. Otherwise a CLI using files misses a
// memory-backed server for the same wallet.
func TestResolvedWalletDir_IsBackendIndependent(t *testing.T) {
	walletDir = t.TempDir()
	t.Cleanup(func() { walletDir = "" })
	t.Setenv(storage.EnvVar, storage.KindMemory)
	store, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.Dir != resolvedWalletDir() {
		t.Fatalf("store dir %s, the CLI routes by %s", store.Dir, resolvedWalletDir())
	}
}

func TestOpenStore_SeedFlagBeatsEnvironment(t *testing.T) {
	walletDir = t.TempDir()
	t.Cleanup(func() { walletDir, storageSpec, keySeed = "", "", "" })
	t.Setenv(wallet.SeedEnvVar, "")
	storageSpec = storage.KindFile
	keySeed = "bench"
	store, err := openStore()
	if err != nil || !store.Seeded() {
		t.Fatalf("--seed with an empty environment seed: seeded %t, %v", store.Seeded(), err)
	}
}
