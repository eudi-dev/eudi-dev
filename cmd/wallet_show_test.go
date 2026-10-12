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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func setupWalletWithCredential(t *testing.T) (string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("load wallet: %v", err)
	}

	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Key:    key,
		Claims: mock.DefaultClaims,
	})
	if err != nil {
		t.Fatalf("generate sdjwt: %v", err)
	}

	imported, err := w.ImportCredential(raw)
	if err != nil {
		t.Fatalf("import credential: %v", err)
	}
	if err := store.Save(w); err != nil {
		t.Fatalf("save wallet: %v", err)
	}

	return wDir, imported.ID
}

func TestWalletShow_Raw(t *testing.T) {
	wDir, credID := setupWalletWithCredential(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "show", credID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet show: %v", err)
	}
}

func TestWalletShow_Decoded(t *testing.T) {
	wDir, credID := setupWalletWithCredential(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "show", "--decoded", credID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet show --decoded: %v", err)
	}
}

func TestWalletShow_DecodedJSON(t *testing.T) {
	wDir, credID := setupWalletWithCredential(t)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"--json", "wallet", "show", "--decoded", credID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet show --decoded --json: %v", err)
	}
}

func TestWalletShow_NotFound(t *testing.T) {
	wDir, _ := setupWalletWithCredential(t)

	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "show", "nonexistent-id"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent credential")
	}
}

func TestWalletShow_MissingArg(t *testing.T) {
	rootCmd.SetArgs([]string{"wallet", "show"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing argument")
	}
}
