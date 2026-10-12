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

import (
	"crypto/ecdsa"
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

// Stores opened for the same wallet must share persisted state, keys and CA material.
func TestWalletStore_SameNameSharesStateAcrossOpeners(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	backend := storage.NewMemory()

	first := NewWalletStoreOn(dir, backend)
	w, err := first.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: "Shared", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(w); err != nil {
		t.Fatal(err)
	}
	if _, err := credtemplate.Save(first.Templates(), credtemplate.Template{Name: "shared", Format: "sdjwt", Claims: map[string]any{"x": 1}}); err != nil {
		t.Fatal(err)
	}

	second := NewWalletStoreOn(dir, backend)
	reloaded, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Credentials) != 1 || reloaded.Credentials[0].VCT != "Shared" {
		t.Fatalf("second opener sees %d credentials", len(reloaded.Credentials))
	}
	if !reloaded.HolderKey.Equal(w.HolderKey) || !reloaded.CAKey.Equal(w.CAKey) {
		t.Fatal("second opener generated its own keys")
	}
	if _, err := credtemplate.Load("shared", second.Templates()); err != nil {
		t.Fatalf("second opener does not see the template: %v", err)
	}

	other := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend)
	if w, err := other.LoadOrCreate(); err != nil || len(w.Credentials) != 0 {
		t.Fatalf("a wallet under another directory shares state: %d credentials, %v", len(w.Credentials), err)
	}
}

func TestNewWalletStore_FollowsTheStorageEnvironment(t *testing.T) {
	t.Setenv(storage.EnvVar, storage.KindMemory)
	if kind := NewWalletStore(t.TempDir()).Backend().Kind(); kind != storage.KindMemory {
		t.Fatalf("backend = %s", kind)
	}

	t.Setenv(storage.EnvVar, "h2")
	if _, err := NewWalletStore(t.TempDir()).LoadOrCreate(); err == nil {
		t.Fatal("an unknown backend loaded a wallet")
	}
	if _, err := OpenWalletStore(t.TempDir(), "h2"); err == nil {
		t.Fatal("OpenWalletStore accepted an unknown backend")
	}
}

// The default prefix is independent of the home directory so host commands and
// containers can share a Postgres wallet.
func TestWalletKeyPrefix(t *testing.T) {
	t.Setenv("EUDI_DEV_HOME", filepath.Join(t.TempDir(), "state"))
	if got := walletKeyPrefix(DefaultWalletDir()); got != "wallet" {
		t.Fatalf("default wallet prefix = %q", got)
	}
	if got := walletKeyPrefix(filepath.Join(filepath.Dir(DefaultWalletDir()), "second")); got != "second" {
		t.Fatalf("sibling wallet prefix = %q", got)
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if got := walletKeyPrefix(outside); got != filepath.ToSlash(outside)[1:] {
		t.Fatalf("outside wallet prefix = %q", got)
	}
}

func TestServerReloadSeesAnotherOpenersWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	backend := storage.NewMemory()
	srv := newTestServer(t, false)
	first := NewWalletStoreOn(dir, backend)
	if _, err := first.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	srv.SetStore(first)
	if creds := decodeJSONArray(t, serverRequest(t, srv, http.MethodGet, "/api/credentials", "")); len(creds) != 0 {
		t.Fatalf("fresh wallet lists %d credentials", len(creds))
	}

	second := NewWalletStoreOn(dir, backend)
	w, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: "Elsewhere", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatal(err)
	}
	if err := second.Save(w); err != nil {
		t.Fatal(err)
	}

	creds := decodeJSONArray(t, serverRequest(t, srv, http.MethodGet, "/api/credentials", ""))
	if len(creds) != 1 || creds[0].(map[string]any)["vct"] != "Elsewhere" {
		t.Fatalf("server lists %v after another opener saved", creds)
	}
}

func TestConfigReportsTheStorageBackend(t *testing.T) {
	t.Setenv(SeedEnvVar, "")
	srv := newTestServer(t, false)
	srv.SetStore(NewWalletStoreOn(t.TempDir(), storage.NewMemory()))
	config := decodeJSON(t, serverRequest(t, srv, http.MethodGet, "/api/config", ""))
	if config["storage"] != storage.KindMemory || config["seeded_keys"] != false {
		t.Fatalf("storage = %v, seeded_keys = %v", config["storage"], config["seeded_keys"])
	}
}

// A seed preserves generated identities across fresh starts without persistent state.
func TestWalletStore_SeededKeysAreStableAcrossFreshStarts(t *testing.T) {
	fresh := func(seed string) (*Wallet, *WalletStore) {
		store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
		store.SetSeed(seed)
		w, err := store.LoadOrCreate()
		if err != nil {
			t.Fatal(err)
		}
		return w, store
	}
	first, firstStore := fresh("bench")
	again, againStore := fresh("bench")
	if !first.HolderKey.Equal(again.HolderKey) || !first.IssuerKey.Equal(again.IssuerKey) || !first.CAKey.Equal(again.CAKey) {
		t.Fatal("the same seed gave different keys on a fresh start")
	}
	tls, _ := firstStore.LoadOrCreateIssuerTLSCertificate("localhost")
	tlsAgain, _ := againStore.LoadOrCreateIssuerTLSCertificate("localhost")
	if !tls.PrivateKey.(*ecdsa.PrivateKey).Equal(tlsAgain.PrivateKey) {
		t.Fatal("the same seed gave different TLS keys")
	}
	if !firstStore.Seeded() {
		t.Fatal("a seeded store reports no seed")
	}

	other, _ := fresh("bench-2")
	random, randomStore := fresh("")
	if other.HolderKey.Equal(first.HolderKey) || random.HolderKey.Equal(first.HolderKey) || randomStore.Seeded() {
		t.Fatal("another seed or no seed repeated the keys")
	}
}

// auto uses the public seed only for memory storage.
func TestWalletStore_AutoSeedAppliesToMemoryOnly(t *testing.T) {
	memory := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
	memory.SetSeed("auto")
	file := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewFile(t.TempDir()))
	file.SetSeed("auto")
	if !memory.Seeded() || file.Seeded() {
		t.Fatalf("seeded: memory %t, file %t", memory.Seeded(), file.Seeded())
	}
	t.Setenv(SeedEnvVar, "auto")
	if !NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory()).Seeded() {
		t.Fatal("the environment's auto did not seed a memory store")
	}
}

// A one-shot command serves under URLs of its own run. The stored URLs
// belong to wallet serve, so a save keeps them (ADR-0019).
func TestOverrideURLsHoldForOneRun(t *testing.T) {
	for name, store := range map[string]*WalletStore{
		"file":   NewWalletStore(t.TempDir()),
		"memory": NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory()),
	} {
		t.Run(name, func(t *testing.T) {
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			w.BaseURL, w.IssuerURL = "https://wallet.example", "https://wallet.example"
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			w.OverrideURLs("http://localhost:9000", "https://localhost:9001")
			if w.StatusListURL() != "https://localhost:9001/api/statuslist" {
				t.Fatalf("the run does not use its own URLs: %s", w.StatusListURL())
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := NewWalletStoreOn(store.Dir, store.Backend()).LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.BaseURL != "https://wallet.example" || reloaded.IssuerURL != "https://wallet.example" {
				t.Fatalf("the run stored its URLs: %q %q", reloaded.BaseURL, reloaded.IssuerURL)
			}
		})
	}
}

type writeCounter struct {
	storage.Store
	writes int
}

func (c *writeCounter) Write(key string, data []byte, perm fs.FileMode) (storage.Stamp, error) {
	c.writes++
	return c.Store.Write(key, data, perm)
}

func (c *writeCounter) WriteIf(key string, data []byte, perm fs.FileMode, expected string) (storage.Stamp, error) {
	c.writes++
	return c.Store.WriteIf(key, data, perm, expected)
}

// GET /api/certificates/tls reads the stored certificate. Reading it writes
// nothing.
func TestReadingTheTLSCertificateWritesNothing(t *testing.T) {
	backend := &writeCounter{Store: storage.NewMemory()}
	store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend)
	if _, err := store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL("https://localhost:8086"); err != nil {
		t.Fatal(err)
	}
	backend.writes = 0
	if _, err := store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL("https://localhost:8086"); err != nil {
		t.Fatal(err)
	}
	if backend.writes != 0 {
		t.Fatalf("reading the stored certificate wrote %d times", backend.writes)
	}
}

type readCounter struct {
	storage.Store
	reads atomic.Int64
}

func (c *readCounter) Read(key string) ([]byte, error) {
	c.reads.Add(1)
	return c.Store.Read(key)
}

func (c *readCounter) ReadBlob(key string) (storage.Blob, error) {
	c.reads.Add(1)
	return c.Store.ReadBlob(key)
}

// walletFileReads counts the reads of wallet.json. A file Stat reads the
// content to hash it, so it counts as a read.
type walletFileReads struct {
	storage.Store
	reads atomic.Int64
}

func (c *walletFileReads) count(key string) {
	if path.Base(key) == "wallet.json" {
		c.reads.Add(1)
	}
}

func (c *walletFileReads) Read(key string) ([]byte, error) {
	c.count(key)
	return c.Store.Read(key)
}

func (c *walletFileReads) ReadBlob(key string) (storage.Blob, error) {
	c.count(key)
	return c.Store.ReadBlob(key)
}

func (c *walletFileReads) Stat(key string) (storage.Stamp, error) {
	c.count(key)
	return c.Store.Stat(key)
}

// A server on the file backend reads wallet.json once when another process
// changed it, and once to see that it did not change.
func TestFileBackendReloadReadsTheWalletOnce(t *testing.T) {
	dir := t.TempDir()
	backend := &walletFileReads{Store: storage.NewFile(dir)}
	store := NewWalletStoreOn(filepath.Join(dir, "wallet"), backend)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(w, 0, nil)
	srv.SetStore(store)

	other := NewWalletStoreOn(filepath.Join(dir, "wallet"), backend)
	o, err := other.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	importTestCredential(t, o, "Elsewhere")
	if err := other.Save(o); err != nil {
		t.Fatal(err)
	}

	backend.reads.Store(0)
	if err := srv.reloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if reads := backend.reads.Load(); reads != 1 {
		t.Fatalf("reloading a changed wallet read wallet.json %d times", reads)
	}
	if creds := w.GetCredentials(); len(creds) != 1 || creds[0].VCT != "Elsewhere" {
		t.Fatalf("the reload loaded %d credentials", len(creds))
	}

	backend.reads.Store(0)
	if err := srv.reloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if reads := backend.reads.Load(); reads != 1 {
		t.Fatalf("checking an unchanged wallet read wallet.json %d times", reads)
	}
}

// --arf takes the anchors of access certificates, registration certificates
// and their status lists from the same trusted lists. A request reads the
// lists once.
func TestPrepareARFChecksReadsTheTrustedListsOnce(t *testing.T) {
	backend := &readCounter{Store: storage.NewMemory()}
	w, err := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	w.IssuerURL = "https://wallet.example"
	w.RequireARF = true
	w.TrustedLists().Lists()
	backend.reads.Store(0)
	w.TrustedLists().Lists()
	once := backend.reads.Load()

	backend.reads.Store(0)
	w.PrepareARFChecks(&oid4vp.Request{})
	// A second pass over the lists would double the count.
	if reads := backend.reads.Load(); reads >= 2*once {
		t.Fatalf("preparing the checks read %d blobs, one pass over the lists reads %d", reads, once)
	}
}
