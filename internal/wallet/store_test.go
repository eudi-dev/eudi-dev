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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

func TestWalletStore_LoadOrCreate_NewWallet(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	if w.HolderKey == nil {
		t.Fatal("expected non-nil holder key")
	}
	if w.IssuerKey == nil {
		t.Fatal("expected non-nil issuer key")
	}
	if w.CAKey == nil || len(w.CertChain) < 2 {
		t.Fatal("expected shared CA-backed certificate chain")
	}
	if len(w.Credentials) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(w.Credentials))
	}

	if _, err := store.Backend().Stat(store.key("holder.pem")); err != nil {
		t.Error("expected holder.pem to exist")
	}
	if _, err := store.Backend().Stat(store.key("issuer.pem")); err != nil {
		t.Error("expected issuer.pem to exist")
	}
}

func TestWalletStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatalf("importing: %v", err)
	}
	if err := w.RegisterIssuedAttestation(provider.IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "TestCred"}); err != nil {
		t.Fatal(err)
	}

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}

	creds := w2.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential after reload, got %d", len(creds))
	}
	if creds[0].VCT != "TestCred" {
		t.Errorf("expected VCT TestCred, got %s", creds[0].VCT)
	}
	if len(creds[0].Disclosures) == 0 {
		t.Error("expected disclosures to be rehydrated")
	}
	if len(w2.IssuedAttestations) != 1 {
		t.Fatalf("expected 1 issued-attestation entry after reload, got %d", len(w2.IssuedAttestations))
	}
}

func TestWalletStore_Save_ConcurrentWritersLeaveValidFile(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	// Different document sizes expose trailing data left by interleaved writes.
	big, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	for i := 0; i < 200; i++ {
		big.Log = append(big.Log, LogEntry{Time: time.Now(), Action: "test", Detail: strings.Repeat("x", 200)})
	}

	done := make(chan error, 2)
	for _, wallet := range []*Wallet{w, big} {
		go func(w *Wallet) {
			for i := 0; i < 50; i++ {
				if err := store.Save(w); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(wallet)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Save: %v", err)
		}
	}

	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("LoadOrCreate after concurrent saves: %v", err)
	}
}

func TestWalletStore_SaveAndLoad_PersistsIssuerURLs(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	if w2.BaseURL != w.BaseURL {
		t.Fatalf("expected BaseURL %s, got %s", w.BaseURL, w2.BaseURL)
	}
	if w2.IssuerURL != w.IssuerURL {
		t.Fatalf("expected IssuerURL %s, got %s", w.IssuerURL, w2.IssuerURL)
	}
}

func TestWalletStore_SaveAndLoad_PersistsLog(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.AddLogDetails("presentation", "Received presentation request from verifier.example", true, map[string]any{
		"client_id":      "verifier.example",
		"response_uri":   "https://verifier.example/callback",
		"request_object": map[string]any{"nonce": "n-1"},
	})

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}

	logs := w2.GetLog()
	if len(logs) != 1 {
		t.Fatalf("expected 1 persisted log entry, got %d", len(logs))
	}
	if logs[0].Action != "presentation" {
		t.Fatalf("expected action presentation, got %s", logs[0].Action)
	}
	if logs[0].Details["client_id"] != "verifier.example" {
		t.Fatalf("expected client_id detail, got %v", logs[0].Details["client_id"])
	}
	requestObject, ok := logs[0].Details["request_object"].(map[string]any)
	if !ok {
		t.Fatalf("expected request_object detail, got %T", logs[0].Details["request_object"])
	}
	if requestObject["nonce"] != "n-1" {
		t.Fatalf("expected nonce n-1, got %v", requestObject["nonce"])
	}
}

func TestWalletStore_ClearLog(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.AddLog("issuance", "Received credential", true)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.ClearLog(); err != nil {
		t.Fatalf("ClearLog: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after clear: %v", err)
	}
	if got := len(w2.GetLog()); got != 0 {
		t.Fatalf("expected cleared log, got %d entries", got)
	}
}

func TestWalletStore_ClearLog_PreventsOldInMemoryLogsFromResurrecting(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.AddLog("issuance", "old credential", true)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.ClearLog(); err != nil {
		t.Fatalf("ClearLog: %v", err)
	}

	// The entry is newer than the clear, however coarse the clock.
	w.appendLogEntry(LogEntry{Time: store.loadLogCleanMarker().Add(time.Second), Action: "issuance", Detail: "new credential", Success: true})
	if err := store.Save(w); err != nil {
		t.Fatalf("Save after clean: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	logs := w2.GetLog()
	if len(logs) != 1 {
		t.Fatalf("expected only the new log entry, got %d", len(logs))
	}
	if logs[0].Detail != "new credential" {
		t.Fatalf("expected new credential log, got %q", logs[0].Detail)
	}
}

func TestWalletStore_KeyPersistence(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w1, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate second time: %v", err)
	}

	if !w1.HolderKey.Equal(w2.HolderKey) {
		t.Error("expected same holder key across loads")
	}
	if !w1.IssuerKey.Equal(w2.IssuerKey) {
		t.Error("expected same issuer key across loads")
	}
}

func TestNewWalletStore_DefaultDir(t *testing.T) {
	store := NewWalletStore("")
	if store.Dir == "" {
		t.Error("expected non-empty default dir")
	}
}

func TestWalletStore_FileLayout(t *testing.T) {
	store := NewWalletStoreOn("/tmp/test-wallet", storage.NewFile("/tmp"))
	locate := store.Backend().Locate
	for key, want := range map[string]string{
		store.walletKey():                    "/tmp/test-wallet/wallet.json",
		store.key("holder.pem"):              "/tmp/test-wallet/holder.pem",
		store.key("issuer.pem"):              "/tmp/test-wallet/issuer.pem",
		store.tlsCertPEM():                   "/tmp/test-wallet/wallet-tls-cert.pem",
		store.tlsKeyPEM():                    "/tmp/test-wallet/wallet-tls-key.pem",
		store.assetKey("x.png"):              "/tmp/test-wallet/assets/x.png",
		store.Templates().Prefix + "/t.json": "/tmp/test-wallet/templates/t.json",
		store.sharedCACertPEM():              "/tmp/wallet-ca-cert.pem",
		store.sharedCAKeyPEM():               "/tmp/wallet-ca-key.pem",
	} {
		if got := locate(key); got != want {
			t.Errorf("%s lives at %s, want %s", key, got, want)
		}
	}
	if store.Location() != "/tmp/test-wallet" {
		t.Errorf("Location = %s", store.Location())
	}
}

func TestDefaultWalletDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("EUDI_DEV_HOME", "")

	if got, want := DefaultWalletDir(), filepath.Join(home, ".eudi-dev", "wallet"); got != want {
		t.Errorf("wallet dir %s, want %s", got, want)
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_Persists(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	cert1, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate: %v", err)
	}
	cert2, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate second time: %v", err)
	}

	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("expected persisted issuer TLS certificate")
	}
	if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("expected issuer TLS certificate to persist across loads")
	}
	_, caCert, err := store.LoadOrCreateSharedCA()
	if err != nil {
		t.Fatalf("LoadOrCreateSharedCA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
		t.Fatalf("expected wallet TLS cert to chain to shared CA: %v", err)
	}
	if _, err := store.Backend().Stat(store.key("wallet-tls-cert.pem")); err != nil {
		t.Fatal("expected wallet-tls-cert.pem to exist")
	}
	if _, err := store.Backend().Stat(store.key("wallet-tls-key.pem")); err != nil {
		t.Fatal("expected wallet-tls-key.pem to exist")
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_MigratesLegacyPaths(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	certPEM, keyPEM, err := generateIssuerTLSCertificatePEMWithCA("localhost", nil, nil)
	if err != nil {
		t.Fatalf("generateIssuerTLSCertificatePEMWithCA: %v", err)
	}
	if _, err := store.Backend().Write(store.legacyTLSCertPEM(), certPEM, 0o644); err != nil {
		t.Fatalf("write legacy cert: %v", err)
	}
	if _, err := store.Backend().Write(store.legacyTLSKeyPEM(), keyPEM, 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	cert, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected migrated wallet TLS certificate")
	}
	if _, err := store.Backend().Stat(store.key("wallet-tls-cert.pem")); err != nil {
		t.Fatal("expected wallet-tls-cert.pem to exist after migration")
	}
	if _, err := store.Backend().Stat(store.key("wallet-tls-key.pem")); err != nil {
		t.Fatal("expected wallet-tls-key.pem to exist after migration")
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_RegeneratesForNewHost(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	cert1, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate localhost: %v", err)
	}
	cert2, err := store.LoadOrCreateIssuerTLSCertificate("issuer.example")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate issuer.example: %v", err)
	}

	if bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("expected issuer TLS certificate to regenerate for a different host")
	}
}

func TestWalletStore_LoadOrCreateSharedCA_SameParentDir(t *testing.T) {
	root := t.TempDir()
	store1 := NewWalletStore(filepath.Join(root, "wallet-a"))
	store2 := NewWalletStore(filepath.Join(root, "wallet-b"))

	_, cert1, err := store1.LoadOrCreateSharedCA()
	if err != nil {
		t.Fatalf("store1 LoadOrCreateSharedCA: %v", err)
	}
	_, cert2, err := store2.LoadOrCreateSharedCA()
	if err != nil {
		t.Fatalf("store2 LoadOrCreateSharedCA: %v", err)
	}

	if !bytes.Equal(cert1.Raw, cert2.Raw) {
		t.Fatal("expected stores under the same parent directory to share the same CA certificate")
	}
}

// Corrupt or mismatched CA material is reported, and the stored files stay as
// they are so the user can inspect them.
func TestWalletStore_LoadOrCreateSharedCA_RefusesUnusableMaterial(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(store *WalletStore) []byte{
		"unparseable certificate": func(*WalletStore) []byte { return []byte("not a certificate") },
		"certificate of another key": func(*WalletStore) []byte {
			cert, err := mock.GenerateRootCACert(otherKey)
			if err != nil {
				t.Fatal(err)
			}
			return certPEM(cert)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := NewWalletStore(filepath.Join(t.TempDir(), "wallet"))
			if _, _, err := store.LoadOrCreateSharedCA(); err != nil {
				t.Fatal(err)
			}
			keyBefore, err := store.Backend().Read(store.sharedCAKeyPEM())
			if err != nil {
				t.Fatal(err)
			}
			stored := corrupt(store)
			if _, err := store.Backend().Write(store.sharedCACertPEM(), stored, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.LoadOrCreateSharedCA(); err == nil {
				t.Fatal("LoadOrCreateSharedCA accepted unusable CA material")
			}
			keyAfter, _ := store.Backend().Read(store.sharedCAKeyPEM())
			certAfter, _ := store.Backend().Read(store.sharedCACertPEM())
			if !bytes.Equal(keyAfter, keyBefore) || !bytes.Equal(certAfter, stored) {
				t.Fatal("the stored CA material changed")
			}
		})
	}
}

// A CA certificate without its key cannot sign anything, so creating a new key
// beside it would leave two CAs under one name.
func TestWalletStore_LoadOrCreateSharedCA_RefusesACertificateWithoutKey(t *testing.T) {
	store := NewWalletStore(filepath.Join(t.TempDir(), "wallet"))
	if _, _, err := store.LoadOrCreateSharedCA(); err != nil {
		t.Fatal(err)
	}
	if err := store.Backend().Delete(store.sharedCAKeyPEM()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadOrCreateSharedCA(); err == nil {
		t.Fatal("LoadOrCreateSharedCA created a key beside an existing certificate")
	}
	if _, err := store.Backend().Stat(store.sharedCAKeyPEM()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("CA key Stat = %v, want no key", err)
	}
}

func TestWalletStore_LoadOrCreate_UsesSharedCA(t *testing.T) {
	root := t.TempDir()
	store1 := NewWalletStore(filepath.Join(root, "wallet-a"))
	store2 := NewWalletStore(filepath.Join(root, "wallet-b"))

	w1, err := store1.LoadOrCreate()
	if err != nil {
		t.Fatalf("store1 LoadOrCreate: %v", err)
	}
	w2, err := store2.LoadOrCreate()
	if err != nil {
		t.Fatalf("store2 LoadOrCreate: %v", err)
	}
	if len(w1.CertChain) < 2 || len(w2.CertChain) < 2 {
		t.Fatal("expected CA-backed cert chains on both wallets")
	}
	if !bytes.Equal(w1.CertChain[len(w1.CertChain)-1].Raw, w2.CertChain[len(w2.CertChain)-1].Raw) {
		t.Fatal("expected both wallets to use the same shared CA certificate")
	}
}

// Older files use pending_issuances. Loading must preserve those deferred credentials.
func TestLoadReadsTheLegacyPendingIssuancesField(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStoreOn(dir, storage.NewFile(filepath.Dir(dir)))
	legacy := `{
	  "credentials": [],
	  "pending_issuances": [
	    {"id": "def-1", "transaction_id": "tx-1", "deferred_endpoint": "https://issuer.example/deferred"}
	  ]
	}`
	if _, err := store.Backend().Write(store.walletKey(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	got := w.DeferredIssuanceList()
	if len(got) != 1 {
		t.Fatalf("deferred issuances = %d, want 1 (the legacy field was dropped)", len(got))
	}
	if got[0].TransactionID != "tx-1" {
		t.Errorf("transaction id = %q, want tx-1", got[0].TransactionID)
	}

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}
	saved, err := store.Backend().Read(store.walletKey())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), `"deferred_issuances"`) {
		t.Error("save did not write deferred_issuances")
	}
}

// Log entries arrive outside the server lock. An earlier snapshot must not overwrite a
// later import.
func TestStoreSavesDoNotLoseConcurrentWrites(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	w := generateTestWallet(t)
	srv := NewServer(w, 0, func() { _ = store.Save(w) })
	srv.SetStore(store)
	store.saveDelay = func() { time.Sleep(2 * time.Millisecond) }
	// A larger wallet makes concurrent saves more likely to overlap.
	padding := strings.Repeat("x", 4096)
	for i := 0; i < 100; i++ {
		w.PutCredential(StoredCredential{ID: fmt.Sprintf("pad-%03d", i), Format: "dc+sd-jwt", Raw: padding})
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Log callbacks run outside the server lock.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				w.AddLog("test", fmt.Sprintf("noise %d", i), true)
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = srv.reloadFromStore()
			}
		}
	}()

	for i := 0; i < 40; i++ {
		cred := StoredCredential{ID: fmt.Sprintf("cred-%02d", i), Format: "dc+sd-jwt", Raw: "a.b.c"}
		srv.saveMutation(func() bool {
			w.PutCredential(cred)
			return true
		})
	}
	close(stop)
	wg.Wait()

	if err := srv.reloadFromStore(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("cred-%02d", i)
		if _, ok := w.GetCredential(id); !ok {
			t.Fatalf("credential %s was lost by a concurrent save", id)
		}
	}
}

// statFailingBackend reports an outage on Stat and Exists while reads and
// writes work.
type statFailingBackend struct {
	storage.Store
}

func (statFailingBackend) Stat(string) (storage.Stamp, error) {
	return storage.Stamp{}, errors.New("database unreachable")
}

func (statFailingBackend) Exists(string) (bool, error) {
	return false, errors.New("database unreachable")
}

// A storage outage must not look like a missing counter. Allocating would
// restart the status list at index 0 and hand out used indices again.
func TestAllocateStatusIndexReportsAStorageOutage(t *testing.T) {
	backend := storage.NewMemory()
	store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.allocateStatusIndex(w); err != nil {
		t.Fatal(err)
	}
	store.backend = statFailingBackend{backend}
	if _, err := store.allocateStatusIndex(w); err == nil {
		t.Fatal("allocateStatusIndex succeeded while the backend failed")
	}
	data, err := backend.Read(store.counterKey())
	if err != nil || string(data) != "1" {
		t.Fatalf("status counter = %q, %v, want 1", data, err)
	}
}

// A storage outage fails storing a display image. The image is not kept embedded.
func TestStoreDisplayAssetReportsAStorageOutage(t *testing.T) {
	backend := storage.NewMemory()
	store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend)
	store.backend = statFailingBackend{backend}
	if _, _, err := store.storeDisplayAsset(tinyPNGDataURI); err == nil {
		t.Fatal("storeDisplayAsset succeeded while the backend failed")
	}
}

// On the file backend a flow logs outside the store lock while other
// requests reload. Every entry reaches the file.
func TestFileBackendKeepsLogEntriesAcrossConcurrentReloads(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(w, 0, nil)
	srv.SetStore(store)

	const entries = 200
	stop := make(chan struct{})
	reloaded := make(chan struct{})
	go func() {
		defer close(reloaded)
		for {
			select {
			case <-stop:
				return
			default:
				if err := srv.reloadFromStore(); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	for i := range entries {
		w.AddLog("test", fmt.Sprintf("entry %03d", i), true)
	}
	close(stop)
	<-reloaded

	saved, err := NewWalletStore(dir).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range saved.GetLog() {
		if entry.Action == "test" {
			found++
		}
	}
	if found != entries {
		t.Errorf("the file holds %d of %d log entries", found, entries)
	}
}

// The server's own save does not make the next request parse the file again.
func TestFileBackendSkipsReloadingItsOwnSave(t *testing.T) {
	store, err := OpenWalletStore(t.TempDir(), storage.KindFile)
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(w, 0, nil)
	srv.SetStore(store)
	srv.saveMutation(func() bool {
		w.AddLog("test", "saved by the server", true)
		return true
	})
	stamp, err := store.WalletStamp()
	if err != nil {
		t.Fatal(err)
	}
	srv.storeSyncMu.Lock()
	current := srv.lastWalletStamp
	srv.storeSyncMu.Unlock()
	if current != stamp {
		t.Error("the server reparses the file it saved itself")
	}
}
