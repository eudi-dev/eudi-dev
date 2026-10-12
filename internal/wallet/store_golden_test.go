package wallet

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden files of the stored wallet state")

// The stored wallet state is the contract with existing wallets: wallet.json
// on files and the entity rows on the other backends. A load and a save keep
// every field under its name.
func TestStoredStateMatchesTheGoldenFiles(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("testdata", "golden", "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	fileStore := goldenFileStore(t)
	if _, err := fileStore.backend.Write(fileStore.walletKey(), input, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := fileStore.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := fileStore.Save(w); err != nil {
		t.Fatal(err)
	}
	saved, err := fileStore.backend.Read(fileStore.walletKey())
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "wallet.json", saved)

	entityStore := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
	if err := entityStore.Save(w); err != nil {
		t.Fatal(err)
	}
	rows := goldenEntityRows(t, entityStore)
	compareGolden(t, "entities.json", rows)

	reloaded, err := entityStore.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	again := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
	if err := again.Save(reloaded); err != nil {
		t.Fatal(err)
	}
	if got := goldenEntityRows(t, again); string(got) != string(rows) {
		t.Errorf("the entity rows changed on a load and save:\n%s\nwant\n%s", got, rows)
	}
}

func goldenFileStore(t *testing.T) *WalletStore {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "wallet")
	store, err := OpenWalletStore(dir, storage.KindFile)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// goldenEntityRows lists the state rows by key below the state section. The
// revision rows hold random marks and are left out.
func goldenEntityRows(t *testing.T, store *WalletStore) []byte {
	t.Helper()
	blobs, err := store.backend.ReadAll(store.stateKey())
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]json.RawMessage{}
	prefix := store.stateKey() + "/"
	for key, blob := range blobs {
		name := strings.TrimPrefix(key, prefix)
		if strings.HasPrefix(name, revisionSection+"/") {
			continue
		}
		rows[name] = blob.Data
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from the golden file:\n%s\nwant\n%s", name, got, want)
	}
}
