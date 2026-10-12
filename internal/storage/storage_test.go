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

package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Tests share the Postgres table, so each uses its own key prefix.
func backends(t *testing.T) map[string]Store {
	t.Helper()
	stores := map[string]Store{
		KindFile:   NewFile(t.TempDir()),
		KindMemory: NewMemory(),
	}
	if dsn := os.Getenv(EnvVar); isPostgresSpec(dsn) {
		pg, err := openPostgres(dsn)
		if err != nil {
			t.Fatalf("opening postgres: %v", err)
		}
		stores[KindPostgres] = pg
	}
	return stores
}

func scope(t *testing.T) string {
	return strings.ReplaceAll(t.Name(), "/", "-") + "-" + strconv.Itoa(os.Getpid())
}

// A reader that caches a parse keeps the stamp ReadBlob returns, so the stamp
// must be the one Write and Stat report for that content.
func TestStore_ReadBlobReturnsTheStampOfItsContent(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			key := scope(t) + "/wallet/wallet.json"
			defer store.Delete(key)

			if _, err := store.ReadBlob(key); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("missing key: got %v, want fs.ErrNotExist", err)
			}
			written, err := store.Write(key, []byte("content"), 0o600)
			if err != nil {
				t.Fatal(err)
			}
			blob, err := store.ReadBlob(key)
			if err != nil || string(blob.Data) != "content" {
				t.Fatalf("ReadBlob = %q, %v", blob.Data, err)
			}
			stat, _ := store.Stat(key)
			if blob.Stamp != written || blob.Stamp != stat {
				t.Fatalf("ReadBlob stamp %+v, Write %+v, Stat %+v", blob.Stamp, written, stat)
			}
		})
	}
}

func TestStore_ReadWriteDeleteRoundTrip(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			key := scope(t) + "/wallet/wallet.json"
			defer store.Delete(key)

			if _, err := store.Read(key); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("missing key: got %v, want fs.ErrNotExist", err)
			}
			if _, err := store.Stat(key); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Stat of a missing key: got %v, want fs.ErrNotExist", err)
			}

			if _, err := store.Write(key, []byte("one"), 0o600); err != nil {
				t.Fatal(err)
			}
			data, err := store.Read(key)
			if err != nil || string(data) != "one" {
				t.Fatalf("Read = %q, %v", data, err)
			}
			first, err := store.Stat(key)
			if err != nil || first.Size != 3 {
				t.Fatalf("Stat = %+v, %v", first, err)
			}

			if _, err := store.Write(key, []byte("second"), 0o600); err != nil {
				t.Fatal(err)
			}
			second, _ := store.Stat(key)
			if second == first {
				t.Fatal("stamp did not change on rewrite")
			}
			if data, _ := store.Read(key); string(data) != "second" {
				t.Fatalf("Read after rewrite = %q", data)
			}
			if _, err := store.Write(key, []byte("SECOND"), 0o600); err != nil {
				t.Fatal(err)
			}
			if third, _ := store.Stat(key); third == second {
				t.Fatal("stamp did not change on a same-size rewrite")
			}

			if err := store.Delete(key); err != nil {
				t.Fatal(err)
			}
			if err := store.Delete(key); err != nil {
				t.Fatalf("deleting a missing key: %v", err)
			}
			if _, err := store.Read(key); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("after delete: %v", err)
			}
		})
	}
}

func TestStore_ListNamesDirectChildrenOnly(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			root := scope(t)
			keys := []string{root + "/assets/b.png", root + "/assets/a.png", root + "/assets/nested/c.png", root + "/wallet.json"}
			for _, key := range keys {
				if _, err := store.Write(key, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				defer store.Delete(key)
			}
			names, err := store.List(root + "/assets")
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"a.png", "b.png"}; !reflect.DeepEqual(names, want) {
				t.Fatalf("List = %v, want %v", names, want)
			}
			names, err = store.List(root + "/missing")
			if err != nil || len(names) != 0 {
				t.Fatalf("List of a missing prefix = %v, %v", names, err)
			}
		})
	}
}

func TestStore_ReadAllReturnsEveryBlobUnderPrefix(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			root := scope(t)
			for _, key := range []string{root + "/state/log/1", root + "/state/credentials/a", root + "/other"} {
				if _, err := store.Write(key, []byte(key), 0o600); err != nil {
					t.Fatal(err)
				}
				defer store.Delete(key)
			}
			blobs, err := store.ReadAll(root + "/state")
			if err != nil {
				t.Fatal(err)
			}
			if len(blobs) != 2 || string(blobs[root+"/state/log/1"].Data) != root+"/state/log/1" || string(blobs[root+"/state/credentials/a"].Data) != root+"/state/credentials/a" {
				t.Fatalf("ReadAll = %v", blobs)
			}
			if stamp, _ := store.Stat(root + "/state/log/1"); blobs[root+"/state/log/1"].Stamp != stamp {
				t.Fatalf("ReadAll stamp %+v, Stat %+v", blobs[root+"/state/log/1"].Stamp, stamp)
			}
			if blobs, err := store.ReadAll(root + "/missing"); err != nil || len(blobs) != 0 {
				t.Fatalf("ReadAll of a missing prefix = %v, %v", blobs, err)
			}
			stamps, err := store.Stamps(root + "/state")
			if err != nil || len(stamps) != 2 || stamps[root+"/state/log/1"] != blobs[root+"/state/log/1"].Stamp {
				t.Fatalf("Stamps = %v, %v (ReadAll stamp %+v)", stamps, err, blobs[root+"/state/log/1"].Stamp)
			}
		})
	}
}

// WriteIf lets several openers share a counter. A write that lost the race
// reports the conflict and keeps the winner's value. The file backend takes
// no lock and is left out.
func TestStore_WriteIfRefusesAStaleVersion(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			key := scope(t) + "/counter"
			defer store.Delete(key)
			if _, err := store.WriteIf(key, []byte("1"), 0o600, "9"); !errors.Is(err, ErrConflict) {
				t.Fatalf("creating with a version: %v", err)
			}
			if _, err := store.WriteIf(key, []byte("1"), 0o600, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := store.WriteIf(key, []byte("1"), 0o600, ""); !errors.Is(err, ErrConflict) {
				t.Fatalf("creating twice: %v", err)
			}
			stamp, _ := store.Stat(key)
			if _, err := store.WriteIf(key, []byte("2"), 0o600, stamp.Version); err != nil {
				t.Fatal(err)
			}
			if _, err := store.WriteIf(key, []byte("3"), 0o600, stamp.Version); !errors.Is(err, ErrConflict) {
				t.Fatalf("writing with the old version: %v", err)
			}
			if data, _ := store.Read(key); string(data) != "2" {
				t.Fatalf("counter = %s", data)
			}
		})
	}
}

// Concurrent counter allocation must return each value once.
func TestStore_WriteIfSerialisesConcurrentIncrements(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			key := scope(t) + "/counter"
			defer store.Delete(key)
			var mu sync.Mutex
			seen := make(map[int]bool)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for n := 0; n < 25; n++ {
						for {
							next, expected := 0, ""
							if stamp, err := store.Stat(key); err == nil {
								expected = stamp.Version
								data, err := store.Read(key)
								if err != nil {
									continue
								}
								next, _ = strconv.Atoi(string(data))
							}
							_, err := store.WriteIf(key, []byte(strconv.Itoa(next+1)), 0o600, expected)
							if errors.Is(err, ErrConflict) {
								continue
							}
							if err != nil {
								t.Error(err)
								return
							}
							mu.Lock()
							if seen[next] {
								t.Errorf("value %d handed out twice", next)
							}
							seen[next] = true
							mu.Unlock()
							break
						}
					}
				}()
			}
			wg.Wait()
			if len(seen) != 200 {
				t.Fatalf("%d distinct values, want 200", len(seen))
			}
		})
	}
}

// A reader that sees a revision written after a row also sees that row. The
// wallet's per-request reload checks the revision first and reads the state
// after.
func TestStore_ARowWrittenBeforeARevisionIsVisibleWithIt(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			root := scope(t)
			revision := root + "/revision"
			defer store.Delete(revision)
			defer func() {
				rows, _ := store.ReadAll(root + "/rows")
				for key := range rows {
					_ = store.Delete(key)
				}
			}()
			var wg sync.WaitGroup
			done := make(chan struct{})
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(done)
				for n := 0; n < 300; n++ {
					key := root + "/rows/" + strconv.Itoa(n)
					if _, err := store.Write(key, []byte("x"), 0o600); err != nil {
						t.Error(err)
						return
					}
					if _, err := store.Write(revision, []byte(strconv.Itoa(n)), 0o600); err != nil {
						t.Error(err)
						return
					}
				}
			}()
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-done:
							return
						default:
						}
						data, err := store.Read(revision)
						if err != nil {
							continue
						}
						n, _ := strconv.Atoi(string(data))
						rows, err := store.ReadAll(root + "/rows")
						if err != nil {
							t.Error(err)
							return
						}
						for k := 0; k <= n; k++ {
							if _, ok := rows[root+"/rows/"+strconv.Itoa(k)]; !ok {
								t.Errorf("revision of row %d seen, row %d not", n, k)
								return
							}
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestStore_RejectsEscapingKeys(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			for _, key := range []string{"", "/abs", "../up", "a/../b", "a/./b", "a//b"} {
				if _, err := store.Write(key, []byte("x"), 0o600); err == nil {
					t.Errorf("Write(%q) accepted", key)
				}
				if _, err := store.Read(key); err == nil {
					t.Errorf("Read(%q) accepted", key)
				}
			}
		})
	}
}

func TestStore_ConcurrentWritersLeaveWholeBlobs(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			key := scope(t) + "/wallet.json"
			defer store.Delete(key)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					body := []byte(fmt.Sprintf("{\"writer\":%d,\"pad\":\"%s\"}", i, strings.Repeat("x", 4096)))
					for j := 0; j < 20; j++ {
						if _, err := store.Write(key, body, 0o600); err != nil {
							t.Error(err)
							return
						}
						if got, err := store.Read(key); err != nil || len(got) != len(body) {
							t.Errorf("read a torn blob: len %d, err %v", len(got), err)
							return
						}
					}
				}(i)
			}
			wg.Wait()
		})
	}
}

func TestFile_LayoutMatchesTheWalletDirectory(t *testing.T) {
	root := t.TempDir()
	store := NewFile(root)
	if _, err := store.Write("wallet/wallet.json", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write("wallet/templates/t.json", []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if store.Locate("wallet/wallet.json") != filepath.Join(root, "wallet", "wallet.json") {
		t.Fatalf("Locate = %s", store.Locate("wallet/wallet.json"))
	}
	walletInfo, err := os.Stat(filepath.Join(root, "wallet"))
	if err != nil || walletInfo.Mode().Perm() != 0o700 {
		t.Fatalf("wallet dir mode = %v, %v", walletInfo.Mode(), err)
	}
	templatesInfo, err := os.Stat(filepath.Join(root, "wallet", "templates"))
	if err != nil || templatesInfo.Mode().Perm() != 0o755 {
		t.Fatalf("templates dir mode = %v, %v", templatesInfo.Mode(), err)
	}
	fileInfo, _ := os.Stat(filepath.Join(root, "wallet", "wallet.json"))
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("wallet.json mode = %v", fileInfo.Mode())
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, "wallet", ".tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// List must hide temporary files until the write completes.
func TestFile_ListHidesInFlightWrites(t *testing.T) {
	root := t.TempDir()
	store := NewFile(root)
	if _, err := store.Write("wallet/assets/a.png", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wallet", "assets", ".tmp-b.png-0a1b"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := store.List("wallet/assets")
	if err != nil || !reflect.DeepEqual(names, []string{"a.png"}) {
		t.Fatalf("List = %v, %v", names, err)
	}
}

// Coarse filesystem timestamps give two quick writes the same modification
// time. WriteIf must still refuse the version read before the second write.
func TestFile_WriteIfRefusesAVersionFromTheSameTimestampTick(t *testing.T) {
	root := t.TempDir()
	store := NewFile(root)
	stale, err := store.Write("wallet/counter", []byte("aaaa"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "wallet", "counter")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write("wallet/counter", []byte("bbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteIf("wallet/counter", []byte("cccc"), 0o600, stale.Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("WriteIf with the stale version: %v, want ErrConflict", err)
	}
}

// A blob that exists but cannot be read is an error, never a missing key.
func TestStore_ExistsReportsABlob(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			key := scope(t) + "/assets/image.png"
			defer store.Delete(key)
			if ok, err := store.Exists(key); ok || err != nil {
				t.Fatalf("Exists of a missing key = %v, %v", ok, err)
			}
			if _, err := store.Write(key, []byte("png"), 0o600); err != nil {
				t.Fatal(err)
			}
			if ok, err := store.Exists(key); !ok || err != nil {
				t.Fatalf("Exists of a written key = %v, %v", ok, err)
			}
		})
	}
}

// An existence check on the file backend reads the file's metadata only, so
// it answers for a blob it may not read.
func TestFile_ExistsReadsNoContent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of their mode")
	}
	root := t.TempDir()
	store := NewFile(root)
	if _, err := store.Write("assets/image.png", []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "assets", "image.png"), 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Exists("assets/image.png"); !ok || err != nil {
		t.Fatalf("Exists of an unreadable blob = %v, %v", ok, err)
	}
}

func TestStat_ReportsErrorsOtherThanAMissingKey(t *testing.T) {
	failing := failingStore{err: errors.New("database unreachable")}
	if _, err := failing.Stat("wallet/wallet.json"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat on an unreachable backend = %v, want the backend error", err)
	}

	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of their mode")
	}
	root := t.TempDir()
	store := NewFile(root)
	if _, err := store.Write("wallet/wallet.json", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "wallet", "wallet.json"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stat("wallet/wallet.json"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat of an unreadable blob = %v, want a read error", err)
	}
}

func TestPostgres_PrefixIndexExists(t *testing.T) {
	pg, ok := backends(t)[KindPostgres].(*postgresStore)
	if !ok {
		t.Skip("runs when the suite runs on the postgres backend")
	}
	if _, err := pg.db.Exec(`DROP INDEX IF EXISTS ` + postgresTable + `_prefix`); err != nil {
		t.Fatal(err)
	}
	pg.prepared = false
	if _, err := pg.Write(scope(t)+"/row", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pg.db.QueryRow(`SELECT count(*) FROM pg_indexes WHERE indexname = $1`, postgresTable+"_prefix").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("prefix indexes = %d, want 1", n)
	}
}

func TestMemory_IsSharedPerProcess(t *testing.T) {
	key := scope(t) + "/shared"
	first, _ := Open(KindMemory, Options{})
	second, _ := Open(KindMemory, Options{})
	defer first.Delete(key)
	if _, err := first.Write(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(key); err != nil {
		t.Fatalf("second opener does not see the blob: %v", err)
	}
	if _, err := NewMemory().Read(key); err == nil {
		t.Fatal("an isolated memory store sees the shared blob")
	}
}

func TestOpen_SelectsBackends(t *testing.T) {
	root := t.TempDir()
	for spec, kind := range map[string]string{"": KindFile, "file": KindFile, "memory": KindMemory} {
		store, err := Open(spec, Options{Root: root})
		if err != nil || store.Kind() != kind {
			t.Errorf("Open(%q) = %v, %v", spec, store, err)
		}
	}
	if _, err := Open("h2", Options{Root: root}); err == nil {
		t.Fatal("unknown spec accepted")
	}
}

func TestOpen_AutoPicksFilesForANamedOrExistingRoot(t *testing.T) {
	t.Cleanup(func() { autoOnce = sync.Once{} })
	auto := func(opts Options) string {
		autoOnce = sync.Once{}
		store, err := Open("auto", opts)
		if err != nil {
			t.Fatal(err)
		}
		return store.Kind()
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if kind := auto(Options{Root: missing}); kind != KindMemory {
		t.Fatalf("missing root: %s", kind)
	}
	if kind := auto(Options{Root: missing, RootRequested: true}); kind != KindFile {
		t.Fatalf("requested root: %s", kind)
	}
	if kind := auto(Options{Root: t.TempDir()}); kind != KindFile {
		t.Fatalf("empty root (a mounted volume): %s", kind)
	}

	// The instance registry of a memory-backed server is not wallet state, so
	// the next start of the same container still picks memory.
	bookkeeping := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bookkeeping, "instances"), 0o755); err != nil {
		t.Fatal(err)
	}
	if kind := auto(Options{Root: bookkeeping}); kind != KindMemory {
		t.Fatalf("root holding only the registry: %s", kind)
	}
	if err := os.MkdirAll(filepath.Join(bookkeeping, "wallet"), 0o700); err != nil {
		t.Fatal(err)
	}
	if kind := auto(Options{Root: bookkeeping}); kind != KindFile {
		t.Fatalf("root holding a wallet: %s", kind)
	}

	if kind := auto(Options{Root: missing}); kind != KindMemory {
		t.Fatal("expected memory")
	}
	if err := os.MkdirAll(missing, 0o700); err != nil {
		t.Fatal(err)
	}
	if store, _ := Open("auto", Options{Root: missing}); store.Kind() != KindMemory {
		t.Fatal("auto changed within the process")
	}
}

func TestPostgresLabelDropsCredentials(t *testing.T) {
	if got := postgresLabel("postgres://user:secret@db.example:5432/eudi?sslmode=disable"); got != "postgres://db.example:5432/eudi" {
		t.Fatalf("label = %s", got)
	}
}

// Another process can delete a blob while a reader lists the directory.
func TestFile_WalkSkipsABlobDeletedDuringTheWalk(t *testing.T) {
	dir := t.TempDir()
	s := NewFile(dir).(*fileStore)
	for _, key := range []string{"w/a", "w/b", "w/c"} {
		if _, err := s.Write(key, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	err := s.walk("w", func(key string, _ []byte) error {
		seen = append(seen, key)
		if key == "w/a" {
			return os.Remove(filepath.Join(dir, "w", "b"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !reflect.DeepEqual(seen, []string{"w/a", "w/c"}) {
		t.Fatalf("walk visited %v, want [w/a w/c]", seen)
	}
}
