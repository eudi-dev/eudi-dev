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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gofrs/flock"
)

// tempPrefix marks an in-flight write. No wallet key starts with it, so List
// can hide such files.
const tempPrefix = ".tmp-"

type fileStore struct {
	root string
}

// NewFile returns a store rooted at dir. The directory is created on the
// first write.
func NewFile(dir string) Store {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return &fileStore{root: dir}
}

func (s *fileStore) path(key string) string {
	return filepath.Join(s.root, filepath.FromSlash(key))
}

func (s *fileStore) Read(key string) ([]byte, error) {
	key, err := cleanKey(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(s.path(key))
}

// Write creates a missing directory with 0755 for a world-readable blob and
// 0700 otherwise. The file is written beside the target and renamed into
// place, so a concurrent reader never sees a partial file. The sync before
// the rename keeps a crash from leaving an empty file under the key.
func (s *fileStore) Write(key string, data []byte, perm fs.FileMode) (Stamp, error) {
	lock, err := s.writeLock()
	if err != nil {
		return Stamp{}, err
	}
	defer func() { _ = lock.Close() }()
	return s.write(key, data, perm)
}

func (s *fileStore) writeLock() (*flock.Flock, error) {
	if err := os.MkdirAll(s.root, 0700); err != nil {
		return nil, err
	}
	lock := flock.New(filepath.Join(s.root, tempPrefix+"write.lock"))
	if err := lock.Lock(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func (s *fileStore) write(key string, data []byte, perm fs.FileMode) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	target := s.path(key)
	dir := filepath.Dir(target)
	dirPerm := fs.FileMode(0o700)
	if perm&0o004 != 0 {
		dirPerm = 0o755
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return Stamp{}, fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := createTemp(dir, filepath.Base(target), perm)
	if err != nil {
		return Stamp{}, fmt.Errorf("creating temporary file for %s: %w", target, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return Stamp{}, fmt.Errorf("writing %s: %w", target, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Stamp{}, fmt.Errorf("writing %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		return Stamp{}, fmt.Errorf("writing %s: %w", target, err)
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return Stamp{}, err
	}
	return contentStamp(data), nil
}

func createTemp(dir, base string, perm fs.FileMode) (*os.File, error) {
	for {
		var suffix [4]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, tempPrefix+base+"-"+hex.EncodeToString(suffix[:]))
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
}

func (s *fileStore) Delete(key string) error {
	lock, err := s.writeLock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	key, err = cleanKey(key)
	if err != nil {
		return err
	}
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s *fileStore) Stat(key string) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	info, err := os.Stat(s.path(key))
	if err != nil {
		return Stamp{}, err
	}
	if info.IsDir() {
		return Stamp{}, notExist("stat", key)
	}
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		return Stamp{}, err
	}
	return contentStamp(data), nil
}

func (s *fileStore) Exists(key string) (bool, error) {
	key, err := cleanKey(key)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

func (s *fileStore) List(prefix string) ([]string, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.path(prefix))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), tempPrefix) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (s *fileStore) ReadAll(prefix string) (map[string]Blob, error) {
	blobs := make(map[string]Blob)
	err := s.walk(prefix, func(key string, data []byte) error {
		blobs[key] = Blob{Data: data, Stamp: contentStamp(data)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return blobs, nil
}

func (s *fileStore) Stamps(prefix string) (map[string]Stamp, error) {
	stamps := make(map[string]Stamp)
	err := s.walk(prefix, func(key string, data []byte) error {
		stamps[key] = contentStamp(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stamps, nil
}

func (s *fileStore) walk(prefix string, visit func(key string, data []byte) error) error {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = root.Close() }()
	rootFS := root.FS()
	if prefix == "" {
		prefix = "."
	}
	return fs.WalkDir(rootFS, prefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), tempPrefix) {
			return nil
		}
		data, err := fs.ReadFile(rootFS, p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return visit(p, data)
	})
}

// Modification times are too coarse on some filesystems to tell two writes
// apart, so the file backend versions a blob by its content.
func contentStamp(data []byte) Stamp {
	sum := sha256.Sum256(data)
	return Stamp{Version: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func (s *fileStore) WriteIf(key string, data []byte, perm fs.FileMode, expected string) (Stamp, error) {
	lock, err := s.writeLock()
	if err != nil {
		return Stamp{}, err
	}
	defer func() { _ = lock.Close() }()
	current, err := s.Stat(key)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Stamp{}, err
	}
	if (exists && current.Version != expected) || (!exists && expected != "") {
		return Stamp{}, ErrConflict
	}
	return s.write(key, data, perm)
}

func (s *fileStore) Locate(key string) string {
	if key == "" {
		return s.root
	}
	return s.path(key)
}

func (s *fileStore) Kind() string { return KindFile }
