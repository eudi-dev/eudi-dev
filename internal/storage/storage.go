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

// Package storage stores wallet state, keys, certificates, assets and templates as
// blobs under slash-separated keys. File storage keeps the wallet directory layout.
package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
)

const EnvVar = "EUDI_DEV_STORAGE"

const (
	KindFile     = "file"
	KindMemory   = "memory"
	KindPostgres = "postgres"
)

// Store holds blobs under slash-separated keys relative to its root.
type Store interface {
	// Read returns the blob at key. A missing key returns an error that
	// satisfies errors.Is(err, fs.ErrNotExist).
	Read(key string) ([]byte, error)
	// Write replaces the blob at key atomically. A concurrent reader sees the
	// old or the new content. Only the file backend applies perm. Write returns
	// the blob's new stamp.
	Write(key string, data []byte, perm fs.FileMode) (Stamp, error)
	// Delete removes the blob at key. A missing key is not an error.
	Delete(key string) error
	// Stat returns the blob's stamp. A missing key returns an error that
	// satisfies errors.Is(err, fs.ErrNotExist).
	Stat(key string) (Stamp, error)
	// Exists reports whether a blob is at key. Unlike Stat it reads no
	// content.
	Exists(key string) (bool, error)
	// List returns the names of the blobs directly under prefix, sorted. A
	// missing prefix lists nothing.
	List(prefix string) ([]string, error)
	// ReadAll returns every blob under prefix, at any depth, by key.
	ReadAll(prefix string) (map[string]Blob, error)
	// Stamps returns the stamp of every blob under prefix, at any depth, by
	// key.
	Stamps(prefix string) (map[string]Stamp, error)
	// WriteIf replaces the blob at key only while its stamp version equals
	// expected. An expected value of "" means the blob must not exist yet. A
	// mismatch returns ErrConflict. WriteIf returns the blob's new stamp.
	WriteIf(key string, data []byte, perm fs.FileMode, expected string) (Stamp, error)
	// Locate returns a readable location of key for messages, such as the file
	// path on the file backend. An empty key returns the root.
	Locate(key string) string
	Kind() string
}

// ErrConflict reports that a WriteIf found the blob changed by someone else.
var ErrConflict = errors.New("storage: blob changed concurrently")

type Blob struct {
	Data  []byte
	Stamp Stamp
}

// Stamp identifies a blob's current content. The version changes whenever the
// content changes. A rewrite with identical content may keep it. A reader that
// cached a parse compares stamps to skip reparsing.
type Stamp struct {
	Version string
	Size    int64
}

type Options struct {
	// Root is the directory of the file backend. "auto" inspects it.
	Root string
	// RootRequested reports that a flag or an environment variable set the state
	// location. "auto" then picks files.
	RootRequested bool
}

var (
	autoOnce sync.Once
	autoKind string
)

// Open resolves auto once per process so all callers use the same backend. A requested
// or existing state directory selects files. Otherwise auto selects memory.
func Open(spec string, opts Options) (Store, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "" || spec == KindFile:
		return NewFile(opts.Root), nil
	case spec == KindMemory:
		return processMemory, nil
	case spec == "auto":
		autoOnce.Do(func() {
			autoKind = KindMemory
			if opts.RootRequested || rootHoldsState(opts.Root) {
				autoKind = KindFile
			}
		})
		return Open(autoKind, opts)
	case isPostgresSpec(spec):
		return openPostgres(spec)
	default:
		return nil, fmt.Errorf("unknown storage %q: use file, memory, auto or a postgres:// URL", spec)
	}
}

// The instance registry and remote target are local files that also exist with
// memory storage. They do not count as wallet state.
func rootHoldsState(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	if len(entries) == 0 {
		return true
	}
	for _, entry := range entries {
		if entry.Name() != "instances" && entry.Name() != "remote.json" {
			return true
		}
	}
	return false
}

// FromEnv returns a store that reports invalid backend configuration on first use.
func FromEnv(opts Options) Store {
	store, err := Open(os.Getenv(EnvVar), opts)
	if err != nil {
		return failingStore{err: err}
	}
	return store
}

type failingStore struct {
	err error
}

func (f failingStore) Read(string) ([]byte, error) { return nil, f.err }
func (f failingStore) Write(string, []byte, fs.FileMode) (Stamp, error) {
	return Stamp{}, f.err
}
func (f failingStore) Delete(string) error                     { return f.err }
func (f failingStore) Stat(string) (Stamp, error)              { return Stamp{}, f.err }
func (f failingStore) Exists(string) (bool, error)             { return false, f.err }
func (f failingStore) List(string) ([]string, error)           { return nil, f.err }
func (f failingStore) ReadAll(string) (map[string]Blob, error) { return nil, f.err }
func (f failingStore) Stamps(string) (map[string]Stamp, error) { return nil, f.err }
func (f failingStore) WriteIf(string, []byte, fs.FileMode, string) (Stamp, error) {
	return Stamp{}, f.err
}
func (f failingStore) Locate(string) string { return f.err.Error() }
func (f failingStore) Kind() string         { return "" }

// existsByStat answers Exists for a backend whose Stat reads no content.
func existsByStat(stat func(string) (Stamp, error), key string) (bool, error) {
	_, err := stat(key)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func isPostgresSpec(spec string) bool {
	return strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://")
}

func cleanKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("storage: empty key")
	}
	if strings.HasPrefix(key, "/") || path.Clean(key) != key || key == ".." || strings.HasPrefix(key, "../") {
		return "", fmt.Errorf("storage: invalid key %q", key)
	}
	return key, nil
}

func cleanPrefix(prefix string) (string, error) {
	if prefix == "" {
		return "", nil
	}
	return cleanKey(prefix)
}

// Every backend reports a missing key as fs.ErrNotExist.
func notExist(op, key string) error {
	return &fs.PathError{Op: op, Path: key, Err: fs.ErrNotExist}
}
