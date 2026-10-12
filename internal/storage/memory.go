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
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type memoryStore struct {
	mu    sync.RWMutex
	blobs map[string]memoryBlob
	seq   uint64
}

type memoryBlob struct {
	data    []byte
	version uint64
}

func (b memoryBlob) stamp() Stamp {
	return Stamp{Version: strconv.FormatUint(b.version, 10), Size: int64(len(b.data))}
}

// processMemory is the memory store shared by every opener in the process.
var processMemory = NewMemory()

// NewMemory returns a new empty memory store. Tests use it for isolation from
// the process-wide store.
func NewMemory() Store {
	return &memoryStore{blobs: make(map[string]memoryBlob)}
}

func (s *memoryStore) Read(key string) ([]byte, error) {
	key, err := cleanKey(key)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.blobs[key]
	if !ok {
		return nil, notExist("read", key)
	}
	return append([]byte(nil), blob.data...), nil
}

func (s *memoryStore) ReadBlob(key string) (Blob, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Blob{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.blobs[key]
	if !ok {
		return Blob{}, notExist("read", key)
	}
	return Blob{Data: append([]byte(nil), blob.data...), Stamp: blob.stamp()}, nil
}

func (s *memoryStore) Write(key string, data []byte, _ fs.FileMode) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.put(key, data), nil
}

// put stores data under key and returns the new stamp. Caller holds mu.
func (s *memoryStore) put(key string, data []byte) Stamp {
	s.seq++
	blob := memoryBlob{data: append([]byte(nil), data...), version: s.seq}
	s.blobs[key] = blob
	return blob.stamp()
}

func (s *memoryStore) Delete(key string) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, key)
	return nil
}

func (s *memoryStore) Stat(key string) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.blobs[key]
	if !ok {
		return Stamp{}, notExist("stat", key)
	}
	return blob.stamp(), nil
}

func (s *memoryStore) Exists(key string) (bool, error) { return existsByStat(s.Stat, key) }

func (s *memoryStore) List(prefix string) ([]string, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var names []string
	for key := range s.blobs {
		name, ok := strings.CutPrefix(key, prefix)
		if !ok || strings.Contains(name, "/") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *memoryStore) ReadAll(prefix string) (map[string]Blob, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blobs := make(map[string]Blob)
	for key, blob := range s.blobs {
		if strings.HasPrefix(key, prefix) {
			blobs[key] = Blob{Data: append([]byte(nil), blob.data...), Stamp: blob.stamp()}
		}
	}
	return blobs, nil
}

func (s *memoryStore) Stamps(prefix string) (map[string]Stamp, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stamps := make(map[string]Stamp)
	for key, blob := range s.blobs {
		if strings.HasPrefix(key, prefix) {
			stamps[key] = blob.stamp()
		}
	}
	return stamps, nil
}

func (s *memoryStore) WriteIf(key string, data []byte, _ fs.FileMode, expected string) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, ok := s.blobs[key]
	if (ok && blob.stamp().Version != expected) || (!ok && expected != "") {
		return Stamp{}, ErrConflict
	}
	return s.put(key, data), nil
}

func (s *memoryStore) Locate(key string) string {
	if key == "" {
		return KindMemory
	}
	return KindMemory + ":" + key
}

func (s *memoryStore) Kind() string { return KindMemory }
