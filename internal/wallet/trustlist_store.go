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
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
)

type storedTrustList struct {
	Identity   string    `json:"identity"`
	Sequence   int       `json:"sequence"`
	NextUpdate time.Time `json:"next_update"`
	JWT        string    `json:"jwt"`
}

func (s *signingStore) trustListDir(issuer, listPath string) string {
	id := sha256.Sum256([]byte(issuer + listPath))
	return path.Join(s.prefix, "trustlists", fmt.Sprintf("%x", id))
}

func (s *signingStore) archiveTrustList(dir string, list storedTrustList) error {
	key := path.Join(dir, "history", strconv.Itoa(list.Sequence)+".jwt")
	_, err := s.backend.WriteIf(key, []byte(list.JWT), 0644, "")
	if errors.Is(err, storage.ErrConflict) {
		return nil
	}
	return err
}

func (s *signingStore) trustList(key *ecdsa.PrivateKey, ca *x509.Certificate, opts trustListOptions) (string, error) {
	options, err := json.Marshal(opts)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	hash.Write(ca.Raw)
	hash.Write(options)
	identity := fmt.Sprintf("%x", hash.Sum(nil))
	dir := s.trustListDir(opts.Issuer, opts.TrustListPath)
	at := path.Join(dir, "current.json")
	for range 5 {
		blobs, err := s.backend.ReadAll(dir)
		if err != nil {
			return "", err
		}
		blob, exists := blobs[at]
		var current storedTrustList
		if exists {
			if err := json.Unmarshal(blob.Data, &current); err != nil {
				return "", fmt.Errorf("reading persisted trust list: %w", err)
			}
			if err := s.archiveTrustList(dir, current); err != nil {
				return "", err
			}
			if current.Identity == identity && time.Now().Before(current.NextUpdate) {
				return current.JWT, nil
			}
		}
		opts.Sequence = current.Sequence + 1
		jwt, err := generateTrustListJWTWithOptions(key, ca, opts)
		if err != nil {
			return "", err
		}
		updated := storedTrustList{Identity: identity, Sequence: opts.Sequence, NextUpdate: time.Now().UTC().Truncate(time.Second).Add(24 * time.Hour), JWT: jwt}
		data, err := json.Marshal(updated) //nolint:gosec // The signed trust list is public data.
		if err != nil {
			return "", err
		}
		if _, err := s.backend.WriteIf(at, data, 0644, blob.Stamp.Version); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				continue
			}
			return "", err
		}
		if err := s.archiveTrustList(dir, updated); err != nil {
			return "", err
		}
		return jwt, nil
	}
	return "", fmt.Errorf("trust list changed concurrently too often")
}
