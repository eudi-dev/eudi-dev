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

package provider

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

// DefaultTrustListPath serves the PID list for clients that know a single
// trusted list.
const DefaultTrustListPath = "/api/trustlist"

type storedTrustList struct {
	Identity   string    `json:"identity"`
	Sequence   int       `json:"sequence"`
	NextUpdate time.Time `json:"next_update"`
	JWT        string    `json:"jwt"`
}

func (s *Keys) trustListDir(issuer, listPath string) string {
	id := sha256.Sum256([]byte(issuer + listPath))
	return path.Join(s.prefix, "trustlists", fmt.Sprintf("%x", id))
}

func (s *Keys) archiveTrustList(dir string, list storedTrustList) error {
	key := path.Join(dir, "history", strconv.Itoa(list.Sequence)+".jwt")
	_, err := s.backend.WriteIf(key, []byte(list.JWT), 0644, "")
	if errors.Is(err, storage.ErrConflict) {
		return nil
	}
	return err
}

// TrustList returns the current list that key signs under ca with the
// options. Unset options take the wallet's defaults. A list without a type
// is an EAA list.
func (s *Keys) TrustList(key *ecdsa.PrivateKey, ca *x509.Certificate, opts lote.Options) (string, error) {
	options, err := json.Marshal(opts)
	if err != nil {
		return "", err
	}
	return s.sequencedList(s.trustListDir(opts.Issuer, opts.Path), ca, options, func(sequence int) (string, error) {
		opts.Sequence = sequence
		return SignTrustList(key, ca, opts)
	})
}

// SignTrustList signs a list with the wallet's defaults for unset options.
func SignTrustList(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate, opts lote.Options) (string, error) {
	if strings.TrimSpace(opts.OperatorName) == "" {
		opts.OperatorName = config.WalletName
	}
	if opts.Profile.LoTEType == "" {
		opts.Profile = CategoryProfile(credtemplate.CategoryEAA)
	}
	if opts.Profile.SchemeTerritory == "" {
		opts.Profile.SchemeTerritory = mock.DefaultCertificateCountry
	}
	eaa := CategoryProfile(credtemplate.CategoryEAA)
	opts.Profile.StatusDeterminationApproach = firstNonEmpty(opts.Profile.StatusDeterminationApproach, eaa.StatusDeterminationApproach)
	opts.Profile.SchemeTypeCommunityRules = firstNonEmpty(opts.Profile.SchemeTypeCommunityRules, eaa.SchemeTypeCommunityRules)
	opts.Path = firstNonEmpty(opts.Path, DefaultTrustListPath)
	opts.Country = firstNonEmpty(opts.Country, mock.DefaultCertificateCountry)
	return lote.Sign(signingKey, caCert, opts)
}

// SequencedList returns the current list that the issuer publishes at
// listPath. It signs a new one with the next sequence number when the content
// changed or the list reached its next update (ETSI TS 119 602 V1.1.1 §6.3.2
// and §6.3.15).
func (s *Keys) SequencedList(issuer, listPath string, ca *x509.Certificate, content []byte, sign func(sequence int) (string, error)) (string, error) {
	return s.sequencedList(s.trustListDir(issuer, listPath), ca, content, sign)
}

func (s *Keys) sequencedList(dir string, ca *x509.Certificate, content []byte, sign func(sequence int) (string, error)) (string, error) {
	hash := sha256.New()
	hash.Write(ca.Raw)
	hash.Write(content)
	identity := fmt.Sprintf("%x", hash.Sum(nil))
	at := path.Join(dir, "current.json")
	for range 5 {
		data, version, exists, err := readVersioned(s.backend, at)
		if err != nil {
			return "", err
		}
		var current storedTrustList
		if exists {
			if err := json.Unmarshal(data, &current); err != nil {
				return "", fmt.Errorf("reading persisted trusted list: %w", err)
			}
			if current.Identity == identity && time.Now().Before(current.NextUpdate) {
				return current.JWT, nil
			}
			// The history keeps every list the wallet published.
			if err := s.archiveTrustList(dir, current); err != nil {
				return "", err
			}
		}
		sequence := current.Sequence + 1
		jwt, err := sign(sequence)
		if err != nil {
			return "", err
		}
		updated := storedTrustList{Identity: identity, Sequence: sequence, NextUpdate: time.Now().UTC().Truncate(time.Second).Add(lote.UpdateInterval), JWT: jwt}
		data, err = json.Marshal(updated) //nolint:gosec // The signed trusted list is public data.
		if err != nil {
			return "", err
		}
		if _, err := s.backend.WriteIf(at, data, 0644, version); err != nil {
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
	return "", fmt.Errorf("trusted list changed concurrently too often")
}

// TrustListHistory returns a list the issuer published at listPath, by its
// sequence number.
func (s *Keys) TrustListHistory(issuer, listPath string, sequence int) ([]byte, error) {
	return s.backend.Read(path.Join(s.trustListDir(issuer, listPath), "history", strconv.Itoa(sequence)+".jwt"))
}

// TrustListSequences returns the sequence numbers of the lists the issuer
// published at listPath, in ascending order.
func (s *Keys) TrustListSequences(issuer, listPath string) ([]int, error) {
	files, err := s.backend.List(path.Join(s.trustListDir(issuer, listPath), "history"))
	if err != nil {
		return nil, err
	}
	var sequences []int
	for _, file := range files {
		if sequence, err := strconv.Atoi(strings.TrimSuffix(file, ".jwt")); err == nil {
			sequences = append(sequences, sequence)
		}
	}
	sort.Ints(sequences)
	return sequences, nil
}
