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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustedlists"
)

// Memory and Postgres store entities separately under <prefix>/state/. Saves write
// changed entities and section revisions. Reloads compare revisions and row versions.
// See ADR-0016 for the layout and ADR-0018 for the design rationale.
const (
	stateSection              = "state"
	credentialsSection        = "credentials"
	logSection                = "log"
	statusSection             = "status"
	deferredSection           = "deferred"
	attestationsSection       = "attestations"
	registrarSection          = "relying-parties"
	registrationStatusSection = "registration-status"
	catalogSection            = "attestation-catalog"
	trustSection              = "trust"
	settingsSection           = "settings"
	revisionSection           = "revision"
	statusCounterEntity       = "status-counter"
)

// Running servers reload only serverSections. They manage deferred issuances in memory
// and use their own configured URLs.
var (
	allSections    = []string{credentialsSection, logSection, statusSection, deferredSection, attestationsSection, registrarSection, registrationStatusSection, catalogSection, trustSection, settingsSection}
	serverSections = []string{credentialsSection, logSection, statusSection, attestationsSection, registrarSection, registrationStatusSection, catalogSection, trustSection}
)

const logTrimEvery = 64

// Read the full section in one query when more than this many rows changed.
const bulkReadAbove = 16

// Readers compare only the revision row's version. A stamp version changes
// with the content, so every bump writes new content.
func revisionMark() []byte {
	return []byte(rand.Text())
}

// Snapshots are immutable so saves can read them outside the wallet lock.
type stateSnapshot map[string]storage.Blob

type walletSettings struct {
	BaseURL   string `json:"base_url,omitempty"`
	IssuerURL string `json:"issuer_url,omitempty"`
}

// Store the credential ID explicitly because it may not be recoverable from the key.
type statusRecord struct {
	CredentialID string `json:"credential_id"`
	StatusEntry
}

// Preserves insertion order within a section.
type orderedEntity struct {
	Seq   int             `json:"seq"`
	Value json.RawMessage `json:"value"`
}

func (s *WalletStore) entityMode() bool {
	return s.backend.Kind() != storage.KindFile
}

func (s *WalletStore) stateKey(parts ...string) string {
	return s.key(append([]string{stateSection}, parts...)...)
}

func (s *WalletStore) credentialKey(id string) string {
	return s.stateKey(credentialsSection, entityName(id))
}

func (s *WalletStore) counterKey() string { return s.stateKey(statusCounterEntity, "value") }

func (s *WalletStore) settingsKey() string { return s.stateKey(settingsSection, "value") }

func (s *WalletStore) revisionKey(section string) string {
	return s.stateKey(revisionSection, section)
}

func (s *WalletStore) sectionOf(key string) string {
	rest := strings.TrimPrefix(key, s.stateKey()+"/")
	section, _, _ := strings.Cut(rest, "/")
	if section == statusCounterEntity {
		return statusSection
	}
	return section
}

// Include the activity log only when requested.
func (s *WalletStore) changedSections(w *Wallet, includeLog bool) ([]string, error) {
	revisions, err := s.backend.Stamps(s.stateKey(revisionSection))
	if err != nil {
		return nil, fmt.Errorf("reading wallet revisions: %w", err)
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	var changed []string
	for _, section := range serverSections {
		if section == logSection && !includeLog {
			continue
		}
		if revisions[s.revisionKey(section)] != w.revisions[section] {
			changed = append(changed, section)
		}
	}
	return changed, nil
}

// Read revisions first so changes made during loading are detected on the next check.
// Keep unchanged credential objects and their stored bytes so unsaved in-memory
// changes remain detectable.
func (s *WalletStore) loadSections(w *Wallet, sections []string) error {
	revisions, err := s.backend.Stamps(s.stateKey(revisionSection))
	if err != nil {
		return fmt.Errorf("reading wallet revisions: %w", err)
	}
	w.mu.RLock()
	known, knownSeqs, wasSaved := w.persisted, w.entitySeqs, w.savedCredentials
	held := make(map[string]StoredCredential, len(w.Credentials))
	for _, cred := range w.Credentials {
		held[s.credentialKey(cred.ID)] = cred
	}
	w.mu.RUnlock()

	updated := maps.Clone(known)
	if updated == nil {
		updated = make(stateSnapshot)
	}
	for _, section := range sections {
		if err := s.refreshSection(section, known, updated); err != nil {
			return err
		}
	}
	loaded, seqs, err := s.parseSections(updated, sections, known, knownSeqs, held)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, section := range sections {
		switch section {
		case credentialsSection:
			w.Credentials = loaded.credentials
		case logSection:
			w.Log = s.filterLogEntries(loaded.log)
		case statusSection:
			w.StatusEntries = loaded.statusEntries
			w.StatusListCounter = loaded.statusListCounter
		case deferredSection:
			w.DeferredIssuances = loaded.deferred
		case attestationsSection:
			w.IssuedAttestations = provider.DedupeIssuedAttestations(loaded.attestations)
		case registrarSection:
			w.RelyingParties = loaded.relyingParties
		case registrationStatusSection:
			w.RegistrationStatuses = loaded.registrationStatuses
		case catalogSection:
			w.Catalog = loaded.catalog
		case trustSection:
			w.TrustedEntities = loaded.trust.Entities
			w.AddedTrustedLists = loaded.trust.Lists
		case settingsSection:
			w.BaseURL = loaded.settings.BaseURL
			w.IssuerURL = loaded.settings.IssuerURL
		}
	}
	w.persisted = updated
	maps.DeleteFunc(seqs, func(key string, _ int) bool { _, kept := updated[key]; return !kept })
	w.entitySeqs = seqs
	if slices.Contains(sections, credentialsSection) {
		w.savedCredentials = make(map[string]StoredCredential, len(loaded.credentials))
		for _, cred := range loaded.credentials {
			key := s.credentialKey(cred.ID)
			if before, ok := wasSaved[key]; ok && known[key].Stamp == updated[key].Stamp {
				cred = before
			}
			w.savedCredentials[key] = cred
		}
	}
	if w.revisions == nil {
		w.revisions = make(map[string]storage.Stamp)
	}
	for _, section := range sections {
		w.revisions[section] = revisions[s.revisionKey(section)]
	}
	w.allocateStatusIndex = s.allocateStatusIndex
	return nil
}

func (s *WalletStore) refreshSection(section string, known, updated stateSnapshot) error {
	stamps, err := s.sectionStamps(section)
	if err != nil {
		return err
	}
	for key := range known {
		if _, present := stamps[key]; !present && s.sectionOf(key) == section {
			delete(updated, key)
		}
	}
	var changed []string
	for key, stamp := range stamps {
		if blob, ok := known[key]; !ok || blob.Stamp != stamp {
			changed = append(changed, key)
		}
	}
	if len(changed) > bulkReadAbove {
		blobs, err := s.backend.ReadAll(s.stateKey(section))
		if err != nil {
			return fmt.Errorf("reading wallet state: %w", err)
		}
		maps.Copy(updated, blobs)
		changed = slices.DeleteFunc(changed, func(key string) bool { _, ok := blobs[key]; return ok })
	}
	for _, key := range changed {
		data, err := s.backend.Read(key)
		if errors.Is(err, fs.ErrNotExist) {
			delete(updated, key)
			continue
		}
		if err != nil {
			return fmt.Errorf("reading wallet state: %w", err)
		}
		updated[key] = storage.Blob{Data: data, Stamp: stamps[key]}
	}
	return nil
}

// The status counter uses its own prefix but belongs to the status section.
func (s *WalletStore) sectionStamps(section string) (map[string]storage.Stamp, error) {
	stamps, err := s.backend.Stamps(s.stateKey(section))
	if err != nil {
		return nil, fmt.Errorf("reading wallet state: %w", err)
	}
	if section == statusSection {
		counter, err := s.backend.Stamps(s.stateKey(statusCounterEntity))
		if err != nil {
			return nil, fmt.Errorf("reading wallet state: %w", err)
		}
		maps.Copy(stamps, counter)
	}
	return stamps, nil
}

type loadedSections struct {
	credentials          []StoredCredential
	log                  []LogEntry
	statusEntries        map[string]StatusEntry
	statusListCounter    int
	deferred             []DeferredIssuance
	attestations         []provider.IssuedAttestationSpec
	relyingParties       []registrar.WalletRelyingParty
	registrationStatuses []registrar.RegistrationStatus
	catalog              []registrar.CatalogAttestation
	trust                storedTrust
	settings             walletSettings
}

// storedTrust holds the providers and lists added by users.
type storedTrust struct {
	Entities []trustedlists.Entity `json:"entities,omitempty"`
	Lists    []string              `json:"lists,omitempty"`
}

// Keep held credentials whose stored row has not changed.
func (s *WalletStore) parseSections(blobs stateSnapshot, sections []string, known stateSnapshot, knownSeqs map[string]int, held map[string]StoredCredential) (loadedSections, map[string]int, error) {
	var loaded loadedSections
	seqs := maps.Clone(knownSeqs)
	if seqs == nil {
		seqs = make(map[string]int)
	}
	var deferred []orderedEntity
	registrarEntities := map[string][]orderedEntity{}
	for _, key := range slices.Sorted(maps.Keys(blobs)) {
		section := s.sectionOf(key)
		if !slices.Contains(sections, section) {
			continue
		}
		data := blobs[key].Data
		var err error
		switch section {
		case credentialsSection:
			if before, ok := held[key]; ok && known[key].Stamp == blobs[key].Stamp {
				if _, ok := seqs[key]; ok {
					loaded.credentials = append(loaded.credentials, before)
					break
				}
			}
			var entity orderedEntity
			var cred StoredCredential
			if err = json.Unmarshal(data, &entity); err == nil {
				err = json.Unmarshal(entity.Value, &cred)
			}
			if err == nil {
				if err := cred.Rehydrate(); err != nil {
					fmt.Fprintf(os.Stderr, "warning: rehydrating credential %s: %v\n", cred.ID, err)
				}
				seqs[key] = entity.Seq
				loaded.credentials = append(loaded.credentials, cred)
			}
		case deferredSection:
			var entity orderedEntity
			if err = json.Unmarshal(data, &entity); err == nil {
				seqs[key] = entity.Seq
				deferred = append(deferred, entity)
			}
		case logSection:
			var entry LogEntry
			if err = json.Unmarshal(data, &entry); err == nil {
				loaded.log = append(loaded.log, entry)
			}
		case statusSection:
			if key == s.counterKey() {
				loaded.statusListCounter, err = strconv.Atoi(string(data))
				break
			}
			var record statusRecord
			if err = json.Unmarshal(data, &record); err == nil {
				if loaded.statusEntries == nil {
					loaded.statusEntries = make(map[string]StatusEntry)
				}
				loaded.statusEntries[record.CredentialID] = record.StatusEntry
			}
		case attestationsSection:
			var spec provider.IssuedAttestationSpec
			if err = json.Unmarshal(data, &spec); err == nil {
				loaded.attestations = append(loaded.attestations, spec)
			}
		case registrarSection, registrationStatusSection:
			var entity orderedEntity
			if err = json.Unmarshal(data, &entity); err == nil {
				seqs[key] = entity.Seq
				registrarEntities[section] = append(registrarEntities[section], entity)
			}
		case catalogSection:
			var entry registrar.CatalogAttestation
			if err = json.Unmarshal(data, &entry); err == nil {
				loaded.catalog = append(loaded.catalog, entry)
			}
		case trustSection:
			err = json.Unmarshal(data, &loaded.trust)
		case settingsSection:
			err = json.Unmarshal(data, &loaded.settings)
		}
		if err != nil {
			return loaded, nil, fmt.Errorf("parsing wallet state %s: %w", key, err)
		}
	}
	sort.SliceStable(loaded.credentials, func(i, j int) bool {
		return seqs[s.credentialKey(loaded.credentials[i].ID)] < seqs[s.credentialKey(loaded.credentials[j].ID)]
	})
	sort.SliceStable(deferred, func(i, j int) bool { return deferred[i].Seq < deferred[j].Seq })
	for section, entities := range registrarEntities {
		sort.SliceStable(entities, func(i, j int) bool { return entities[i].Seq < entities[j].Seq })
		for _, entity := range entities {
			if section == registrarSection {
				var rp registrar.WalletRelyingParty
				if err := json.Unmarshal(entity.Value, &rp); err != nil {
					return loaded, nil, fmt.Errorf("parsing a stored registration: %w", err)
				}
				loaded.relyingParties = append(loaded.relyingParties, rp)
				continue
			}
			var status registrar.RegistrationStatus
			if err := json.Unmarshal(entity.Value, &status); err != nil {
				return loaded, nil, fmt.Errorf("parsing a stored registration status: %w", err)
			}
			loaded.registrationStatuses = append(loaded.registrationStatuses, status)
		}
	}
	for _, entity := range deferred {
		var d DeferredIssuance
		if err := json.Unmarshal(entity.Value, &d); err != nil {
			return loaded, nil, fmt.Errorf("parsing a stored deferred issuance: %w", err)
		}
		loaded.deferred = append(loaded.deferred, d)
	}
	return loaded, seqs, nil
}

// Write changed entities, delete removed entities, then update section revisions. Read
// wallet state and its snapshot under one lock so a concurrent reload cannot pair
// state with the wrong snapshot.
func (s *WalletStore) saveEntities(w *Wallet) error {
	w.mu.RLock()
	snapshot := w.persisted
	revisions := maps.Clone(w.revisions)
	current, saved, seqs, err := s.currentEntities(w, snapshot)
	w.mu.RUnlock()
	if err != nil {
		return err
	}
	if s.saveDelay != nil {
		s.saveDelay()
	}

	next := make(stateSnapshot, len(current))
	touched := make(map[string]bool)
	for key, data := range current {
		if blob, ok := snapshot[key]; ok && bytes.Equal(blob.Data, data) {
			next[key] = blob
			continue
		}
		stamp, err := s.backend.Write(key, data, 0o600)
		if err != nil {
			return fmt.Errorf("writing wallet state: %w", err)
		}
		next[key] = storage.Blob{Data: data, Stamp: stamp}
		touched[s.sectionOf(key)] = true
	}
	for key := range snapshot {
		if _, kept := current[key]; kept {
			continue
		}
		if err := s.backend.Delete(key); err != nil {
			return fmt.Errorf("deleting wallet state: %w", err)
		}
		touched[s.sectionOf(key)] = true
	}

	// On a WriteIf conflict, retain the older cached revision so the next request
	// reloads the section.
	own := make(map[string]storage.Stamp)
	for section := range touched {
		key := s.revisionKey(section)
		stamp, err := s.backend.WriteIf(key, revisionMark(), 0o600, revisions[section].Version)
		if errors.Is(err, storage.ErrConflict) {
			_, err = s.backend.Write(key, revisionMark(), 0o600)
		} else if err == nil {
			own[section] = stamp
		}
		if err != nil {
			return fmt.Errorf("writing wallet revision: %w", err)
		}
	}
	if err := s.trimLogPeriodically(); err != nil {
		return err
	}

	// Keep a concurrent reload's snapshot. The next save may repeat these writes.
	w.mu.Lock()
	if w.persisted.is(snapshot) {
		w.persisted = next
		w.savedCredentials = saved
		w.entitySeqs = seqs
		if w.revisions == nil {
			w.revisions = make(map[string]storage.Stamp)
		}
		maps.Copy(w.revisions, own)
	}
	w.mu.Unlock()
	return nil
}

// Append one log entry without comparing the rest of the wallet.
func (s *WalletStore) appendLogEntry(w *Wallet, entry LogEntry) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.loadLogCleanMarker().After(entry.Time) {
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding wallet state log: %w", err)
	}
	key := s.stateKey(logSection, logEntryName(entry))
	stamp, err := s.backend.Write(key, data, 0o600)
	if err != nil {
		return fmt.Errorf("writing wallet state: %w", err)
	}
	w.mu.RLock()
	expected := w.revisions[logSection].Version
	w.mu.RUnlock()
	revision, err := s.backend.WriteIf(s.revisionKey(logSection), revisionMark(), 0o600, expected)
	own := err == nil
	if errors.Is(err, storage.ErrConflict) {
		_, err = s.backend.Write(s.revisionKey(logSection), revisionMark(), 0o600)
	}
	if err != nil {
		return fmt.Errorf("writing wallet revision: %w", err)
	}
	if err := s.trimLogPeriodically(); err != nil {
		return err
	}
	w.mu.Lock()
	w.persisted = w.persisted.with(key, storage.Blob{Data: data, Stamp: stamp})
	if own {
		if w.revisions == nil {
			w.revisions = make(map[string]storage.Stamp)
		}
		w.revisions[logSection] = revision
	}
	w.mu.Unlock()
	return nil
}

func (s *WalletStore) trimLogPeriodically() error {
	s.saves++
	if s.saves%logTrimEvery != 0 {
		return nil
	}
	return s.trimLogRows()
}

func (s *WalletStore) trimLogRows() error {
	names, err := s.backend.List(s.stateKey(logSection))
	if err != nil {
		return fmt.Errorf("listing the wallet log: %w", err)
	}
	if len(names) <= maxLogEntries {
		return nil
	}
	for _, name := range names[:len(names)-maxLogEntries] {
		if err := s.backend.Delete(s.stateKey(logSection, name)); err != nil {
			return fmt.Errorf("trimming the wallet log: %w", err)
		}
	}
	_, err = s.backend.Write(s.revisionKey(logSection), revisionMark(), 0o600)
	return err
}

// Caller must hold w.mu. Reuse stored bytes for unchanged credentials to avoid
// serializing them again.
func (s *WalletStore) currentEntities(w *Wallet, snapshot stateSnapshot) (map[string][]byte, map[string]StoredCredential, map[string]int, error) {
	current := make(map[string][]byte)
	put := func(key string, v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding wallet state %s: %w", key, err)
		}
		current[key] = data
		return nil
	}
	putOrdered := func(key string, seq int, v any) error {
		value, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding wallet state %s: %w", key, err)
		}
		return put(key, orderedEntity{Seq: seq, Value: value})
	}

	seqs := make(map[string]int)
	creds, err := s.withStoredAssets(append([]StoredCredential(nil), w.Credentials...))
	if err != nil {
		return nil, nil, nil, err
	}
	saved := make(map[string]StoredCredential, len(creds))
	credentialSeqs := s.orderedSeqs(credentialsSection, w.entitySeqs, len(creds), func(i int) string { return creds[i].ID })
	for i, cred := range creds {
		key := s.credentialKey(cred.ID)
		seqs[key] = credentialSeqs[i]
		saved[key] = cred
		if before, ok := w.savedCredentials[key]; ok && reflect.DeepEqual(before, cred) {
			if blob, stored := snapshot[key]; stored && w.entitySeqs[key] == credentialSeqs[i] {
				current[key] = blob.Data
				continue
			}
		}
		if err := putOrdered(key, credentialSeqs[i], cred); err != nil {
			return nil, nil, nil, err
		}
	}
	deferred := w.DeferredIssuances
	deferredSeqs := s.orderedSeqs(deferredSection, w.entitySeqs, len(deferred), func(i int) string { return deferred[i].ID })
	for i, d := range deferred {
		key := s.stateKey(deferredSection, entityName(d.ID))
		seqs[key] = deferredSeqs[i]
		if err := putOrdered(key, deferredSeqs[i], d); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, entry := range s.filterLogEntries(w.Log) {
		key := s.stateKey(logSection, logEntryName(entry))
		if blob, ok := snapshot[key]; ok {
			current[key] = blob.Data
			continue
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("encoding wallet state log: %w", err)
		}
		current[key] = data
	}
	for id, entry := range w.StatusEntries {
		if err := put(s.stateKey(statusSection, entityName(id)), statusRecord{CredentialID: id, StatusEntry: entry}); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, spec := range provider.DedupeIssuedAttestations(w.IssuedAttestations) {
		if err := put(s.stateKey(attestationsSection, shortHash(spec.Format+"|"+spec.VCT+"|"+spec.DocType)), spec); err != nil {
			return nil, nil, nil, err
		}
	}
	// The registrar lists registrations in the order they were made, and the
	// newest status entry of a certificate is the valid one.
	parties := w.RelyingParties
	partySeqs := s.orderedSeqs(registrarSection, w.entitySeqs, len(parties), func(i int) string { return parties[i].Identifier[0].Identifier })
	for i, rp := range parties {
		key := s.stateKey(registrarSection, entityName(rp.Identifier[0].Identifier))
		seqs[key] = partySeqs[i]
		if err := putOrdered(key, partySeqs[i], rp); err != nil {
			return nil, nil, nil, err
		}
	}
	statuses := w.RegistrationStatuses
	statusSeqs := s.orderedSeqs(registrationStatusSection, w.entitySeqs, len(statuses), func(i int) string { return strconv.Itoa(statuses[i].Index) })
	for i, status := range statuses {
		key := s.stateKey(registrationStatusSection, entityName(strconv.Itoa(status.Index)))
		seqs[key] = statusSeqs[i]
		if err := putOrdered(key, statusSeqs[i], status); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, entry := range w.Catalog {
		if err := put(s.stateKey(catalogSection, entityName(entry.Schema.ID)), entry); err != nil {
			return nil, nil, nil, err
		}
	}
	if len(w.TrustedEntities) > 0 || len(w.AddedTrustedLists) > 0 {
		if err := put(s.stateKey(trustSection, "lists"), storedTrust{Entities: w.TrustedEntities, Lists: w.AddedTrustedLists}); err != nil {
			return nil, nil, nil, err
		}
	}
	settings := walletSettings{}
	settings.BaseURL, settings.IssuerURL = w.savedURLsLocked()
	if err := put(s.settingsKey(), settings); err != nil {
		return nil, nil, nil, err
	}
	// Only the allocator advances the counter. An ordinary save must not overwrite it
	// with an older value. An explicit reset to zero is still persisted.
	counterKey := s.counterKey()
	if stored, ok := snapshot[counterKey]; ok {
		current[counterKey] = stored.Data
		if w.StatusListCounter == 0 {
			current[counterKey] = []byte("0")
		}
	}
	return current, saved, seqs, nil
}

// Keep existing positions and append new items after them to preserve insertion order
// on reload.
func (s *WalletStore) orderedSeqs(section string, known map[string]int, n int, idAt func(int) string) []int {
	prefix := s.stateKey(section) + "/"
	next := 0
	for key, seq := range known {
		if strings.HasPrefix(key, prefix) && seq >= next {
			next = seq + 1
		}
	}
	seqs := make([]int, n)
	for i := range seqs {
		if seq, ok := known[s.stateKey(section, entityName(idAt(i)))]; ok {
			seqs[i] = seq
			continue
		}
		seqs[i] = next
		next++
	}
	return seqs
}

// The content hash distinguishes entries with the same timestamp.
func logEntryName(entry LogEntry) string {
	return fmt.Sprintf("%020d-%s", entry.Time.UnixNano(), shortHash(entry.Action+"\x00"+entry.Detail+"\x00"+entry.Severity+"\x00"+strconv.FormatBool(entry.Success)))
}

func entityName(id string) string {
	if id == "" || strings.Contains(id, "/") || strings.HasPrefix(id, ".") {
		return shortHash(id)
	}
	return id
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// Use compare-and-swap to allocate distinct status indices across servers. Update the
// status revision so other servers reload the counter used to size their lists.
func (s *WalletStore) allocateStatusIndex(w *Wallet) (int, error) {
	key := s.counterKey()
	for attempt := 0; attempt < 100; attempt++ {
		// Read the version before the value. If the value changed meanwhile, WriteIf
		// fails and retries.
		next, expected := 0, ""
		stamp, err := s.backend.Stat(key)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("reading the status counter: %w", err)
		}
		if err == nil {
			expected = stamp.Version
			data, err := s.backend.Read(key)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return 0, fmt.Errorf("reading the status counter: %w", err)
			}
			if next, err = strconv.Atoi(string(data)); err != nil {
				return 0, fmt.Errorf("parsing the status counter: %w", err)
			}
		}
		stored := []byte(strconv.Itoa(next + 1))
		stamp, err = s.backend.WriteIf(key, stored, 0o600, expected)
		if errors.Is(err, storage.ErrConflict) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if _, err := s.backend.Write(s.revisionKey(statusSection), revisionMark(), 0o600); err != nil {
			return 0, fmt.Errorf("writing wallet revision: %w", err)
		}
		w.mu.Lock()
		w.StatusListCounter = next + 1
		w.persisted = w.persisted.with(key, storage.Blob{Data: stored, Stamp: stamp})
		w.mu.Unlock()
		return next, nil
	}
	return 0, errors.New("the status counter kept changing under the allocation")
}

func (snap stateSnapshot) is(other stateSnapshot) bool {
	return reflect.ValueOf(snap).Pointer() == reflect.ValueOf(other).Pointer()
}

func (snap stateSnapshot) with(key string, blob storage.Blob) stateSnapshot {
	next := maps.Clone(snap)
	if next == nil {
		next = stateSnapshot{}
	}
	next[key] = blob
	return next
}

func (s *WalletStore) storedCredentialsFromEntities() ([]StoredCredential, error) {
	blobs, err := s.backend.ReadAll(s.stateKey(credentialsSection))
	if err != nil {
		return nil, err
	}
	creds := make([]StoredCredential, 0, len(blobs))
	for _, blob := range blobs {
		var entity orderedEntity
		var cred StoredCredential
		if json.Unmarshal(blob.Data, &entity) == nil && json.Unmarshal(entity.Value, &cred) == nil {
			creds = append(creds, cred)
		}
	}
	return creds, nil
}
