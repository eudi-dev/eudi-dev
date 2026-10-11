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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

// WalletStore uses wallet.json on the file backend and separate entities under state/
// on memory and Postgres. Keys, certificates, assets and templates use the wallet
// prefix. The shared CA uses its parent prefix.
type WalletStore struct {
	// Dir identifies the wallet for the instance registry and remote CLI on every
	// backend. On the file backend it is also the storage directory.
	Dir string

	backend storage.Store
	// prefix identifies the wallet's keys. sharedPrefix identifies the parent prefix
	// holding the shared CA. See walletKeyPrefix.
	prefix       string
	sharedPrefix string

	// An empty seed generates random keys.
	seed mock.Seed

	// Serialize snapshots and writes so an older snapshot cannot overwrite a newer
	// save. Log and issuer callbacks save outside the server lock and rely on this.
	saveMu sync.Mutex

	// Tests use this hook to pause between taking a snapshot and writing it.
	saveDelay func()

	// Counts saves so the entity log is trimmed every logTrimEvery saves.
	saves int
}

var walletRuntimeRegistry sync.Map

type walletJSON struct {
	PersistedState
	BaseURL   string `json:"base_url,omitempty"`
	IssuerURL string `json:"issuer_url,omitempty"`
	Port      int    `json:"port,omitempty"`

	// Read the old field name so existing deferred issuances can still be collected.
	// Saves use only the current name.
	LegacyPendingIssuances []DeferredIssuance `json:"pending_issuances,omitempty"`
}

// DefaultWalletDir returns the wallet directory under the config base directory
// (~/.eudi-dev/wallet by default).
func DefaultWalletDir() string {
	return filepath.Join(config.BaseDir(), "wallet")
}

// ResolveWalletDir selects the default directory when dir is empty.
func ResolveWalletDir(dir string) string {
	if dir == "" {
		dir = DefaultWalletDir()
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return dir
}

// NewWalletStore reads its backend from EUDI_DEV_STORAGE. An unset variable uses files.
func NewWalletStore(dir string) *WalletStore {
	return NewWalletStoreOn(dir, storage.FromEnv(storageOptions(dir)))
}

func OpenWalletStore(dir, spec string) (*WalletStore, error) {
	backend, err := storage.Open(spec, storageOptions(dir))
	if err != nil {
		return nil, err
	}
	return NewWalletStoreOn(dir, backend), nil
}

// An explicit wallet directory or state directory counts as a requested location when
// resolving auto storage.
func storageOptions(dir string) storage.Options {
	requested := dir != "" || os.Getenv("EUDI_DEV_HOME") != ""
	return storage.Options{Root: filepath.Dir(ResolveWalletDir(dir)), RootRequested: requested}
}

func NewWalletStoreOn(dir string, backend storage.Store) *WalletStore {
	dir = ResolveWalletDir(dir)
	prefix := filepath.Base(dir)
	if backend.Kind() != storage.KindFile {
		prefix = walletKeyPrefix(dir)
	}
	sharedPrefix := path.Dir(prefix)
	if sharedPrefix == "." {
		sharedPrefix = ""
	}
	store := &WalletStore{Dir: dir, backend: backend, prefix: prefix, sharedPrefix: sharedPrefix}
	store.SetSeed(os.Getenv(SeedEnvVar))
	return store
}

// SeedEnvVar sets the key seed. The value auto seeds memory storage only. Other
// backends then generate random keys.
const SeedEnvVar = "EUDI_DEV_SEED"

// The built-in seed is public. It is used by the image and by auto on memory storage.
const defaultSeed = "eudi-dev"

// SetSeed selects random keys when the seed is empty.
func (s *WalletStore) SetSeed(seed string) {
	if seed == "auto" {
		seed = ""
		if s.backend.Kind() == storage.KindMemory {
			seed = defaultSeed
		}
	}
	s.seed = mock.Seed(seed)
}

func (s *WalletStore) Seeded() bool {
	return len(s.seed) > 0
}

const BuiltInSeedSource = "built-in seed"

// SeedSource returns an empty string without a seed, seed for a custom seed, or
// BuiltInSeedSource for the public image seed.
func (s *WalletStore) SeedSource() string {
	switch string(s.seed) {
	case "":
		return ""
	case defaultSeed:
		return BuiltInSeedSource
	default:
		return "seed"
	}
}

// Use the wallet path relative to the state directory when possible. Otherwise use its
// absolute path with forward slashes and no leading separator. The default wallet
// prefix is wallet on every machine.
func walletKeyPrefix(dir string) string {
	base := filepath.Dir(ResolveWalletDir(""))
	if rel, err := filepath.Rel(base, dir); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
		return filepath.ToSlash(rel)
	}
	slash := filepath.ToSlash(dir)
	if volume := filepath.VolumeName(dir); volume != "" {
		slash = strings.TrimPrefix(slash, filepath.ToSlash(volume))
	}
	return strings.TrimPrefix(slash, "/")
}

func (s *WalletStore) Backend() storage.Store {
	return s.backend
}

func (s *WalletStore) Location() string {
	return s.backend.Locate(s.prefix)
}

func (s *WalletStore) Templates() credtemplate.Location {
	return credtemplate.Location{Store: s.backend, Prefix: s.key("templates")}
}

func (s *WalletStore) Exists() (bool, error) {
	if s.entityMode() {
		names, err := s.backend.List(s.stateKey(revisionSection))
		if err != nil {
			return false, fmt.Errorf("reading wallet revisions: %w", err)
		}
		return len(names) > 0, nil
	}
	_, err := s.WalletStamp()
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (s *WalletStore) runtime() *consent.Runtime {
	runtime, _ := walletRuntimeRegistry.LoadOrStore(s.Dir, consent.NewRuntime())
	return runtime.(*consent.Runtime)
}

func (s *WalletStore) key(parts ...string) string {
	return path.Join(append([]string{s.prefix}, parts...)...)
}

func (s *WalletStore) walletKey() string { return s.key("wallet.json") }

// WalletStamp returns an fs.ErrNotExist error when the wallet has never been saved.
func (s *WalletStore) WalletStamp() (storage.Stamp, error) {
	return s.backend.Stat(s.walletKey())
}

// Store display images separately so reloading wallet state does not also parse image
// data.
func (s *WalletStore) assetKey(name string) string {
	return s.key("assets", name)
}

// Store images by their content hash and return an asset:<sha256>.<ext> reference.
// Identical images share one immutable asset. Existing references and external URLs
// pass through unchanged, so the conversion can run on every save.
func (s *WalletStore) storeDisplayAsset(uri string) (ref string, converted bool, err error) {
	contentType, data, ok := dataURIImage(uri)
	if !ok {
		return uri, false, nil
	}
	sum := sha256.Sum256(data)
	name := hex.EncodeToString(sum[:]) + "." + assetExtension(contentType)
	key := s.assetKey(name)
	_, err = s.backend.Stat(key)
	if errors.Is(err, fs.ErrNotExist) {
		_, err = s.backend.Write(key, data, 0o600)
	}
	if err != nil {
		return "", false, fmt.Errorf("storing display image: %w", err)
	}
	return "asset:" + name, true, nil
}

// ReadDisplayAsset returns ok=false for missing assets and references that do not identify
// assets.
func (s *WalletStore) ReadDisplayAsset(ref string) (contentType string, data []byte, ok bool) {
	name, found := strings.CutPrefix(ref, "asset:")
	// Restrict reads to the asset directory even though generated names contain only a
	// hash and extension.
	if !found || name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", nil, false
	}
	data, err := s.backend.Read(s.assetKey(name))
	if err != nil {
		return "", nil, false
	}
	return assetContentType(name), data, true
}

// PruneUnreferencedAssets removes assets that nothing references. It reads the
// references under saveMu so it cannot race a save. Errors are ignored because an
// unused asset is harmless.
func (s *WalletStore) PruneUnreferencedAssets() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	stored, err := s.storedCredentials()
	if err != nil {
		return
	}
	referenced := make(map[string]bool)
	for _, c := range stored {
		if c.Display == nil {
			continue
		}
		for _, uri := range []string{c.Display.LogoURI, c.Display.BackgroundURI} {
			if name, ok := strings.CutPrefix(uri, "asset:"); ok {
				referenced[name] = true
			}
		}
	}

	names, err := s.backend.List(s.key("assets"))
	if err != nil {
		return
	}
	for _, name := range names {
		if referenced[name] {
			continue
		}
		_ = s.backend.Delete(s.assetKey(name))
	}
}

func (s *WalletStore) storedCredentials() ([]StoredCredential, error) {
	if s.entityMode() {
		return s.storedCredentialsFromEntities()
	}
	var wj walletJSON
	data, err := s.backend.Read(s.walletKey())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &wj); err != nil {
		return nil, err
	}
	return wj.Credentials, nil
}

func assetExtension(contentType string) string {
	switch contentType {
	case "image/png":
		return "png"
	case "image/jpeg":
		return "jpg"
	case "image/svg+xml":
		return "svg"
	case "image/webp":
		return "webp"
	case "image/gif":
		return "gif"
	default:
		return "bin"
	}
}

func assetContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".jpg"):
		return "image/jpeg"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".webp"):
		return "image/webp"
	case strings.HasSuffix(name, ".gif"):
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

// The shared CA sits one level above the wallet, so every wallet under the
// same state directory shares one CA.
func (s *WalletStore) sharedCAKeyPEM() string { return path.Join(s.sharedPrefix, "wallet-ca-key.pem") }

func (s *WalletStore) sharedCACertPEM() string {
	return path.Join(s.sharedPrefix, "wallet-ca-cert.pem")
}

func (s *WalletStore) tlsCertPEM() string { return s.key("wallet-tls-cert.pem") }

func (s *WalletStore) tlsKeyPEM() string { return s.key("wallet-tls-key.pem") }

func (s *WalletStore) legacyTLSCertPEM() string { return s.key("issuer-tls-cert.pem") }

func (s *WalletStore) legacyTLSKeyPEM() string { return s.key("issuer-tls-key.pem") }

func (s *WalletStore) logCleanMarkerKey() string { return s.key("wallet-log-cleaned-at") }

// LoadOrCreate loads the stored wallet. It generates keys that are missing.
func (s *WalletStore) LoadOrCreate() (*Wallet, error) {
	holderKey, issuerKey, err := s.LoadOrCreateKeys()
	if err != nil {
		return nil, err
	}
	caKey, caCert, err := s.LoadOrCreateSharedCA()
	if err != nil {
		return nil, err
	}

	w := newWallet(holderKey, issuerKey, false)
	w.signers = provider.NewKeys(s.backend, s.prefix, s.seed)
	w.runtime = s.runtime()
	w.Templates = s.Templates()
	if err := w.SetCertificateAuthority(caKey, caCert); err != nil {
		return nil, fmt.Errorf("configuring shared wallet CA: %w", err)
	}

	if s.entityMode() {
		if err := s.loadSections(w, allSections); err != nil {
			return nil, err
		}
		rehydrate(w)
		return w, nil
	}

	data, err := s.backend.Read(s.walletKey())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return w, nil
		}
		return nil, fmt.Errorf("reading wallet.json: %w", err)
	}

	var wj walletJSON
	if err := json.Unmarshal(data, &wj); err != nil {
		return nil, fmt.Errorf("parsing wallet.json: %w", err)
	}

	w.PersistedState = wj.PersistedState
	if len(w.DeferredIssuances) == 0 {
		w.DeferredIssuances = wj.LegacyPendingIssuances
	}
	w.IssuedAttestations = provider.DedupeIssuedAttestations(w.IssuedAttestations)
	w.Log = s.filterLogEntries(w.Log)
	w.BaseURL = wj.BaseURL
	w.IssuerURL = wj.IssuerURL
	rehydrate(w)
	return w, nil
}

// Restore parsed fields from Raw because they are not serialized.
func rehydrate(w *Wallet) {
	for i := range w.Credentials {
		if err := w.Credentials[i].Rehydrate(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: rehydrating credential %s: %v\n", w.Credentials[i].ID, err)
		}
	}
}

func (s *WalletStore) Save(w *Wallet) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	if s.entityMode() {
		return s.saveEntities(w)
	}
	creds, err := s.withStoredAssets(w.GetCredentials())
	if err != nil {
		return err
	}
	w.mu.RLock()
	wj := walletJSON{PersistedState: w.PersistedState.clone()}
	wj.BaseURL, wj.IssuerURL = w.savedURLsLocked()
	w.mu.RUnlock()
	wj.Credentials = creds
	wj.IssuedAttestations = provider.DedupeIssuedAttestations(wj.IssuedAttestations)
	wj.Log = s.filterLogEntries(wj.Log)

	data, err := json.MarshalIndent(wj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling wallet.json: %w", err)
	}
	if s.saveDelay != nil {
		s.saveDelay()
	}
	if _, err := s.backend.Write(s.walletKey(), data, 0o600); err != nil {
		return fmt.Errorf("writing wallet.json: %w", err)
	}
	return nil
}

// Replace embedded display images with asset references in the supplied copy. The live
// wallet keeps its current values until reloaded.
func (s *WalletStore) withStoredAssets(creds []StoredCredential) ([]StoredCredential, error) {
	for i := range creds {
		if creds[i].Display == nil {
			continue
		}
		logo, logoConverted, err := s.storeDisplayAsset(creds[i].Display.LogoURI)
		if err != nil {
			return nil, err
		}
		background, backgroundConverted, err := s.storeDisplayAsset(creds[i].Display.BackgroundURI)
		if err != nil {
			return nil, err
		}
		if logoConverted || backgroundConverted {
			d := *creds[i].Display
			d.LogoURI = logo
			d.BackgroundURI = background
			creds[i].Display = &d
		}
	}
	return creds, nil
}

func (s *WalletStore) ClearLog() error {
	w, err := s.LoadOrCreate()
	if err != nil {
		return err
	}
	if err := s.writeLogCleanMarker(time.Now()); err != nil {
		return err
	}
	w.mu.Lock()
	w.Log = nil
	w.mu.Unlock()
	return s.Save(w)
}

func (s *WalletStore) filterLogEntries(entries []LogEntry) []LogEntry {
	cleanedAt := s.loadLogCleanMarker()
	if cleanedAt.IsZero() {
		return append([]LogEntry(nil), entries...)
	}
	filtered := make([]LogEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Time.After(cleanedAt) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (s *WalletStore) loadLogCleanMarker() time.Time {
	data, err := s.backend.Read(s.logCleanMarkerKey())
	if err != nil {
		return time.Time{}
	}
	cleanedAt, err := time.Parse(time.RFC3339Nano, string(data))
	if err != nil {
		return time.Time{}
	}
	return cleanedAt
}

func (s *WalletStore) writeLogCleanMarker(cleanedAt time.Time) error {
	_, err := s.backend.Write(s.logCleanMarkerKey(), []byte(cleanedAt.Format(time.RFC3339Nano)), 0o600)
	return err
}

func (s *WalletStore) LoadOrCreateKeys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	holderKey, err := s.loadOrGenerateKey(s.key("holder.pem"), "holder")
	if err != nil {
		return nil, nil, err
	}

	issuerKey, err := s.loadOrGenerateKey(s.key("issuer.pem"), "issuer")
	if err != nil {
		return nil, nil, err
	}

	return holderKey, issuerKey, nil
}

// LoadOrCreateSharedCA creates the CA only while neither its key nor its certificate
// exists. WriteIf lets one of several concurrent creators install its key. The others
// wait for the certificate that the winner writes next.
func (s *WalletStore) LoadOrCreateSharedCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	for attempt := 0; attempt < sharedCAWaitAttempts; attempt++ {
		keyData, keyErr := s.backend.Read(s.sharedCAKeyPEM())
		certData, certErr := s.backend.Read(s.sharedCACertPEM())
		if keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("reading wallet CA key: %w", keyErr)
		}
		if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("reading wallet CA certificate: %w", certErr)
		}
		switch {
		case keyErr == nil && certErr == nil:
			return s.parseSharedCA(keyData, certData)
		case keyErr == nil:
			time.Sleep(sharedCAWaitInterval)
		case certErr == nil:
			return nil, nil, fmt.Errorf("the wallet CA certificate %s has no key at %s", s.backend.Locate(s.sharedCACertPEM()), s.backend.Locate(s.sharedCAKeyPEM()))
		default:
			caKey, caCert, err := s.createSharedCA()
			if errors.Is(err, storage.ErrConflict) {
				continue
			}
			return caKey, caCert, err
		}
	}
	return nil, nil, fmt.Errorf("the wallet CA key %s has no certificate at %s", s.backend.Locate(s.sharedCAKeyPEM()), s.backend.Locate(s.sharedCACertPEM()))
}

const (
	sharedCAWaitAttempts = 50
	sharedCAWaitInterval = 100 * time.Millisecond
)

func (s *WalletStore) parseSharedCA(keyData, certData []byte) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := keys.ParseECKeyPEM(keyData, "wallet CA")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", s.backend.Locate(s.sharedCAKeyPEM()), err)
	}
	cert, err := keys.ParseCertificatePEM(certData, "wallet CA")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", s.backend.Locate(s.sharedCACertPEM()), err)
	}
	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, nil, fmt.Errorf("%s is not a self-signed CA certificate", s.backend.Locate(s.sharedCACertPEM()))
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("the wallet CA key %s does not match the certificate %s", s.backend.Locate(s.sharedCAKeyPEM()), s.backend.Locate(s.sharedCACertPEM()))
	}
	return key, cert, nil
}

// createSharedCA returns storage.ErrConflict when another creator installed its key
// first.
func (s *WalletStore) createSharedCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	caKey, caCert, err := s.generateCA()
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.backend.WriteIf(s.sharedCAKeyPEM(), keys.ECKeyPEM(caKey), 0o600, ""); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("saving wallet CA key: %w", err)
	}
	if _, err := s.backend.WriteIf(s.sharedCACertPEM(), certPEM(caCert), 0o644, ""); err != nil {
		return nil, nil, fmt.Errorf("saving wallet CA certificate: %w", err)
	}
	return caKey, caCert, nil
}

func (s *WalletStore) generateCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	caKey, err := s.seed.Key("ca")
	if err != nil {
		return nil, nil, fmt.Errorf("generating wallet CA key: %w", err)
	}
	caCert, err := mock.GenerateRootCACert(caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating wallet CA certificate: %w", err)
	}
	return caKey, caCert, nil
}

func (s *WalletStore) LoadOrCreateSharedCACertificatePEM() ([]byte, error) {
	if _, _, err := s.LoadOrCreateSharedCA(); err != nil {
		return nil, err
	}
	certPEM, err := s.backend.Read(s.sharedCACertPEM())
	if err != nil {
		return nil, fmt.Errorf("reading wallet CA certificate: %w", err)
	}
	return certPEM, nil
}

// LoadOrCreateIssuerTLSCertificate replaces certificates that no longer match the
// requested host.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificate(serverName string) (tls.Certificate, error) {
	certPEM, keyPEM, err := s.loadIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading issuer TLS certificate: %w", err)
	}
	return cert, nil
}

func (s *WalletStore) LoadOrCreateIssuerTLSCertificateForURL(issuerURL string) (tls.Certificate, error) {
	return s.LoadOrCreateIssuerTLSCertificate(parseIssuerHost(issuerURL))
}

func (s *WalletStore) LoadOrCreateIssuerTLSCertificatePEM(serverName string) ([]byte, error) {
	certPEM, _, err := s.loadIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

func (s *WalletStore) LoadOrCreateIssuerTLSLeafCertificatePEM(serverName string) ([]byte, error) {
	certPEM, err := s.LoadOrCreateIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return nil, err
	}
	return firstCertificatePEM(certPEM)
}

func (s *WalletStore) LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL string) ([]byte, error) {
	return s.LoadOrCreateIssuerTLSLeafCertificatePEM(parseIssuerHost(issuerURL))
}

func (s *WalletStore) loadIssuerTLSCertificatePEM(serverName string) ([]byte, []byte, error) {
	if serverName == "" {
		serverName = "localhost"
	}
	caKey, caCert, err := s.LoadOrCreateSharedCA()
	if err != nil {
		return nil, nil, err
	}

	certPEM, certErr := s.backend.Read(s.tlsCertPEM())
	keyPEM, keyErr := s.backend.Read(s.tlsKeyPEM())
	legacy := errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist)
	if legacy {
		certPEM, certErr = s.backend.Read(s.legacyTLSCertPEM())
		keyPEM, keyErr = s.backend.Read(s.legacyTLSKeyPEM())
	}
	if certErr == nil && keyErr == nil {
		if cert, err := tls.X509KeyPair(certPEM, keyPEM); err == nil && issuerTLSCertificateMatches(cert, serverName, caCert) {
			// A pair under the legacy names moves to the current ones.
			if legacy {
				if err := s.saveIssuerTLSPEM(certPEM, keyPEM); err != nil {
					return nil, nil, err
				}
			}
			return certPEM, keyPEM, nil
		}
	}

	if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading wallet TLS certificate: %w", certErr)
	}
	if keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading wallet TLS key: %w", keyErr)
	}

	tlsKey, err := s.seed.Key("tls")
	if err != nil {
		return nil, nil, fmt.Errorf("generating TLS key: %w", err)
	}
	certPEM, keyPEM, err = issuerTLSCertificatePEM(serverName, tlsKey, caKey, caCert)
	if err != nil {
		return nil, nil, err
	}
	if !errors.Is(keyErr, fs.ErrNotExist) {
		// Replace the stored pair when it does not match serverName.
		if err := s.saveIssuerTLSPEM(certPEM, keyPEM); err != nil {
			return nil, nil, err
		}
		return certPEM, keyPEM, nil
	}
	// WriteIf selects one key during concurrent creation. Other servers read that
	// key's certificate.
	_, err = s.backend.WriteIf(s.tlsKeyPEM(), keyPEM, 0o600, "")
	if errors.Is(err, storage.ErrConflict) {
		for attempt := 0; attempt < 50; attempt++ {
			storedCert, certErr := s.backend.Read(s.tlsCertPEM())
			storedKey, keyErr := s.backend.Read(s.tlsKeyPEM())
			if certErr == nil && keyErr == nil {
				if cert, err := tls.X509KeyPair(storedCert, storedKey); err == nil && issuerTLSCertificateMatches(cert, serverName, caCert) {
					return storedCert, storedKey, nil
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil, nil, errors.New("the wallet TLS key was created elsewhere without a matching certificate")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("saving wallet TLS key: %w", err)
	}
	if _, err := s.backend.Write(s.tlsCertPEM(), certPEM, 0o644); err != nil {
		return nil, nil, fmt.Errorf("saving wallet TLS certificate: %w", err)
	}
	return certPEM, keyPEM, nil
}

func (s *WalletStore) saveIssuerTLSPEM(certPEM, keyPEM []byte) error {
	if _, err := s.backend.Write(s.tlsKeyPEM(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("saving wallet TLS key: %w", err)
	}
	if _, err := s.backend.Write(s.tlsCertPEM(), certPEM, 0o644); err != nil {
		return fmt.Errorf("saving wallet TLS certificate: %w", err)
	}
	return nil
}

func issuerTLSCertificateMatches(cert tls.Certificate, serverName string, caCert *x509.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false
	}
	if leaf.VerifyHostname(serverName) != nil {
		return false
	}
	if caCert == nil {
		return true
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: serverName,
	}
	if _, err := leaf.Verify(opts); err != nil {
		return false
	}
	return true
}

func (s *WalletStore) loadOrGenerateKey(at, label string) (*ecdsa.PrivateKey, error) {
	data, err := s.backend.Read(at)
	if err == nil {
		return keys.ParseECKeyPEM(data, label)
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading %s key: %w", label, err)
	}

	key, err := s.seed.Key(label)
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}
	// Use the key already saved by a concurrent creator.
	_, err = s.backend.WriteIf(at, keys.ECKeyPEM(key), 0o600, "")
	if errors.Is(err, storage.ErrConflict) {
		data, err := s.backend.Read(at)
		if err != nil {
			return nil, fmt.Errorf("reading %s key: %w", label, err)
		}
		return keys.ParseECKeyPEM(data, label)
	}
	if err != nil {
		return nil, fmt.Errorf("saving %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated %s key: %s\n", label, s.backend.Locate(at))
	return key, nil
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func firstCertificatePEM(data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM CERTIFICATE block found")
	}
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), nil
}
