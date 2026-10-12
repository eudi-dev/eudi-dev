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

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
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
	Credentials        []StoredCredential      `json:"credentials"`
	IssuedAttestations []IssuedAttestationSpec `json:"issued_attestations,omitempty"`
	Log                []LogEntry              `json:"log,omitempty"`
	DeferredIssuances  []DeferredIssuance      `json:"deferred_issuances,omitempty"`
	StatusEntries      map[string]StatusEntry  `json:"status_entries,omitempty"`
	StatusListCounter  int                     `json:"status_list_counter,omitempty"`
	BaseURL            string                  `json:"base_url,omitempty"`
	IssuerURL          string                  `json:"issuer_url,omitempty"`
	Port               int                     `json:"port,omitempty"`

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
	requested := dir != "" || os.Getenv("EUDI_DEV_HOME") != "" || os.Getenv("OID4VC_DEV_HOME") != ""
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

func (s *WalletStore) Exists() bool {
	if s.entityMode() {
		names, err := s.backend.List(s.stateKey(revisionSection))
		return err == nil && len(names) > 0
	}
	_, ok := s.WalletStamp()
	return ok
}

func (s *WalletStore) runtime() *WalletRuntime {
	runtime, _ := walletRuntimeRegistry.LoadOrStore(s.Dir, newWalletRuntime())
	return runtime.(*WalletRuntime)
}

func (s *WalletStore) key(parts ...string) string {
	return path.Join(append([]string{s.prefix}, parts...)...)
}

func (s *WalletStore) walletKey() string { return s.key("wallet.json") }

// WalletStamp returns ok=false when the wallet has never been saved.
func (s *WalletStore) WalletStamp() (storage.Stamp, bool) {
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
func (s *WalletStore) storeDisplayAsset(uri string) (ref string, converted bool) {
	contentType, data, ok := dataURIImage(uri)
	if !ok {
		return uri, false
	}
	sum := sha256.Sum256(data)
	name := hex.EncodeToString(sum[:]) + "." + assetExtension(contentType)
	key := s.assetKey(name)
	if _, exists := s.backend.Stat(key); exists {
		return "asset:" + name, true
	}
	if _, err := s.backend.Write(key, data, 0o600); err != nil {
		return uri, false
	}
	return "asset:" + name, true
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

	w := New(holderKey, issuerKey, false)
	w.signers = &signingStore{backend: s.backend, prefix: s.prefix, seed: s.seed}
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

	w.Credentials = wj.Credentials
	w.DeferredIssuances = wj.DeferredIssuances
	if len(w.DeferredIssuances) == 0 {
		w.DeferredIssuances = wj.LegacyPendingIssuances
	}
	w.IssuedAttestations = dedupeIssuedAttestations(wj.IssuedAttestations)
	w.Log = s.filterLogEntries(wj.Log)
	w.StatusEntries = wj.StatusEntries
	w.StatusListCounter = wj.StatusListCounter
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
	creds := s.withStoredAssets(w.GetCredentials())
	w.mu.RLock()
	issuedAttestations := dedupeIssuedAttestations(w.IssuedAttestations)
	deferredIssuances := append([]DeferredIssuance(nil), w.DeferredIssuances...)
	logEntries := s.filterLogEntries(w.Log)
	statusEntries := w.StatusEntries
	statusListCounter := w.StatusListCounter
	baseURL := w.BaseURL
	issuerURL := w.IssuerURL
	w.mu.RUnlock()
	wj := walletJSON{
		Credentials:        creds,
		DeferredIssuances:  deferredIssuances,
		IssuedAttestations: issuedAttestations,
		Log:                logEntries,
		StatusEntries:      statusEntries,
		StatusListCounter:  statusListCounter,
		BaseURL:            baseURL,
		IssuerURL:          issuerURL,
	}

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
func (s *WalletStore) withStoredAssets(creds []StoredCredential) []StoredCredential {
	for i := range creds {
		if creds[i].Display == nil {
			continue
		}
		logo, logoConverted := s.storeDisplayAsset(creds[i].Display.LogoURI)
		background, backgroundConverted := s.storeDisplayAsset(creds[i].Display.BackgroundURI)
		if logoConverted || backgroundConverted {
			d := *creds[i].Display
			d.LogoURI = logo
			d.BackgroundURI = background
			creds[i].Display = &d
		}
	}
	return creds
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

// LoadOrCreateSharedCA uses WriteIf so concurrent creators agree on one CA key. The
// other server waits for the matching certificate.
func (s *WalletStore) LoadOrCreateSharedCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	for attempt := 0; ; attempt++ {
		keyData, keyErr := s.backend.Read(s.sharedCAKeyPEM())
		certData, certErr := s.backend.Read(s.sharedCACertPEM())
		if keyErr == nil && certErr == nil {
			key, err := parsePEMKey(keyData, "wallet CA")
			if err == nil {
				cert, err := parsePEMCertificate(certData, "wallet CA")
				if err == nil && cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
					return key, cert, nil
				}
			}
			break
		}
		if keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("reading wallet CA key: %w", keyErr)
		}
		if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("reading wallet CA certificate: %w", certErr)
		}
		if attempt == 50 {
			break
		}
		if keyErr == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		caKey, caCert, err := s.generateCA()
		if err != nil {
			return nil, nil, err
		}
		_, err = s.backend.WriteIf(s.sharedCAKeyPEM(), keyPEM(caKey), 0o600, "")
		if errors.Is(err, storage.ErrConflict) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("saving wallet CA key: %w", err)
		}
		if err := s.saveCertPEM(s.sharedCACertPEM(), caCert); err != nil {
			return nil, nil, fmt.Errorf("saving wallet CA certificate: %w", err)
		}
		return caKey, caCert, nil
	}

	// Replace the stored CA if it is unusable.
	caKey, caCert, err := s.generateCA()
	if err != nil {
		return nil, nil, err
	}
	if err := s.saveKeyPEM(s.sharedCAKeyPEM(), caKey); err != nil {
		return nil, nil, fmt.Errorf("saving wallet CA key: %w", err)
	}
	if err := s.saveCertPEM(s.sharedCACertPEM(), caCert); err != nil {
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

func (s *WalletStore) LoadOrCreateIssuerTLSCertificatePEMForURL(issuerURL string) ([]byte, error) {
	return s.LoadOrCreateIssuerTLSCertificatePEM(parseIssuerHost(issuerURL))
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
	if errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist) {
		certPEM, certErr = s.backend.Read(s.legacyTLSCertPEM())
		keyPEM, keyErr = s.backend.Read(s.legacyTLSKeyPEM())
	}
	if certErr == nil && keyErr == nil {
		if cert, err := tls.X509KeyPair(certPEM, keyPEM); err == nil && issuerTLSCertificateMatches(cert, serverName, caCert) {
			if err := s.saveIssuerTLSPEM(certPEM, keyPEM); err != nil {
				return nil, nil, err
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
		return parsePEMKey(data, label)
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading %s key: %w", label, err)
	}

	key, err := s.seed.Key(label)
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}
	// Use the key already saved by a concurrent creator.
	_, err = s.backend.WriteIf(at, keyPEM(key), 0o600, "")
	if errors.Is(err, storage.ErrConflict) {
		data, err := s.backend.Read(at)
		if err != nil {
			return nil, fmt.Errorf("reading %s key: %w", label, err)
		}
		return parsePEMKey(data, label)
	}
	if err != nil {
		return nil, fmt.Errorf("saving %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated %s key: %s\n", label, s.backend.Locate(at))
	return key, nil
}

func parsePEMKey(data []byte, label string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s key: no PEM block found", label)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, fmt.Errorf("%s key: not an EC key", label)
	}

	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s key: unable to parse PEM: %w", label, err)
	}
	return ecKey, nil
}

func parsePEMCertificate(data []byte, label string) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s certificate: no PEM block found", label)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: unable to parse PEM: %w", label, err)
	}
	return cert, nil
}

func (s *WalletStore) saveKeyPEM(at string, key *ecdsa.PrivateKey) error {
	_, err := s.backend.Write(at, keyPEM(key), 0o600)
	return err
}

func keyPEM(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func (s *WalletStore) saveCertPEM(at string, cert *x509.Certificate) error {
	_, err := s.backend.Write(at, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
	return err
}

func firstCertificatePEM(data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM CERTIFICATE block found")
	}
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), nil
}
