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

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/remote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

// Management commands use the same API documents for local and remote wallets. Prefer
// a running server over direct file access to keep one writer per wallet directory.
// Explicit remote targets take precedence over discovery.
type walletService interface {
	// URL is the managed instance's base URL, empty for the local store.
	URL() string
	Credentials() ([]map[string]any, error)
	Credential(id string) (map[string]any, error)
	// DeferredIssuances are credentials an issuer accepted but has not handed
	// over yet. They are not in the store, so they are listed separately.
	DeferredIssuances() ([]map[string]any, error)
	ImportCredential(raw string) (map[string]any, error)
	RefreshCredential(id string) (map[string]any, error)
	RemoveCredential(id string) error
	RemoveAllCredentials() (wallet.RemovedCredentials, error)
	Issue(req map[string]any) (map[string]any, error)
	Logs() ([]wallet.LogEntry, error)
	ClearLogs() error
	Templates() ([]credtemplate.Template, error)
	Template(name string) (*credtemplate.Template, error)
	// SaveTemplate returns the saved file path when the backend knows it
	// (the local store does, a remote instance does not).
	SaveTemplate(tpl credtemplate.Template) (string, error)
	DeleteTemplate(name string) error
	Certificate(kind, certFormat string, opts walletCertOptions) ([]byte, error)
	RegistrationCertificate(req registrar.RegistrationCertificateRequest) (*registrar.RegistrationCertificateResult, error)
	AccessCertificate(req registrar.AccessCertificateRequest) (*registrar.AccessCertificateResult, error)
	RegisterRelyingParty(rp registrar.WalletRelyingParty) (registrar.WalletRelyingParty, error)
	RegistrarRecords() ([]registrar.WalletRelyingParty, error)
	Enrol(e registrar.Enrolment, update bool) (*registrar.EnrolmentResult, error)
	RegistrationCertificateViews(identifier string) ([]registrar.RegistrationStatusView, error)
	SetRegistrationCertificatesRevoked(identifier string, scope registrar.RegistrationScope, revoked bool) (int, error)
	DeleteRelyingParty(identifier string) error
	CatalogAttestations() ([]registrar.CatalogAttestation, error)
	AddCatalogAttestation(entry registrar.CatalogAttestation) (registrar.CatalogAttestation, error)
	DeleteCatalogAttestation(id string) error
	TrustState() (wallet.TrustedListState, error)
	AddTrustedEntity(list, name, certificatesPEM string) (wallet.TrustedEntity, error)
	RemoveTrustedEntity(id string) error
	AddTrustedList(url string) (wallet.TrustedListLink, error)
	RemoveTrustedList(url string) error
	Config() (map[string]any, error)
}

// walletCertOptions carries the derivation inputs for the local TLS leaf
// certificate. A remote instance derives its own URLs, so the fields only
// apply to the local store.
type walletCertOptions struct {
	port    int
	baseURL string
	docker  bool
}

func managedWallet() (walletService, error) {
	return managedWalletWithLoader(loadWallet)
}

func managedWalletWithLoader(load func() (*wallet.Wallet, *wallet.WalletStore, error)) (walletService, error) {
	c, err := remoteClientIfConfigured()
	if err != nil {
		return nil, err
	}
	if c != nil {
		if walletCmd.PersistentFlags().Changed("mode") {
			return nil, checkRemoteConformanceFlags([]string{"--mode"})
		}
		return &remoteWallet{c: c}, nil
	}
	return &localWallet{load: load}, nil
}

type remoteWallet struct {
	c *remote.Client
}

func (r *remoteWallet) URL() string { return r.c.BaseURL }

func (r *remoteWallet) Credentials() ([]map[string]any, error) { return r.c.Credentials() }

func (r *remoteWallet) Credential(id string) (map[string]any, error) { return r.c.Credential(id) }

func (r *remoteWallet) DeferredIssuances() ([]map[string]any, error) { return r.c.DeferredIssuances() }

func (r *remoteWallet) ImportCredential(raw string) (map[string]any, error) {
	return r.c.ImportCredential(raw)
}

func (r *remoteWallet) RefreshCredential(id string) (map[string]any, error) {
	return r.c.RefreshCredential(id)
}

func (r *remoteWallet) RemoveCredential(id string) error { return r.c.RemoveCredential(id) }

func (r *remoteWallet) RemoveAllCredentials() (wallet.RemovedCredentials, error) {
	var out wallet.RemovedCredentials
	err := r.c.RemoveAllCredentials(&out)
	return out, err
}

func (r *remoteWallet) Issue(req map[string]any) (map[string]any, error) { return r.c.Issue(req) }

func (r *remoteWallet) Logs() ([]wallet.LogEntry, error) {
	data, err := r.c.Log()
	if err != nil {
		return nil, err
	}
	var entries []wallet.LogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decoding remote log: %w", err)
	}
	return entries, nil
}

func (r *remoteWallet) ClearLogs() error { return r.c.ClearLog() }

func (r *remoteWallet) Templates() ([]credtemplate.Template, error) {
	docs, err := r.c.Templates()
	if err != nil {
		return nil, err
	}
	templates := make([]credtemplate.Template, 0, len(docs))
	for _, doc := range docs {
		tpl, err := decodeTemplateDoc(doc)
		if err != nil {
			return nil, err
		}
		templates = append(templates, *tpl)
	}
	return templates, nil
}

func (r *remoteWallet) Template(name string) (*credtemplate.Template, error) {
	doc, err := r.c.Template(name)
	if err != nil {
		return nil, err
	}
	return decodeTemplateDoc(doc)
}

func (r *remoteWallet) SaveTemplate(tpl credtemplate.Template) (string, error) {
	if _, err := r.c.PutTemplate(tpl.Name, tpl); err != nil {
		return "", err
	}
	return "", nil
}

func (r *remoteWallet) DeleteTemplate(name string) error { return r.c.DeleteTemplate(name) }

func (r *remoteWallet) Certificate(kind, certFormat string, _ walletCertOptions) ([]byte, error) {
	return r.c.Certificate(kind, certFormat)
}

func (r *remoteWallet) RegisterRelyingParty(rp registrar.WalletRelyingParty) (registrar.WalletRelyingParty, error) {
	var out registrar.WalletRelyingParty
	err := r.c.RegisterRelyingParty(rp, &out)
	return out, err
}

func (r *remoteWallet) Enrol(e registrar.Enrolment, update bool) (*registrar.EnrolmentResult, error) {
	var out registrar.EnrolmentResult
	if err := r.c.Enrol(e, update, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *remoteWallet) RegistrationCertificateViews(identifier string) ([]registrar.RegistrationStatusView, error) {
	var out []registrar.RegistrationStatusView
	err := r.c.RegistrationCertificateViews(identifier, &out)
	return out, err
}

func (r *remoteWallet) RegistrarRecords() ([]registrar.WalletRelyingParty, error) {
	var out []registrar.WalletRelyingParty
	err := r.c.RegistrarRecords(&out)
	return out, err
}

func (r *remoteWallet) SetRegistrationCertificatesRevoked(identifier string, scope registrar.RegistrationScope, revoked bool) (int, error) {
	var out struct {
		Changed int `json:"changed"`
	}
	err := r.c.SetRegistrationCertificateStatus(map[string]any{
		"identifier":            identifier,
		"serviceIdentifier":     scope.ServiceIdentifier,
		"intendedUseIdentifier": scope.IntendedUseIdentifier,
		"revoked":               revoked,
	}, &out)
	return out.Changed, err
}

func (r *remoteWallet) DeleteRelyingParty(identifier string) error {
	return r.c.DeleteRelyingParty(identifier)
}

func (r *remoteWallet) CatalogAttestations() ([]registrar.CatalogAttestation, error) {
	var out []registrar.CatalogAttestation
	err := r.c.CatalogAttestations(&out)
	return out, err
}

func (r *remoteWallet) AddCatalogAttestation(entry registrar.CatalogAttestation) (registrar.CatalogAttestation, error) {
	var out registrar.CatalogAttestation
	err := r.c.AddCatalogAttestation(entry, &out)
	return out, err
}

func (r *remoteWallet) DeleteCatalogAttestation(id string) error {
	return r.c.DeleteCatalogAttestation(id)
}

func (r *remoteWallet) TrustState() (wallet.TrustedListState, error) {
	var out wallet.TrustedListState
	err := r.c.TrustState(&out)
	return out, err
}

func (r *remoteWallet) AddTrustedEntity(list, name, certificatesPEM string) (wallet.TrustedEntity, error) {
	var out wallet.TrustedEntity
	err := r.c.AddTrustedEntity(map[string]string{"list": list, "name": name, "certificates": certificatesPEM}, &out)
	return out, err
}

func (r *remoteWallet) RemoveTrustedEntity(id string) error {
	return r.c.RemoveTrustedEntity(id)
}

func (r *remoteWallet) AddTrustedList(url string) (wallet.TrustedListLink, error) {
	var link wallet.TrustedListLink
	err := r.c.AddTrustedList(url, &link)
	return link, err
}

func (r *remoteWallet) RemoveTrustedList(url string) error {
	return r.c.RemoveTrustedList(url)
}

func (r *remoteWallet) AccessCertificate(req registrar.AccessCertificateRequest) (*registrar.AccessCertificateResult, error) {
	var out registrar.AccessCertificateResult
	if err := r.c.AccessCertificate(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *remoteWallet) RegistrationCertificate(req registrar.RegistrationCertificateRequest) (*registrar.RegistrationCertificateResult, error) {
	var out registrar.RegistrationCertificateResult
	if err := r.c.RegistrationCertificate(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *remoteWallet) Config() (map[string]any, error) {
	cfg, err := r.c.ServerConfig()
	if err != nil {
		return nil, err
	}
	cfg["remote_url"] = r.c.BaseURL
	return cfg, nil
}

func decodeTemplateDoc(doc map[string]any) (*credtemplate.Template, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var tpl credtemplate.Template
	if err := json.Unmarshal(data, &tpl); err != nil {
		return nil, fmt.Errorf("decoding remote template: %w", err)
	}
	return &tpl, nil
}

type localWallet struct {
	load func() (*wallet.Wallet, *wallet.WalletStore, error)
}

func (l *localWallet) URL() string { return "" }

// management loads the wallet and runs the operations that the HTTP API runs.
func (l *localWallet) management() (*wallet.Management, *wallet.Wallet, *wallet.WalletStore, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, nil, nil, err
	}
	return wallet.NewManagement(w, func() error {
		if err := store.Save(w); err != nil {
			return fmt.Errorf("saving wallet: %w", err)
		}
		return nil
	}), w, store, nil
}

func (l *localWallet) Credentials() ([]map[string]any, error) {
	m, _, _, err := l.management()
	if err != nil {
		return nil, err
	}
	listing, _ := m.CredentialListing(0, 0)
	return listing, nil
}

func (l *localWallet) RefreshCredential(id string) (map[string]any, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	renewed, err := w.RefreshCredential(id)
	if err != nil {
		return nil, err
	}
	if err := store.Save(w); err != nil {
		return nil, fmt.Errorf("saving the renewed credential: %w", err)
	}
	return wallet.CredentialSummary(*renewed), nil
}

// DeferredIssuances reads the pending records straight out of the store. A
// local wallet has no poller, so these only move when a wallet server runs.
func (l *localWallet) DeferredIssuances() ([]map[string]any, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	pending := w.DeferredIssuanceList()
	out := make([]map[string]any, 0, len(pending))
	for _, p := range pending {
		out = append(out, wallet.DeferredIssuanceSummary(p))
	}
	return out, nil
}

func (l *localWallet) Credential(id string) (map[string]any, error) {
	m, _, _, err := l.management()
	if err != nil {
		return nil, err
	}
	return m.Credential(id)
}

func (l *localWallet) ImportCredential(raw string) (map[string]any, error) {
	m, _, _, err := l.management()
	if err != nil {
		return nil, err
	}
	return m.ImportCredential(raw)
}

func (l *localWallet) RemoveCredential(id string) error {
	m, _, _, err := l.management()
	if err != nil {
		return err
	}
	return m.RemoveCredential(id)
}

func (l *localWallet) RemoveAllCredentials() (wallet.RemovedCredentials, error) {
	m, _, _, err := l.management()
	if err != nil {
		return wallet.RemovedCredentials{}, err
	}
	return m.RemoveAllCredentials()
}

func (l *localWallet) Issue(req map[string]any) (map[string]any, error) {
	m, w, store, err := l.management()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var apiReq wallet.IssueAPIRequest
	if err := json.Unmarshal(data, &apiReq); err != nil {
		return nil, fmt.Errorf("building issue request: %w", err)
	}
	summary, err := m.Issue(apiReq)
	if err != nil {
		return nil, err
	}
	warnIssuedEndpointsOffline(store, w)
	return summary, nil
}

func (l *localWallet) Logs() ([]wallet.LogEntry, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	return w.GetLog(), nil
}

func (l *localWallet) ClearLogs() error {
	_, store, err := l.load()
	if err != nil {
		return err
	}
	return store.ClearLog()
}

func (l *localWallet) Templates() ([]credtemplate.Template, error) {
	loc, err := resolveTemplates()
	if err != nil {
		return nil, err
	}
	return credtemplate.List(loc)
}

func (l *localWallet) Template(name string) (*credtemplate.Template, error) {
	loc, err := resolveTemplates()
	if err != nil {
		return nil, err
	}
	return credtemplate.Load(name, loc)
}

func (l *localWallet) SaveTemplate(tpl credtemplate.Template) (string, error) {
	loc, err := resolveTemplates()
	if err != nil {
		return "", err
	}
	return credtemplate.Save(loc, tpl)
}

func (l *localWallet) DeleteTemplate(name string) error {
	loc, err := resolveTemplates()
	if err != nil {
		return err
	}
	return credtemplate.Delete(loc, name)
}

func (l *localWallet) RegisterRelyingParty(rp registrar.WalletRelyingParty) (registrar.WalletRelyingParty, error) {
	w, store, err := l.load()
	if err != nil {
		return registrar.WalletRelyingParty{}, err
	}
	stored, err := w.Registrar().RegisterRelyingParty(rp)
	if err != nil {
		return registrar.WalletRelyingParty{}, err
	}
	if err := store.Save(w); err != nil {
		return registrar.WalletRelyingParty{}, fmt.Errorf("saving wallet: %w", err)
	}
	return stored, nil
}

func (l *localWallet) DeleteRelyingParty(identifier string) error {
	w, store, err := l.load()
	if err != nil {
		return err
	}
	if err := w.Registrar().DeleteRelyingParty(identifier); err != nil {
		return err
	}
	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}
	return nil
}

func (l *localWallet) CatalogAttestations() ([]registrar.CatalogAttestation, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	return w.Registrar().CatalogAttestations(), nil
}

func (l *localWallet) AddCatalogAttestation(entry registrar.CatalogAttestation) (registrar.CatalogAttestation, error) {
	w, store, err := l.load()
	if err != nil {
		return registrar.CatalogAttestation{}, err
	}
	stored, err := w.Registrar().AddCatalogAttestation(entry)
	if err != nil {
		return registrar.CatalogAttestation{}, err
	}
	if err := store.Save(w); err != nil {
		return registrar.CatalogAttestation{}, fmt.Errorf("saving wallet: %w", err)
	}
	return stored, nil
}

func (l *localWallet) DeleteCatalogAttestation(id string) error {
	w, store, err := l.load()
	if err != nil {
		return err
	}
	if err := w.Registrar().DeleteCatalogAttestation(id); err != nil {
		return err
	}
	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}
	return nil
}

func (l *localWallet) TrustState() (wallet.TrustedListState, error) {
	w, _, err := l.load()
	if err != nil {
		return wallet.TrustedListState{}, err
	}
	return w.TrustState(), nil
}

func (l *localWallet) AddTrustedEntity(list, name, certificatesPEM string) (wallet.TrustedEntity, error) {
	var entity wallet.TrustedEntity
	err := l.change(func(w *wallet.Wallet) (err error) {
		entity, err = w.AddTrustedEntity(list, name, certificatesPEM)
		return err
	})
	return entity, err
}

func (l *localWallet) RemoveTrustedEntity(id string) error {
	return l.change(func(w *wallet.Wallet) error { return w.RemoveTrustedEntity(id) })
}

func (l *localWallet) AddTrustedList(url string) (wallet.TrustedListLink, error) {
	var link wallet.TrustedListLink
	err := l.change(func(w *wallet.Wallet) error {
		var err error
		link, err = w.AddTrustedList(url)
		return err
	})
	return link, err
}

func (l *localWallet) RemoveTrustedList(url string) error {
	return l.change(func(w *wallet.Wallet) error { return w.RemoveTrustedList(url) })
}

// change applies a change to the local wallet and saves it.
func (l *localWallet) change(apply func(*wallet.Wallet) error) error {
	w, store, err := l.load()
	if err != nil {
		return err
	}
	if err := apply(w); err != nil {
		return err
	}
	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}
	return nil
}

func (l *localWallet) Enrol(e registrar.Enrolment, update bool) (*registrar.EnrolmentResult, error) {
	var result *registrar.EnrolmentResult
	err := l.change(func(w *wallet.Wallet) (err error) {
		result, err = w.Registrar().Enrol(e, update)
		return err
	})
	return result, err
}

func (l *localWallet) RegistrationCertificateViews(identifier string) ([]registrar.RegistrationStatusView, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	return w.Registrar().RegistrationCertificateViews(identifier), nil
}

func (l *localWallet) RegistrarRecords() ([]registrar.WalletRelyingParty, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	return w.Registrar().RegisteredRelyingParties(), nil
}

func (l *localWallet) AccessCertificate(req registrar.AccessCertificateRequest) (*registrar.AccessCertificateResult, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	return w.Registrar().IssueAccessCertificate(req)
}

func (l *localWallet) RegistrationCertificate(req registrar.RegistrationCertificateRequest) (*registrar.RegistrationCertificateResult, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	result, err := w.Registrar().IssueRegistrationCertificate(req)
	if err != nil {
		return nil, err
	}
	if err := store.Save(w); err != nil {
		return nil, fmt.Errorf("saving wallet: %w", err)
	}
	return result, nil
}

func (l *localWallet) SetRegistrationCertificatesRevoked(identifier string, scope registrar.RegistrationScope, revoked bool) (int, error) {
	w, store, err := l.load()
	if err != nil {
		return 0, err
	}
	changed, err := w.Registrar().SetRegistrationCertificatesRevoked(identifier, scope, revoked)
	if err != nil {
		return 0, err
	}
	if err := store.Save(w); err != nil {
		return 0, fmt.Errorf("saving wallet: %w", err)
	}
	return changed, nil
}

func (l *localWallet) Certificate(kind, certFormat string, opts walletCertOptions) ([]byte, error) {
	store, err := openStore()
	if err != nil {
		return nil, err
	}
	var certPEM []byte
	switch kind {
	case "ca":
		var err error
		certPEM, err = store.LoadOrCreateSharedCACertificatePEM()
		if err != nil {
			return nil, fmt.Errorf("loading wallet CA certificate: %w", err)
		}
	case "tls":
		issuerURL, err := deriveWalletIssuerURL(opts.port, opts.baseURL, opts.docker)
		if err != nil {
			return nil, err
		}
		certPEM, err = store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL)
		if err != nil {
			return nil, fmt.Errorf("loading wallet TLS certificate: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown certificate kind %q", kind)
	}
	if certFormat == "jwks" {
		return keys.CertificatePEMToJWKS(certPEM)
	}
	return certPEM, nil
}

func (l *localWallet) Config() (map[string]any, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	// Use the same configuration fields as GET /api/config so local and remote wallet
	// info agree.
	return map[string]any{
		"remote_url":                "",
		"wallet_dir":                store.Dir,
		"storage":                   store.Backend().Kind(),
		"seeded_keys":               store.Seeded(),
		"templates_dir":             w.Templates.String(),
		"base_url":                  w.BaseURL,
		"issuer_url":                w.IssuerURL,
		"status_list_url":           w.StatusListURL(),
		"preferred_format":          w.PreferredFormat,
		"key_attestation_level":     w.KeyAttestationLevelSetting(),
		"validation_mode":           string(w.ValidationMode),
		"vci_version":               string(w.VCIFeatureVersion()),
		"auto_accept":               w.AutoAccept,
		"session_transcript":        string(w.SessionTranscript),
		"require_haip":              w.RequireHAIP,
		"require_haip_issuance":     w.RequireHAIP,
		"require_arf":               w.RequireARF,
		"require_encrypted_request": w.RequireEncryptedRequest,
		"credential_count":          len(w.GetCredentials()),
	}, nil
}
