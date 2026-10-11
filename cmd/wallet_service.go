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
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustedlists"
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
	TrustState() (trustedlists.Summary, error)
	// TrustListIndex describes the lists the wallet signs, like /api/trustlists.
	TrustListIndex() ([]map[string]any, error)
	AddTrustedEntity(list, name, certificatesPEM string) (trustedlists.Entity, error)
	RemoveTrustedEntity(id string) error
	AddTrustedList(url string) (trustedlists.Link, error)
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
		var set []string
		var want walletConformance
		if walletFlags.Changed("mode") {
			mode, err := wallet.ParseValidationMode(walletValidationMode)
			if err != nil {
				return nil, err
			}
			set = []string{"--mode"}
			want.settings.ValidationMode = mode
		}
		if err := checkRemoteSettings(c, set, want); err != nil {
			return nil, err
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
		tpl, err := decodeDoc[credtemplate.Template](doc)
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
	return decodeDoc[credtemplate.Template](doc)
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

func (r *remoteWallet) TrustListIndex() ([]map[string]any, error) { return r.c.TrustLists() }

func (r *remoteWallet) TrustState() (trustedlists.Summary, error) {
	var out trustedlists.Summary
	err := r.c.TrustState(&out)
	return out, err
}

func (r *remoteWallet) AddTrustedEntity(list, name, certificatesPEM string) (trustedlists.Entity, error) {
	var out trustedlists.Entity
	err := r.c.AddTrustedEntity(map[string]string{"list": list, "name": name, "certificates": certificatesPEM}, &out)
	return out, err
}

func (r *remoteWallet) RemoveTrustedEntity(id string) error {
	return r.c.RemoveTrustedEntity(id)
}

func (r *remoteWallet) AddTrustedList(url string) (trustedlists.Link, error) {
	var link trustedlists.Link
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

// decodeDoc decodes a JSON document of a remote wallet into T.
func decodeDoc[T any](doc map[string]any) (*T, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decoding the remote wallet's %T: %w", out, err)
	}
	return &out, nil
}

type localWallet struct {
	load func() (*wallet.Wallet, *wallet.WalletStore, error)
}

func (l *localWallet) URL() string { return "" }

// management loads the wallet and runs the operations that the HTTP API runs.
func (l *localWallet) management() (*wallet.Management, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	return wallet.NewManagement(w, store), nil
}

// with runs read on the loaded wallet's management.
func with[T any](l *localWallet, read func(*wallet.Management) (T, error)) (T, error) {
	m, err := l.management()
	if err != nil {
		var zero T
		return zero, err
	}
	return read(m)
}

func (l *localWallet) Credentials() ([]map[string]any, error) {
	return with(l, func(m *wallet.Management) ([]map[string]any, error) {
		listing, _ := m.CredentialListing(0, 0)
		return listing, nil
	})
}

func (l *localWallet) RefreshCredential(id string) (map[string]any, error) {
	return with(l, func(m *wallet.Management) (map[string]any, error) {
		renewed, err := m.RefreshCredential(id)
		if err != nil {
			return nil, err
		}
		return wallet.CredentialSummary(*renewed), nil
	})
}

// DeferredIssuances reads the pending records out of the store. A local
// wallet has no poller, so these only move when a wallet server runs.
func (l *localWallet) DeferredIssuances() ([]map[string]any, error) {
	return with(l, func(m *wallet.Management) ([]map[string]any, error) { return m.DeferredIssuances(), nil })
}

func (l *localWallet) Credential(id string) (map[string]any, error) {
	return with(l, func(m *wallet.Management) (map[string]any, error) { return m.Credential(id) })
}

func (l *localWallet) ImportCredential(raw string) (map[string]any, error) {
	return with(l, func(m *wallet.Management) (map[string]any, error) { return m.ImportCredential(raw) })
}

func (l *localWallet) RemoveCredential(id string) error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.RemoveCredential(id) })
	return err
}

func (l *localWallet) RemoveAllCredentials() (wallet.RemovedCredentials, error) {
	return with(l, func(m *wallet.Management) (wallet.RemovedCredentials, error) { return m.RemoveAllCredentials() })
}

func (l *localWallet) Issue(req map[string]any) (map[string]any, error) {
	w, store, err := l.load()
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
	summary, err := wallet.NewManagement(w, store).Issue(apiReq)
	if err != nil {
		return nil, err
	}
	warnIssuedEndpointsOffline(store, w)
	return summary, nil
}

func (l *localWallet) Logs() ([]wallet.LogEntry, error) {
	return with(l, func(m *wallet.Management) ([]wallet.LogEntry, error) { return m.Log(), nil })
}

func (l *localWallet) ClearLogs() error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.ClearLog() })
	return err
}

func (l *localWallet) Templates() ([]credtemplate.Template, error) {
	return with(l, func(m *wallet.Management) ([]credtemplate.Template, error) { return m.Templates() })
}

func (l *localWallet) Template(name string) (*credtemplate.Template, error) {
	return with(l, func(m *wallet.Management) (*credtemplate.Template, error) { return m.Template(name) })
}

func (l *localWallet) SaveTemplate(tpl credtemplate.Template) (string, error) {
	return with(l, func(m *wallet.Management) (string, error) { return m.SaveTemplate(tpl, nil) })
}

func (l *localWallet) DeleteTemplate(name string) error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.DeleteTemplate(name) })
	return err
}

func (l *localWallet) RegisterRelyingParty(rp registrar.WalletRelyingParty) (registrar.WalletRelyingParty, error) {
	return with(l, func(m *wallet.Management) (registrar.WalletRelyingParty, error) { return m.RegisterRelyingParty(rp) })
}

func (l *localWallet) Enrol(e registrar.Enrolment, update bool) (*registrar.EnrolmentResult, error) {
	return with(l, func(m *wallet.Management) (*registrar.EnrolmentResult, error) { return m.Enrol(e, update) })
}

func (l *localWallet) DeleteRelyingParty(identifier string) error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.DeleteRelyingParty(identifier) })
	return err
}

func (l *localWallet) RegistrarRecords() ([]registrar.WalletRelyingParty, error) {
	return with(l, func(m *wallet.Management) ([]registrar.WalletRelyingParty, error) { return m.RegistrarRecords(), nil })
}

func (l *localWallet) RegistrationCertificateViews(identifier string) ([]registrar.RegistrationStatusView, error) {
	return with(l, func(m *wallet.Management) ([]registrar.RegistrationStatusView, error) {
		return m.RegistrationCertificateViews(identifier), nil
	})
}

func (l *localWallet) SetRegistrationCertificatesRevoked(identifier string, scope registrar.RegistrationScope, revoked bool) (int, error) {
	return with(l, func(m *wallet.Management) (int, error) {
		return m.SetRegistrationCertificatesRevoked(identifier, scope, revoked)
	})
}

func (l *localWallet) CatalogAttestations() ([]registrar.CatalogAttestation, error) {
	return with(l, func(m *wallet.Management) ([]registrar.CatalogAttestation, error) {
		return m.CatalogAttestations(), nil
	})
}

func (l *localWallet) AddCatalogAttestation(entry registrar.CatalogAttestation) (registrar.CatalogAttestation, error) {
	return with(l, func(m *wallet.Management) (registrar.CatalogAttestation, error) {
		return m.AddCatalogAttestation(entry)
	})
}

func (l *localWallet) DeleteCatalogAttestation(id string) error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.DeleteCatalogAttestation(id) })
	return err
}

func (l *localWallet) AccessCertificate(req registrar.AccessCertificateRequest) (*registrar.AccessCertificateResult, error) {
	return with(l, func(m *wallet.Management) (*registrar.AccessCertificateResult, error) {
		return m.AccessCertificate(req)
	})
}

func (l *localWallet) RegistrationCertificate(req registrar.RegistrationCertificateRequest) (*registrar.RegistrationCertificateResult, error) {
	return with(l, func(m *wallet.Management) (*registrar.RegistrationCertificateResult, error) {
		return m.RegistrationCertificate(req)
	})
}

func (l *localWallet) TrustListIndex() ([]map[string]any, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(w.TrustedLists().IndexEntries(w.IssuerURL))
	if err != nil {
		return nil, err
	}
	entries := []map[string]any{}
	return entries, json.Unmarshal(data, &entries)
}

func (l *localWallet) TrustState() (trustedlists.Summary, error) {
	return with(l, func(m *wallet.Management) (trustedlists.Summary, error) { return m.TrustState(), nil })
}

func (l *localWallet) AddTrustedEntity(list, name, certificatesPEM string) (trustedlists.Entity, error) {
	return with(l, func(m *wallet.Management) (trustedlists.Entity, error) {
		return m.AddTrustedEntity(list, name, certificatesPEM)
	})
}

func (l *localWallet) RemoveTrustedEntity(id string) error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.RemoveTrustedEntity(id) })
	return err
}

func (l *localWallet) AddTrustedList(url string) (trustedlists.Link, error) {
	return with(l, func(m *wallet.Management) (trustedlists.Link, error) { return m.AddTrustedList(url) })
}

func (l *localWallet) RemoveTrustedList(url string) error {
	_, err := with(l, func(m *wallet.Management) (struct{}, error) { return struct{}{}, m.RemoveTrustedList(url) })
	return err
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
		origin, err := walletOrigin(opts.port, opts.baseURL, opts.docker)
		if err != nil {
			return nil, err
		}
		certPEM, err = store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL(origin.Issuer)
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
	return with(l, func(m *wallet.Management) (map[string]any, error) {
		cfg := m.Config()
		cfg["remote_url"] = ""
		return cfg, nil
	})
}
