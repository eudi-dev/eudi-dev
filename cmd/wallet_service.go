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

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
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
	RemoveAllCredentials() (int, error)
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

func (r *remoteWallet) RemoveAllCredentials() (int, error) { return r.c.RemoveAllCredentials() }

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

func (l *localWallet) Credentials() ([]map[string]any, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	// Collapse batches just as the HTTP listing does so local and remote output agree.
	creds := w.ListedCredentials()
	wallet.SortCredentialsNewestFirst(creds)
	summaries := make([]map[string]any, len(creds))
	for i, c := range creds {
		summaries[i] = w.CredentialSummaryWithBatch(c)
		// Omit raw credentials and claim values to match the HTTP listing.
		wallet.TrimCredentialListing(summaries[i])
	}
	return summaries, nil
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
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	cred, ok := w.GetCredential(id)
	if !ok {
		return nil, fmt.Errorf("credential %s not found", id)
	}
	return w.CredentialSummaryWithBatch(cred), nil
}

func (l *localWallet) ImportCredential(raw string) (map[string]any, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("importing credential: %w", err)
	}
	if err := store.Save(w); err != nil {
		return nil, fmt.Errorf("saving wallet: %w", err)
	}
	return w.CredentialSummaryWithStatus(*imported), nil
}

func (l *localWallet) RemoveCredential(id string) error {
	w, store, err := l.load()
	if err != nil {
		return err
	}
	if w.IsProtected(id) {
		return fmt.Errorf("credential %s is protected: remove it from the wallet file to delete it", id)
	}
	if !w.RemoveCredential(id) {
		return fmt.Errorf("credential %s not found", id)
	}
	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}
	return nil
}

func (l *localWallet) RemoveAllCredentials() (int, error) {
	w, store, err := l.load()
	if err != nil {
		return 0, err
	}
	count := w.ClearCredentials()
	if err := store.Save(w); err != nil {
		return 0, fmt.Errorf("saving wallet: %w", err)
	}
	return count, nil
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
	opts, err := apiReq.Options()
	if err != nil {
		return nil, err
	}
	summary, err := w.IssueSummary(opts)
	if err != nil {
		return nil, err
	}
	if err := store.Save(w); err != nil {
		return nil, fmt.Errorf("saving wallet: %w", err)
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
		"require_encrypted_request": w.RequireEncryptedRequest,
		"credential_count":          len(w.GetCredentials()),
	}, nil
}
