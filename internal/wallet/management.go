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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

var (
	ErrCredentialNotFound  = errors.New("credential not found")
	ErrCredentialProtected = errors.New("credential is protected and can only be removed through the wallet file")
)

// Management runs the management operations of the HTTP API and the local
// CLI. Each operation changes the wallet, writes its activity log entry and
// persists the change through commit. The result is the same whether a
// server runs or the CLI changes the store directly. Network calls run
// before commit, so a server does not hold its reload lock while it waits.
type Management struct {
	wallet *Wallet
	store  *WalletStore
	// commit applies change and persists the wallet when change succeeds.
	commit func(change func() error) error
}

// NewManagement persists each change to store.
func NewManagement(w *Wallet, store *WalletStore) *Management {
	return &Management{wallet: w, store: store, commit: func(change func() error) error {
		if err := change(); err != nil {
			return err
		}
		if err := store.Save(w); err != nil {
			return fmt.Errorf("saving wallet: %w", err)
		}
		return nil
	}}
}

// CredentialListing lists each batch once, newest first, without raw
// credentials and claims. A zero limit returns every credential from offset.
// total counts every listed credential.
func (m *Management) CredentialListing(offset, limit int) (listing []map[string]any, total int) {
	return m.wallet.CredentialsListingWindow(offset, limit), len(m.wallet.ListedCredentials())
}

func (m *Management) Credential(id string) (map[string]any, error) {
	cred, ok := m.wallet.GetCredential(id)
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return m.wallet.CredentialSummaryWithBatch(cred), nil
}

func (m *Management) ImportCredential(raw string) (map[string]any, error) {
	var imported *StoredCredential
	err := m.commit(func() error {
		var err error
		if imported, err = m.wallet.ImportCredential(raw); err != nil {
			return err
		}
		m.wallet.AddLog("management", fmt.Sprintf("Imported %s credential %s", imported.Format, credentialLabel(*imported)), true)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m.wallet.CredentialSummaryWithStatus(*imported), nil
}

func (m *Management) RemoveCredential(id string) error {
	if m.wallet.IsProtected(id) {
		return ErrCredentialProtected
	}
	label := id
	if cred, ok := m.wallet.GetCredential(id); ok {
		label = credentialLabel(cred)
	}
	return m.commit(func() error {
		if !m.wallet.RemoveCredential(id) {
			return ErrCredentialNotFound
		}
		m.wallet.AddLog("management", fmt.Sprintf("Deleted credential %s", label), true)
		return nil
	})
}

// RemovedCredentials reports a removal of every deletable credential.
type RemovedCredentials struct {
	Deleted       int `json:"deleted"`
	KeptProtected int `json:"kept_protected"`
}

func (m *Management) RemoveAllCredentials() (RemovedCredentials, error) {
	var removed RemovedCredentials
	err := m.commit(func() error {
		removed.Deleted = m.wallet.ClearCredentials()
		removed.KeptProtected = len(m.wallet.GetCredentials())
		detail := fmt.Sprintf("Deleted all credentials (%d)", removed.Deleted)
		if removed.KeptProtected > 0 {
			detail = fmt.Sprintf("Deleted all deletable credentials (%d, kept %d protected)", removed.Deleted, removed.KeptProtected)
		}
		m.wallet.AddLog("management", detail, true)
		return nil
	})
	return removed, err
}

func (m *Management) Issue(req IssueAPIRequest) (map[string]any, error) {
	opts, err := req.Options()
	if err != nil {
		return nil, err
	}
	// The display images of the request are fetched first. The issuance then
	// reads them from the data URIs.
	if opts.Display != nil {
		if err := m.wallet.checkDisplayImages(opts.Display.Logo, opts.Display.BackgroundImage); err != nil {
			return nil, err
		}
		display := *opts.Display
		display.Logo = m.wallet.cacheDisplayImage(strings.TrimSpace(display.Logo), "logo")
		display.BackgroundImage = m.wallet.cacheDisplayImage(strings.TrimSpace(display.BackgroundImage), "background_image")
		opts.Display = &display
	}
	var summary map[string]any
	err = m.commit(func() error {
		var err error
		if summary, err = m.wallet.IssueSummary(opts); err != nil {
			return err
		}
		m.wallet.AddLog("management", fmt.Sprintf("Issued %s credential %s", summary["format"], credentialTypeLabel(summary)), true)
		return nil
	})
	return summary, err
}

// RefreshCredential renews a credential with its refresh token. A failed
// renewal can still have rotated the refresh token, so the wallet saves the
// credential either way.
func (m *Management) RefreshCredential(id string) (*StoredCredential, error) {
	renewed, err := m.wallet.RefreshCredential(id)
	if err != nil {
		if cred, ok := m.wallet.GetCredential(id); ok {
			_ = m.commit(func() error {
				m.wallet.PutCredential(cred)
				return nil
			})
		}
		return nil, err
	}
	return renewed, m.saveRenewed(*renewed)
}

// saveRenewed puts the renewed credential back, because a concurrent reload
// may have reverted it. A renewed credential starts with status 0. Its entry
// is registered again, because a reload may have removed or reverted it.
func (m *Management) saveRenewed(renewed StoredCredential) error {
	return m.commit(func() error {
		m.wallet.PutCredential(renewed)
		if ref := m.wallet.ownStatusRef(renewed); ref != nil {
			m.wallet.RegisterStatusEntry(renewed.ID, ref.Idx)
		}
		return nil
	})
}

// DeferredIssuances omits the access token, a bearer secret only the wallet
// uses.
func (m *Management) DeferredIssuances() []map[string]any {
	pending := m.wallet.DeferredIssuanceList()
	out := make([]map[string]any, 0, len(pending))
	for _, p := range pending {
		out = append(out, DeferredIssuanceSummary(p))
	}
	return out
}

func (m *Management) Log() []LogEntry {
	return m.wallet.GetLog()
}

// ClearLog also writes the clear marker, which removes the entries that other
// servers append to a shared store.
func (m *Management) ClearLog() error {
	if m.store != nil {
		if err := m.store.writeLogCleanMarker(time.Now()); err != nil {
			return fmt.Errorf("clearing the stored log: %w", err)
		}
	}
	return m.commit(func() error {
		m.wallet.ClearLog()
		return nil
	})
}

// Templates lists the templates. The templates that visitors can't change
// show as predefined.
func (m *Management) Templates() ([]credtemplate.Template, error) {
	templates, err := credtemplate.List(m.wallet.Templates)
	for i := range templates {
		templates[i].Predefined = templates[i].Predefined || m.wallet.TemplateFixed(templates[i])
	}
	return templates, err
}

func (m *Management) Template(name string) (*credtemplate.Template, error) {
	return credtemplate.Load(name, m.wallet.Templates)
}

// SaveTemplate stores a template and, if entry is set, adds it to the
// catalogue as a new entry.
func (m *Management) SaveTemplate(tpl credtemplate.Template, entry *registrar.CatalogAttestation) (string, error) {
	if entry != nil {
		checked, err := m.wallet.Registrar().TemplateCatalogEntry(tpl, *entry)
		if err != nil {
			return "", err
		}
		tpl.Category = checked.Category
		entry = &checked
	}
	var path string
	err := m.commit(func() error {
		var err error
		path, err = m.wallet.SaveTemplate(tpl, entry)
		return err
	})
	return path, err
}

func (m *Management) DeleteTemplate(name string) error {
	return m.wallet.DeleteTemplate(name)
}

func (m *Management) TrustState() TrustedListState {
	return m.wallet.TrustState()
}

func (m *Management) AddTrustedEntity(list, name, certificatesPEM string) (TrustedEntity, error) {
	entity, err := NewTrustedEntity(list, name, certificatesPEM)
	if err != nil {
		return TrustedEntity{}, err
	}
	return entity, m.commit(func() error { return m.wallet.storeTrustedEntity(entity) })
}

func (m *Management) RemoveTrustedEntity(id string) error {
	return m.commit(func() error { return m.wallet.RemoveTrustedEntity(id) })
}

// AddTrustedList refuses in a full wallet before it fetches the list.
func (m *Management) AddTrustedList(url string) (TrustedListLink, error) {
	if err := m.wallet.trustedListRoom(url); err != nil {
		return TrustedListLink{}, err
	}
	added, err := m.wallet.CheckTrustedList(url)
	if err != nil {
		return TrustedListLink{}, err
	}
	return added, m.commit(func() error { return m.wallet.storeTrustedList(added.URL) })
}

func (m *Management) RemoveTrustedList(url string) error {
	return m.commit(func() error { return m.wallet.RemoveTrustedList(strings.TrimSpace(url)) })
}

// The registrar operations below serve the local CLI. A server runs the
// same registrar methods through registrar.Server and saves them with its
// Mutate hook.

func (m *Management) RegisterRelyingParty(rp registrar.WalletRelyingParty) (stored registrar.WalletRelyingParty, err error) {
	err = m.commit(func() (err error) {
		stored, err = m.wallet.Registrar().RegisterRelyingParty(rp)
		return err
	})
	return stored, err
}

func (m *Management) Enrol(e registrar.Enrolment, update bool) (result *registrar.EnrolmentResult, err error) {
	err = m.commit(func() (err error) {
		result, err = m.wallet.Registrar().Enrol(e, update)
		return err
	})
	return result, err
}

func (m *Management) DeleteRelyingParty(identifier string) error {
	return m.commit(func() error { return m.wallet.Registrar().DeleteRelyingParty(identifier) })
}

func (m *Management) RegistrarRecords() []registrar.WalletRelyingParty {
	return m.wallet.Registrar().RegisteredRelyingParties()
}

func (m *Management) RegistrationCertificateViews(identifier string) []registrar.RegistrationStatusView {
	return m.wallet.Registrar().RegistrationCertificateViews(identifier)
}

func (m *Management) SetRegistrationCertificatesRevoked(identifier string, scope registrar.RegistrationScope, revoked bool) (changed int, err error) {
	err = m.commit(func() (err error) {
		changed, err = m.wallet.Registrar().SetRegistrationCertificatesRevoked(identifier, scope, revoked)
		return err
	})
	return changed, err
}

func (m *Management) CatalogAttestations() []registrar.CatalogAttestation {
	return m.wallet.Registrar().CatalogAttestations()
}

func (m *Management) AddCatalogAttestation(entry registrar.CatalogAttestation) (stored registrar.CatalogAttestation, err error) {
	err = m.commit(func() (err error) {
		stored, err = m.wallet.Registrar().AddCatalogAttestation(entry)
		return err
	})
	return stored, err
}

func (m *Management) DeleteCatalogAttestation(id string) error {
	return m.commit(func() error { return m.wallet.Registrar().DeleteCatalogAttestation(id) })
}

func (m *Management) AccessCertificate(req registrar.AccessCertificateRequest) (*registrar.AccessCertificateResult, error) {
	return m.wallet.Registrar().IssueAccessCertificate(req)
}

func (m *Management) RegistrationCertificate(req registrar.RegistrationCertificateRequest) (result *registrar.RegistrationCertificateResult, err error) {
	err = m.commit(func() (err error) {
		result, err = m.wallet.Registrar().IssueRegistrationCertificate(req)
		return err
	})
	return result, err
}

// Config is the document of GET /api/config. A server adds what only it
// knows, such as its port.
func (m *Management) Config() map[string]any {
	w := m.wallet
	doc := w.conformanceDocument()
	doc["base_url"] = w.BaseURL
	doc["issuer_url"] = w.IssuerURL
	doc["status_list_url"] = w.StatusListURL()
	doc["preferred_format"] = w.PreferredFormatSetting()
	doc["auto_accept"] = w.AutoAcceptSetting()
	doc["session_transcript"] = string(w.SessionTranscript)
	doc["adhoc_display_images"] = w.AdhocDisplayImages
	doc["credential_count"] = len(w.GetCredentials())
	doc["templates_dir"] = w.Templates.String()
	doc["wallet_dir"], doc["storage"], doc["seeded_keys"] = "", "", false
	if m.store != nil {
		doc["wallet_dir"] = m.store.Dir
		doc["storage"] = m.store.Backend().Kind()
		doc["seeded_keys"] = m.store.Seeded()
	}
	return doc
}

// conformanceDocument reports the settings every flow applies. GET
// /api/config and the conformance endpoints share it.
func (w *Wallet) conformanceDocument() map[string]any {
	w.mu.RLock()
	defer w.mu.RUnlock()
	c := w.ConformanceSettings
	vciVersion := c.VCIVersion
	if vciVersion == "" {
		vciVersion = VCIVersion10
	}
	var override any
	if c.tlsVerify != nil {
		override = *c.tlsVerify
	}
	return map[string]any{
		"tls_verify":          w.tlsVerificationLocked(),
		"tls_verify_override": override,
		"validation_mode":     string(c.ValidationMode),
		"require_haip":        c.RequireHAIP,
		// Issuance and presentation use the same flag, and each has its
		// own field.
		"require_haip_issuance":     c.RequireHAIP,
		"require_arf":               c.RequireARF,
		"require_encrypted_request": c.RequireEncryptedRequest,
		"vci_version":               string(vciVersion),
		"key_attestation_level":     c.KeyAttestationLevel,
		"force_client_attestation":  w.ForceClientAttestation,
	}
}
