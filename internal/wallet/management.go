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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

var (
	ErrCredentialNotFound  = errors.New("credential not found")
	ErrCredentialProtected = errors.New("credential is protected and can only be removed through the wallet file")
	ErrStatusProtected     = errors.New("credential is protected and its status can only be changed through the wallet file")
	ErrNoStatusEntry       = errors.New("credential has no status entry")
	// ErrInvalidStatus follows draft-ietf-oauth-status-list §7. It limits
	// status values to 0 through 255.
	ErrInvalidStatus = errors.New("a status type takes a value from 0 to 255")
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
	typed := m.wallet.typeMetadata(raw, "wallet")
	var imported *StoredCredential
	err := m.commit(func() error {
		var err error
		if imported, err = m.wallet.importCredential(raw, "", "", typed); err != nil {
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

// SetCredentialStatus changes the status of a credential on the wallet's own
// status list, and of every copy of its batch.
func (m *Management) SetCredentialStatus(id string, status int) (StatusEntry, error) {
	if cred, ok := m.wallet.GetCredential(id); ok {
		id = cred.ID
	}
	if m.wallet.IsProtected(id) {
		return StatusEntry{}, ErrStatusProtected
	}
	if status < 0 || status > 255 {
		return StatusEntry{}, fmt.Errorf("%w, not %d", ErrInvalidStatus, status)
	}
	var entry StatusEntry
	err := m.commit(func() error {
		var ok bool
		if entry, ok = m.wallet.SetCredentialStatus(id, status); !ok {
			return ErrNoStatusEntry
		}
		verb := fmt.Sprintf("Set status %d on", status)
		switch status {
		case 0:
			verb = "Activated"
		case 1:
			verb = "Revoked"
		case 2:
			verb = "Suspended"
		}
		m.wallet.AddLog("management", fmt.Sprintf("%s credential %s", verb, id), true)
		return nil
	})
	return entry, err
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
	if m.wallet.visitorRules().OwnSigningKeys && (strings.TrimSpace(req.SigningKey) != "" || strings.TrimSpace(req.SigningCert) != "") {
		return nil, visitorLimit("the public demo can't override the signing key")
	}
	opts, err := req.Options()
	if err != nil {
		return nil, err
	}
	// The display images of the request are fetched before the commit, which
	// holds the store lock.
	if opts.Display != nil {
		display := *opts.Display
		display.Logo = m.wallet.storeLinkedImage(display.Logo, "logo")
		display.BackgroundImage = m.wallet.storeLinkedImage(display.BackgroundImage, "background_image")
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

// RenewCredential renews a credential with its refresh token. The wallet
// stores the renewal and a rotated refresh token under the store lock. The
// commit persists them for the local CLI because it has no server to save them.
// A failed renewal can still have rotated the refresh token, so the commit
// runs either way.
func (m *Management) RenewCredential(id string) (*StoredCredential, error) {
	renewed, err := m.wallet.RenewCredential(id)
	if commitErr := m.commit(func() error { return nil }); err == nil {
		err = commitErr
	}
	if err != nil {
		return nil, err
	}
	return renewed, nil
}

// DeferredIssuances omits the access token. It is a bearer secret for the
// wallet only.
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

// ClearLog also writes the clear marker. The marker removes entries appended
// to a shared store by other servers.
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

// SaveTemplate stores a template together with the catalogue entry requested
// by entry (see Wallet.TemplateCatalogRequest).
func (m *Management) SaveTemplate(tpl credtemplate.Template, entry *registrar.CatalogAttestation) (string, error) {
	// A visitor template stores its linked images, so no card loads them from
	// elsewhere. They are fetched before the commit, which holds the store
	// lock.
	if tpl.Display != nil && m.wallet.visitorRules().EmbeddedImagesOnly {
		display := *tpl.Display
		display.Logo = m.wallet.storeLinkedImage(display.Logo, "logo")
		display.BackgroundImage = m.wallet.storeLinkedImage(display.BackgroundImage, "background_image")
		tpl.Display = &display
	}
	entry, err := m.wallet.TemplateCatalogRequest(&tpl, entry)
	if err != nil {
		return "", err
	}
	var path string
	err = m.commit(func() error {
		var err error
		path, err = m.wallet.SaveTemplate(tpl, entry)
		return err
	})
	return path, err
}

func (m *Management) DeleteTemplate(name string) error {
	return m.wallet.DeleteTemplate(name)
}

func (m *Management) TrustState() trustedlists.Summary {
	return m.wallet.TrustedLists().Summary()
}

func (m *Management) AddTrustedEntity(list, name, certificatesPEM string) (trustedlists.Entity, error) {
	entity, err := trustedlists.NewEntity(list, name, certificatesPEM)
	if err != nil {
		return trustedlists.Entity{}, err
	}
	return entity, m.commit(func() error { return m.wallet.TrustedLists().StoreEntity(entity) })
}

func (m *Management) RemoveTrustedEntity(id string) error {
	return m.commit(func() error { return m.wallet.TrustedLists().RemoveEntity(id) })
}

// AddTrustedList refuses in a full wallet before it fetches the list.
func (m *Management) AddTrustedList(url string) (trustedlists.Link, error) {
	if err := m.wallet.TrustedLists().ListRoom(url); err != nil {
		return trustedlists.Link{}, err
	}
	added, err := m.wallet.TrustedLists().CheckList(url)
	if err != nil {
		return trustedlists.Link{}, err
	}
	return added, m.commit(func() error { return m.wallet.TrustedLists().StoreList(added.URL) })
}

func (m *Management) RemoveTrustedList(url string) error {
	return m.commit(func() error { return m.wallet.TrustedLists().RemoveList(strings.TrimSpace(url)) })
}

// Registrar runs a registrar operation for the local CLI and persists its
// change. A server runs the same registrar methods through registrar.Server
// and saves them with its Mutate hook.
func (m *Management) Registrar(op func(*registrar.Registrar) error) error {
	return m.commit(func() error { return op(m.wallet.Registrar()) })
}

// Config is the document of GET /api/config. A server adds its own details,
// such as its port.
func (m *Management) Config() map[string]any {
	w := m.wallet
	doc := map[string]any{}
	if data, err := json.Marshal(w.ConformanceDocument()); err == nil {
		_ = json.Unmarshal(data, &doc)
	}
	doc["base_url"] = w.BaseURL
	doc["issuer_url"] = w.IssuerURL
	doc["status_list_url"] = w.StatusListURL()
	doc["preferred_format"] = w.PreferredFormatSetting()
	doc["auto_accept"] = w.AutoAcceptSetting()
	doc["session_transcript"] = string(w.SessionTranscript)
	doc["adhoc_display_images"] = w.AdhocDisplayImages
	doc["credential_count"] = len(w.GetCredentials())
	doc["form_defaults"] = formDefaults()
	doc["templates_dir"] = w.Templates.String()
	doc["wallet_dir"], doc["storage"], doc["seeded_keys"] = "", "", false
	if m.store != nil {
		doc["wallet_dir"] = m.store.Dir
		doc["storage"] = m.store.Backend().Kind()
		doc["seeded_keys"] = m.store.Seeded()
	}
	return doc
}
