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

// Package trustedlists holds the wallet's trusted lists (ADR-0022, ADR-0023):
// the lists signed by the wallet itself, the providers and lists added by
// users, the external lists read by the wallet, and their trust anchors.
package trustedlists

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

// Additions are the providers and lists added by users through `trust` or the
// API. The wallet embeds them, so they are saved with the wallet.
type Additions struct {
	TrustedEntities   []Entity `json:"trusted_entities,omitempty"`
	AddedTrustedLists []string `json:"trusted_lists,omitempty"`
}

// Clone copies the lists, so the copy and the original change independently.
func (a Additions) Clone() Additions {
	return Additions{TrustedEntities: slices.Clone(a.TrustedEntities), AddedTrustedLists: slices.Clone(a.AddedTrustedLists)}
}

// Settings are the trust settings of the wallet: the CAs from
// --relying-party-ca and --trusted-list-ca, the lists from --trusted-list and
// how many providers and lists users may add. Zero means no bound.
type Settings struct {
	RelyingPartyCAPEM []byte
	ListCAPEM         []byte
	ConfiguredLists   []string
	MaxEntities       int
	MaxLists          int
}

// Env gives the trusted lists access to the wallet that holds them.
type Env interface {
	Signer() *provider.Signer
	// IssuedAttestationSpecs are the credential types issued by the wallet.
	IssuedAttestationSpecs() []provider.IssuedAttestationSpec
	TemplateLocation() credtemplate.Location
	// IssuerURL is where the wallet publishes its own lists.
	IssuerURL() string
	// RegistrarBase is the base URL of the wallet's own lists.
	RegistrarBase() string
	HTTPClient() *http.Client
	// Strict reports strict validation mode.
	Strict() bool
	// ListedProviderName is the name of the wallet's own provider on its lists.
	ListedProviderName() string
}

// Set works on the Additions stored in a wallet while holding the lock of
// that wallet. settings is a copy taken when the wallet created the Set.
type Set struct {
	mu        *sync.RWMutex
	additions *Additions
	cache     *ListCache
	settings  Settings
	env       Env
}

func New(mu *sync.RWMutex, additions *Additions, cache *ListCache, settings Settings, env Env) *Set {
	return &Set{mu: mu, additions: additions, cache: cache, settings: settings, env: env}
}

// The IDs of the list of trusted lists and of the list of trusted list
// operators.
const (
	// ListOfListsID is the list that points to all of the wallet's trusted
	// lists (ETSI TS 119 602 V1.1.1 §6.3.13).
	ListOfListsID = "lists"
	// TrustedListCAID takes the CAs of trusted list operators, like
	// --trusted-list-ca. The wallet doesn't publish it.
	TrustedListCAID = "trusted-list-ca"
	ListOfListsType = "https://eudi-test.dev/LoTEType/ListOfTrustedLists"
)

// Entity is a provider added by a user to one of the wallet's trusted lists.
// The wallet signs the list with the entity on it, so the entity's
// certificates anchor the --arf checks.
type Entity struct {
	ID   string `json:"id"`
	List string `json:"list"`
	Name string `json:"name"`
	// Certificates are base64 DER certificates of the provider's CAs or
	// signers.
	Certificates []string `json:"certificates"`
}

// ErrNotFound reports a trusted entity or list missing from the wallet.
var ErrNotFound = errors.New("not on the wallet's trusted lists")

// ErrFull reports that the wallet holds as many added providers or lists as
// its capacity allows.
var ErrFull = errors.New("the wallet is full")

// EntityLists are the wallet lists that take trusted entities.
func EntityLists() []string {
	return append(slices.Clone(credtemplate.Categories), provider.WalletProviderListID, provider.AccessCAListID, provider.RegistrarListID, TrustedListCAID)
}

// NewEntity reads the provider with the certificates in PEM. Its ID follows
// from the list and the certificates.
func NewEntity(list, name, certificatesPEM string) (Entity, error) {
	list, name = strings.TrimSpace(list), strings.TrimSpace(name)
	if !slices.Contains(EntityLists(), list) {
		return Entity{}, fmt.Errorf("list %q is not one of %s", list, strings.Join(EntityLists(), ", "))
	}
	certs, err := keys.ParseCertificatesPEM([]byte(certificatesPEM))
	if err != nil {
		return Entity{}, fmt.Errorf("the certificates: %w", err)
	}
	entity := Entity{List: list, Name: jsonutil.FirstNonEmpty(name, certs[0].Subject.CommonName, "Trusted provider")}
	digest := sha256.New()
	digest.Write([]byte(list))
	for _, cert := range certs {
		entity.Certificates = append(entity.Certificates, base64.StdEncoding.EncodeToString(cert.Raw))
		digest.Write(cert.Raw)
	}
	entity.ID = hex.EncodeToString(digest.Sum(nil)[:8])
	return entity, nil
}

// certificates decodes the stored base64 DER certificates.
func (e Entity) certificates() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(e.Certificates))
	for _, encoded := range e.Certificates {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// StoreEntity puts the entity on its list, unless the wallet is full.
func (t *Set) StoreEntity(entity Entity) error {
	limit := t.settings.MaxEntities
	t.mu.Lock()
	defer t.mu.Unlock()
	others := slices.DeleteFunc(slices.Clone(t.additions.TrustedEntities), func(e Entity) bool { return e.ID == entity.ID })
	if limit > 0 && len(others) >= limit {
		return fmt.Errorf("%w: it holds at most %d added providers. Remove one first", ErrFull, limit)
	}
	t.additions.TrustedEntities = append(others, entity)
	return nil
}

// RemoveEntity takes a provider off its list.
func (t *Set) RemoveEntity(id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	before := len(t.additions.TrustedEntities)
	t.additions.TrustedEntities = slices.DeleteFunc(t.additions.TrustedEntities, func(e Entity) bool { return e.ID == id })
	if len(t.additions.TrustedEntities) == before {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return nil
}

// Entities returns the entities added by users.
func (t *Set) Entities() []Entity {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return slices.Clone(t.additions.TrustedEntities)
}

// listEntities returns the entities on a wallet list besides the wallet's
// own provider: those added by users and, on the access-ca and registrar
// lists, the CAs from --relying-party-ca. Their CAs anchor both the issued
// certificates and the status lists.
func (t *Set) listEntities(listID string) []lote.Entity {
	var out []lote.Entity
	for _, entity := range t.Entities() {
		if entity.List == listID {
			out = append(out, lote.Entity{Name: entity.Name, Issuance: entity.Certificates, Revocation: entity.Certificates})
		}
	}
	if listID == provider.AccessCAListID || listID == provider.RegistrarListID {
		configured, err := keys.ParseCertificatesPEM(t.settings.RelyingPartyCAPEM)
		if err == nil {
			for _, cert := range configured {
				encoded := base64.StdEncoding.EncodeToString(cert.Raw)
				out = append(out, lote.Entity{Name: jsonutil.FirstNonEmpty(cert.Subject.CommonName, "Relying party CA"), Issuance: []string{encoded}, Revocation: []string{encoded}})
			}
		}
	}
	return out
}

// ListCAs are the CAs trusted under --arf for the signer of a trusted list.
// The wallet's list operator key, certified by the wallet CA, signs the
// wallet's own lists. The Commission seals its compiled lists the same way
// (ARF TLPub_07). --trusted-list-ca and the trusted-list-ca entities add
// others.
func (t *Set) ListCAs() ([]*x509.Certificate, error) {
	var cas []*x509.Certificate
	if anchor := t.env.Signer().TrustAnchor(); anchor != nil {
		cas = append(cas, anchor)
	}
	if pemData := t.settings.ListCAPEM; len(pemData) > 0 {
		configured, err := keys.ParseCertificatesPEM(pemData)
		if err != nil {
			return nil, fmt.Errorf("the trusted list CAs: %w", err)
		}
		cas = append(cas, configured...)
	}
	for _, entity := range t.Entities() {
		if entity.List != TrustedListCAID {
			continue
		}
		certs, err := entity.certificates()
		if err != nil {
			return nil, fmt.Errorf("the trusted list CA %s: %w", entity.Name, err)
		}
		cas = append(cas, certs...)
	}
	return cas, nil
}
