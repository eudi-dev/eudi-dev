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

package validate

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
)

// Trust is what one credential validation trusts. A supplied key or trusted
// list is the only trust source. Without one, the trusted list of the
// credential's entry in a wallet's attestation catalogue anchors it.
type Trust struct {
	// Keys are public keys supplied by the caller.
	Keys []crypto.PublicKey
	// Issuance and Revocation are the supplied anchors. Issuance services
	// anchor credentials, revocation services their status lists (ETSI TS
	// 119 602 V1.1.1 Table D.3).
	Issuance, Revocation []*x509.Certificate
	// Supplied is set once the caller supplies a key or a trusted list, even
	// a list without services.
	Supplied bool
	// Pending is set when a supplied trusted list is only reachable over the
	// network and the validation runs offline.
	Pending bool
	// Err is why the supplied trust could not be read. The signature and
	// status checks fail with it.
	Err error
	// Findings list the unreadable parts of the supplied trusted lists.
	Findings []string

	// Catalogue is the wallet whose attestation catalogue is consulted. Nil
	// means there is no wallet.
	Catalogue Catalogue
	// CatalogueErr is why the wallet could not be read.
	CatalogueErr error

	// HTTPClient fetches issuer metadata and status lists. Nil selects the
	// default client.
	HTTPClient *http.Client
}

// AddKey adds a supplied public key.
func (t *Trust) AddKey(key crypto.PublicKey) {
	t.Supplied = true
	t.Keys = append(t.Keys, key)
}

// AddTrustedList adds the services of a supplied ETSI TS 119 602 list. The
// public keys of its issuance services also verify a credential without a
// certificate chain.
func (t *Trust) AddTrustedList(raw string, now time.Time) error {
	t.Supplied = true
	tl, err := lote.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing trusted list: %w", err)
	}
	issuance, err := lote.Anchors(tl, lote.IssuanceServices, now)
	if err != nil {
		return err
	}
	revocation, err := lote.Anchors(tl, lote.RevocationServices, now)
	if err != nil {
		return err
	}
	t.Issuance = append(t.Issuance, issuance...)
	t.Revocation = append(t.Revocation, revocation...)
	for _, cert := range issuance {
		t.Keys = append(t.Keys, cert.PublicKey)
	}
	t.Findings = append(t.Findings, tl.Findings...)
	return nil
}

// Catalogue validates a credential with the trusted lists of its entry in a
// wallet's attestation catalogue. found is false when the catalogue has no
// entry for the credential's type.
type Catalogue interface {
	CheckCatalogueAnchoring(raw string) (anchoring CatalogueAnchoring, found bool)
}

// CatalogueAnchoring is the result of validating a credential with the
// trusted lists of its catalogue entry.
type CatalogueAnchoring struct {
	Entry    string `json:"entry"`
	Category string `json:"category"`
	// AnchoredBy is the list whose issuance service anchors the credential.
	AnchoredBy string   `json:"anchored_by,omitempty"`
	Findings   []string `json:"findings,omitempty"`
	// Warnings list the lists of an EAA entry without anchors. ARF ISSU_10
	// asks to check an EAA only when the wallet has its anchors, so these are
	// no findings.
	Warnings []string `json:"warnings,omitempty"`
	// IssuanceAnchors and StatusAnchors are the certificates of the issuance
	// and revocation services of that list. The revocation service anchors
	// the credential's status list (ETSI TS 119 602 V1.1.1 Tables D.3 and
	// H.3).
	IssuanceAnchors []*x509.Certificate `json:"-"`
	StatusAnchors   []*x509.Certificate `json:"-"`
}

// Service types of an Anchor. The issuance service of a list anchors a
// credential and its revocation service the credential's status list (ETSI TS
// 119 602 V1.1.1 Table D.3).
const (
	ServiceIssuance   = "issuance"
	ServiceRevocation = "revocation"
)

// Anchor is the trusted list service that anchors a credential or its status
// list.
type Anchor struct {
	// Entry is the catalogue entry that links the list. It is empty when no
	// single entry does.
	Entry   string `json:"entry,omitempty"`
	ListURL string `json:"list_url"`
	Service string `json:"service"`
}

// Anchor returns the anchor of the credential's service, or nil when no list
// of the catalogue anchors the credential.
func (a CatalogueAnchoring) Anchor(service string) *Anchor {
	if a.AnchoredBy == "" {
		return nil
	}
	return &Anchor{Entry: a.Entry, ListURL: a.AnchoredBy, Service: service}
}

// String is the one-line form, such as "German PID, trusted list pid".
func (a Anchor) String() string {
	name := "trusted list " + path.Base(strings.TrimRight(a.ListURL, "/"))
	if a.Entry == "" {
		return name
	}
	return a.Entry + ", " + name
}
