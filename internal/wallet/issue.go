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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

const DefaultIssueExpiry = credtemplate.DefaultExp

const DefaultMDOCDocType = credtemplate.DefaultDocType

// IssueOptions describes a credential to issue with the wallet's issuer key
// and import into the wallet. It is shared by the `issue ... --wallet` CLI
// commands and the wallet server's POST /api/issue endpoint.
type IssueOptions struct {
	// Format is "sdjwt", "jwt" or "mdoc". The stored identifiers "dc+sd-jwt",
	// "jwt_vc_json" and "mso_mdoc" also work. Empty uses the template's format.
	Format string
	// Template is a template name or file path in the wallet's template
	// directory. Claims are merged on top of its claims. Its VCT, doc type,
	// namespace and expiry apply when the matching option is unset.
	Template string
	// Claims nil with no template uses a small default claim set. With PID set,
	// it uses all PID Rulebook claims from the PID template for VCT.
	Claims map[string]any
	PID    bool
	// AlwaysDisclosed lists claims (dotted paths for nested claims) that go
	// into the SD-JWT payload in plain form. It adds to the template's list.
	// An mdoc rejects it because every mdoc element is selectively disclosable.
	AlwaysDisclosed []string
	// SaveTemplate is the name of a user template that stores the resolved
	// parameters after a successful issuance.
	SaveTemplate string
	// Catalog adds the saved template to the attestation catalogue with these
	// catalogue fields. It needs SaveTemplate.
	Catalog *registrar.CatalogAttestation
	// Omit removes top-level claims from the resolved claim set.
	Omit []string
	// VCT applies to sdjwt and jwt and defaults to mock.DefaultPIDVCT.
	VCT string
	// DocType and Namespace apply to mdoc. DocType defaults to
	// DefaultMDOCDocType and Namespace defaults to DocType. A claim key
	// "namespace:element" puts that element in its own namespace.
	DocType   string
	Namespace string
	// ExpiresIn defaults to DefaultIssueExpiry.
	ExpiresIn time.Duration
	NotBefore *time.Time
	// A nil StatusListURI uses the wallet's own status list when one is
	// configured. An empty URI embeds no status reference. A nil index takes
	// the next free index on the wallet's list.
	StatusListURI *string
	StatusListIdx *int
	// Category is pid, qeaa, pub-eaa, eaa or unlisted. Empty takes the category
	// of the template or the catalogue entry, else eaa.
	Category string
	// Trust is registration metadata stored with the issued credential type.
	// Its Format, VCT and DocType are replaced by the resolved values.
	Trust provider.IssuedAttestationSpec
	// Display follows OpenID4VCI §12.2.4.
	Display *IssueDisplay
	// BatchSize is the number of copies, each with its own holder key (ARF
	// batch method C). Values below two issue one credential. A JWT VC has no
	// holder binding, so it cannot be issued as a batch.
	BatchSize int
	// DisplayTemplate supplies the display when a form sends its own claims.
	// Display fields override it. Empty uses Template.
	DisplayTemplate string
	// SigningKey and SigningCertChain replace the wallet's issuer key and chain.
	// They are set together and the leaf must certify the key. Trust is
	// ignored, and the type is on none of the wallet's lists.
	SigningKey       *ecdsa.PrivateKey
	SigningCertChain []*x509.Certificate
	// Unbound issues the credential without a holder key. An SD-JWT VC then
	// has no cnf, which SD-JWT VC §3.2.2.2 makes optional. An mdoc has no MSO
	// deviceKey, which ISO 18013-5 §9.1.2.4 makes mandatory. That malformed
	// mdoc tests verifier rejection.
	Unbound bool
}

// ParseSigningOverride reads a signing override: a PEM or JWK private key and
// a PEM certificate chain, leaf first. Both must be given and the leaf must
// certify the key.
func ParseSigningOverride(keyData, certData string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	keyData, certData = strings.TrimSpace(keyData), strings.TrimSpace(certData)
	if keyData == "" && certData == "" {
		return nil, nil, nil
	}
	if keyData == "" || certData == "" {
		return nil, nil, fmt.Errorf("signing key and signing certificate must be given together")
	}
	parsed, err := keys.ParsePrivateKey([]byte(keyData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("the signing key must be an EC private key")
	}
	chain, err := keys.ParseCertificatesPEM([]byte(certData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing signing certificate: %w", err)
	}
	leafPub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafPub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("the leaf certificate does not certify the signing key")
	}
	return key, chain, nil
}

// judgeSigningChainAnchor checks an override chain that includes its
// self-signed root. Strict mode refuses it. Debug mode warns and embeds it, so
// verifier rejection can be tested. A JWT VC is exempt because RFC 7515 lets
// x5c carry the root.
func (w *Wallet) judgeSigningChainAnchor(format string, chain []*x509.Certificate) error {
	if format == "jwt" || len(certchain.WithoutSelfSignedAnchor(chain)) == len(chain) {
		return nil
	}
	finding := "HAIP 1.0 §6.1.1: the signing certificate chain includes its self-signed root, which MUST NOT be included in the credential's x5c"
	if format == "mdoc" {
		finding = "ISO 18013-5: the signing certificate chain includes its self-signed root, which does not belong in the x5chain header"
	}
	return w.reportDeviation(deviation{action: "management", event: "signing_chain_anchor", detail: finding})
}

type IssueDisplay struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	Logo            string `json:"logo"`
	LogoAltText     string `json:"logo_alt_text"`
	BackgroundImage string `json:"background_image"`
}

type IssueResult struct {
	Raw        string
	Credential *StoredCredential
	// StatusIdx is only meaningful when StatusRegistered is true.
	StatusIdx int
	// StatusRegistered reports whether the credential is on the wallet's own
	// status list.
	StatusRegistered bool
	TemplatePath     string
}

// IssueCredential leaves saving to the caller. The credential, its status
// entry and the type registration exist only in memory until then. A failed
// request leaves no credential behind.
func (w *Wallet) IssueCredential(opts IssueOptions) (result *IssueResult, err error) {
	resolved, tpl, err := w.resolveIssue(opts)
	if err != nil {
		return nil, err
	}

	// The template and its catalogue entry are checked before the credential
	// is issued, so a bad entry stores nothing.
	var saved *credtemplate.Template
	var catalogEntry registrar.CatalogAttestation
	if name := strings.TrimSpace(opts.SaveTemplate); name != "" {
		t := resolved.Template(name)
		saved = &t
		if opts.Catalog != nil {
			if catalogEntry, err = w.Registrar().TemplateCatalogEntry(*saved, *opts.Catalog); err != nil {
				return nil, err
			}
			saved.Category = catalogEntry.Category
		}
	} else if opts.Catalog != nil {
		return nil, fmt.Errorf("adding to the catalogue needs a template name")
	}

	statusURI, statusIdx, registerStatus, err := w.resolveIssueStatus(opts.StatusListURI, opts.StatusListIdx, opts.BatchSize >= 2)
	if err != nil {
		return nil, err
	}

	spec := opts.Trust
	switch resolved.Format {
	case "sdjwt":
		spec.Format, spec.VCT, spec.DocType = credtype.FormatSDJWT, resolved.VCT, ""
	case "jwt":
		spec.Format, spec.VCT, spec.DocType = credtype.FormatJWTVC, resolved.VCT, ""
	case "mdoc":
		spec.Format, spec.VCT, spec.DocType = credtype.FormatMDOC, "", resolved.DocType
	}
	if saved != nil && saved.Category != "" {
		spec.Category = jsonutil.FirstNonEmpty(spec.Category, saved.Category)
	}
	spec.Category = jsonutil.FirstNonEmpty(spec.Category, w.CredentialCategory(tpl, spec))
	spec, err = provider.NormalizeIssuedAttestationSpec(spec, opts.Category)
	if err != nil {
		return nil, err
	}
	signer, err := w.issueSigner(opts, resolved, spec, statusURI)
	if err != nil {
		return nil, err
	}

	if opts.BatchSize > MaxBatchSize {
		return nil, fmt.Errorf("a batch holds at most %d copies", MaxBatchSize)
	}
	if opts.BatchSize >= 2 {
		if resolved.Format == "jwt" {
			return nil, fmt.Errorf("batch issuance needs holder binding, which jwt_vc_json does not carry")
		}
		if opts.Unbound {
			return nil, fmt.Errorf("an unbound credential cannot be issued as a batch (a batch needs a distinct holder key per copy)")
		}
	}
	display, err := w.issueDisplay(tpl, opts)
	if err != nil {
		return nil, err
	}

	var issued []string
	defer func() {
		if err != nil {
			w.discardCredentials(issued)
		}
	}()
	keep := func(cred *StoredCredential, idx int) {
		issued = append(issued, cred.ID)
		if display != nil {
			w.rememberDisplay(cred, display)
		}
		if registerStatus {
			w.RegisterStatusEntry(cred.ID, idx)
		}
	}

	var holderPub *ecdsa.PublicKey
	if holderKey := w.HolderKeyPair(); !opts.Unbound && holderKey != nil {
		holderPub = &holderKey.PublicKey
	}
	raw, err := signer.sign(holderPub, statusIdx)
	if err != nil {
		return nil, fmt.Errorf("generating credential: %w", err)
	}
	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("importing to wallet: %w", err)
	}
	keep(imported, statusIdx)

	// Each batch copy gets its own holder key and status index, so rotated
	// presentations share no identifier.
	if opts.BatchSize >= 2 {
		group := newCredentialID()
		w.setBatchFields(imported.ID, group, "")
		imported.BatchGroup = group
		for i := 1; i < opts.BatchSize; i++ {
			copyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generating batch copy key: %w", err)
			}
			copyIdx := statusIdx
			if registerStatus {
				if copyIdx, err = w.NextStatusIndex(); err != nil {
					return nil, err
				}
			}
			copyRaw, err := signer.sign(&copyKey.PublicKey, copyIdx)
			if err != nil {
				return nil, fmt.Errorf("generating batch copy: %w", err)
			}
			pem, err := encodeECPrivateKeyPEM(copyKey)
			if err != nil {
				return nil, err
			}
			copyCred, err := w.importBatchCopy(copyRaw, group, pem)
			if err != nil {
				return nil, fmt.Errorf("importing batch copy: %w", err)
			}
			keep(copyCred, copyIdx)
		}
	}

	// The wallet's lists name the wallet CA, so a credential signed with an
	// override chain is on none of them.
	if opts.SigningKey == nil {
		if err := w.RegisterIssuedAttestation(spec); err != nil {
			return nil, fmt.Errorf("registering issued-attestation metadata: %w", err)
		}
	}

	result = &IssueResult{
		Raw:              raw,
		Credential:       imported,
		StatusIdx:        statusIdx,
		StatusRegistered: registerStatus,
	}
	if saved != nil {
		var entry *registrar.CatalogAttestation
		if opts.Catalog != nil {
			entry = &catalogEntry
		}
		if result.TemplatePath, err = w.SaveTemplate(*saved, entry); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// resolveIssue applies the issue options to their template.
func (w *Wallet) resolveIssue(opts IssueOptions) (credtemplate.Resolved, *credtemplate.Template, error) {
	tpl, pidTemplate, err := w.resolveIssueTemplate(opts)
	if err != nil {
		return credtemplate.Resolved{}, nil, err
	}
	resolved, err := credtemplate.Resolve(tpl, credtemplate.Request{
		Format:          opts.Format,
		Claims:          opts.Claims,
		Omit:            opts.Omit,
		AlwaysDisclosed: opts.AlwaysDisclosed,
		VCT:             opts.VCT,
		DocType:         opts.DocType,
		Namespace:       opts.Namespace,
		Exp:             opts.ExpiresIn,
		ClaimSet:        pidTemplate,
	})
	return resolved, tpl, err
}

// credentialSigner signs the credentials of one issue request.
type credentialSigner struct {
	resolved  credtemplate.Resolved
	issuer    string
	certIss   string
	issuedAt  *time.Time
	notBefore *time.Time
	statusURI string
	key       *ecdsa.PrivateKey
	chain     []*x509.Certificate
	// keepAnchor embeds an override chain as given, root included, to test
	// verifier rejection.
	keepAnchor bool
}

// newCredentialSigner signs with the key and chain of the attestation type.
// An empty issuer takes the wallet's issuer URL.
func (w *Wallet) newCredentialSigner(resolved credtemplate.Resolved, spec provider.IssuedAttestationSpec, issuer, statusURI string) (*credentialSigner, error) {
	key, chain, err := w.Signer().ForCredential(spec, resolved.Claims)
	if err != nil {
		return nil, err
	}
	issuer = strings.TrimRight(strings.TrimSpace(jsonutil.FirstNonEmpty(issuer, w.IssuerURL)), "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}
	return &credentialSigner{resolved: resolved, issuer: issuer, certIss: w.IssuerURL, statusURI: statusURI, key: key, chain: chain}, nil
}

func (w *Wallet) issueSigner(opts IssueOptions, resolved credtemplate.Resolved, spec provider.IssuedAttestationSpec, statusURI string) (*credentialSigner, error) {
	if opts.SigningKey == nil {
		signer, err := w.newCredentialSigner(resolved, spec, "", statusURI)
		if err != nil {
			return nil, err
		}
		signer.notBefore = opts.NotBefore
		return signer, nil
	}
	if err := w.judgeSigningChainAnchor(resolved.Format, opts.SigningCertChain); err != nil {
		return nil, err
	}
	issuer := strings.TrimRight(strings.TrimSpace(w.IssuerURL), "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}
	return &credentialSigner{
		resolved: resolved, issuer: issuer, certIss: w.IssuerURL, notBefore: opts.NotBefore,
		statusURI: statusURI, key: opts.SigningKey, chain: opts.SigningCertChain, keepAnchor: true,
	}, nil
}

// HolderSigning describes a credential that the wallet's issuer signs for
// another holder.
type HolderSigning struct {
	// Issuer is the iss claim. Empty uses the wallet's issuer URL.
	Issuer string
	// StatusListURI is the wallet's status list. The credential gets the next
	// index on it. Empty issues it without a status.
	StatusListURI string
}

// SignForHolder signs a credential of the resolved template for a holder key
// outside the wallet. It registers the attestation type and takes the status
// index under one save, before another request reloads the wallet state. The
// issuance time is rounded to the hour, so the credentials of one holder are
// not linkable by the issuance second (RFC 9901 §10.1).
func (w *Wallet) SignForHolder(resolved credtemplate.Resolved, spec provider.IssuedAttestationSpec, holderKey *ecdsa.PublicKey, opts HolderSigning) (string, error) {
	spec, err := provider.NormalizeIssuedAttestationSpec(spec, "")
	if err != nil {
		return "", err
	}
	statusIdx := 0
	w.saveChange(func() bool {
		var changed bool
		if changed, err = w.EnsureIssuedAttestation(spec); err != nil {
			err = fmt.Errorf("registering the attestation type: %w", err)
			return false
		}
		if opts.StatusListURI != "" {
			if statusIdx, err = w.NextStatusIndex(); err != nil {
				return false
			}
			changed = true
		}
		return changed
	})
	if err != nil {
		return "", err
	}
	signer, err := w.newCredentialSigner(resolved, spec, opts.Issuer, opts.StatusListURI)
	if err != nil {
		return "", fmt.Errorf("building the signing certificate chain: %w", err)
	}
	issuedAt := time.Now().Truncate(time.Hour)
	signer.issuedAt = &issuedAt
	return signer.sign(holderKey, statusIdx)
}

func (s *credentialSigner) sign(holderPub *ecdsa.PublicKey, statusIdx int) (string, error) {
	r := s.resolved
	claims := r.CredentialClaims()
	switch r.Format {
	case "sdjwt":
		return mock.GenerateSDJWT(mock.SDJWTConfig{
			CertificateIssuer: s.certIss,
			Issuer:            s.issuer, VCT: r.VCT, ExpiresIn: r.Exp, IssuedAt: s.issuedAt, NotBefore: s.notBefore,
			Claims: claims, Key: s.key, HolderKey: holderPub,
			StatusListURI: s.statusURI, StatusListIdx: statusIdx, CertChain: s.chain,
			AlwaysDisclosed: r.AlwaysDisclosed, KeepTrustAnchor: s.keepAnchor,
		})
	case "jwt":
		return mock.GenerateJWT(mock.JWTConfig{
			Issuer: s.issuer, VCT: r.VCT, ExpiresIn: r.Exp, NotBefore: s.notBefore,
			Claims: claims, Key: s.key,
			StatusListURI: s.statusURI, StatusListIdx: statusIdx, CertChain: s.chain,
		})
	case "mdoc":
		return mock.GenerateMDOC(mock.MDOCConfig{
			CertificateIssuer: s.certIss,
			DocType:           r.DocType, Namespace: r.Namespace, Claims: claims,
			Key: s.key, HolderKey: holderPub, ExpiresIn: r.Exp, ValidFrom: s.notBefore,
			StatusListURI: s.statusURI, StatusListIdx: statusIdx, CertChain: s.chain,
			KeepTrustAnchor: s.keepAnchor,
		})
	}
	return "", fmt.Errorf("unsupported format %q", r.Format)
}

// issueDisplay merges display fields one by one, so setting a name or color
// keeps the template's images.
func (w *Wallet) issueDisplay(tpl *credtemplate.Template, opts IssueOptions) (*oid4vc.CredentialDisplay, error) {
	source := tpl
	if opts.DisplayTemplate != "" {
		dt, err := credtemplate.Load(opts.DisplayTemplate, w.Templates)
		if err != nil {
			return nil, fmt.Errorf("loading the display template %q: %w", opts.DisplayTemplate, err)
		}
		source = dt
	}
	var display *oid4vc.CredentialDisplay
	if source != nil {
		display = w.templateDisplay(source.Display)
	}
	if opts.Display != nil {
		display = mergeCredentialDisplay(display, w.issuedDisplay(*opts.Display))
	}
	return display, nil
}

// discardCredentials removes credentials and their status entries.
func (w *Wallet) discardCredentials(ids []string) {
	if len(ids) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deleteCredentialsLocked(func(c StoredCredential) bool { return slices.Contains(ids, c.ID) })
}

// SaveTemplate stores a template and, if entry is set, its catalogue entry.
// The entry is added first, because the catalogue can refuse it and a stored
// template is hard to take back when it replaced another one.
func (w *Wallet) SaveTemplate(tpl credtemplate.Template, entry *registrar.CatalogAttestation) (string, error) {
	if err := w.checkTemplateSave(tpl); err != nil {
		return "", err
	}
	tpl.Visitor = w.visitorRules().VisitorTemplates
	var added registrar.CatalogAttestation
	if entry != nil {
		var err error
		if added, err = w.Registrar().AddCatalogAttestation(*entry); err != nil {
			return "", fmt.Errorf("adding the template to the catalogue: %w", err)
		}
	}
	path, err := credtemplate.Save(w.Templates, tpl)
	if err != nil {
		if entry != nil {
			err = errors.Join(err, w.Registrar().DeleteCatalogAttestation(added.Schema.ID))
		}
		return "", fmt.Errorf("saving template: %w", err)
	}
	return path, nil
}

// CredentialCategory is the category of the template, or else of the
// catalogue entry for the credential type. It is empty without either, and
// the type is then an EAA.
func (w *Wallet) CredentialCategory(tpl *credtemplate.Template, spec provider.IssuedAttestationSpec) string {
	if tpl != nil && tpl.Category != "" {
		return tpl.Category
	}
	if entry, ok := w.catalogueEntryFor(spec.Format, []string{jsonutil.FirstNonEmpty(spec.VCT, spec.DocType)}); ok {
		return entry.Category
	}
	return ""
}

// resolveIssueTemplate reports pidTemplate for a PID template chosen through
// opts.PID. Only a named template has to match the requested format.
func (w *Wallet) resolveIssueTemplate(opts IssueOptions) (tpl *credtemplate.Template, pidTemplate bool, err error) {
	if name := strings.TrimSpace(opts.Template); name != "" {
		tpl, err = credtemplate.Load(name, w.Templates)
		return tpl, false, err
	}
	if opts.PID && opts.Claims == nil {
		sdName, mdocName, _ := credtemplate.PIDTemplateNames(opts.VCT, w.Templates)
		name := sdName
		if format, _ := credtemplate.NormalizeFormat(opts.Format); format == "mdoc" {
			name = mdocName
		}
		tpl, err = credtemplate.Load(name, w.Templates)
		return tpl, true, err
	}
	return nil, false, nil
}

// resolveIssueStatus follows the status flags of the issue commands. An
// explicit URI wins. It registers on the wallet's list only when it is that
// list. An index alone needs the wallet's list. With neither, the wallet's
// list is used when configured.
func (w *Wallet) resolveIssueStatus(uri *string, idx *int, batch bool) (string, int, bool, error) {
	own := strings.TrimSpace(w.StatusListURL())
	statusURI := own
	switch {
	case uri != nil:
		statusURI = strings.TrimSpace(*uri)
		if statusURI == "" {
			return "", 0, false, nil
		}
		if statusURI != own {
			statusIdx := 0
			if idx != nil {
				statusIdx = *idx
			}
			return statusURI, statusIdx, false, nil
		}
	case idx != nil:
		if own == "" {
			return "", 0, false, fmt.Errorf("wallet status list is not configured")
		}
	case own == "":
		return "", 0, false, nil
	}
	statusIdx, err := w.ownStatusIndex(idx, batch)
	if err != nil {
		return "", 0, false, err
	}
	return statusURI, statusIdx, true, nil
}
