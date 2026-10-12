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
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

const DefaultIssueExpiry = 720 * time.Hour

const DefaultMDOCDocType = "eu.europa.ec.eudi.pid.1"

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
	// Claims nil with no template uses a small default claim set. With PID
	// set it uses the full PID Rulebook claim set from the PID template for VCT.
	Claims map[string]any
	PID    bool
	// AlwaysDisclosed lists claims (dotted paths for nested claims) that go
	// into the SD-JWT payload in plain form. It adds to the template's list.
	// An mdoc rejects it because every mdoc element is selectively disclosable.
	AlwaysDisclosed []string
	// SaveTemplate is the name of a user template that stores the resolved
	// parameters after a successful issuance.
	SaveTemplate string
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
	// TrustProfile is "", "auto", "pid" or "local".
	TrustProfile string
	// Trust is registration metadata stored with the issued credential type.
	// Its Format, VCT and DocType are replaced by the resolved values.
	Trust IssuedAttestationSpec
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
	// ignored, so the type registers like an imported foreign credential.
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
	if format == "jwt" || len(mock.WithoutSelfSignedTrustAnchor(chain)) == len(chain) {
		return nil
	}
	finding := "HAIP 1.0 §6.1.1: the signing certificate chain includes its self-signed root, which MUST NOT be included in the credential's x5c"
	if format == "mdoc" {
		finding = "ISO 18013-5: the signing certificate chain includes its self-signed root, which does not belong in the x5chain header"
	}
	if w.Mode() == ValidationModeStrict {
		return fmt.Errorf("%s", finding)
	}
	w.AddWarning("management", finding+". It is embedded as given.", nil)
	return nil
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
// entry and the type registration exist only in memory until then.
func (w *Wallet) IssueCredential(opts IssueOptions) (*IssueResult, error) {
	tpl, pidTemplate, err := w.resolveIssueTemplate(opts)
	if err != nil {
		return nil, err
	}

	formatInput := opts.Format
	if strings.TrimSpace(formatInput) == "" && tpl != nil {
		formatInput = tpl.Format
	}
	format, err := normalizeIssueFormat(formatInput)
	if err != nil {
		return nil, err
	}
	// A named template has to match the requested format. A PID template
	// chosen through opts.PID only supplies claims, so a jwt request can use
	// the SD-JWT PID claims.
	if tpl != nil && tpl.Format != "" && !pidTemplate {
		tplFormat, err := credtemplate.NormalizeFormat(tpl.Format)
		if err != nil {
			return nil, err
		}
		if tplFormat != "" && tplFormat != format {
			return nil, fmt.Errorf("template %q is for format %s, not %s", tpl.Name, tplFormat, format)
		}
	}

	claims := opts.Claims
	if tpl != nil {
		claims = credtemplate.MergeClaims(tpl.Claims, opts.Claims)
	} else if claims == nil {
		claims = mock.DefaultClaims
	}
	claims = omitIssueClaims(claims, opts.Omit)

	alwaysDisclosed := opts.AlwaysDisclosed
	if tpl != nil {
		alwaysDisclosed = mergeAlwaysDisclosed(tpl.AlwaysDisclosed, opts.AlwaysDisclosed)
	}
	if format == "mdoc" && len(alwaysDisclosed) > 0 {
		return nil, fmt.Errorf("always-disclosed claims are not supported for mdoc: every mdoc element is selectively disclosable")
	}

	expiresIn := opts.ExpiresIn
	if expiresIn == 0 && tpl != nil && tpl.Exp != "" {
		expiresIn, err = time.ParseDuration(tpl.Exp)
		if err != nil {
			return nil, fmt.Errorf("template %q: invalid exp duration: %w", tpl.Name, err)
		}
	}
	if expiresIn == 0 {
		expiresIn = DefaultIssueExpiry
	}

	vct := strings.TrimSpace(opts.VCT)
	if vct == "" && tpl != nil {
		vct = strings.TrimSpace(tpl.VCT)
	}
	if vct == "" {
		vct = mock.DefaultPIDVCT
	}
	docType := strings.TrimSpace(opts.DocType)
	if docType == "" && tpl != nil {
		docType = strings.TrimSpace(tpl.DocType)
	}
	if docType == "" {
		docType = DefaultMDOCDocType
	}
	namespace := strings.TrimSpace(opts.Namespace)
	if namespace == "" && tpl != nil {
		namespace = strings.TrimSpace(tpl.Namespace)
	}
	if namespace == "" {
		namespace = docType
	}

	statusURI, statusIdx, registerStatus, err := w.resolveIssueStatus(opts.StatusListURI, opts.StatusListIdx)
	if err != nil {
		return nil, err
	}

	spec := opts.Trust
	switch format {
	case "sdjwt":
		spec.Format, spec.VCT, spec.DocType = "dc+sd-jwt", vct, ""
	case "jwt":
		spec.Format, spec.VCT, spec.DocType = "jwt_vc_json", vct, ""
	case "mdoc":
		spec.Format, spec.VCT, spec.DocType = "mso_mdoc", "", docType
	}
	spec, err = NormalizeIssuedAttestationSpec(spec, opts.TrustProfile)
	if err != nil {
		return nil, err
	}
	signingKey := w.IssuerKey
	var certChain []*x509.Certificate
	if opts.SigningKey != nil {
		signingKey = opts.SigningKey
		certChain = opts.SigningCertChain
		if err := w.judgeSigningChainAnchor(format, certChain); err != nil {
			return nil, err
		}
	} else {
		certChain, err = w.SigningCertChainForIssuedCredential(spec, claims)
		if err != nil {
			return nil, err
		}
	}

	issuer := strings.TrimRight(strings.TrimSpace(w.IssuerURL), "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}

	var holderPub *ecdsa.PublicKey
	if !opts.Unbound && w.HolderKey != nil {
		holderPub = &w.HolderKey.PublicKey
	}

	if opts.BatchSize >= 2 {
		if format == "jwt" {
			return nil, fmt.Errorf("batch issuance needs holder binding, which jwt_vc_json does not carry")
		}
		if opts.Unbound {
			return nil, fmt.Errorf("an unbound credential cannot be issued as a batch (a batch needs a distinct holder key per copy)")
		}
	}

	signCopy := func(holderPub *ecdsa.PublicKey, statusIdx int) (string, error) {
		// An override chain is embedded as given, root included, to test
		// verifier rejection.
		keepAnchor := opts.SigningKey != nil
		switch format {
		case "sdjwt":
			return mock.GenerateSDJWT(mock.SDJWTConfig{
				CertificateIssuer: w.IssuerURL,
				Issuer:            issuer, VCT: vct, ExpiresIn: expiresIn, NotBefore: opts.NotBefore,
				Claims: claims, Key: signingKey, HolderKey: holderPub,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
				AlwaysDisclosed: alwaysDisclosed, KeepTrustAnchor: keepAnchor,
			})
		case "jwt":
			return mock.GenerateJWT(mock.JWTConfig{
				Issuer: issuer, VCT: vct, ExpiresIn: expiresIn, NotBefore: opts.NotBefore,
				Claims: claims, Key: signingKey,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
			})
		case "mdoc":
			return mock.GenerateMDOC(mock.MDOCConfig{
				CertificateIssuer: w.IssuerURL,
				DocType:           docType, NamespaceClaims: splitClaimsByNamespace(claims, namespace),
				Key: signingKey, HolderKey: holderPub, ExpiresIn: expiresIn, ValidFrom: opts.NotBefore,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
				KeepTrustAnchor: keepAnchor,
			})
		}
		return "", fmt.Errorf("unsupported format %q", format)
	}

	// Display fields merge one by one, so setting a name or color keeps the
	// template's images.
	displaySource := tpl
	if opts.DisplayTemplate != "" {
		dt, err := credtemplate.Load(opts.DisplayTemplate, w.Templates)
		if err != nil {
			return nil, fmt.Errorf("loading the display template %q: %w", opts.DisplayTemplate, err)
		}
		displaySource = dt
	}
	var issuedDisplay *CredentialDisplay
	if displaySource != nil {
		issuedDisplay = w.templateDisplay(displaySource.Display)
	}
	if opts.Display != nil {
		issuedDisplay = mergeCredentialDisplay(issuedDisplay, w.issuedDisplay(*opts.Display))
	}
	applyIssuedDisplay := func(cred *StoredCredential) {
		if issuedDisplay != nil {
			w.rememberDisplay(cred, issuedDisplay)
		}
	}

	// A shared status index would link two presentations of a batch. So every
	// copy, the first included, takes its index from the counter. With no URI
	// and no index the first copy already has one from the counter.
	if opts.BatchSize >= 2 && registerStatus && (opts.StatusListIdx != nil || opts.StatusListURI != nil) {
		if statusIdx, err = w.NextStatusIndex(); err != nil {
			return nil, err
		}
	}

	raw, err := signCopy(holderPub, statusIdx)
	if err != nil {
		return nil, fmt.Errorf("generating credential: %w", err)
	}
	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("importing to wallet: %w", err)
	}
	applyIssuedDisplay(imported)
	if registerStatus {
		w.RegisterStatusEntry(imported.ID, statusIdx)
	}

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
			copyRaw, err := signCopy(&copyKey.PublicKey, copyIdx)
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
			applyIssuedDisplay(copyCred)
			if registerStatus {
				w.RegisterStatusEntry(copyCred.ID, copyIdx)
			}
		}
	}

	// The trust metadata describes the wallet CA. An override chain keeps the
	// plain registration from the import.
	if opts.SigningKey == nil {
		if err := w.RegisterIssuedAttestation(spec); err != nil {
			return nil, fmt.Errorf("registering issued-attestation metadata: %w", err)
		}
	}

	result := &IssueResult{
		Raw:              raw,
		Credential:       imported,
		StatusIdx:        statusIdx,
		StatusRegistered: registerStatus,
	}

	if name := strings.TrimSpace(opts.SaveTemplate); name != "" {
		saved := credtemplate.Template{
			Name:            name,
			Format:          format,
			Exp:             formatIssueExpiry(expiresIn),
			Claims:          claims,
			AlwaysDisclosed: alwaysDisclosed,
		}
		switch format {
		case "mdoc":
			saved.DocType = docType
			saved.Namespace = namespace
		default:
			saved.VCT = vct
		}
		path, err := credtemplate.Save(w.Templates, saved)
		if err != nil {
			return nil, fmt.Errorf("saving template: %w", err)
		}
		result.TemplatePath = path
	}

	return result, nil
}

// resolveIssueTemplate reports pidTemplate for a PID template chosen through
// opts.PID. Only a named template has to match the requested format.
func (w *Wallet) resolveIssueTemplate(opts IssueOptions) (tpl *credtemplate.Template, pidTemplate bool, err error) {
	if name := strings.TrimSpace(opts.Template); name != "" {
		tpl, err = credtemplate.Load(name, w.Templates)
		return tpl, false, err
	}
	if opts.PID && opts.Claims == nil {
		sdName, mdocName, _ := credtemplate.PIDTemplateNames(opts.VCT)
		name := sdName
		if format, _ := normalizeIssueFormat(opts.Format); format == "mdoc" {
			name = mdocName
		}
		tpl, err = credtemplate.Load(name, w.Templates)
		return tpl, true, err
	}
	return nil, false, nil
}

func mergeAlwaysDisclosed(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	var out []string
	for _, list := range [][]string{base, extra} {
		for _, path := range list {
			path = strings.TrimSpace(path)
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

func formatIssueExpiry(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	}
	return d.String()
}

func normalizeIssueFormat(format string) (string, error) {
	switch strings.TrimSpace(format) {
	case "sdjwt", "sd-jwt", "dc+sd-jwt":
		return "sdjwt", nil
	case "jwt", "jwt_vc_json":
		return "jwt", nil
	case "mdoc", "mso_mdoc":
		return "mdoc", nil
	default:
		return "", fmt.Errorf("unsupported credential format %q: expected sdjwt, jwt, or mdoc", format)
	}
}

// resolveIssueStatus follows the status flags of the issue commands. An
// explicit URI wins. It registers on the wallet's list only when it is that
// list. An index alone needs the wallet's list. With neither, the wallet's
// list is used when configured.
func (w *Wallet) resolveIssueStatus(uri *string, idx *int) (string, int, bool, error) {
	switch {
	case uri != nil:
		statusURI := strings.TrimSpace(*uri)
		if statusURI == "" {
			return "", 0, false, nil
		}
		statusIdx := 0
		if idx != nil {
			statusIdx = *idx
		}
		return statusURI, statusIdx, statusURI == w.StatusListURL(), nil
	case idx != nil:
		statusURI := strings.TrimSpace(w.StatusListURL())
		if statusURI == "" {
			return "", 0, false, fmt.Errorf("wallet status list is not configured")
		}
		return statusURI, *idx, true, nil
	default:
		statusURI := strings.TrimSpace(w.StatusListURL())
		if statusURI == "" {
			return "", 0, false, nil
		}
		idx, err := w.NextStatusIndex()
		if err != nil {
			return "", 0, false, err
		}
		return statusURI, idx, true, nil
	}
}

func splitClaimsByNamespace(claims map[string]any, defaultNamespace string) map[string]map[string]any {
	return mock.SplitClaimsByNamespace(claims, defaultNamespace)
}

func omitIssueClaims(claims map[string]any, omit []string) map[string]any {
	if len(omit) == 0 {
		return claims
	}
	exclude := make(map[string]bool, len(omit))
	for _, name := range omit {
		exclude[strings.TrimSpace(name)] = true
	}
	result := make(map[string]any, len(claims))
	for k, v := range claims {
		if !exclude[k] {
			result[k] = v
		}
	}
	return result
}
