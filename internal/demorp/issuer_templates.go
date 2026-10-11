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

package demorp

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

// The demo issuer offers the ticket and every credential template as a
// credential configuration. The configuration id is the template name. PID
// types are signed by the PID signer, so a wallet that needs a PID provider
// can use the demo issuer.

// templateConfiguration is a credential configuration backed by a template.
type templateConfiguration struct {
	id       string
	format   string
	vct      string
	docType  string
	template credtemplate.Template
}

// templateConfigurations lists the templates that the demo issuer can issue,
// sorted by name. It skips templates that are neither SD-JWT nor mdoc.
func (d *DemoRP) templateConfigurations() []templateConfiguration {
	templates, err := credtemplate.List(d.wallet.Templates)
	if err != nil {
		log.Printf("[Demo issuer] WARNING: the issuer offers no templates it can't read: %v", err)
	}
	configs := make([]templateConfiguration, 0, len(templates))
	for _, tpl := range templates {
		if tpl.Name == "" {
			continue
		}
		format, err := credtemplate.NormalizeFormat(tpl.Format)
		if err != nil {
			continue
		}
		cfg := templateConfiguration{id: tpl.Name, template: tpl}
		switch format {
		case "sdjwt":
			if tpl.VCT == "" {
				continue
			}
			cfg.format, cfg.vct = "dc+sd-jwt", tpl.VCT
		case "mdoc":
			if tpl.DocType == "" {
				continue
			}
			cfg.format, cfg.docType = "mso_mdoc", tpl.DocType
		default:
			continue
		}
		configs = append(configs, cfg)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].id < configs[j].id })
	return configs
}

func (d *DemoRP) templateConfiguration(id string) (templateConfiguration, bool) {
	for _, cfg := range d.templateConfigurations() {
		if cfg.id == id {
			return cfg, true
		}
	}
	return templateConfiguration{}, false
}

// offeredConfigurationIDs returns every template configuration, the ticket
// first.
func (d *DemoRP) offeredConfigurationIDs() []string {
	ids := []string{ticketConfigurationID}
	for _, cfg := range d.templateConfigurations() {
		if cfg.id != ticketConfigurationID {
			ids = append(ids, cfg.id)
		}
	}
	return ids
}

// credentialConfigurations lists the template configurations as the
// credential_configurations_supported entries of OpenID4VCI 1.0 §12.2.4.
func (d *DemoRP) credentialConfigurations() map[string]any {
	base := map[string]any{}
	for _, cfg := range d.templateConfigurations() {
		entry := map[string]any{
			"format": cfg.format,
			"scope":  cfg.id,
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
			},
			"credential_signing_alg_values_supported": []string{"ES256"},
		}
		switch cfg.format {
		case "dc+sd-jwt":
			entry["vct"] = cfg.vct
			entry["cryptographic_binding_methods_supported"] = []string{"jwk"}
		case "mso_mdoc":
			entry["doctype"] = cfg.docType
			entry["credential_signing_alg_values_supported"] = []int{-7}
			entry["cryptographic_binding_methods_supported"] = []string{"cose_key"}
		}
		display := map[string]any{"name": cfg.id, "locale": "en-US"}
		if tpl := cfg.template.Display; tpl != nil {
			if tpl.Name != "" {
				display["name"] = tpl.Name
			}
			if tpl.Description != "" {
				display["description"] = tpl.Description
			}
			if tpl.BackgroundColor != "" {
				display["background_color"] = tpl.BackgroundColor
			}
			if tpl.TextColor != "" {
				display["text_color"] = tpl.TextColor
			}
			if uri := d.templateImageURL(cfg.id, "logo", tpl.Logo); uri != "" {
				logo := map[string]any{"uri": uri}
				if tpl.LogoAltText != "" {
					logo["alt_text"] = tpl.LogoAltText
				}
				display["logo"] = logo
			}
			if uri := d.templateImageURL(cfg.id, "background_image", tpl.BackgroundImage); uri != "" {
				display["background_image"] = map[string]any{"uri": uri}
			}
		}
		entry["credential_metadata"] = map[string]any{
			"display": []map[string]any{display},
			"claims":  templateClaimPaths(cfg),
		}
		base[cfg.id] = entry
	}
	return base
}

// templateImageURL is the metadata URL of a template image. The issuer serves
// bundled images and uploaded ones (data URIs) itself, since a data URI would
// put the whole image into the metadata. An http or https image keeps its own
// URL.
func (d *DemoRP) templateImageURL(id, field, ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return ref
	}
	if _, _, ok := wallet.TemplateImage(ref); ok {
		return d.issuerID() + "/templates/" + url.PathEscape(id) + "/" + field
	}
	return ""
}

// handleTemplateImage serves the logo or background image of a template. The
// browser checks the ETag on every load, because a template can change.
func (d *DemoRP) handleTemplateImage(w http.ResponseWriter, r *http.Request) {
	var ref string
	for _, cfg := range d.templateConfigurations() {
		if cfg.id != r.PathValue("id") || cfg.template.Display == nil {
			continue
		}
		switch r.PathValue("field") {
		case "logo":
			ref = cfg.template.Display.Logo
		case "background_image":
			ref = cfg.template.Display.BackgroundImage
		}
	}
	contentType, data, ok := wallet.TemplateImage(ref)
	if !ok {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// Anyone can upload a template image, and an SVG opened on its own could
	// run scripts on the wallet's origin.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// templateClaimPaths lists the top-level claims of the template. For an mdoc
// each path starts with the namespace.
func templateClaimPaths(cfg templateConfiguration) []map[string]any {
	names := make([]string, 0, len(cfg.template.Claims))
	for name := range cfg.template.Claims {
		names = append(names, name)
	}
	sort.Strings(names)
	paths := make([]map[string]any, 0, len(names))
	for _, name := range names {
		path := []string{name}
		if cfg.format == "mso_mdoc" {
			namespace := cfg.template.Namespace
			if namespace == "" {
				namespace = cfg.docType
			}
			path = []string{namespace, name}
		}
		paths = append(paths, map[string]any{"path": path})
	}
	// Only tickets issued after wallet attestation have this claim.
	if cfg.id == ticketConfigurationID {
		paths = append(paths, map[string]any{"path": []string{"wallet_attestation"}})
	}
	return paths
}

// signTemplate issues one credential from the template claims, bound to
// holderKey. Holder claims from the offer override the template claims.
func (d *DemoRP) signTemplate(cfg templateConfiguration, holderKey *ecdsa.PublicKey, granted ticketGrant) (string, error) {
	tpl := cfg.template
	expiresIn := 30 * 24 * time.Hour
	if tpl.Exp != "" {
		if parsed, err := time.ParseDuration(tpl.Exp); err == nil && parsed > 0 {
			expiresIn = parsed
		}
	}
	merged := credtemplate.MergeClaims(tpl.Claims, granted.holderClaims)
	// The demo ticket records the wallet attestation of its issuance and its
	// trust status, since the demo accepts attestations from unknown CAs.
	if cfg.id == ticketConfigurationID && granted.clientAuth != nil {
		merged["wallet_attestation"] = granted.clientAuth.ticketClaim()
	}
	claims := tpl.WithUniqueClaims(merged)
	spec := wallet.IssuedAttestationSpec{Format: cfg.format, VCT: cfg.vct, DocType: cfg.docType}
	spec.Category = d.wallet.CredentialCategory(&tpl, spec)
	spec, err := wallet.NormalizeIssuedAttestationSpec(spec, "")
	if err != nil {
		return "", fmt.Errorf("building attestation spec for %s: %w", cfg.id, err)
	}
	changed, err := d.wallet.EnsureIssuedAttestation(spec)
	if err != nil {
		return "", fmt.Errorf("registering the attestation type of %s: %w", cfg.id, err)
	}
	signingKey, chain, err := d.wallet.SigningMaterialForIssuedCredential(spec, claims)
	if err != nil {
		return "", fmt.Errorf("building signing certificate chain for %s: %w", cfg.id, err)
	}
	statusURI, statusIdx := "", 0
	if granted.withStatus {
		statusURI = d.statusListURI()
		if statusURI == "" {
			return "", fmt.Errorf("this wallet has no status list URL")
		}
		statusIdx, err = d.wallet.NextStatusIndex()
		if err != nil {
			return "", err
		}
		changed = true
	}
	if changed {
		d.saveWallet()
	}
	switch cfg.format {
	case "dc+sd-jwt":
		issuedAt := time.Now().Truncate(time.Hour)
		return mock.GenerateSDJWT(mock.SDJWTConfig{
			CertificateIssuer: d.wallet.IssuerURL,
			Issuer:            d.issuerID(),
			VCT:               cfg.vct,
			ExpiresIn:         expiresIn,
			IssuedAt:          &issuedAt,
			Claims:            claims,
			Key:               signingKey,
			HolderKey:         holderKey,
			CertChain:         chain,
			AlwaysDisclosed:   tpl.AlwaysDisclosed,
			StatusListURI:     statusURI,
			StatusListIdx:     statusIdx,
		})
	case "mso_mdoc":
		namespace := tpl.Namespace
		if namespace == "" {
			namespace = cfg.docType
		}
		return mock.GenerateMDOC(mock.MDOCConfig{
			CertificateIssuer: d.wallet.IssuerURL,
			DocType:           cfg.docType,
			Namespace:         namespace,
			Claims:            claims,
			Key:               signingKey,
			HolderKey:         holderKey,
			ExpiresIn:         expiresIn,
			CertChain:         chain,
			StatusListURI:     statusURI,
			StatusListIdx:     statusIdx,
		})
	}
	return "", fmt.Errorf("configuration %s has an unknown format %s", cfg.id, cfg.format)
}

// offerConfigurationIDs checks the configurations requested for an offer. An
// empty request means the ticket.
func (d *DemoRP) offerConfigurationIDs(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return []string{ticketConfigurationID}, nil
	}
	offered := d.offeredConfigurationIDs()
	ids := make([]string, 0, len(requested))
	for _, id := range requested {
		if !slices.Contains(offered, id) {
			return nil, fmt.Errorf("this issuer offers %v, not %q", offered, id)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
