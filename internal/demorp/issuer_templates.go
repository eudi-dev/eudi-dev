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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/httpsec"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
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
	d.warnUnreadableTemplates(err)
	configs := make([]templateConfiguration, 0, len(templates))
	for _, tpl := range templates {
		if cfg, ok := configurationOf(tpl); ok {
			configs = append(configs, cfg)
		}
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].id < configs[j].id })
	return configs
}

// configurationOf is the configuration of an SD-JWT or mdoc template.
func configurationOf(tpl credtemplate.Template) (templateConfiguration, bool) {
	format, err := credtemplate.NormalizeFormat(tpl.Format)
	if tpl.Name == "" || err != nil {
		return templateConfiguration{}, false
	}
	cfg := templateConfiguration{id: tpl.Name, template: tpl}
	switch {
	case format == "sdjwt" && tpl.VCT != "":
		cfg.format, cfg.vct = credtype.FormatSDJWT, tpl.VCT
	case format == "mdoc" && tpl.DocType != "":
		cfg.format, cfg.docType = credtype.FormatMDOC, tpl.DocType
	default:
		return templateConfiguration{}, false
	}
	return cfg, true
}

// warnUnreadableTemplates logs a change in the templates the issuer can't
// read. Every metadata request lists the templates.
func (d *DemoRP) warnUnreadableTemplates(err error) {
	var message string
	if err != nil {
		message = err.Error()
	}
	d.mu.Lock()
	changed := message != d.templateWarning
	d.templateWarning = message
	d.mu.Unlock()
	if changed && message != "" {
		log.Printf("[Demo issuer] WARNING: the issuer offers no templates it can't read: %v", err)
	}
}

// templateConfiguration reads the one template a credential request names.
// An id that looks like a path names no template, since Load would read it
// from disk.
func (d *DemoRP) templateConfiguration(id string) (templateConfiguration, bool) {
	if id == "" || strings.ContainsAny(id, `/\`) {
		return templateConfiguration{}, false
	}
	tpl, err := credtemplate.Load(id, d.wallet.Templates)
	if err != nil {
		return templateConfiguration{}, false
	}
	cfg, ok := configurationOf(*tpl)
	return cfg, ok && cfg.id == id
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
				"jwt": map[string]any{"proof_signing_alg_values_supported": []string{jws.AlgES256}},
			},
			"credential_signing_alg_values_supported": []string{jws.AlgES256},
		}
		switch cfg.format {
		case credtype.FormatSDJWT:
			entry["vct"] = cfg.vct
			entry["cryptographic_binding_methods_supported"] = []string{"jwk"}
		case credtype.FormatMDOC:
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
	httpsec.ServeImage(w, r, contentType, data)
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
		if cfg.format == credtype.FormatMDOC {
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
	resolved, err := credtemplate.Resolve(&tpl, credtemplate.Request{
		Format: cfg.format, Claims: granted.holderClaims, VCT: cfg.vct, DocType: cfg.docType,
	})
	if err != nil {
		return "", fmt.Errorf("resolving the template of %s: %w", cfg.id, err)
	}
	// The demo ticket records the wallet attestation of its issuance and its
	// trust status, since the demo accepts attestations from unknown CAs.
	if cfg.id == ticketConfigurationID && granted.clientAuth != nil {
		resolved.Claims["wallet_attestation"] = granted.clientAuth.ticketClaim()
	}
	spec := provider.IssuedAttestationSpec{Format: cfg.format, VCT: cfg.vct, DocType: cfg.docType}
	spec.Category = d.wallet.CredentialCategory(&tpl, spec)
	opts := wallet.HolderSigning{Issuer: d.issuerID()}
	if granted.withStatus {
		if opts.StatusListURI = d.statusListURI(); opts.StatusListURI == "" {
			return "", fmt.Errorf("this wallet has no status list URL")
		}
	}
	credential, err := d.wallet.SignForHolder(resolved, spec, holderKey, opts)
	if err != nil {
		return "", fmt.Errorf("signing %s: %w", cfg.id, err)
	}
	return credential, nil
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
