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

package registrar

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
)

// AttestationSchema is the SchemaMeta of the catalogue of attestations (EC
// TS11 v1.0 §4.3.1 and the normative JSON schema of Annex A.2).
type AttestationSchema struct {
	ID                 string           `json:"id,omitempty"`
	Version            string           `json:"version"`
	RulebookURI        string           `json:"rulebookURI"`
	TrustedAuthorities []TrustAuthority `json:"trustedAuthorities,omitempty"`
	AttestationLoS     string           `json:"attestationLoS"`
	BindingType        string           `json:"bindingType"`
	SupportedFormats   []string         `json:"supportedFormats"`
	SchemaURIs         []SchemaURI      `json:"schemaURIs"`
}

// SchemaURI binds a format to its schema (TS11 v1.0 §4.3.2).
type SchemaURI struct {
	FormatIdentifier string `json:"formatIdentifier"`
	URI              string `json:"uri"`
}

// TrustAuthority identifies the trust framework of an attestation type (TS11 v1.0
// §4.3.3). The Annex A.2 schema spells the qualifier isLOTE.
type TrustAuthority struct {
	FrameworkType string `json:"frameworkType"`
	Value         string `json:"value"`
	IsLOTE        *bool  `json:"isLOTE,omitempty"`
}

// CatalogAttestation is a catalogue entry. Schema is its SchemaMeta in the
// TS11 API. Name and Credentials make up the format-specific schemas behind
// its schema URIs (TS11 v1.0 §4.3.4).
type CatalogAttestation struct {
	Name        string              `json:"name"`
	Credentials []CatalogCredential `json:"credentials"`
	Schema      AttestationSchema   `json:"schema"`
	// Category is pid, qeaa, pub-eaa or eaa. The wallet signs the attestation
	// with the provider CA of that category. An entry without trusted
	// authorities links the wallet's trusted list of that category.
	Category string `json:"category,omitempty"`
	// Template marks an entry built from a credential template. Editing the
	// template changes the entry. The catalogue API can't change it.
	Template bool `json:"template,omitempty"`
	// Removed marks the deleted entry of a predefined template. The catalogue
	// derives that entry from the template, so the stored catalogue keeps
	// only this marker with its id.
	Removed bool `json:"removed,omitempty"`
}

// CatalogCredential is one format of an attestation: its vct or doctype and
// its claim paths. An mdoc claim path is namespace and element identifier.
type CatalogCredential struct {
	Format string  `json:"format"`
	Type   string  `json:"type"`
	Claims [][]any `json:"claims,omitempty"`
}

const (
	catalogSchemaPath = "/api/catalog/schemas"
	maxCatalogEntries = 200
	// maxPageSize caps the limit of the list endpoints.
	maxPageSize = 200
)

var (
	errCatalogNotFound = errors.New("attestation not in the catalogue")
	errCatalogTemplate = errors.New("this entry belongs to a predefined credential template and can't be changed")
	errCatalogFull     = errors.New("the catalogue holds the maximum number of attestations")
	semanticVersion    = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

	frameworkTypes = []string{"aki", "etsi_tl", "openid_federation"}
)

// SchemaOption is one value of a catalogue schema field, with the label the
// UI shows.
type SchemaOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// AttestationLevels are the TS11 attestationLoS values, the ISO/IEC 18045
// attack potentials, from the lowest.
var AttestationLevels = []SchemaOption{
	{"iso_18045_basic", "Basic"},
	{"iso_18045_enhanced-basic", "Enhanced basic"},
	{"iso_18045_moderate", "Moderate"},
	{"iso_18045_high", "High"},
}

// BindingTypes are the TS11 bindingType values: how an attestation is bound
// to its holder.
var BindingTypes = []SchemaOption{
	{"key", "Bound to a wallet key"},
	{"claim", "Linked to another credential"},
	{"biometric", "Bound to biometrics"},
	{"none", "Not bound to the holder"},
}

// OptionValues lists the values of options.
func OptionValues(options []SchemaOption) []string {
	values := make([]string, len(options))
	for i, o := range options {
		values[i] = o.Value
	}
	return values
}

// CatalogAttestations lists the template entries first, then the added
// entries.
func (r *Registrar) CatalogAttestations() []CatalogAttestation {
	base := r.env.RegistrarBase()
	r.mu.RLock()
	added := slices.DeleteFunc(slices.Clone(r.state.Catalog), func(e CatalogAttestation) bool { return e.Removed })
	removed := r.removedTemplateTypesLocked()
	r.mu.RUnlock()
	entries := slices.DeleteFunc(r.templateCatalog(base), removed.hides)
	sort.SliceStable(added, func(i, j int) bool { return strings.ToLower(added[i].Name) < strings.ToLower(added[j].Name) })
	for _, entry := range added {
		entries = append(entries, r.completed(cloneCatalogAttestation(entry), base))
	}
	return entries
}

// CatalogAttestation returns the entry with the schema id.
func (r *Registrar) CatalogAttestation(id string) (CatalogAttestation, bool) {
	for _, entry := range r.CatalogAttestations() {
		if entry.Schema.ID == id {
			return entry, true
		}
	}
	return CatalogAttestation{}, false
}

// AddCatalogAttestation stores a new entry. The catalogue assigns its id and
// its schema URIs (TS11 v1.0 §5.2.3).
func (r *Registrar) AddCatalogAttestation(entry CatalogAttestation) (CatalogAttestation, error) {
	base := r.env.RegistrarBase()
	entry = cloneCatalogAttestation(entry)
	entry.Template = false
	entry.Schema.ID = uuid.NewString()
	if err := normalizeCatalogAttestation(&entry, base); err != nil {
		return CatalogAttestation{}, err
	}
	fromTemplates := r.templateCatalog(base)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkNewCatalogEntryLocked(entry, fromTemplates); err != nil {
		return CatalogAttestation{}, err
	}
	r.state.Catalog = append(r.state.Catalog, entry)
	return r.completed(cloneCatalogAttestation(entry), base), nil
}

// CheckCatalogAttestation reports whether AddCatalogAttestation would accept
// entry, without adding it.
func (r *Registrar) CheckCatalogAttestation(entry CatalogAttestation) error {
	base := r.env.RegistrarBase()
	entry = cloneCatalogAttestation(entry)
	if err := normalizeCatalogAttestation(&entry, base); err != nil {
		return err
	}
	fromTemplates := r.templateCatalog(base)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.checkNewCatalogEntryLocked(entry, fromTemplates)
}

// checkNewCatalogEntryLocked keeps names and types unique. The wallet finds
// the trusted list of a received credential by its type.
func (r *Registrar) checkNewCatalogEntryLocked(entry CatalogAttestation, fromTemplates []CatalogAttestation) error {
	removed := r.removedTemplateTypesLocked()
	for _, existing := range append(fromTemplates, r.state.Catalog...) {
		if existing.Removed || (existing.Template && removed.hides(existing)) {
			continue
		}
		if strings.EqualFold(existing.Name, entry.Name) {
			return fmt.Errorf("the catalogue already lists %q", existing.Name)
		}
		for _, c := range entry.Credentials {
			if slices.ContainsFunc(existing.Credentials, func(e CatalogCredential) bool { return e.Format == c.Format && e.Type == c.Type }) {
				return fmt.Errorf("the catalogue already lists %s (%s) under %q", c.Type, c.Format, existing.Name)
			}
		}
	}
	// The markers of removed template entries don't take a place.
	added := len(r.state.Catalog) - removed.markers
	if added >= maxCatalogEntries {
		return errCatalogFull
	}
	return nil
}

// TemplateCatalogEntry builds the catalogue entry for template t from the
// catalogue fields in entry and checks it.
func (r *Registrar) TemplateCatalogEntry(t credtemplate.Template, entry CatalogAttestation) (CatalogAttestation, error) {
	entry, err := TemplateCatalogAttestation(t, entry)
	if err != nil {
		return CatalogAttestation{}, err
	}
	if err := r.CheckCatalogAttestation(entry); err != nil {
		return CatalogAttestation{}, err
	}
	return entry, nil
}

// TemplateCatalogAttestation completes entry with the format, type and claims
// of t. An empty name becomes the template's display name or its name.
func TemplateCatalogAttestation(t credtemplate.Template, entry CatalogAttestation) (CatalogAttestation, error) {
	if _, err := credtemplate.NormalizeFormat(t.Format); err != nil {
		return CatalogAttestation{}, err
	}
	credential, ok := templateCatalogCredential(t)
	if !ok {
		return CatalogAttestation{}, fmt.Errorf("only an SD-JWT VC template with a vct or an mdoc template with a doctype can be added to the catalogue")
	}
	entry = cloneCatalogAttestation(entry)
	entry.Credentials = []CatalogCredential{credential}
	entry.Category = jsonutil.FirstNonEmpty(entry.Category, t.Category, credtemplate.CategoryEAA)
	if strings.TrimSpace(entry.Name) == "" {
		entry.Name = t.Name
		if t.Display != nil && t.Display.Name != "" {
			entry.Name = t.Display.Name
		}
	}
	return entry, nil
}

// UpdateCatalogSchema replaces the SchemaMeta of an added entry (TS11 v1.0
// §5.3.2). The formats and schema URIs follow from the entry's credentials,
// so an update can't change them.
func (r *Registrar) UpdateCatalogSchema(id string, schema AttestationSchema) (CatalogAttestation, error) {
	base := r.env.RegistrarBase()
	if r.isTemplateCatalogID(id, base) {
		return CatalogAttestation{}, errCatalogTemplate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i := slices.IndexFunc(r.state.Catalog, func(e CatalogAttestation) bool { return e.Schema.ID == id })
	if i < 0 {
		return CatalogAttestation{}, fmt.Errorf("%w: %s", errCatalogNotFound, id)
	}
	stored := r.completed(cloneCatalogAttestation(r.state.Catalog[i]), base)
	if (schema.SupportedFormats != nil && !slices.Equal(schema.SupportedFormats, stored.Schema.SupportedFormats)) ||
		(schema.SchemaURIs != nil && !slices.Equal(schema.SchemaURIs, stored.Schema.SchemaURIs)) {
		return CatalogAttestation{}, fmt.Errorf("supportedFormats and schemaURIs follow from the attestation's credentials and can't be changed")
	}
	if schema.ID != "" && schema.ID != id {
		return CatalogAttestation{}, fmt.Errorf("the id in the body is %q, not %q", schema.ID, id)
	}
	updated := cloneCatalogAttestation(r.state.Catalog[i])
	schema.ID = id
	updated.Schema = schema
	if err := normalizeCatalogAttestation(&updated, base); err != nil {
		return CatalogAttestation{}, err
	}
	r.state.Catalog[i] = updated
	return r.completed(cloneCatalogAttestation(updated), base), nil
}

// DeleteCatalogAttestation removes an entry. The entry of a predefined
// template is recorded as removed, because the catalogue derives it from the
// template.
func (r *Registrar) DeleteCatalogAttestation(id string) error {
	base := r.env.RegistrarBase()
	templates := r.templateCatalog(base)
	if i := slices.IndexFunc(templates, func(e CatalogAttestation) bool { return e.Schema.ID == id }); i >= 0 {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.removedTemplateTypesLocked().hides(templates[i]) {
			return fmt.Errorf("%w: %s", errCatalogNotFound, id)
		}
		r.state.Catalog = append(r.state.Catalog, CatalogAttestation{Template: true, Removed: true, Schema: AttestationSchema{ID: id}, Credentials: templates[i].Credentials})
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i := slices.IndexFunc(r.state.Catalog, func(e CatalogAttestation) bool { return e.Schema.ID == id && !e.Removed })
	if i < 0 {
		return fmt.Errorf("%w: %s", errCatalogNotFound, id)
	}
	r.state.Catalog = slices.Delete(r.state.Catalog, i, i+1)
	return nil
}

// removedTemplateTypes are the types of the removed template entries. A
// marker records the types, so a template entry stays removed when its
// template is renamed.
type removedTemplateTypes struct {
	types   map[string]bool
	markers int
}

func (r *Registrar) removedTemplateTypesLocked() removedTemplateTypes {
	removed := removedTemplateTypes{types: map[string]bool{}}
	for _, e := range r.state.Catalog {
		if !e.Removed {
			continue
		}
		removed.markers++
		for _, c := range e.Credentials {
			removed.types[c.Format+" "+c.Type] = true
		}
	}
	return removed
}

// hides reports whether a template entry names a removed type.
func (removed removedTemplateTypes) hides(entry CatalogAttestation) bool {
	return slices.ContainsFunc(entry.Credentials, func(c CatalogCredential) bool { return removed.types[c.Format+" "+c.Type] })
}

// IsTemplateCatalogID reports whether an entry comes from a predefined
// template.
func (r *Registrar) IsTemplateCatalogID(id string) bool {
	return r.isTemplateCatalogID(id, r.env.RegistrarBase())
}

func (r *Registrar) isTemplateCatalogID(id, base string) bool {
	return slices.ContainsFunc(r.templateCatalog(base), func(e CatalogAttestation) bool { return e.Schema.ID == id })
}

// normalizeCatalogAttestation checks an entry against the TS11 v1.0 §4.3 data
// model and fills in defaults. It accepts the two EUDI formats, dc+sd-jwt and
// mso_mdoc.
func normalizeCatalogAttestation(entry *CatalogAttestation, base string) error {
	entry.Name = strings.TrimSpace(entry.Name)
	if entry.Name == "" {
		return fmt.Errorf("an attestation needs a name")
	}
	entry.Category = jsonutil.FirstNonEmpty(entry.Category, credtemplate.CategoryEAA)
	if err := credtemplate.CheckCategory(entry.Category); err != nil {
		return err
	}
	if len(entry.Credentials) == 0 {
		return fmt.Errorf("an attestation needs at least one format with its type")
	}
	if len(entry.Credentials) > 2 {
		return fmt.Errorf("an attestation has at most one dc+sd-jwt and one mso_mdoc format")
	}
	formats := map[string]bool{}
	for i := range entry.Credentials {
		c := &entry.Credentials[i]
		c.Type = strings.TrimSpace(c.Type)
		if c.Format != credtype.FormatSDJWT && c.Format != credtype.FormatMDOC {
			return fmt.Errorf("format %q is not dc+sd-jwt or mso_mdoc", c.Format)
		}
		if formats[c.Format] {
			return fmt.Errorf("format %s is listed twice. TS11 binds one schema URI to each format", c.Format)
		}
		formats[c.Format] = true
		if c.Type == "" {
			return fmt.Errorf("the %s format needs its type (vct or doctype)", c.Format)
		}
		if len(c.Claims) > maxRegisteredClaims {
			return fmt.Errorf("a format may list at most %d claims", maxRegisteredClaims)
		}
		c.Claims = slices.DeleteFunc(c.Claims, func(path []any) bool { return len(path) == 0 })
		if c.Format == credtype.FormatMDOC && slices.ContainsFunc(c.Claims, func(path []any) bool { return len(path) != 2 }) {
			return fmt.Errorf("an mdoc claim is a namespace and an element identifier")
		}
	}
	s := &entry.Schema
	s.Version = jsonutil.FirstNonEmpty(s.Version, "1.0.0")
	if !semanticVersion.MatchString(s.Version) {
		return fmt.Errorf("version %q does not follow semantic versioning (TS11 v1.0 §4.5.1)", s.Version)
	}
	s.RulebookURI = jsonutil.FirstNonEmpty(s.RulebookURI, base+"/rulebook")
	if !format.IsWebURL(s.RulebookURI) {
		return fmt.Errorf("rulebookURI %q is not an http or https URL", s.RulebookURI)
	}
	s.AttestationLoS = jsonutil.FirstNonEmpty(s.AttestationLoS, CategoryOf(entry.Category).AttestationLoS)
	if levels := OptionValues(AttestationLevels); !slices.Contains(levels, s.AttestationLoS) {
		return fmt.Errorf("attestationLoS %q is not one of %s", s.AttestationLoS, strings.Join(levels, ", "))
	}
	s.BindingType = jsonutil.FirstNonEmpty(s.BindingType, "key")
	if bindings := OptionValues(BindingTypes); !slices.Contains(bindings, s.BindingType) {
		return fmt.Errorf("bindingType %q is not one of %s", s.BindingType, strings.Join(bindings, ", "))
	}
	if len(s.TrustedAuthorities) > maxRegistrationItems {
		return fmt.Errorf("an attestation may list at most %d trusted authorities", maxRegistrationItems)
	}
	for _, a := range s.TrustedAuthorities {
		if !slices.Contains(frameworkTypes, a.FrameworkType) {
			return fmt.Errorf("frameworkType %q is not one of %s", a.FrameworkType, strings.Join(frameworkTypes, ", "))
		}
		if strings.TrimSpace(a.Value) == "" {
			return fmt.Errorf("a trusted authority needs a value")
		}
		if a.IsLOTE != nil && a.FrameworkType != "etsi_tl" {
			return fmt.Errorf("isLOTE applies only to the etsi_tl framework type (TS11 v1.0 §4.3.3)")
		}
		// An aki value is a key identifier. The other framework types identify
		// a list or an entity by URI, and the UI links them.
		if a.FrameworkType != "aki" && !format.IsWebURL(a.Value) {
			return fmt.Errorf("the %s value %q is not an http or https URL", a.FrameworkType, a.Value)
		}
	}
	s.SupportedFormats, s.SchemaURIs = nil, nil
	return nil
}

// completed fills in the formats with their schema URIs on the wallet. An
// entry without trusted authorities gets the trusted list of its category.
func (r *Registrar) completed(entry CatalogAttestation, base string) CatalogAttestation {
	entry.Category = jsonutil.FirstNonEmpty(entry.Category, credtemplate.CategoryEAA)
	if len(entry.Schema.TrustedAuthorities) == 0 {
		isLOTE := true
		entry.Schema.TrustedAuthorities = []TrustAuthority{{FrameworkType: "etsi_tl", Value: r.env.TrustedListURL(entry.Category), IsLOTE: &isLOTE}}
	}
	entry.Schema.SupportedFormats = nil
	entry.Schema.SchemaURIs = nil
	for _, c := range entry.Credentials {
		entry.Schema.SupportedFormats = append(entry.Schema.SupportedFormats, c.Format)
		entry.Schema.SchemaURIs = append(entry.Schema.SchemaURIs, SchemaURI{
			FormatIdentifier: c.Format,
			URI:              catalogSchemaURL(base, entry.Schema.ID, c.Format),
		})
	}
	return entry
}

func catalogSchemaURL(base, id, format string) string {
	return base + catalogSchemaPath + "/" + url.PathEscape(id) + "/" + url.PathEscape(format)
}

// FormatSchema is the format-specific schema behind a schema URI (TS11 v1.0
// §4.3.4). For dc+sd-jwt it is SD-JWT VC Type Metadata
// (draft-ietf-oauth-sd-jwt-vc-19 §5.2), with the claims of §5.6. For mso_mdoc
// TS11 refers to the DocType format of ISO 23220-2. eudi-dev serves the
// doctype with its namespaces and element identifiers instead.
func (entry CatalogAttestation) FormatSchema(format string) (map[string]any, bool) {
	i := slices.IndexFunc(entry.Credentials, func(c CatalogCredential) bool { return c.Format == format })
	if i < 0 {
		return nil, false
	}
	c := entry.Credentials[i]
	if format == credtype.FormatSDJWT {
		claims := make([]map[string]any, 0, len(c.Claims))
		for _, path := range c.Claims {
			claims = append(claims, map[string]any{"path": path})
		}
		return map[string]any{"vct": c.Type, "name": entry.Name, "claims": claims}, true
	}
	namespaces := map[string][]map[string]any{}
	for _, path := range c.Claims {
		namespace := fmt.Sprint(path[0])
		namespaces[namespace] = append(namespaces[namespace], map[string]any{"identifier": fmt.Sprint(path[1])})
	}
	return map[string]any{"docType": c.Type, "name": entry.Name, "namespaces": namespaces}, true
}

func cloneCatalogAttestation(entry CatalogAttestation) CatalogAttestation {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return entry
	}
	var clone CatalogAttestation
	if json.Unmarshal(encoded, &clone) != nil {
		return entry
	}
	return clone
}

// templateCatalogNamespace makes the ids of template entries stable across
// restarts and instances. Stored entries carry ids derived from it, so the
// name keeps the repository's first location.
var templateCatalogNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/dominikschlosser/eudi-dev/catalog"))

// templateCatalog lists the attestations of the predefined credential
// templates, including a user template that replaces one. Other user templates
// are added only on request and are then added entries. Templates with the
// same display name are one attestation in two formats. The template's
// category sets the entry's category and level of security.
func (r *Registrar) templateCatalog(base string) []CatalogAttestation {
	templates, err := credtemplate.List(r.env.TemplateLocation())
	if err != nil {
		log.Printf("[Registrar] WARNING: the catalogue leaves out templates it can't read: %v", err)
	}
	var entries []CatalogAttestation
	index := map[string]int{}
	for _, t := range templates {
		if _, ok := credtemplate.Predefined(t.Name); !ok {
			continue
		}
		credential, ok := templateCatalogCredential(t)
		if !ok {
			continue
		}
		name := t.Name
		if t.Display != nil && t.Display.Name != "" {
			name = t.Display.Name
		}
		i, ok := index[name]
		if ok && slices.ContainsFunc(entries[i].Credentials, func(c CatalogCredential) bool { return c.Format == credential.Format }) {
			continue
		}
		if !ok {
			entry := CatalogAttestation{
				Name:     name,
				Category: jsonutil.FirstNonEmpty(t.Category, credtemplate.CategoryEAA),
				Template: true,
				Schema: AttestationSchema{
					ID:          uuid.NewSHA1(templateCatalogNamespace, []byte(name)).String(),
					Version:     "1.0.0",
					RulebookURI: jsonutil.FirstNonEmpty(t.Rulebook, base+"/rulebook"),
					BindingType: "key",
				},
			}
			entry.Schema.AttestationLoS = CategoryOf(entry.Category).AttestationLoS
			index[name] = len(entries)
			entries = append(entries, entry)
			i = len(entries) - 1
		}
		entries[i].Credentials = append(entries[i].Credentials, credential)
	}
	for i := range entries {
		sort.Slice(entries[i].Credentials, func(a, b int) bool { return entries[i].Credentials[a].Format < entries[i].Credentials[b].Format })
		entries[i] = r.completed(entries[i], base)
	}
	sort.SliceStable(entries, func(a, b int) bool { return strings.ToLower(entries[a].Name) < strings.ToLower(entries[b].Name) })
	return entries
}

// templateCatalogCredential lists a template's claims as paths. An SD-JWT
// object claim is listed with its members. An mdoc claim key is an element of
// the template's namespace, or namespace:element. A template without a type,
// or in the plain JWT format, has no entry.
func templateCatalogCredential(t credtemplate.Template) (CatalogCredential, bool) {
	t.Format, _ = credtemplate.NormalizeFormat(t.Format)
	switch {
	case t.Format == "mdoc" && t.DocType != "":
		c := CatalogCredential{Format: credtype.FormatMDOC, Type: t.DocType}
		for _, key := range slices.Sorted(maps.Keys(t.Claims)) {
			namespace, element := jsonutil.FirstNonEmpty(t.Namespace, t.DocType), key
			if at := strings.LastIndex(key, ":"); at > 0 {
				namespace, element = key[:at], key[at+1:]
			}
			c.Claims = append(c.Claims, []any{namespace, element})
		}
		return c, true
	case t.Format == "sdjwt" && t.VCT != "":
		c := CatalogCredential{Format: credtype.FormatSDJWT, Type: t.VCT}
		for _, key := range slices.Sorted(maps.Keys(t.Claims)) {
			c.Claims = append(c.Claims, []any{key})
			if members, ok := t.Claims[key].(map[string]any); ok {
				for _, member := range slices.Sorted(maps.Keys(members)) {
					c.Claims = append(c.Claims, []any{key, member})
				}
			}
		}
		return c, true
	}
	return CatalogCredential{}, false
}
