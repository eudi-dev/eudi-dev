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
	"reflect"
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
	// Operator marks an entry of the operator's catalogue file (wallet serve
	// --catalog). Every start and every demo reset load the file again.
	Operator bool `json:"operator,omitempty"`
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
	errCatalogTemplate = errors.New("this entry belongs to a credential template and can't be changed here. Change the template instead")
	errCatalogFull     = errors.New("the catalogue holds the maximum number of attestations")
	semanticVersion    = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

	frameworkTypes = []string{"aki", "etsi_tl", "openid_federation"}
)

// SchemaOption is one value of a catalogue schema field, with its UI label.
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
	entry.Template, entry.Operator = false, false
	entry.Schema.ID = uuid.NewString()
	if err := normalizeCatalogAttestation(&entry, base); err != nil {
		return CatalogAttestation{}, err
	}
	fromTemplates := r.templateCatalog(base)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := checkNewCatalogEntry(entry, fromTemplates, r.state.Catalog); err != nil {
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
	return checkNewCatalogEntry(entry, fromTemplates, r.state.Catalog)
}

// checkNewCatalogEntry keeps names and types unique. The wallet finds the
// trusted list of a received credential by its type.
func checkNewCatalogEntry(entry CatalogAttestation, fromTemplates, stored []CatalogAttestation) error {
	removed := removedTemplateTypesIn(stored)
	for _, existing := range slices.Concat(fromTemplates, stored) {
		if existing.Removed || (existing.Template && removed.hides(existing)) {
			continue
		}
		if err := catalogClash(entry, existing); err != nil {
			return err
		}
	}
	// The markers of removed template entries don't take a place.
	added := len(stored) - removed.markers
	if added >= maxCatalogEntries {
		return errCatalogFull
	}
	return nil
}

// catalogClash reports whether entry takes the name or a type of existing.
func catalogClash(entry, existing CatalogAttestation) error {
	if strings.EqualFold(existing.Name, entry.Name) {
		return fmt.Errorf("the catalogue already lists %q", existing.Name)
	}
	for _, c := range entry.Credentials {
		if slices.ContainsFunc(existing.Credentials, func(e CatalogCredential) bool { return e.Format == c.Format && e.Type == c.Type }) {
			return fmt.Errorf("the catalogue already lists %s (%s) under %q", c.Type, c.Format, existing.Name)
		}
	}
	return nil
}

// SetOperatorCatalog stores entries as the operator's catalogue file. The id
// of an entry derives from its name, so an entry keeps its id across
// restarts. Entries of an earlier file missing from entries are removed. An
// entry added through the API is removed too when it takes the name or a type
// of an operator entry. A visitor of a public demo then can't stop the start.
// It reports whether the stored catalogue changed.
func (r *Registrar) SetOperatorCatalog(entries []CatalogAttestation) (bool, error) {
	base := r.env.RegistrarBase()
	fromTemplates := r.templateCatalog(base)
	normalized := make([]CatalogAttestation, len(entries))
	for i, entry := range entries {
		entry = cloneCatalogAttestation(entry)
		entry.Template, entry.Removed, entry.Operator = false, false, true
		if err := normalizeCatalogAttestation(&entry, base); err != nil {
			return false, &CatalogEntryError{Index: i, Err: err}
		}
		entry.Schema.ID = catalogEntryID(entry.Name)
		normalized[i] = entry
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	replaced := map[string]bool{}
	var others []CatalogAttestation
	for _, e := range r.state.Catalog {
		if e.Operator {
			continue
		}
		if !e.Removed && slices.ContainsFunc(normalized, func(o CatalogAttestation) bool { return catalogClash(o, e) != nil }) {
			log.Printf("[Registrar] The operator's catalogue replaces the entry %q added through the API", e.Name)
			replaced[e.Schema.ID] = true
			continue
		}
		others = append(others, e)
	}
	byID := map[string]CatalogAttestation{}
	var order []string
	for i, entry := range normalized {
		if err := checkNewCatalogEntry(entry, fromTemplates, others); err != nil {
			return false, &CatalogEntryError{Index: i, Err: err}
		}
		others = append(others, entry)
		byID[entry.Schema.ID] = entry
		order = append(order, entry.Schema.ID)
	}
	// An entry that stays keeps its place, so an unchanged file leaves the
	// stored catalogue as it is.
	var catalog []CatalogAttestation
	for _, e := range r.state.Catalog {
		if !e.Operator {
			if !replaced[e.Schema.ID] {
				catalog = append(catalog, e)
			}
			continue
		}
		if updated, ok := byID[e.Schema.ID]; ok {
			catalog = append(catalog, updated)
			delete(byID, e.Schema.ID)
		}
	}
	for _, id := range order {
		if entry, ok := byID[id]; ok {
			catalog = append(catalog, entry)
		}
	}
	changed := len(r.state.Catalog)+len(catalog) > 0 && !reflect.DeepEqual(r.state.Catalog, catalog)
	r.state.Catalog = catalog
	return changed, nil
}

// CatalogEntryError is the refusal of one entry of a list.
type CatalogEntryError struct {
	Index int
	Err   error
}

func (e *CatalogEntryError) Error() string { return fmt.Sprintf("entry %d: %v", e.Index+1, e.Err) }

func (e *CatalogEntryError) Unwrap() error { return e.Err }

// CheckCatalogEntry reports whether entry fits the TS11 data model, as
// AddCatalogAttestation checks it. It does not compare it with other entries.
func CheckCatalogEntry(entry CatalogAttestation) error {
	entry = cloneCatalogAttestation(entry)
	return normalizeCatalogAttestation(&entry, "https://wallet.invalid")
}

// IsOperatorCatalogID reports whether an entry comes from the operator's
// catalogue file.
func (r *Registrar) IsOperatorCatalogID(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.ContainsFunc(r.state.Catalog, func(e CatalogAttestation) bool { return e.Operator && e.Schema.ID == id })
}

// catalogEntryID derives the id of a template entry or an operator entry from
// its name.
func catalogEntryID(name string) string {
	return uuid.NewSHA1(templateCatalogNamespace, []byte(name)).String()
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
	return removedTemplateTypesIn(r.state.Catalog)
}

func removedTemplateTypesIn(catalog []CatalogAttestation) removedTemplateTypes {
	removed := removedTemplateTypes{types: map[string]bool{}}
	for _, e := range catalog {
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

// hides reports whether a template entry has a removed type.
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

// templateCatalog lists the attestations of the credential templates: each
// predefined template, including a user template that replaces one, and each
// template that carries a catalog object. Other user templates are added only
// on request and are then added entries. Templates with the same entry name
// are one attestation in two formats. The template's category sets the
// entry's category and level of security. It leaves out the catalog objects
// that CheckTemplateCatalog refuses.
func (r *Registrar) templateCatalog(base string) []CatalogAttestation {
	templates, err := credtemplate.List(r.env.TemplateLocation())
	if err != nil {
		log.Printf("[Registrar] WARNING: the catalogue leaves out templates it can't read: %v", err)
	}
	built, _ := r.buildTemplateCatalog(templates, base)
	entries := make([]CatalogAttestation, 0, len(built))
	// A template file can reach the directory without CheckTemplateCatalog. Its
	// catalog object then must not list a type or name a second time, because
	// the wallet finds the trusted list of a credential by its one entry.
	for i, b := range built {
		if clash := ownedEntryClash(built, i); clash != nil {
			log.Printf("[Registrar] WARNING: the catalogue leaves out the entry of template %q: %v", b.owners[0], clash)
			continue
		}
		entries = append(entries, b.entry)
	}
	return entries
}

// ownedEntryClash reports whether the catalog object of a template repeats
// the name or a type of an entry with priority: a predefined entry, or an
// earlier template entry.
func ownedEntryClash(built []templateCatalogEntry, i int) error {
	if len(built[i].owners) == 0 {
		return nil
	}
	for j, other := range built {
		if j == i || (len(other.owners) > 0 && j > i) {
			continue
		}
		if err := catalogClash(built[i].entry, other.entry); err != nil {
			return err
		}
	}
	return nil
}

// templateCatalogEntry is a template entry with the templates whose catalog
// objects make it up.
type templateCatalogEntry struct {
	entry  CatalogAttestation
	owners []string
}

// templateCatalogProblem is a catalog object of a template that the
// catalogue can't take.
type templateCatalogProblem struct {
	template string
	err      error
}

// buildTemplateCatalog builds the entries of templates, sorted by name.
func (r *Registrar) buildTemplateCatalog(templates []credtemplate.Template, base string) (built []templateCatalogEntry, problems []templateCatalogProblem) {
	index := map[string]int{}
	// Predefined templates come first, so a user template can't take over
	// their entries.
	ordered := slices.Clone(templates)
	sort.SliceStable(ordered, func(a, b int) bool {
		_, pa := credtemplate.Predefined(ordered[a].Name)
		_, pb := credtemplate.Predefined(ordered[b].Name)
		return pa && !pb
	})
	for _, t := range ordered {
		_, predefined := credtemplate.Predefined(t.Name)
		if !predefined && t.Catalog == nil {
			continue
		}
		entry, ok, err := templateEntry(t, base)
		if err != nil {
			problems = append(problems, templateCatalogProblem{t.Name, err})
			continue
		}
		if !ok {
			continue
		}
		credential := entry.Credentials[0]
		i, ok := index[entry.Name]
		if ok && slices.ContainsFunc(built[i].entry.Credentials, func(c CatalogCredential) bool { return c.Format == credential.Format }) {
			if t.Catalog != nil {
				problems = append(problems, templateCatalogProblem{t.Name, fmt.Errorf("another template already makes up %q in %s", entry.Name, credential.Format)})
			}
			continue
		}
		if !ok {
			index[entry.Name] = len(built)
			built = append(built, templateCatalogEntry{entry: entry})
			i = len(built) - 1
		} else {
			built[i].entry.Credentials = append(built[i].entry.Credentials, credential)
		}
		if t.Catalog != nil {
			built[i].owners = append(built[i].owners, t.Name)
		}
	}
	for i := range built {
		credentials := built[i].entry.Credentials
		sort.Slice(credentials, func(a, b int) bool { return credentials[a].Format < credentials[b].Format })
		built[i].entry = r.completed(built[i].entry, base)
	}
	sort.SliceStable(built, func(a, b int) bool {
		return strings.ToLower(built[a].entry.Name) < strings.ToLower(built[b].entry.Name)
	})
	return built, problems
}

// templateEntry builds the entry of one template in one format. A template
// with a catalog object takes its fields with the rules of a catalogue
// request (TemplateCatalogAttestation). A template without a type has no
// entry, and ok is false.
func templateEntry(t credtemplate.Template, base string) (entry CatalogAttestation, ok bool, err error) {
	credential, ok := templateCatalogCredential(t)
	if t.Catalog == nil {
		if !ok {
			return CatalogAttestation{}, false, nil
		}
		name := t.Name
		if t.Display != nil && t.Display.Name != "" {
			name = t.Display.Name
		}
		entry = CatalogAttestation{
			Name:        name,
			Category:    jsonutil.FirstNonEmpty(t.Category, credtemplate.CategoryEAA),
			Credentials: []CatalogCredential{credential},
			Schema: AttestationSchema{
				Version:     "1.0.0",
				RulebookURI: jsonutil.FirstNonEmpty(t.Rulebook, base+"/rulebook"),
				BindingType: "key",
			},
		}
		entry.Schema.AttestationLoS = CategoryOf(entry.Category).AttestationLoS
	} else {
		var requested CatalogAttestation
		if err := json.Unmarshal(t.Catalog, &requested); err != nil {
			return CatalogAttestation{}, false, fmt.Errorf("catalog: %w", err)
		}
		if entry, err = TemplateCatalogAttestation(t, requested); err != nil {
			return CatalogAttestation{}, false, err
		}
		entry.Schema.RulebookURI = jsonutil.FirstNonEmpty(entry.Schema.RulebookURI, t.Rulebook)
		if err := normalizeCatalogAttestation(&entry, base); err != nil {
			return CatalogAttestation{}, false, err
		}
	}
	entry.Template, entry.Operator, entry.Removed = true, false, false
	entry.Schema.ID = catalogEntryID(entry.Name)
	return entry, true, nil
}

// CheckTemplateCatalog reports the catalog objects of templates that the
// catalogue can't take: an invalid one, or one whose entry takes the name or
// a type of another entry. With replace set, it checks the templates as they
// are after saving replace and reports only the problems of replace.
func (r *Registrar) CheckTemplateCatalog(replace *credtemplate.Template) error {
	base := r.env.RegistrarBase()
	templates, _ := credtemplate.List(r.env.TemplateLocation())
	if replace != nil {
		templates = slices.DeleteFunc(templates, func(t credtemplate.Template) bool { return t.Name == replace.Name })
		templates = append(templates, *replace)
		sort.SliceStable(templates, func(a, b int) bool { return templates[a].Name < templates[b].Name })
	}
	built, problems := r.buildTemplateCatalog(templates, base)
	r.mu.RLock()
	stored := slices.Clone(r.state.Catalog)
	r.mu.RUnlock()
	removed := removedTemplateTypesIn(stored)
	for i, b := range built {
		if len(b.owners) == 0 || removed.hides(b.entry) {
			continue
		}
		var others []CatalogAttestation
		for j, other := range built {
			if j != i && !removed.hides(other.entry) {
				others = append(others, other.entry)
			}
		}
		for _, other := range append(others, stored...) {
			if other.Removed {
				continue
			}
			if err := catalogClash(b.entry, other); err != nil {
				problems = append(problems, templateCatalogProblem{b.owners[0], err})
				break
			}
		}
	}
	var errs []error
	for _, p := range problems {
		if replace == nil || p.template == replace.Name {
			errs = append(errs, fmt.Errorf("template %q: %w", p.template, p.err))
		}
	}
	return errors.Join(errs...)
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
