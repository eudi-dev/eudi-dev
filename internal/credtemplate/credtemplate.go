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

// Package credtemplate stores reusable claim sets and issuance defaults. The
// built-in templates are the template files of the defaults tree. They cover
// the EU PID, national PIDs and a demo ticket. A user template replaces the
// built-in template with the same name.
package credtemplate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/defaults"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/yamljson"
)

// Template describes a reusable credential template. All fields except Claims
// are optional. An empty Format means any format. Empty VCT, DocType, Namespace
// and Exp fall back to the issuance defaults.
type Template struct {
	// Name identifies the template. For file-based templates it defaults to
	// the file name without extension.
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// Format is "sdjwt", "jwt" or "mdoc". The aliases "dc+sd-jwt", "jwt_vc_json"
	// and "mso_mdoc" are accepted. Empty means any format.
	Format    string `json:"format,omitempty"`
	VCT       string `json:"vct,omitempty"`
	DocType   string `json:"doctype,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	// Exp is a Go duration string (e.g. "720h").
	Exp string `json:"exp,omitempty"`
	// Claims is the default claim set. Callers may override individual
	// top-level claims at issuance time. A string value "embedded:<file>"
	// becomes a data URI of that file of the defaults tree.
	Claims map[string]any `json:"claims"`
	// AlwaysDisclosed lists claims that appear in plain text in an SD-JWT payload.
	// Nested claims use dotted paths such as "address.country".
	AlwaysDisclosed []string `json:"always_disclosed,omitempty"`
	// Category is the kind of attestation: pid, qeaa, pub-eaa or eaa (ARF
	// ISSU_07 to ISSU_10). Each category has its own provider CA, and the
	// trusted list of the category lists that CA.
	Category string `json:"category,omitempty"`
	// UniqueClaims lists claims that get a new random value for every
	// credential, such as the opaque subject of IT-Wallet 1.4.7 §11.1.2.1.
	UniqueClaims []string `json:"unique_claims,omitempty"`
	// Rulebook links the rulebook or specification of the credential type.
	Rulebook string `json:"rulebook,omitempty"`
	// Baseline marks the PIDs that every wallet holds by default.
	Baseline bool `json:"baseline,omitempty"`
	// Display sets the OpenID4VCI §12.2.4 appearance of credentials issued from
	// this template. Image fields take "embedded:<file>", a data URI or an
	// https URL.
	Display *TemplateDisplay `json:"display,omitempty"`
	// Catalog is the template's own entry in the attestation catalogue, in the
	// shape of a catalogue request. The registrar reads it, and its category
	// is the template's category.
	Catalog json.RawMessage `json:"catalog,omitempty"`
	// Predefined marks the built-in templates. Template files can't set it.
	Predefined bool `json:"predefined,omitempty"`
	// Visitor marks a template that a visitor of a public demo saved. The
	// operator's templates are the others.
	Visitor bool `json:"visitor,omitempty"`
}

type TemplateDisplay struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
	Logo            string `json:"logo,omitempty"`
	LogoAltText     string `json:"logo_alt_text,omitempty"`
	BackgroundImage string `json:"background_image,omitempty"`
	// Claims maps a top-level claim name to its display name.
	Claims map[string]string `json:"claims,omitempty"`
}

var templateExtensions = []string{".json", ".template", ".yaml", ".yml"}

// Location is a prefix inside a store that holds user templates. The zero
// Location is the default wallet's template directory.
type Location struct {
	Store  storage.Store
	Prefix string
}

func FileLocation(dir string) Location {
	return Location{Store: storage.NewFile(dir)}
}

func (l Location) orDefault() Location {
	if l.Store == nil {
		return FileLocation(filepath.Join(config.BaseDir(), "wallet", "templates"))
	}
	return l
}

func (l Location) String() string {
	l = l.orDefault()
	return l.Store.Locate(l.Prefix)
}

func (l Location) key(name string) string {
	return path.Join(l.Prefix, name)
}

// Credential categories. Each has its own trusted list.
const (
	CategoryPID    = "pid"
	CategoryQEAA   = "qeaa"
	CategoryPubEAA = "pub-eaa"
	CategoryEAA    = "eaa"
)

// Categories lists the credential categories in the order the UI shows them.
var Categories = []string{CategoryPID, CategoryQEAA, CategoryPubEAA, CategoryEAA}

// CheckCategory accepts an empty category or one of Categories.
func CheckCategory(category string) error {
	if category == "" || slices.Contains(Categories, category) {
		return nil
	}
	return fmt.Errorf("category %q is not one of %s", category, strings.Join(Categories, ", "))
}

// NormalizeFormat maps format aliases to "sdjwt", "jwt", or "mdoc". An empty
// input stays empty (meaning any format).
func NormalizeFormat(format string) (string, error) {
	switch strings.TrimSpace(format) {
	case "":
		return "", nil
	case "sdjwt", "sd-jwt", credtype.FormatSDJWT:
		return "sdjwt", nil
	case "jwt", credtype.FormatJWTVC:
		return "jwt", nil
	case "mdoc", credtype.FormatMDOC:
		return "mdoc", nil
	default:
		return "", fmt.Errorf("unsupported template format %q: expected sdjwt, jwt, or mdoc", format)
	}
}

// PredefinedTemplates reads the built-in templates from the defaults tree.
// Every call returns fresh copies with current dates, so a long-running
// server issues PIDs with the current date.
func PredefinedTemplates() []Template {
	entries, err := defaults.ReadDir(predefinedDir)
	if err != nil {
		panic(fmt.Sprintf("reading the predefined templates: %v", err))
	}
	var templates []Template
	for _, entry := range entries {
		if !hasTemplateExtension(entry.Name()) {
			continue
		}
		data, err := defaults.ReadFile(path.Join(predefinedDir, entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("reading the predefined template %s: %v", entry.Name(), err))
		}
		t, err := parse(data, entry.Name())
		if err != nil {
			panic(fmt.Sprintf("predefined template: %v", err))
		}
		t.Predefined = true
		templates = append(templates, *t)
	}
	return templates
}

const predefinedDir = "templates"

// Predefined returns the built-in template with the given name.
func Predefined(name string) (Template, bool) {
	for _, t := range PredefinedTemplates() {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}

// PIDTemplateNames returns the SD-JWT and mdoc templates in loc for the PID
// type vct. The SD-JWT template has that type, and the mdoc template issues the
// PID doctype under the same display name. A predefined template wins over a
// user template of the same type. ok reports whether such templates exist.
// For any other type it returns the names of the predefined templates of the
// country-independent PID, which a user template may replace.
func PIDTemplateNames(vct string, loc Location) (sdjwt, mdoc string, ok bool) {
	if vct == "" {
		vct = credtype.PIDVCT
	}
	// List returns every readable template with its error.
	templates, _ := List(loc)
	slices.SortStableFunc(templates, func(a, b Template) int {
		switch {
		case a.Predefined == b.Predefined:
			return 0
		case a.Predefined:
			return -1
		}
		return 1
	})
	sdjwt, mdoc = pidTemplatePair(vct, templates)
	baseSDJWT, baseMDOC := pidTemplatePair(credtype.PIDVCT, PredefinedTemplates())
	if sdjwt == "" {
		return baseSDJWT, baseMDOC, false
	}
	if mdoc == "" {
		mdoc = baseMDOC
	}
	return sdjwt, mdoc, true
}

func pidTemplatePair(vct string, templates []Template) (sdjwt, mdoc string) {
	var display string
	for _, t := range templates {
		if format, _ := NormalizeFormat(t.Format); format == "sdjwt" && t.VCT == vct {
			sdjwt, display = t.Name, displayName(t)
			break
		}
	}
	if sdjwt == "" {
		return "", ""
	}
	for _, t := range templates {
		if format, _ := NormalizeFormat(t.Format); format == "mdoc" && t.DocType == credtype.PIDDocType && displayName(t) == display {
			return sdjwt, t.Name
		}
	}
	return sdjwt, ""
}

func displayName(t Template) string {
	if t.Display == nil {
		return ""
	}
	return t.Display.Name
}

// PIDTypes returns the SD-JWT VC types of the PID templates in loc, the
// country-independent PID first.
func PIDTypes(loc Location) []string {
	templates, err := List(loc)
	if err != nil {
		return []string{credtype.PIDVCT}
	}
	types := []string{credtype.PIDVCT}
	for _, t := range templates {
		if format, _ := NormalizeFormat(t.Format); format == "sdjwt" && strings.HasPrefix(t.VCT, credtype.PIDVCTPrefix) && !slices.Contains(types, t.VCT) {
			types = append(types, t.VCT)
		}
	}
	return types
}

// WithUniqueClaims returns claims with a new random value for each claim
// listed in t.UniqueClaims. Other claims stay unchanged.
func (t *Template) WithUniqueClaims(claims map[string]any) map[string]any {
	if t == nil || len(t.UniqueClaims) == 0 {
		return claims
	}
	fresh := maps.Clone(claims)
	for _, name := range t.UniqueClaims {
		if _, ok := fresh[name]; ok {
			fresh[name] = uuid.NewString()
		}
	}
	return fresh
}

// List returns all templates: predefined templates plus user templates from
// loc (the default directory for the zero Location). A user template with the
// same name as a built-in replaces it. The result is sorted by name.
// List returns the predefined templates and every readable stored template.
// It reports the templates it can't read as an error and still returns the
// others, so a caller that only reads them can go on with what it got.
func List(loc Location) ([]Template, error) {
	loc = loc.orDefault()

	byName := make(map[string]Template)
	for _, t := range PredefinedTemplates() {
		byName[t.Name] = t
	}

	var errs []error
	stored, err := loc.Store.List(loc.Prefix)
	if err != nil {
		errs = append(errs, fmt.Errorf("reading template directory: %w", err))
	}
	files := make(map[string][]string)
	for _, name := range stored {
		if hasTemplateExtension(name) {
			base := strings.TrimSuffix(name, path.Ext(name))
			files[base] = append(files[base], name)
		}
	}
	for _, name := range stored {
		if !hasTemplateExtension(name) {
			continue
		}
		same := files[strings.TrimSuffix(name, path.Ext(name))]
		if len(same) > 1 {
			if name == same[0] {
				errs = append(errs, clashError(loc, same))
			}
			continue
		}
		t, err := loadStored(loc, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		byName[t.Name] = *t
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	templates := make([]Template, 0, len(names))
	for _, name := range names {
		templates = append(templates, byName[name])
	}
	return templates, errors.Join(errs...)
}

// Load resolves a template by name or file path. Names are looked up in loc
// (the default directory for the zero Location) first, then in the
// predefined templates. Anything containing a path separator or a template
// extension is loaded as a file path.
func Load(nameOrPath string, loc Location) (*Template, error) {
	if strings.TrimSpace(nameOrPath) == "" {
		return nil, fmt.Errorf("template name is required")
	}
	loc = loc.orDefault()

	if strings.ContainsRune(nameOrPath, os.PathSeparator) || strings.ContainsRune(nameOrPath, '/') || hasTemplateExtension(nameOrPath) {
		return loadFile(nameOrPath)
	}

	file, err := storedFile(loc, nameOrPath)
	if err == nil {
		return loadStored(loc, file)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	if t, ok := Predefined(nameOrPath); ok {
		return &t, nil
	}

	return nil, fmt.Errorf("template %q not found (looked in %s and the predefined templates, see `templates list`)", nameOrPath, loc)
}

func Save(loc Location, t Template) (string, error) {
	name := strings.TrimSpace(t.Name)
	if name == "" {
		return "", fmt.Errorf("template name is required")
	}
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("invalid template name %q", name)
	}
	if _, err := NormalizeFormat(t.Format); err != nil {
		return "", err
	}
	if err := CheckCategory(t.Category); err != nil {
		return "", err
	}
	loc = loc.orDefault()

	t.Name = name
	t.Predefined = false
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding template: %w", err)
	}
	key := loc.key(name + ".json")
	if _, err := loc.Store.Write(key, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("writing template: %w", err)
	}
	// The saved JSON file replaces a file of the same name in another format.
	for _, ext := range templateExtensions {
		if ext == ".json" {
			continue
		}
		other := loc.key(name + ext)
		exists, err := loc.Store.Exists(other)
		if err == nil && exists {
			err = loc.Store.Delete(other)
		}
		if err != nil {
			return "", fmt.Errorf("replacing template %s: %w", loc.Store.Locate(other), err)
		}
	}
	return loc.Store.Locate(key), nil
}

// ErrNotFound reports a template name with no saved or predefined template.
var ErrNotFound = errors.New("not found")

// Delete removes a user template from loc (the default directory for the
// zero Location). Predefined templates cannot be deleted.
func Delete(loc Location, name string) error {
	loc = loc.orDefault()
	if name != filepath.Base(name) {
		return fmt.Errorf("invalid template name %q", name)
	}
	file, err := storedFile(loc, name)
	if err == nil {
		return loc.Store.Delete(loc.key(file))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, ok := Predefined(name); ok {
		return fmt.Errorf("template %q is predefined and cannot be deleted", name)
	}
	return fmt.Errorf("template %q %w in %s", name, ErrNotFound, loc)
}

// storedFile returns the file name of the stored template name. It refuses
// two files of one name, such as x.json and x.yaml, because either could be
// the template.
func storedFile(loc Location, name string) (string, error) {
	var found []string
	for _, ext := range templateExtensions {
		exists, err := loc.Store.Exists(loc.key(name + ext))
		if err != nil {
			return "", fmt.Errorf("reading template %q: %w", name, err)
		}
		if exists {
			found = append(found, name+ext)
		}
	}
	switch len(found) {
	case 0:
		return "", fs.ErrNotExist
	case 1:
		return found[0], nil
	}
	return "", clashError(loc, found)
}

func clashError(loc Location, files []string) error {
	located := make([]string, len(files))
	for i, file := range files {
		located[i] = loc.Store.Locate(loc.key(file))
	}
	name := strings.TrimSuffix(files[0], path.Ext(files[0]))
	return fmt.Errorf("template %q has more than one file: %s. Remove all but one", name, strings.Join(located, " and "))
}

func hasTemplateExtension(name string) bool {
	for _, ext := range templateExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// IsBareName restricts untrusted input to template names. Load also accepts file paths,
// and a path can read outside template storage.
func IsBareName(s string) bool {
	return s != "" &&
		!strings.ContainsRune(s, os.PathSeparator) &&
		!strings.ContainsRune(s, '/') &&
		!strings.HasPrefix(s, ".") &&
		!hasTemplateExtension(s)
}

func loadFile(file string) (*Template, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}
	return parse(data, file)
}

// loadStored reads a user template from its location. A missing template
// returns an error satisfying errors.Is(err, fs.ErrNotExist).
func loadStored(loc Location, name string) (*Template, error) {
	key := loc.key(name)
	data, err := loc.Store.Read(key)
	if err != nil {
		return nil, fmt.Errorf("reading template %s: %w", name, err)
	}
	return parse(data, loc.Store.Locate(key))
}

// Decode reads a template as it is written, in JSON or YAML. A file name
// ending in .yaml or .yml is YAML, and any other file name is JSON. Without a
// file name, data starting with "{" is JSON and other data is YAML. YAML
// becomes JSON first, so both formats go through the same decoder.
func Decode(data []byte, file string) (Template, error) {
	yamlData := strings.HasSuffix(file, ".yaml") || strings.HasSuffix(file, ".yml")
	if file == "" {
		yamlData = !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{"))
	}
	if yamlData {
		var err error
		data, err = yamljson.Convert(data, yamljson.KeepStrings)
		if err != nil {
			return Template{}, err
		}
	}
	var t Template
	err := json.Unmarshal(data, &t)
	return t, err
}

func parse(data []byte, file string) (*Template, error) {
	t, err := Decode(data, file)
	if err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", file, err)
	}
	if _, err := NormalizeFormat(t.Format); err != nil {
		return nil, fmt.Errorf("template %s: %w", file, err)
	}
	if strings.TrimSpace(t.Name) == "" {
		base := path.Base(filepath.ToSlash(file))
		t.Name = strings.TrimSuffix(base, path.Ext(base))
	}
	if err := t.TakeCatalogCategory(); err != nil {
		return nil, fmt.Errorf("template %s: %w", file, err)
	}
	t.Predefined = false
	t.Claims = resolveEmbedded(t.Claims).(map[string]any)
	if t.Category == CategoryPID {
		fillPIDDates(t.Claims, time.Now())
	}
	return &t, nil
}

// TakeCatalogCategory checks that Catalog is an object and gives the template
// the category of its catalogue entry.
func (t *Template) TakeCatalogCategory() error {
	if t.Catalog == nil || string(bytes.TrimSpace(t.Catalog)) == "null" {
		t.Catalog = nil
		return nil
	}
	var catalog struct {
		Category string `json:"category"`
	}
	if err := json.Unmarshal(t.Catalog, &catalog); err != nil {
		return fmt.Errorf("catalog must be an object with the fields of a catalogue entry: %w", err)
	}
	if catalog.Category != "" {
		t.Category = catalog.Category
	}
	return nil
}

// resolveEmbedded turns every "embedded:<file>" string into a data URI of
// that file. A reference to a missing file stays as it is.
func resolveEmbedded(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			v[k] = resolveEmbedded(item)
		}
	case []any:
		for i, item := range v {
			v[i] = resolveEmbedded(item)
		}
	case string:
		if uri, ok := defaults.DataURI(v); ok {
			return uri
		}
	}
	return value
}

// pidDateClaims are the issuance and expiry dates of the PID in SD-JWT VC
// and mdoc. The expiry follows the German PID rulebook's five year
// administrative expiry (§10a (2) PAuswG). It is a calendar date, independent
// of the credential's validity.
var pidDateClaims = map[string]func(time.Time) time.Time{
	"date_of_issuance": func(now time.Time) time.Time { return now },
	"issuance_date":    func(now time.Time) time.Time { return now },
	"date_of_expiry":   func(now time.Time) time.Time { return now.AddDate(5, 0, 0) },
	"expiry_date":      func(now time.Time) time.Time { return now.AddDate(5, 0, 0) },
}

// fillPIDDates sets the empty date claims of a PID, so a long-running server
// issues current dates.
func fillPIDDates(claims map[string]any, now time.Time) {
	for name, date := range pidDateClaims {
		if value, ok := claims[name]; ok && value == "" {
			claims[name] = date(now.UTC()).Format(time.DateOnly)
		}
	}
}

func deepCopyClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyClaims(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return v
	}
}

// MergeClaims returns the template claims with the given top-level overrides
// applied. The template claims are deep-copied first, so neither input is
// modified.
func MergeClaims(base, overrides map[string]any) map[string]any {
	merged := deepCopyClaims(base)
	for k, v := range overrides {
		merged[k] = v
	}
	return merged
}
