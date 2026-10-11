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

// Package credtemplate stores reusable claim sets and issuance defaults. Built-in
// templates cover the EU PID, national PIDs and a demo ticket. A user template
// replaces the built-in template with the same name.
package credtemplate

import (
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

	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
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
	// top-level claims at issuance time.
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
	// Display sets the OpenID4VCI §12.2.4 appearance of credentials issued from
	// this template. Image fields of a built-in template use "embedded:<file>".
	// A user template uses a data URI or an https URL.
	Display *TemplateDisplay `json:"display,omitempty"`
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
}

var templateExtensions = []string{".json", ".template"}

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
	case "sdjwt", "sd-jwt", "dc+sd-jwt":
		return "sdjwt", nil
	case "jwt", "jwt_vc_json":
		return "jwt", nil
	case "mdoc", "mso_mdoc":
		return "mdoc", nil
	default:
		return "", fmt.Errorf("unsupported template format %q: expected sdjwt, jwt, or mdoc", format)
	}
}

// PredefinedTemplates copies claims and recalculates dates for each issuance, so a
// long-running server issues PIDs with the current date.
func PredefinedTemplates() []Template {
	pidDisplay := func(name, description string) *TemplateDisplay {
		return &TemplateDisplay{
			Name:            name,
			Description:     description,
			BackgroundColor: "#3d59a1",
			TextColor:       "#ffffff",
			Logo:            "embedded:logo.svg",
			LogoAltText:     "eudi-dev logo",
		}
	}
	// Descriptions link to their rulebooks so holders can check the claim definitions.
	// The wallet renders bare URLs as links.
	eudiPIDDisplay := func() *TemplateDisplay {
		return pidDisplay("EUDI PID", "A demo Person Identification Data (PID) credential for testing PID verification flows. Its attributes follow the EUDI PID Rulebook v1.7 (the country-independent EU dataset), populated with the rulebook's own Jan Wijnand sample identity. Created by eudi-dev, not a real identity. Rulebook: https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md")
	}
	germanDisplay := func() *TemplateDisplay {
		d := pidDisplay("German PID", "A demo German PID credential for testing PID verification flows. It extends the EUDI PID with the national attributes of the German PID Rulebook 1.0.0 (the BMI blueprint), for the sample ERIKA MUSTERMANN identity. Created by eudi-dev, not a real identity. Rulebook: https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/")
		d.BackgroundImage = "embedded:german-id-specimen.jpg"
		d.Logo, d.LogoAltText = "embedded:logo-de.svg", "eudi-dev logo on the German flag"
		return d
	}
	// The card images are official specimens. Their licences require the
	// credit in the description.
	italianDisplay := func() *TemplateDisplay {
		d := pidDisplay("Italian PID", "A demo Italian PID credential for testing PID verification flows. Its attributes follow the PID data model of the IT-Wallet Technical Specifications 1.4.7, for Bianca Rossi, the identity of the Carta d'identità elettronica specimen. Created by eudi-dev, not a real identity. Card image: specimen of the Italian electronic identity card by the Ministero dell'Interno and the Istituto Poligrafico e Zecca dello Stato, resized, CC BY 4.0. Specification: https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/credential-data-model-pid.html")
		d.BackgroundImage = "embedded:italian-id-specimen.jpg"
		d.Logo, d.LogoAltText = "embedded:logo-it.svg", "eudi-dev logo on the Italian flag"
		return d
	}
	dutchDisplay := func() *TemplateDisplay {
		d := pidDisplay("Dutch PID", "A demo Dutch PID credential for testing PID verification flows. It follows the working draft of the Dutch PID in the NL Wallet reference implementation, for Willeke Liselotte De Bruijn, the identity of the Dutch identity card specimen, and carries the mandatory EUDI PID attributes. Created by eudi-dev, not a real identity. Card image: specimen of the Dutch identity card by the Rijksdienst voor Identiteitsgegevens, resized, CC BY-SA 4.0. Draft: https://github.com/MinBZK/nl-wallet/blob/ea1402d2ad96202617bee6771ac1395c73e96322/scripts/devenv/eudi_pid_nl_1.json")
		d.BackgroundImage = "embedded:dutch-id-specimen.jpg"
		d.Logo, d.LogoAltText = "embedded:logo-nl.svg", "eudi-dev logo on the Dutch flag"
		return d
	}
	// The Italian PID carries a subject identifier (IT-Wallet 1.4.7 §11.2), which
	// §11.1.2.1 makes opaque and unique per credential.
	const italianSubject = "eu.europa.ec.eudi.pid.it.1:sub"
	italianSDJWTClaims := mock.RefreshPIDDates(deepCopyClaims(mock.SDJWTItalianPIDClaims))
	italianSDJWTClaims["sub"] = uuid.NewString()
	italianMDOCClaims := mock.RefreshPIDDates(deepCopyClaims(mock.MDOCItalianPIDClaims))
	italianMDOCClaims[italianSubject] = uuid.NewString()
	return []Template{
		{
			Name:        "pid-sdjwt",
			Description: "EUDI PID (SD-JWT, EU rulebook sample data)",
			Format:      "sdjwt",
			VCT:         mock.DefaultPIDVCT,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.SDJWTPIDClaims)),
			Display:     eudiPIDDisplay(),
			Category:    CategoryPID,
			Predefined:  true,
		},
		{
			Name:        "pid-mdoc",
			Description: "EUDI PID (mdoc, EU rulebook sample data)",
			Format:      "mdoc",
			DocType:     mock.PIDNamespace,
			Namespace:   mock.PIDNamespace,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.MDOCPIDClaims)),
			Display:     eudiPIDDisplay(),
			Category:    CategoryPID,
			Predefined:  true,
		},
		{
			Name:        "german-pid-sdjwt",
			Description: "German PID (SD-JWT, extends the EUDI PID)",
			Format:      "sdjwt",
			VCT:         "urn:eudi:pid:de:1",
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.SDJWTGermanPIDClaims)),
			Display:     germanDisplay(),
			Category:    CategoryPID,
			Predefined:  true,
		},
		{
			Name:        "german-pid-mdoc",
			Description: "German PID (mdoc, EUDI PID doctype plus the German namespace)",
			Format:      "mdoc",
			DocType:     mock.PIDNamespace,
			Namespace:   mock.PIDNamespace,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.MDOCGermanPIDClaims)),
			Display:     germanDisplay(),
			Category:    CategoryPID,
			Predefined:  true,
		},
		{
			Name:            "italian-pid-sdjwt",
			Description:     "Italian PID (SD-JWT, IT-Wallet 1.4.7)",
			Format:          "sdjwt",
			VCT:             "urn:eudi:pid:it:1",
			Exp:             "720h",
			Claims:          italianSDJWTClaims,
			AlwaysDisclosed: append([]string(nil), mock.ItalianPIDAlwaysDisclosed...),
			UniqueClaims:    []string{"sub"},
			Display:         italianDisplay(),
			Category:        CategoryPID,
			Predefined:      true,
		},
		{
			Name:         "italian-pid-mdoc",
			Description:  "Italian PID (mdoc, EUDI PID doctype plus the Italian namespace)",
			Format:       "mdoc",
			DocType:      mock.PIDNamespace,
			Namespace:    mock.PIDNamespace,
			Exp:          "720h",
			Claims:       italianMDOCClaims,
			UniqueClaims: []string{italianSubject},
			Display:      italianDisplay(),
			Category:     CategoryPID,
			Predefined:   true,
		},
		{
			Name:        "dutch-pid-sdjwt",
			Description: "Dutch PID (SD-JWT, NL Wallet working draft)",
			Format:      "sdjwt",
			VCT:         "urn:eudi:pid:nl:1",
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.SDJWTDutchPIDClaims)),
			Display:     dutchDisplay(),
			Category:    CategoryPID,
			Predefined:  true,
		},
		{
			Name:        "dutch-pid-mdoc",
			Description: "Dutch PID (mdoc, EUDI PID doctype plus the Dutch namespace)",
			Format:      "mdoc",
			DocType:     mock.PIDNamespace,
			Namespace:   mock.PIDNamespace,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.MDOCDutchPIDClaims)),
			Display:     dutchDisplay(),
			Category:    CategoryPID,
			Predefined:  true,
		},
		{
			Name:        "demo-ticket",
			Description: "Demo Event Ticket (SD-JWT, issued by the demo issuer)",
			Format:      "sdjwt",
			VCT:         credtype.DemoTicketVCT,
			Exp:         "720h",
			Claims: map[string]any{
				"event": "EUDI Interop Fest", "tier": "backstage", "seat": "42A",
				"given_name": "Erika", "family_name": "Mustermann",
			},
			Display: &TemplateDisplay{
				Name:            "Demo Event Ticket",
				Description:     "A sample event ticket issued by the demo issuer",
				BackgroundColor: "#0f766e",
				TextColor:       "#ffffff",
				Logo:            "embedded:logo.svg",
				LogoAltText:     "eudi-dev logo",
			},
			Category:   CategoryEAA,
			Predefined: true,
		},
	}
}

// PIDTemplateNames returns the SD-JWT and mdoc templates in loc for the PID
// type vct. The SD-JWT template has that type, and the mdoc template issues the
// PID doctype under the same display name. ok reports whether such templates
// exist. For any other type callers use the country-independent claim set.
func PIDTemplateNames(vct string, loc Location) (sdjwt, mdoc string, ok bool) {
	if vct == "" {
		vct = credtype.PIDVCT
	}
	templates, err := List(loc)
	if err != nil {
		return "pid-sdjwt", "pid-mdoc", false
	}
	// A pre-defined template wins over a user template of the same type.
	templates = append(slices.DeleteFunc(slices.Clone(templates), func(t Template) bool { return !t.Predefined }),
		slices.DeleteFunc(templates, func(t Template) bool { return t.Predefined })...)
	var display string
	for _, t := range templates {
		if format, _ := NormalizeFormat(t.Format); format == "sdjwt" && t.VCT == vct {
			sdjwt, display = t.Name, displayName(t)
			break
		}
	}
	if sdjwt == "" {
		return "pid-sdjwt", "pid-mdoc", false
	}
	for _, t := range templates {
		if format, _ := NormalizeFormat(t.Format); format == "mdoc" && t.DocType == credtype.PIDDocType && displayName(t) == display {
			return sdjwt, t.Name, true
		}
	}
	return sdjwt, "pid-mdoc", true
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

// List returns all templates: pre-defined templates plus user templates from
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
	for _, name := range stored {
		if !hasTemplateExtension(name) {
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
// pre-defined templates. Anything containing a path separator or a template
// extension is loaded as a file path.
func Load(nameOrPath string, loc Location) (*Template, error) {
	if strings.TrimSpace(nameOrPath) == "" {
		return nil, fmt.Errorf("template name is required")
	}
	loc = loc.orDefault()

	if strings.ContainsRune(nameOrPath, os.PathSeparator) || strings.ContainsRune(nameOrPath, '/') || hasTemplateExtension(nameOrPath) {
		return loadFile(nameOrPath)
	}

	for _, ext := range templateExtensions {
		tpl, err := loadStored(loc, nameOrPath+ext)
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			return tpl, err
		}
	}

	for _, t := range PredefinedTemplates() {
		if t.Name == nameOrPath {
			tpl := t
			return &tpl, nil
		}
	}

	return nil, fmt.Errorf("template %q not found (looked in %s and the pre-defined templates, see `templates list`)", nameOrPath, loc)
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
	return loc.Store.Locate(key), nil
}

// ErrNotFound reports a template name with no saved or predefined template.
var ErrNotFound = errors.New("not found")

// Delete removes a user template from loc (the default directory for the
// zero Location). Pre-defined templates cannot be deleted.
func Delete(loc Location, name string) error {
	loc = loc.orDefault()
	if name != filepath.Base(name) {
		return fmt.Errorf("invalid template name %q", name)
	}
	for _, ext := range templateExtensions {
		key := loc.key(name + ext)
		_, err := loc.Store.Stat(key)
		if err == nil {
			return loc.Store.Delete(key)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("reading template %q: %w", name, err)
		}
	}
	for _, t := range PredefinedTemplates() {
		if t.Name == name {
			return fmt.Errorf("template %q is pre-defined and cannot be deleted", name)
		}
	}
	return fmt.Errorf("template %q %w in %s", name, ErrNotFound, loc)
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

func parse(data []byte, file string) (*Template, error) {
	var t Template
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", file, err)
	}
	if _, err := NormalizeFormat(t.Format); err != nil {
		return nil, fmt.Errorf("template %s: %w", file, err)
	}
	if strings.TrimSpace(t.Name) == "" {
		base := path.Base(filepath.ToSlash(file))
		t.Name = strings.TrimSuffix(base, path.Ext(base))
	}
	t.Predefined = false
	return &t, nil
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
