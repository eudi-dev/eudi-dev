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

package credtemplate

import (
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
)

// DefaultClaims are the claims of a credential issued without a template
// and without claims: the name and birth date of the EUDI PID Rulebook's
// sample identity.
var DefaultClaims = map[string]any{
	"given_name":  "Jan Wijnand",
	"family_name": "'t Hart",
	"birthdate":   "1978-02-12",
}

// Issuance defaults for a value that neither the request nor the template
// sets.
const (
	DefaultExp     = 720 * time.Hour
	DefaultDocType = credtype.PIDDocType
)

// Request is what an issuer asks for on top of a template. A zero field takes
// the template's value, then the default.
type Request struct {
	// Format is "sdjwt", "jwt", "mdoc" or one of their aliases.
	Format string
	// Claims override the template's top-level claims. Without a template, nil
	// claims are DefaultClaims.
	Claims map[string]any
	// Omit removes top-level claims from the result.
	Omit []string
	// AlwaysDisclosed adds to the template's list.
	AlwaysDisclosed []string
	VCT             string
	DocType         string
	Namespace       string
	Exp             time.Duration
	// ClaimSet uses the template only for its claims, so its format is not
	// checked. A PID template serves a jwt request this way.
	ClaimSet bool
}

// Resolved is a template applied to a request.
type Resolved struct {
	// Format is "sdjwt", "jwt" or "mdoc".
	Format string
	Claims map[string]any
	// AlwaysDisclosed is empty for a jwt credential, whose claims are all
	// plain.
	AlwaysDisclosed []string
	VCT             string
	DocType         string
	// Namespace defaults to DocType.
	Namespace string
	Exp       time.Duration
	template  *Template
}

// Resolve applies req to tpl. tpl may be nil.
func Resolve(tpl *Template, req Request) (Resolved, error) {
	format, err := NormalizeFormat(firstNonEmpty(req.Format, templateField(tpl, func(t *Template) string { return t.Format })))
	if err != nil {
		return Resolved{}, err
	}
	if format == "" {
		return Resolved{}, fmt.Errorf("no credential format given: expected sdjwt, jwt, or mdoc")
	}
	if tpl != nil && !req.ClaimSet {
		tplFormat, err := NormalizeFormat(tpl.Format)
		if err != nil {
			return Resolved{}, err
		}
		if tplFormat != "" && tplFormat != format {
			return Resolved{}, fmt.Errorf("template %q is for format %s, not %s", tpl.Name, tplFormat, format)
		}
	}

	r := Resolved{Format: format, Exp: req.Exp, template: tpl}
	switch {
	case tpl != nil:
		r.Claims = MergeClaims(tpl.Claims, req.Claims)
	case req.Claims != nil:
		r.Claims = req.Claims
	default:
		r.Claims = DefaultClaims
	}
	r.Claims = OmitClaims(r.Claims, req.Omit)

	var alwaysDisclosed []string
	if tpl != nil {
		alwaysDisclosed = tpl.AlwaysDisclosed
	}
	r.AlwaysDisclosed = mergePaths(alwaysDisclosed, req.AlwaysDisclosed)
	switch format {
	case "mdoc":
		if len(r.AlwaysDisclosed) > 0 {
			return Resolved{}, fmt.Errorf("always-disclosed claims are not supported for mdoc: every mdoc element is selectively disclosable")
		}
	case "jwt":
		r.AlwaysDisclosed = nil
	}

	if r.Exp == 0 && tpl != nil && tpl.Exp != "" {
		if r.Exp, err = time.ParseDuration(tpl.Exp); err != nil {
			return Resolved{}, fmt.Errorf("template %q: invalid exp duration: %w", tpl.Name, err)
		}
	}
	if r.Exp == 0 {
		r.Exp = DefaultExp
	}
	r.VCT = firstNonEmpty(req.VCT, templateField(tpl, func(t *Template) string { return t.VCT }), credtype.PIDVCT)
	r.DocType = firstNonEmpty(req.DocType, templateField(tpl, func(t *Template) string { return t.DocType }), DefaultDocType)
	r.Namespace = firstNonEmpty(req.Namespace, templateField(tpl, func(t *Template) string { return t.Namespace }), r.DocType)
	return r, nil
}

// CredentialClaims returns the claims of one credential. Each unique claim of
// the template gets a new random value.
func (r Resolved) CredentialClaims() map[string]any {
	return r.template.WithUniqueClaims(r.Claims)
}

// Template returns the resolved parameters as a template, to save them.
func (r Resolved) Template(name string) Template {
	saved := Template{
		Name:            name,
		Format:          r.Format,
		Exp:             formatExp(r.Exp),
		Claims:          r.Claims,
		AlwaysDisclosed: r.AlwaysDisclosed,
	}
	if r.Format == "mdoc" {
		saved.DocType, saved.Namespace = r.DocType, r.Namespace
	} else {
		saved.VCT = r.VCT
	}
	if r.template != nil {
		saved.UniqueClaims = r.template.UniqueClaims
	}
	return saved
}

// OmitClaims returns claims without the named top-level claims. claims is not
// modified.
func OmitClaims(claims map[string]any, omit []string) map[string]any {
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

func mergePaths(base, extra []string) []string {
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

func formatExp(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	}
	return d.String()
}

func templateField(tpl *Template, field func(*Template) string) string {
	if tpl == nil {
		return ""
	}
	return strings.TrimSpace(field(tpl))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
