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
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// TemplateFromCredential returns a template that issues credentials like
// cred: its format, type, claims, lifetime and card appearance. An SD-JWT
// claim in the issuer-signed payload goes into always_disclosed. The template
// has no name. image turns a stored card image into a data URI, or returns ""
// to leave it out.
func TemplateFromCredential(cred StoredCredential, image func(uri string) string) (credtemplate.Template, error) {
	format, err := credtemplate.NormalizeFormat(cred.Format)
	if err != nil {
		return credtemplate.Template{}, err
	}
	tpl := credtemplate.Template{Format: format, Exp: credentialLifetime(cred), Display: templateDisplay(cred.Display, image)}
	switch cred.Format {
	case credtype.FormatSDJWT:
		token, err := sdjwt.Parse(cred.Raw)
		if err != nil {
			return credtemplate.Template{}, fmt.Errorf("parsing the SD-JWT: %w", err)
		}
		tpl.VCT = cred.VCT
		tpl.Claims = subjectClaims(token.ResolvedClaims)
		digests := make(map[string]sdjwt.Disclosure, len(token.Disclosures))
		for _, d := range token.Disclosures {
			digests[d.Digest] = d
		}
		tpl.AlwaysDisclosed = plainClaimPaths(token.Payload, "", digests)
		slices.Sort(tpl.AlwaysDisclosed)
	case credtype.FormatMDOC:
		tpl.DocType = cred.DocType
		// Claims of the doc type's own namespace need no prefix. The others
		// keep it (namespace:element).
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return credtemplate.Template{}, fmt.Errorf("parsing the mdoc: %w", err)
		}
		tpl.Claims = map[string]any{}
		for namespace, items := range doc.NameSpaces {
			for _, item := range items {
				tpl.Claims[strings.TrimPrefix(namespace+":"+item.ElementIdentifier, cred.DocType+":")] = templateValue(item.ElementValue)
			}
		}
	default:
		tpl.VCT = cred.VCT
		tpl.Claims = subjectClaims(cred.Claims)
	}
	return tpl, nil
}

// templateValue writes a CBOR byte string, such as a portrait, as a base64
// data URI. Templates write byte strings that way.
func templateValue(value any) any {
	switch v := value.(type) {
	case []byte:
		return "data:" + http.DetectContentType(v) + ";base64," + base64.StdEncoding.EncodeToString(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = templateValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = templateValue(item)
		}
		return out
	}
	return value
}

func subjectClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims))
	for key, value := range claims {
		if !sdjwt.IsProtocolClaim(key) {
			out[key] = value
		}
	}
	return out
}

// plainClaimPaths lists the claims of obj that need no disclosure, as dotted
// paths. It descends into objects that a disclosure reveals, because their
// plain members are always disclosed once the object is.
func plainClaimPaths(obj map[string]any, prefix string, digests map[string]sdjwt.Disclosure) []string {
	var paths []string
	for key, value := range obj {
		if key == "_sd" {
			list, _ := value.([]any)
			for _, digest := range list {
				d, ok := digests[fmt.Sprint(digest)]
				if !ok {
					continue
				}
				if nested, isObject := d.Value.(map[string]any); isObject {
					paths = append(paths, plainClaimPaths(nested, prefix+d.Name+".", digests)...)
				}
			}
			continue
		}
		if prefix == "" && sdjwt.IsProtocolClaim(key) {
			continue
		}
		paths = append(paths, prefix+key)
	}
	return paths
}

// credentialLifetime is the time from issuance to expiry in whole hours, the
// way templates write exp.
func credentialLifetime(cred StoredCredential) string {
	_, expiry := CredentialValidity(cred)
	issued := CredentialIssuedAt(cred)
	if expiry.IsZero() || issued.IsZero() || !expiry.After(issued) {
		return ""
	}
	return fmt.Sprintf("%dh", int(expiry.Sub(issued).Round(time.Hour).Hours()))
}

func templateDisplay(d *oid4vc.CredentialDisplay, image func(uri string) string) *credtemplate.TemplateDisplay {
	if d == nil {
		return nil
	}
	display := &credtemplate.TemplateDisplay{
		Name:            d.Name,
		Description:     d.Description,
		BackgroundColor: d.BackgroundColor,
		TextColor:       d.TextColor,
		Logo:            image(d.LogoURI),
		BackgroundImage: image(d.BackgroundURI),
	}
	if display.Logo != "" {
		display.LogoAltText = d.LogoAltText
	}
	return display
}
