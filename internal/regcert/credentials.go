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

package regcert

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// OverAskingFindings checks a DCQL query against the registration certificate.
// ARF RPRC_21 requires requested claims to be registered. It reports one
// finding for an unregistered credential type, or one per unregistered
// attribute of a registered type.
func OverAskingFindings(cert map[string]any, dcql map[string]any) []string {
	registered := registeredCredentials(cert)
	if len(registered) == 0 {
		// A missing credentials list already has a content finding and provides
		// nothing to compare.
		return nil
	}
	var findings []string
	overAsk := func(what string) {
		findings = append(findings, fmt.Sprintf("ARF RPRC_21: the request asks for %s. The registration certificate does not register it (over-asking)", what))
	}
	for _, cq := range jsonutil.Maps(dcql["credentials"]) {
		format, _ := cq["format"].(string)
		types := registrar.CredentialTypes(cq["meta"])
		if !registersCredential(registered, format, types) {
			overAsk(TypeName(format, types))
			continue
		}
		for _, claim := range jsonutil.Maps(cq["claims"]) {
			path := jsonutil.List(claim["path"])
			if len(path) == 0 {
				continue
			}
			if !registeredCovers(registered, format, types, path) {
				overAsk(describeClaim(format, types, path))
			}
		}
	}
	return findings
}

// registersCredential reports whether every accepted type of the query is
// registered in its format. ETSI TS 119 475 V1.2.1 Annex B.2.9 requires format
// and meta, so an entry without them registers nothing.
func registersCredential(registered []Credential, format string, types []string) bool {
	if len(types) == 0 {
		return false
	}
	for _, t := range types {
		if len(registeredFor(registered, format, t)) == 0 {
			return false
		}
	}
	return true
}

func registeredFor(registered []Credential, format, credentialType string) []Credential {
	var out []Credential
	for _, rc := range registered {
		if rc.format != "" && rc.format == format && slices.Contains(rc.types, credentialType) {
			out = append(out, rc)
		}
	}
	return out
}

// Credential is a credential type that a registration certificate registers.
// An entry without a claim list declares no attributes (ETSI TS 119 475 V1.2.1
// Annex B.2.9), so ARF RPRC_21 counts every requested claim as over-asking.
type Credential struct {
	format string
	types  []string
	paths  [][]any
}

func registeredCredentials(cert map[string]any) []Credential {
	var out []Credential
	for _, entry := range jsonutil.Maps(cert["credentials"]) {
		format, _ := entry["format"].(string)
		rc := Credential{format: format, types: registrar.CredentialTypes(entry["meta"])}
		for _, claim := range jsonutil.Maps(entry["claim"]) {
			if path := jsonutil.List(claim["path"]); len(path) > 0 {
				rc.paths = append(rc.paths, path)
			}
		}
		out = append(out, rc)
	}
	return out
}

// registeredCovers reports whether the claim is registered for every type
// accepted by the query.
func registeredCovers(registered []Credential, format string, types []string, path []any) bool {
	for _, t := range types {
		if !slices.ContainsFunc(registeredFor(registered, format, t), func(rc Credential) bool {
			return slices.ContainsFunc(rc.paths, func(p []any) bool { return pathPrefix(p, path) })
		}) {
			return false
		}
	}
	return len(types) > 0
}

// Registering a parent path such as address also covers children such as
// address.street_address.
func pathPrefix(registered, requested []any) bool {
	if len(registered) > len(requested) {
		return false
	}
	for i := range registered {
		if fmt.Sprint(registered[i]) != fmt.Sprint(requested[i]) {
			return false
		}
	}
	return true
}

func describeClaim(format string, types []string, path []any) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprint(p)
	}
	claim := strings.Join(parts, ".")
	label := TypeName(format, types)
	if label == "" {
		return claim
	}
	return fmt.Sprintf("%s of %s", claim, label)
}

// TypeName names a credential type in a finding.
func TypeName(format string, types []string) string {
	if len(types) > 0 {
		return types[0]
	}
	return format
}
