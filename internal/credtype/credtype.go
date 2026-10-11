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

// Package credtype lists the known EUDI credential types and models the
// inheritance between them.
//
// ARF v3.0.0 Annex 2, PID_14 says the vct "SHALL be urn:eudi:pid:1 for the
// type defined in this document or a domestic type that extends it". A
// national PID therefore answers a request for the general PID type.
//
// Type Metadata with extends (draft-ietf-oauth-sd-jwt-vc-19 §5.4) needs a
// retrievable document, and a URN vct has none. Extends applies PID_14
// directly. The aka_vcts claim (§2.2.2.2) states further types in the
// credential itself, and Chain reads it.
//
// Inheritance grants no issuing authority (§7.7: "Verifiers and Holders MUST
// NOT assume that any issuer who issues a credential extending a known type is
// authorized to do so").
package credtype

import "strings"

// Types of the EUDI PID. ARF PID_04 fixes the mdoc doctype at
// eu.europa.ec.eudi.pid.1 for every PID, and PID_05 uses it as the namespace of
// the PID attributes. PID_14 makes urn:eudi:pid:1 the SD-JWT VC type, and a
// domestic PID type extends it within the urn:eudi:pid: namespace.
const (
	PIDVCT       = "urn:eudi:pid:1"
	PIDDocType   = "eu.europa.ec.eudi.pid.1"
	PIDNamespace = PIDDocType
	// DemoTicketVCT is the type of the demo issuer's event ticket.
	DemoTicketVCT = "urn:eudi-test:demo-ticket:1"
)

// AkaVCTsClaim is the SD-JWT VC claim that lists further types of a credential
// (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2).
const AkaVCTsClaim = "aka_vcts"

const PIDVCTPrefix = "urn:eudi:pid:"

// Extends applies ARF v3.0.0 Annex 2 PID_14 to domestic PID types. A numeric segment
// after urn:eudi:pid: identifies a base PID version. Other segments identify a country
// or region. Types outside this namespace declare inheritance through aka_vcts.
func Extends(vct string) (string, bool) {
	rest, ok := strings.CutPrefix(vct, PIDVCTPrefix)
	if !ok || rest == "" {
		return "", false
	}
	country, _, _ := strings.Cut(rest, ":")
	if country == "" || isNumber(country) {
		return "", false
	}
	return PIDVCT, true
}

func isNumber(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// Chain returns every type of a credential with type vct. The list starts with
// vct, then the types in aka_vcts, then the base types from Extends. It has no
// duplicates. An empty vct yields an empty chain.
func Chain(vct string, akaVCTs []string) []string {
	if vct == "" {
		return nil
	}
	chain := []string{vct}
	seen := map[string]bool{vct: true}
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		chain = append(chain, t)
	}
	for _, aka := range akaVCTs {
		add(aka)
	}
	// A credential also matches indirect base types. The seen set stops cycles.
	for i := 0; i < len(chain); i++ {
		if parent, ok := Extends(chain[i]); ok {
			add(parent)
		}
	}
	return chain
}

func Answers(vct string, akaVCTs []string, requested string) bool {
	if requested == "" || vct == "" {
		return false
	}
	for _, t := range Chain(vct, akaVCTs) {
		if t == requested {
			return true
		}
	}
	return false
}

// AkaVCTs reads the aka_vcts claim of a decoded credential. Anything that is
// not a list of strings is ignored.
func AkaVCTs(claims map[string]any) []string {
	raw, ok := claims[AkaVCTsClaim].([]any)
	if !ok {
		return nil
	}
	types := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			types = append(types, s)
		}
	}
	return types
}

// IsPIDType reports whether a vct or doctype names a PID (ARF PID_04 and
// PID_14).
func IsPIDType(t string) bool {
	t = strings.TrimSpace(t)
	return strings.HasPrefix(t, PIDVCTPrefix) || strings.HasPrefix(t, "eu.europa.ec.eudi.pid.")
}
