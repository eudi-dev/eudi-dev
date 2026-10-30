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

package findings

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Group separates findings about a party's registration and trust from
// findings about the protocol messages.
type Group string

const (
	// GroupProtocol covers the messages and credentials themselves.
	GroupProtocol Group = "protocol"
	// GroupRegistration covers registration with the registrar, access and
	// registration certificates, entitlements and trusted lists.
	GroupRegistration Group = "registration"
)

// Finding is one failed check. Spec is its specification, such as "ARF" or
// "OID4VP 1.0". Rule is the short identifier shown in views, such as
// "ARF RPRC_22a". Citation is the full reference when it says more than Rule.
// URL opens the rule in the published specification.
type Finding struct {
	Spec     string `json:"spec,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Citation string `json:"citation,omitempty"`
	URL      string `json:"url,omitempty"`
	Text     string `json:"text"`
	Group    Group  `json:"group"`
}

// String is the finding as one sentence, starting with its citation. The
// findings text array of the API uses this form.
func (f Finding) String() string {
	citation := f.Citation
	if citation == "" {
		citation = f.Rule
	}
	if citation == "" {
		return f.Text
	}
	return citation + ": " + f.Text
}

// Spec is a cited specification. Views show its label. Its name adds the
// version, which the label leaves out. link turns a rule's reference into the
// URL of the published text, or is nil when there is none.
type Spec struct {
	label, name string
	link        func(ref string) string
}

// newSpec is a specification whose label is its full name.
func newSpec(name string) Spec { return Spec{label: name, name: name} }

// versioned is the specification in one version. Views show the label, and
// the full citation names the version.
func (s Spec) versioned(version string) Spec {
	s.name = s.label + " " + version
	return s
}

// sections links each reference to a section or appendix of the document at
// url. A reference such as "§5.9.3" or "Appendix A.2" gets its anchor. Other
// references open the document.
func (s Spec) sections(url string) Spec {
	s.link = func(ref string) string { return url + sectionAnchor(ref) }
	return s
}

// requirements links each reference, a requirement identifier such as
// RPRC_22a, to its anchor in the document at url.
func (s Spec) requirements(url string) Spec {
	s.link = func(ref string) string {
		if ref == "" {
			return url
		}
		return url + "#" + ref
	}
	return s
}

var sectionRef = regexp.MustCompile(`^(?:§([0-9]+(?:\.[0-9]+)*)|Appendix ([A-Z](?:\.[0-9]+)*))`)

// sectionAnchor is the anchor of a section or appendix in xml2rfc documents,
// such as the OpenID and IETF specifications.
func sectionAnchor(ref string) string {
	m := sectionRef.FindStringSubmatch(ref)
	switch {
	case m == nil:
		return ""
	case m[1] != "":
		return "#section-" + m[1]
	default:
		return "#appendix-" + m[2]
	}
}

// RFC is the IETF RFC with that number.
func RFC(number int) Spec {
	return newSpec(fmt.Sprintf("RFC %d", number)).sections(fmt.Sprintf("https://www.rfc-editor.org/rfc/rfc%d.html", number))
}

// Draft is the IETF Internet-Draft name, such as
// draft-ietf-oauth-attestation-based-client-auth-10, with a shorter label.
func Draft(label, name string) Spec {
	return Spec{label: label, name: name}.sections("https://datatracker.ietf.org/doc/html/" + name)
}

// Cited specifications. ETSI, ISO and the CIRs publish no anchors, so their
// findings have no URL.
var (
	ARF            = newSpec("ARF").requirements("https://eudi.dev/latest/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/")
	OID4VP         = newSpec("OID4VP 1.0").sections("https://openid.net/specs/openid-4-verifiable-presentations-1_0.html")
	OID4VCI        = newSpec("OID4VCI 1.0").sections("https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html")
	OID4VCI11      = newSpec("OID4VCI 1.1").sections("https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_1-wg-draft.html")
	HAIP           = newSpec("HAIP 1.0").sections("https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html")
	SDJWTVC        = Draft("SD-JWT VC", "draft-ietf-oauth-sd-jwt-vc-19")
	FirstPartyApps = Draft("First-Party Apps", "draft-ietf-oauth-first-party-apps-04")
	ISO180135      = newSpec("ISO 18013-5")
	ETSI119475     = newSpec("ETSI TS 119 475").versioned("V1.2.1")
	ETSI1194723    = newSpec("ETSI TS 119 472-3").versioned("V1.1.1")
	CIR20242982    = newSpec("CIR (EU) 2024/2982")
)

// Protocol is a rule of the specification about the protocol messages or
// credentials. ref is the section or requirement, such as "§5.2".
func (s Spec) Protocol(ref string) Rule { return s.rule(ref, GroupProtocol) }

// Registration is a rule of the specification about registration and trust.
func (s Spec) Registration(ref string) Rule { return s.rule(ref, GroupRegistration) }

func (s Spec) rule(ref string, group Group) Rule {
	r := Rule{spec: s.label, id: s.label, group: group}
	if s.link != nil {
		r.url = s.link(ref)
	}
	if ref != "" {
		r.id += " " + ref
	}
	if s.name != s.label {
		r.citation = s.name
		if ref != "" {
			r.citation += " " + ref
		}
	}
	return r
}

// Rule is the cited reference of a finding, with its group.
type Rule struct {
	spec, id, citation, url string
	group                   Group
}

// Cited sets the full citation. The finding text starts with it.
func (r Rule) Cited(citation string) Rule {
	r.citation = citation
	return r
}

// Citation is the full citation, or the identifier when it has none.
func (r Rule) Citation() string {
	if r.citation != "" {
		return r.citation
	}
	return r.id
}

// New is a finding of the rule.
func (r Rule) New(text string) Finding {
	return Finding{Spec: r.spec, Rule: r.id, Citation: r.citation, URL: r.url, Text: text, Group: r.group}
}

// Newf is New with a formatted text.
func (r Rule) Newf(format string, args ...any) Finding {
	return r.New(fmt.Sprintf(format, args...))
}

// Uncited is a protocol finding without a citation.
func Uncited(text string) Finding { return Finding{Text: text, Group: GroupProtocol} }

// UncitedRegistration is a registration finding without a citation.
func UncitedRegistration(text string) Finding { return Finding{Text: text, Group: GroupRegistration} }

// UncitedAll makes an uncited protocol finding of each text.
func UncitedAll(texts []string) List {
	if texts == nil {
		return nil
	}
	list := make(List, len(texts))
	for i, text := range texts {
		list[i] = Uncited(text)
	}
	return list
}

// FromError is the finding of an error, or an uncited finding with the error
// text.
func FromError(err error) Finding {
	var cited interface{ Finding() Finding }
	if errors.As(err, &cited) {
		return cited.Finding()
	}
	return Uncited(err.Error())
}

// List marshals as the array of finding texts. Every client of the findings
// field reads this form. Details gives the structured form.
type List []Finding

// Texts returns each finding as one sentence.
func (l List) Texts() []string {
	if l == nil {
		return nil
	}
	texts := make([]string, len(l))
	for i, finding := range l {
		texts[i] = finding.String()
	}
	return texts
}

// Details is the list as a plain slice, which marshals as objects for the
// finding_details field next to findings.
func (l List) Details() []Finding {
	return []Finding(l)
}

func (l List) MarshalJSON() ([]byte, error) {
	if l == nil {
		return []byte("null"), nil
	}
	return json.Marshal(l.Texts())
}

// UnmarshalJSON reads the text array. The texts carry no rule or group.
func (l *List) UnmarshalJSON(data []byte) error {
	var texts []string
	if err := json.Unmarshal(data, &texts); err != nil {
		return err
	}
	*l = UncitedAll(texts)
	return nil
}
