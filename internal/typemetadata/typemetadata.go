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

// Package typemetadata retrieves and processes SD-JWT VC Type Metadata
// (draft-ietf-oauth-sd-jwt-vc-19 §5). A type is retrievable when its vct is
// an HTTPS URL (§5.3.1). The package has no registry, so a chain that extends
// a URN type cannot be processed.
package typemetadata

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// Document is a Type Metadata document (§5.2).
type Document struct {
	VCT              string    `json:"vct"`
	Name             string    `json:"name,omitempty"`
	Description      string    `json:"description,omitempty"`
	Extends          string    `json:"extends,omitempty"`
	ExtendsIntegrity string    `json:"extends#integrity,omitempty"`
	Display          []Display `json:"display,omitempty"`
	Claims           []Claim   `json:"claims,omitempty"`
}

// Display is the display metadata of a type for one locale (§5.5).
type Display struct {
	Locale      string `json:"locale"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Claim is the metadata of the claims selected by Path (§5.6).
type Claim struct {
	Path      []any          `json:"path"`
	Display   []ClaimDisplay `json:"display,omitempty"`
	Mandatory *bool          `json:"mandatory,omitempty"`
	SD        string         `json:"sd,omitempty"`
	SVGID     string         `json:"svg_id,omitempty"`
}

// ClaimDisplay is the display metadata of a claim for one locale (§5.6.2).
type ClaimDisplay struct {
	Locale      string `json:"locale"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// Metadata is the Type Metadata of a type after applying its extensions
// (§5.4).
type Metadata struct {
	// Types lists the type and every type it extends, nearest first.
	Types   []string  `json:"types"`
	Display []Display `json:"display,omitempty"`
	Claims  []Claim   `json:"claims,omitempty"`
	// Expires is when the documents must be retrieved again (RFC 9111). It is
	// zero when integrity metadata covers every document (§5.3.4).
	Expires time.Time `json:"expires,omitzero"`
}

// Stale reports whether the metadata is past its freshness lifetime.
func (m *Metadata) Stale(now time.Time) bool {
	return !m.Expires.IsZero() && !now.Before(m.Expires)
}

// Retrieval is one document request, for the activity log.
type Retrieval struct {
	URL    string
	Status int
	Body   string
	Err    error
}

// RetrievalError means the Type Metadata is not available. The wallet does
// not require Type Metadata, so the credential stays usable without it.
type RetrievalError struct{ msg string }

func (e *RetrievalError) Error() string { return e.msg }

// ProcessingError means the Type Metadata was retrieved but its processing
// failed. §5.7 and §7.4 require rejecting the credential.
type ProcessingError struct{ msg string }

func (e *ProcessingError) Error() string { return e.msg }

func retrievalErrorf(format string, args ...any) error {
	return &RetrievalError{msg: fmt.Sprintf(format, args...)}
}

func processingErrorf(format string, args ...any) error {
	return &ProcessingError{msg: fmt.Sprintf(format, args...)}
}

// IsRetrievable reports whether Type Metadata can be retrieved for vct
// (§5.3.1).
func IsRetrievable(vct string) bool {
	u, err := url.Parse(vct)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

const (
	// maxChain bounds the extends chain. §7.4 forbids cycles, and the bound
	// also stops a long chain.
	maxChain = 10
	// maxRedirects is the redirect limit §3 requires.
	maxRedirects = 5
)

// Resolver retrieves Type Metadata.
type Resolver struct {
	Client *http.Client
	// OnRetrieval, if set, receives every document request.
	OnRetrieval func(Retrieval)
	// Now defaults to time.Now.
	Now func() time.Time
}

// Resolve retrieves the Type Metadata of vct and of every type it extends,
// and applies the extensions. integrity is the vct#integrity claim.
func (r Resolver) Resolve(vct, integrity string) (*Metadata, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	var docs []Document
	var expires time.Time
	seen := map[string]bool{}
	ref, refIntegrity := vct, integrity
	for {
		if seen[ref] {
			return nil, processingErrorf("SD-JWT VC §7.4: the type %s extends itself through %s", vct, ref)
		}
		if len(docs) == maxChain {
			return nil, processingErrorf("SD-JWT VC §7.4: the type %s extends more than %d types", vct, maxChain)
		}
		seen[ref] = true
		doc, lifetime, err := r.fetch(ref, refIntegrity, now())
		if err != nil {
			return nil, err
		}
		if refIntegrity == "" && (expires.IsZero() || lifetime.Before(expires)) {
			expires = lifetime
		}
		docs = append(docs, doc)
		if doc.Extends == "" {
			break
		}
		ref, refIntegrity = doc.Extends, doc.ExtendsIntegrity
	}
	return merge(docs, expires)
}

// fetch retrieves one document (§3, §5.3.1) and returns it with the end of
// its freshness lifetime.
func (r Resolver) fetch(ref, integrity string, now time.Time) (Document, time.Time, error) {
	if !IsRetrievable(ref) {
		return Document{}, time.Time{}, retrievalErrorf("SD-JWT VC §5.3: the wallet retrieves Type Metadata only from an HTTPS URL, not from %s", ref)
	}
	client := *r.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("more than %d redirects", maxRedirects)
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("a redirect to %s does not use HTTPS", req.URL.Redacted())
		}
		return nil
	}
	retrieval := Retrieval{URL: ref}
	report := func(err error) error {
		retrieval.Err = err
		if r.OnRetrieval != nil {
			r.OnRetrieval(retrieval)
		}
		return err
	}

	req, err := http.NewRequest(http.MethodGet, ref, nil)
	if err != nil {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §5.3.1: requesting %s: %v", ref, err))
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §5.3.1: retrieving %s: %v", ref, err))
	}
	defer resp.Body.Close()
	retrieval.Status = resp.StatusCode
	body, err := format.ReadRemoteBody(resp.Body, "Type Metadata")
	retrieval.Body = string(body)
	if err != nil {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §3: reading %s: %v", ref, err))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §3: %s answered with HTTP %d", ref, resp.StatusCode))
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §5.3.1: %s has the media type %q, not application/json", ref, resp.Header.Get("Content-Type")))
	}
	if integrity != "" {
		if err := VerifyIntegrity(body, integrity); err != nil {
			return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §6: the Type Metadata at %s: %v", ref, err))
		}
	}
	doc, err := parseDocument(body)
	if processing := (*ProcessingError)(nil); errors.As(err, &processing) {
		return Document{}, time.Time{}, report(err)
	}
	if err != nil {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §5.2: the Type Metadata at %s: %v", ref, err))
	}
	// §5.3: the vct of the document must be identical to the reference.
	if doc.VCT != ref {
		return Document{}, time.Time{}, report(retrievalErrorf("SD-JWT VC §5.3: the Type Metadata at %s describes the type %q", ref, doc.VCT))
	}
	return doc, freshUntil(resp.Header, now), report(nil)
}

// freshUntil is the end of the freshness lifetime of a response (RFC 9111
// §4.2.1). A response without max-age or Expires is stale at once.
func freshUntil(header http.Header, now time.Time) time.Time {
	for _, directive := range strings.Split(header.Get("Cache-Control"), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(name) {
		case "no-store", "no-cache":
			return now
		case "max-age":
			if seconds, err := time.ParseDuration(strings.Trim(value, `"`) + "s"); err == nil && seconds > 0 {
				return now.Add(seconds)
			}
			return now
		}
	}
	if expires, err := http.ParseTime(header.Get("Expires")); err == nil && expires.After(now) {
		return expires
	}
	return now
}

// merge applies the extensions of docs, nearest type first (§5.4).
func merge(docs []Document, expires time.Time) (*Metadata, error) {
	m := &Metadata{Expires: expires}
	for _, doc := range docs {
		m.Types = append(m.Types, doc.VCT)
	}
	for i := len(docs) - 1; i >= 0; i-- {
		doc := docs[i]
		// §5.5.2: a type with its own display ignores the extended display.
		if doc.Display != nil {
			m.Display = doc.Display
		}
		for _, claim := range doc.Claims {
			j := pathIndex(m.Claims, claim.Path)
			if j < 0 {
				m.Claims = append(m.Claims, claim)
				continue
			}
			combined, err := combine(m.Claims[j], claim)
			if err != nil {
				return nil, processingErrorf("SD-JWT VC §5.6.5.1: %s %v", doc.VCT, err)
			}
			m.Claims[j] = combined
		}
	}
	return m, nil
}

func pathIndex(claims []Claim, path []any) int {
	for i, claim := range claims {
		if reflect.DeepEqual(claim.Path, path) {
			return i
		}
	}
	return -1
}

// combine applies the claim metadata of an extending type to the extended
// one (§5.6.5). The properties of child take precedence, and their contents
// are never merged.
func combine(base, child Claim) (Claim, error) {
	out := base
	if child.Display != nil {
		out.Display = child.Display
	}
	if child.Mandatory != nil {
		if base.Mandatory != nil && *base.Mandatory && !*child.Mandatory {
			return Claim{}, fmt.Errorf("makes the mandatory claim %s optional", PathString(child.Path))
		}
		out.Mandatory = child.Mandatory
	}
	if child.SD != "" {
		if (base.SD == SDAlways || base.SD == SDNever) && child.SD != base.SD {
			return Claim{}, fmt.Errorf("changes sd of the claim %s from %s to %s", PathString(child.Path), base.SD, child.SD)
		}
		out.SD = child.SD
	}
	if child.SVGID != "" {
		out.SVGID = child.SVGID
	}
	return out, nil
}

// The sd values of §5.6.4.
const (
	SDAlways  = "always"
	SDAllowed = "allowed"
	SDNever   = "never"
)

var svgID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// checkClaims checks the claims property of one document against §5.6 and
// its subsections.
func checkClaims(doc Document) error {
	ids := map[string]bool{}
	for _, claim := range doc.Claims {
		if err := checkPath(claim.Path); err != nil {
			return err
		}
		name := PathString(claim.Path)
		for _, display := range claim.Display {
			if display.Locale == "" || display.Label == "" {
				return fmt.Errorf("§5.6.2: the display of the claim %s needs a locale and a label", name)
			}
		}
		switch claim.SD {
		case "", SDAlways, SDAllowed, SDNever:
		default:
			return fmt.Errorf("§5.6.4: the claim %s has the sd value %q", name, claim.SD)
		}
		if claim.SVGID != "" {
			if !svgID.MatchString(claim.SVGID) || ids[claim.SVGID] {
				return fmt.Errorf("§5.6: the svg_id %q of the claim %s is not a unique identifier of letters, digits and underscores", claim.SVGID, name)
			}
			ids[claim.SVGID] = true
		}
	}
	return nil
}

// checkPath checks a claim path (§5.6.1): "a non-empty array of strings, null
// values, or non-negative integers".
func checkPath(path []any) error {
	if len(path) == 0 {
		return errors.New("§5.6.1: a claim path is empty")
	}
	for _, component := range path {
		switch c := component.(type) {
		case string, nil:
		case float64:
			if c < 0 || c != float64(int(c)) {
				return fmt.Errorf("§5.6.1: the claim path %s has the component %v", PathString(path), c)
			}
		default:
			return fmt.Errorf("§5.6.1: the claim path %s has the component %v", PathString(path), c)
		}
	}
	return nil
}

// PathString renders a claim path for messages, such as address.city or
// degrees[].type.
func PathString(path []any) string {
	var b strings.Builder
	for _, component := range path {
		switch c := component.(type) {
		case string:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(c)
		case nil:
			b.WriteString("[]")
		default:
			fmt.Fprintf(&b, "[%v]", c)
		}
	}
	return b.String()
}
