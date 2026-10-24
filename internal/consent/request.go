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

// Package consent holds what the wallet asks the user and what the user
// answers: consent requests, the credential options of a presentation, the
// selection logic and the in-memory runtime of pending requests and their
// subscribers. A flow belongs to the browser that started it (ADR-0011).
package consent

import (
	"time"

	"github.com/google/uuid"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// TypeIssuancePresentation belongs to the issuance flow that requested it
// (OpenID4VCI 1.1 §6). It uses presentation consent handling.
const (
	TypePresentation         = "presentation"
	TypeIssuance             = "issuance"
	TypeIssuancePresentation = "issuance_presentation"
)

// Status values of a Request.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	// StatusExpired distinguishes a timeout from a denial when the wallet
	// reports why a late answer failed.
	StatusExpired = "expired"
	// StatusCancelled marks a request whose caller stopped waiting, such as a
	// closed Digital Credentials API window.
	StatusCancelled = "cancelled"
)

// Request is a question to the user. Runtime.DocFor gives its wire shape.
type Request struct {
	ID           string
	Type         string // TypePresentation, TypeIssuance or TypeIssuancePresentation
	OfferURI     string
	MatchedCreds []Match
	Status       string // StatusPending until Runtime.Resolve sets another status
	ResultCh     chan Result
	SubmissionCh chan SubmissionResult
	CreatedAt    time.Time
	ClientID     string
	OfferConfigs []string
	OfferDetails *OfferDetails
	Nonce        string
	ResponseURI  string
	DCQLQuery    map[string]any
	// Findings are the checks on the verifier or issuer that failed in debug
	// mode. The consent dialog shows them in a collapsed list.
	Findings []string
	// Purposes and privacy policy links from the request's registration
	// certificates, for the consent dialog.
	Purposes        []string
	PrivacyPolicies []string
	// Alternatives for the Edit view. MatchedCreds retains the automatic selection.
	CredentialOptions *CredentialOptions
	// Marshal leaves the owner out, because another caller could use it to
	// claim the request. Empty means the request is unowned.
	Owner string
	// Keep the offer shown at consent in case its URL cannot be fetched again after
	// approval.
	ResolvedOffer *oid4vc.CredentialOffer
	// True when the Request Object signature verifies against its own key
	// material. This does not establish trust in the verifier.
	ClientAuthSigned bool
	// Empty when ClientAuthSigned is true. Otherwise explains why verification was
	// unavailable or failed.
	ClientAuthDetail string
	// The unverified name from client_metadata.client_name. Empty if absent.
	ClientName string
	// RegisteredName is the relying party name of the registration
	// certificate bound to the request's access certificate.
	RegisteredName string
}

// NewRequest is a pending request of typ that belongs to owner. An empty
// owner leaves the request visible to every caller (ADR-0011).
func NewRequest(typ, owner string) *Request {
	return &Request{
		ID:           uuid.New().String(),
		Type:         typ,
		Owner:        owner,
		Status:       StatusPending,
		ResultCh:     make(chan Result, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
	}
}

type Match struct {
	QueryID      string         `json:"query_id"`
	CredentialID string         `json:"credential_id"`
	Format       string         `json:"format"`
	VCT          string         `json:"vct,omitempty"`
	DocType      string         `json:"doctype,omitempty"`
	Claims       map[string]any `json:"claims"`
	SelectedKeys []string       `json:"selected_keys"`
	// AlwaysDisclosed lists the claims of SelectedKeys and ClaimSets that are
	// always sent, such as plain SD-JWT claims. The holder cannot withhold
	// them.
	AlwaysDisclosed []string `json:"always_disclosed,omitempty"`
	// Debug mode can offer credentials that fail trusted_authorities matching. The
	// consent dialog flags this violation.
	UntrustedAuthority bool `json:"untrusted_authority,omitempty"`
	// Debug mode offers a credential without holder binding to a query that
	// requires it (OpenID4VP 1.0 §6.1). The consent dialog flags it.
	Unbound bool `json:"unbound,omitempty"`
	// Selecting an array without its selectively disclosed elements produces an empty
	// array. Warn so the verifier can request elements with null or an index.
	EmptyArrayClaims []string `json:"empty_array_claims,omitempty"`
	// Debug mode can offer partial matches and shows missing claims as undisclosed.
	// Strict mode requires all claims. Complete matches take precedence over partial
	// matches.
	MissingClaims []string `json:"missing_claims,omitempty"`
	// The consent dialog offers credentials that do not match the query. Mismatches says why.
	Mismatches []string `json:"mismatches,omitempty"`
	// ClaimSets lists the matching claim_sets options when there is more than
	// one. The first is the automatic selection.
	ClaimSets []ClaimSet `json:"claim_sets,omitempty"`
}

// ClaimSet is a matching claim_sets option of a credential. Index
// is its position in the query's claim_sets.
type ClaimSet struct {
	Index  int            `json:"index"`
	Keys   []string       `json:"keys"`
	Claims map[string]any `json:"claims"`
}

// CredentialOptions defaults to the first set option and first candidate for each
// query. Unchanged consent therefore presents the same credentials as auto-accept.
type CredentialOptions struct {
	// Lists satisfiable credential_sets options in preference order. Without
	// credential_sets, every query is required.
	Sets    []SetOptions   `json:"sets,omitempty"`
	Queries []QueryOptions `json:"queries"`
}

type SetOptions struct {
	// Each option lists the query IDs that jointly satisfy the set.
	Options [][]string `json:"options"`
	// required: false lets the user skip the entire set.
	Optional bool `json:"optional,omitempty"`
	// Unmatched lists the options where only non-matching credentials fit (debug
	// mode).
	Unmatched []int `json:"unmatched,omitempty"`
}

type QueryOptions struct {
	ID string `json:"id"`
	// With multiple, every candidate is sent by default. The user can deselect all
	// but one.
	Multiple   bool    `json:"multiple,omitempty"`
	Candidates []Match `json:"candidates"`
	// Debug mode lists the credentials that do not match the query. The user can
	// pick them to test how the verifier handles a wrong answer.
	NonMatching []Match `json:"non_matching,omitempty"`
}

type Result struct {
	Approved       bool
	SelectedClaims map[string][]string
	// A query omitted from Picks retains the wallet's default credentials. Only a
	// query that sets multiple can pick more than one.
	Picks map[string][]string
	// -1 skips an optional set. Missing entries retain the wallet's default option.
	SetChoices []int
	// The claim_sets index per query. A missing entry keeps the first matching
	// option.
	ClaimSetChoices map[string]int
	// Presentations requested during issuance go to the browser that approved the
	// offer.
	Owner string
	// Tab identifies the wallet page that approved. A sign-in prompt of the
	// flow goes to that page.
	Tab string
	// Entered in the consent dialog after the offer declares that a transaction code
	// is required.
	TxCode string
	// ConfigurationID is the credential configuration picked from an offer
	// that lists several.
	ConfigurationID string
}

type SubmissionResult struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	Error       string `json:"error,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	// Findings are the failed checks behind Error, one per entry.
	Findings []string `json:"findings,omitempty"`
	// Deferred issuance is still pending. The wallet continues collecting in the
	// background.
	Pending       bool   `json:"pending,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
}

func marshal(r *Request) map[string]any {
	m := map[string]any{
		"id":                  r.ID,
		"type":                r.Type,
		"status":              r.Status,
		"client_id":           r.ClientID,
		"created_at":          r.CreatedAt.Format(time.RFC3339),
		"matched_credentials": r.MatchedCreds,
	}
	if r.Nonce != "" {
		m["nonce"] = r.Nonce
	}
	if r.ResponseURI != "" {
		m["response_uri"] = r.ResponseURI
	}
	if r.DCQLQuery != nil {
		m["dcql_query"] = r.DCQLQuery
	}
	if len(r.Purposes) > 0 {
		m["purposes"] = r.Purposes
	}
	if len(r.PrivacyPolicies) > 0 {
		m["privacy_policies"] = r.PrivacyPolicies
	}
	if len(r.Findings) > 0 {
		m["findings"] = r.Findings
	}
	if r.CredentialOptions != nil {
		m["credential_options"] = r.CredentialOptions
	}
	if len(r.OfferConfigs) > 0 {
		m["offer_configs"] = r.OfferConfigs
	}
	if r.OfferDetails != nil {
		m["offer_details"] = r.OfferDetails
	}
	// Issuance offers have no Request Object, so only presentations carry
	// client_auth.
	if r.Type == TypePresentation || r.Type == TypeIssuancePresentation {
		m["client_auth"] = map[string]any{
			"signed": r.ClientAuthSigned,
			"detail": r.ClientAuthDetail,
		}
	}
	if r.ClientName != "" {
		m["client_name"] = r.ClientName
	}
	if r.RegisteredName != "" {
		m["registered_name"] = r.RegisteredName
	}
	return m
}

type OfferedCredential struct {
	ID          string   `json:"id"`
	Format      string   `json:"format,omitempty"`
	VCT         string   `json:"vct,omitempty"`
	DocType     string   `json:"doctype,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	// ClaimDisplayNames maps a path in Claims to the claim's display name
	// from the issuer metadata. A claim without a display name has no entry.
	ClaimDisplayNames map[string]string `json:"claim_display_names,omitempty"`
	// Display images get the same address checks as images of issued
	// credentials. --adhoc-display-images can keep HTTPS URLs for the browser.
	Display *oid4vc.CredentialDisplay `json:"display,omitempty"`
}

// OfferDetails combines the offer with optional issuer metadata for the
// consent dialog. Fields stay empty when metadata is missing.
type OfferDetails struct {
	Issuer     string `json:"issuer"`
	IssuerName string `json:"issuer_name,omitempty"`
	IssuerLogo string `json:"issuer_logo,omitempty"`
	Grant      string `json:"grant,omitempty"`
	TxCode     bool   `json:"tx_code,omitempty"`
	TxCodeHint string `json:"tx_code_hint,omitempty"`
	// OID4VCI 1.0 defines these three members on tx_code. The dialog uses them
	// to size and type its input and to show the issuer's wording.
	TxCodeInputMode   string              `json:"tx_code_input_mode,omitempty"`
	TxCodeLength      int                 `json:"tx_code_length,omitempty"`
	TxCodeDescription string              `json:"tx_code_description,omitempty"`
	Credentials       []OfferedCredential `json:"credentials,omitempty"`
	MetadataError     string              `json:"metadata_error,omitempty"`
	// Findings are the metadata, ARF and catalogue findings about the issuer.
	// The ARF requires the wallet to warn the user before it requests the
	// credential.
	Findings []string `json:"-"`
	// ARFFindings are the ARF findings among them. Strict mode refuses an
	// offer that has any before the consent dialog opens.
	ARFFindings []string `json:"-"`
	// OfferURI and ResolveError are set when an offer passed by reference
	// could not be fetched. The dialog then shows the host and the reason.
	OfferURI     string `json:"offer_uri,omitempty"`
	ResolveError string `json:"resolve_error,omitempty"`
}

// Owns reports whether one of the owners may see and answer the request
// (ADR-0011). Unowned requests stay visible to all callers, such as API
// clients without a browser session. A redirected browser can also access the request by its ID
// if cookies are unavailable.
func Owns(owners []string, req *Request, named string) bool {
	if req == nil {
		return false
	}
	return req.Owner == "" || OwnedBy(owners, req.Owner) || (named != "" && req.ID == named)
}

func OwnedBy(owners []string, want string) bool {
	for _, v := range owners {
		if v == want {
			return true
		}
	}
	return false
}
