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

// Package wallet implements a stateful testing wallet for OID4VP presentations and OID4VCI issuance flows.
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

type SessionTranscriptMode string

const (
	// SessionTranscriptISO uses the ISO 18013-7 Annex B.4.4 handover: the
	// SHA-256 of CBOR([client_id, mdocGeneratedNonce]), the SHA-256 of
	// CBOR([response_uri, mdocGeneratedNonce]), and the nonce.
	SessionTranscriptISO SessionTranscriptMode = "iso"

	// SessionTranscriptOID4VP uses the OID4VP 1.0 Appendix B.2.6 handover: the
	// SHA-256 of CBOR([client_id, nonce, jwkThumbprint, response_uri]). This is
	// the default.
	SessionTranscriptOID4VP SessionTranscriptMode = "oid4vp"
)

type StatusEntry struct {
	Index  int `json:"index"`
	Status int `json:"status"` // 0=valid, 1=revoked
}

// NextErrorOverride applies to the next presentation request only.
type NextErrorOverride struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Wallet struct {
	HolderKey *ecdsa.PrivateKey
	IssuerKey *ecdsa.PrivateKey
	CAKey     *ecdsa.PrivateKey
	CertChain []*x509.Certificate // [leaf, CA] certificate chain
	PersistedState
	AutoAccept        bool
	SessionTranscript SessionTranscriptMode // "oid4vp" (default) or "iso"
	PreferredFormat   string                // "" (no preference), "dc+sd-jwt", or "mso_mdoc"
	// The wallet advertises this key even when RequireEncryptedRequest is false.
	RequestEncryptionKey *ecdsa.PrivateKey
	ConformanceSettings  `json:"-"`
	// RelyingPartyCAPEM holds further CAs that issue relying party access and
	// registration certificates (--relying-party-ca).
	RelyingPartyCAPEM []byte
	// TrustListCAPEM holds further CAs of trusted list operators
	// (--trusted-list-ca). With --arf the signer of a fetched trusted list must
	// chain to one of them or to the wallet CA.
	TrustListCAPEM []byte
	// ConfiguredTrustedListURLs are the external lists from --trusted-list.
	ConfiguredTrustedListURLs []string
	// Sends the wallet attestation even without advertised support. Disabled by
	// default because reusing an attestation can link activity across issuers.
	ForceClientAttestation bool
	// Keeps HTTPS image URLs so the browser fetches them on demand. HTTP images,
	// data URIs and template images are still stored. By default every image is
	// fetched through the restricted HTTP client and stored.
	AdhocDisplayImages bool `json:"-"`
	BaseURL            string
	IssuerURL          string
	VCIClientID        string `json:"-"`
	VCIRedirectURI     string `json:"-"`
	// Callback URLs use this origin when BaseURL is unset.
	ServingOrigin string `json:"-"`
	// The zero value uses the default template directory.
	Templates credtemplate.Location `json:"-"`
	mu        sync.RWMutex
	// demoRegistrationMu serializes the demo registrations. Concurrent
	// requests then share one certificate instead of replacing each other's.
	demoRegistrationMu sync.Mutex
	// capacity bounds what a shared wallet stores. Zero means no bound.
	capacity Capacity
	// saveMutation runs a change, such as a registrar change or a batch use
	// count, and saves it. A server sets it to its saveMutation, which takes
	// the store lock. Never call it while holding that lock.
	saveMutation func(change func() bool)
	listCacheMu  sync.Mutex
	listCache    map[string]cachedList
	listFetches  singleflight.Group
	outboundHTTP *http.Client
	// Entity backends track the last loaded or saved snapshot and section revisions.
	// File storage leaves these nil.
	persisted stateSnapshot
	revisions map[string]storage.Stamp
	// Track stored credential values and row positions. Saves serialize a credential
	// only when it changed.
	savedCredentials map[string]StoredCredential
	entitySeqs       map[string]int
	// Entity backends allocate status indices from a shared counter. When nil, use the
	// wallet's local StatusListCounter.
	allocateStatusIndex func(*Wallet) (int, error)
	logSink             func(LogEntry)
	// Forwards imports from a clone to the original wallet.
	credentialSink func(StoredCredential)
	// Forwards batch use from a clone so the original wallet advances its rotation.
	batchPresentedSink func(id string)
	runtime            *WalletRuntime
	signers            *signingStore
	// Marks batch use counts for saving so rotation survives restart.
	batchDirty bool
}

func (w *Wallet) takeBatchStateDirty() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	dirty := w.batchDirty
	w.batchDirty = false
	return dirty
}

// WalletRuntime shares flow state between wallets using the same store directory in this
// process.
type WalletRuntime struct {
	mu                sync.RWMutex
	requests          map[string]*ConsentRequest
	nextError         *NextErrorOverride
	subscribers       map[int64]chan *ConsentRequest
	subID             int64
	errSubscribers    map[int64]chan WalletError
	errSubID          int64
	stateSubscribers  map[int64]chan struct{}
	stateSubID        int64
	authSubscribers   map[int64]chan AuthorizationPrompt
	authSubID         int64
	lastErrors        map[string]*storedError
	authCodeCallbacks map[string]chan url.Values
}

func newWalletRuntime() *WalletRuntime {
	return &WalletRuntime{
		requests:          make(map[string]*ConsentRequest),
		subscribers:       make(map[int64]chan *ConsentRequest),
		errSubscribers:    make(map[int64]chan WalletError),
		stateSubscribers:  make(map[int64]chan struct{}),
		authSubscribers:   make(map[int64]chan AuthorizationPrompt),
		authCodeCallbacks: make(map[string]chan url.Values),
		lastErrors:        make(map[string]*storedError),
	}
}

func (w *Wallet) runtimeState() *WalletRuntime {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.runtime == nil {
		w.runtime = newWalletRuntime()
	}
	return w.runtime
}

// StatusListURL prefers the HTTPS issuer endpoint when available.
func (w *Wallet) StatusListURL() string {
	if w == nil {
		return ""
	}
	if issuer := strings.TrimRight(w.IssuerURL, "/"); issuer != "" {
		return issuer + "/api/statuslist"
	}
	if base := strings.TrimRight(w.BaseURL, "/"); base != "" {
		return base + "/api/statuslist"
	}
	return ""
}

func (w *Wallet) StatusListIssuer() string {
	if w == nil {
		return ""
	}
	if issuer := strings.TrimRight(w.IssuerURL, "/"); issuer != "" {
		return issuer
	}
	return strings.TrimRight(w.BaseURL, "/")
}

// EnsureRequestEncryptionKey generates a key for this wallet instance without persisting
// it.
func (w *Wallet) EnsureRequestEncryptionKey() error {
	if w == nil || w.RequestEncryptionKey != nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating request encryption key: %w", err)
	}
	w.RequestEncryptionKey = key
	return nil
}

type WalletError struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	// Never serialize the owner because another caller could use it to claim the flow.
	Owner string `json:"-"`
}

// PersistedState is the wallet state the store saves. Load, save, reload and
// reset each handle it as a whole.
type PersistedState struct {
	Credentials        []StoredCredential      `json:"credentials"`
	IssuedAttestations []IssuedAttestationSpec `json:"issued_attestations,omitempty"`
	// The registrar's registrations, status entries and catalogue.
	registrar.State
	// TrustedEntities and AddedTrustedLists are added by users through
	// `wallet trust` or the API.
	TrustedEntities   []TrustedEntity        `json:"trusted_entities,omitempty"`
	AddedTrustedLists []string               `json:"trusted_lists,omitempty"`
	Log               []LogEntry             `json:"log,omitempty"`
	DeferredIssuances []DeferredIssuance     `json:"deferred_issuances,omitempty"`
	StatusEntries     map[string]StatusEntry `json:"status_entries,omitempty"`
	StatusListCounter int                    `json:"status_list_counter,omitempty"`
}

// clone copies the lists, so the copy and p change independently.
func (p PersistedState) clone() PersistedState {
	c := p
	c.Credentials = slices.Clone(p.Credentials)
	c.IssuedAttestations = slices.Clone(p.IssuedAttestations)
	c.RelyingParties = slices.Clone(p.RelyingParties)
	c.RegistrationStatuses = slices.Clone(p.RegistrationStatuses)
	c.Catalog = slices.Clone(p.Catalog)
	c.TrustedEntities = slices.Clone(p.TrustedEntities)
	c.AddedTrustedLists = slices.Clone(p.AddedTrustedLists)
	c.Log = slices.Clone(p.Log)
	c.DeferredIssuances = slices.Clone(p.DeferredIssuances)
	c.StatusEntries = maps.Clone(p.StatusEntries)
	return c
}

// ConformanceSettings are the switches a test run changes at runtime. A
// server restores its startup values on DELETE /api/config/conformance.
type ConformanceSettings struct {
	ValidationMode ValidationMode
	RequireHAIP    bool
	// RequireARF turns on the ARF checks of verifiers, issuers and received
	// credentials (--arf).
	RequireARF bool
	// RequireEncryptedRequest rejects unencrypted request_uri responses.
	RequireEncryptedRequest bool
	// Defaults to 1.0. Version 1.1 enables supported draft features when the
	// issuer advertises them.
	VCIVersion VCIVersion
	// Read runtime changes through KeyAttestationLevelSetting. See
	// ParseKeyAttestationLevel for supported claims about key storage.
	KeyAttestationLevel string
	// tlsVerify overrides TLS verification. Nil follows the validation mode.
	tlsVerify *bool
}

type StoredCredential struct {
	ID      string         `json:"id"`
	Format  string         `json:"format"` // "dc+sd-jwt", "mso_mdoc", or "jwt_vc_json"
	Raw     string         `json:"raw"`
	Claims  map[string]any `json:"claims"`
	VCT     string         `json:"vct,omitempty"`
	DocType string         `json:"doctype,omitempty"`
	// Protects shared baseline credentials from deletion or revocation through the UI,
	// API and CLI. Changing this flag requires direct access to stored state.
	Protected bool `json:"protected,omitempty"`
	// Saved only when the issuer provides a refresh token. Renewal secrets are stored
	// unencrypted like the rest of the wallet (ADR-0003).
	Renewal *CredentialRenewal `json:"renewal,omitempty"`
	// The appearance declared by the issuer (OpenID4VCI 1.0 §12.2.4), or the
	// template's appearance for credentials generated by the wallet.
	Display *CredentialDisplay `json:"display,omitempty"`
	// Groups copies issued together with distinct binding keys. Rotating copies
	// reduces linking through repeated use of the same credential (EUDI ARF Annex 2
	// Topic 10 method C, ISSU_51-54). Empty for single issuance.
	BatchGroup string `json:"batch_group,omitempty"`
	// The private holder key for this copy. Empty means the wallet's holder key.
	BindingKeyPEM string `json:"binding_key,omitempty"`
	// Present a random copy among those with the lowest use count. After every copy
	// has been used, the batch cycles through them again (EUDI ARF method C, ISSU_52).
	Uses            int                `json:"uses,omitempty"`
	LastPresentedAt time.Time          `json:"last_presented_at,omitempty"`
	Disclosures     []sdjwt.Disclosure `json:"-"`
	// Parsed issuance time, cached for sorting.
	issuedAt   time.Time
	NameSpaces map[string][]mdoc.IssuerSignedItem `json:"-"`
}

func (w *Wallet) batchSigningKey(cred StoredCredential) (*ecdsa.PrivateKey, error) {
	if cred.BindingKeyPEM == "" {
		return w.HolderKeyPair(), nil
	}
	key, err := decodeECPrivateKeyPEM(cred.BindingKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decoding the binding key of credential %s: %w", cred.ID, err)
	}
	return key, nil
}

// CredentialRenewal preserves issuer context needed after the original issuance flow ends.
type CredentialRenewal struct {
	Issuer             string `json:"issuer"`
	TokenEndpoint      string `json:"token_endpoint"`
	CredentialEndpoint string `json:"credential_endpoint"`
	ConfigurationID    string `json:"credential_configuration_id,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	RefreshToken       string `json:"refresh_token"`
	UseDPoP            bool   `json:"use_dpop,omitempty"`
	// Refresh requests use the same client authentication as the original token
	// request.
	ClientAuth *ClientAuthentication `json:"client_auth,omitempty"`
}

const (
	ClientAuthAttestation   = "attestation"
	ClientAuthPrivateKeyJWT = "private_key_jwt"
)

// ClientAuthentication preserves the method and metadata needed for later token requests,
// including refresh.
type ClientAuthentication struct {
	Method string `json:"method"`
	// The authorization server identifier used as the proof or assertion audience.
	Audience string `json:"audience,omitempty"`
	// Fetch a new challenge for each request because a stored challenge may expire.
	ChallengeEndpoint string `json:"challenge_endpoint,omitempty"`
	// Preserve the ABCA draft chosen at issuance so refresh uses the same claim
	// structure. Zero uses the wallet's current version for older records.
	ABCADraft int `json:"abca_draft,omitempty"`
	// With dpop_combined, the DPoP proof also proves possession for the attestation.
	// Send only OAuth-Client-Attestation (ABCA draft-10 §5.2).
	CombinedPoP bool `json:"combined_pop,omitempty"`
	// LegacyClientID is where eudi-dev 2 stored the client ID. Loading moves it
	// to CredentialRenewal.ClientID.
	LegacyClientID string `json:"client_id,omitempty"`
}

func (c StoredCredential) CanRenew() bool {
	return c.Renewal != nil && c.Renewal.RefreshToken != "" &&
		c.Renewal.TokenEndpoint != "" && c.Renewal.CredentialEndpoint != ""
}

// ConsentTypeIssuancePresentation belongs to the issuance flow that requested it
// (OpenID4VCI 1.1 §6). It uses presentation consent handling.
const (
	ConsentTypePresentation         = "presentation"
	ConsentTypeIssuance             = "issuance"
	ConsentTypeIssuancePresentation = "issuance_presentation"
)

type ConsentRequest struct {
	ID           string                       `json:"id"`
	Type         string                       `json:"type"` // presentation, issuance, or issuance_presentation
	AuthRequest  *oid4vc.AuthorizationRequest `json:"-"`
	OfferURI     string                       `json:"-"`
	MatchedCreds []CredentialMatch            `json:"matched_credentials"`
	Status       string                       `json:"status"` // "pending", "approved", "denied", "expired"
	ResultCh     chan ConsentResult           `json:"-"`
	SubmissionCh chan SubmissionResult        `json:"-"`
	CreatedAt    time.Time                    `json:"created_at"`
	ClientID     string                       `json:"client_id"`
	OfferConfigs []string                     `json:"offer_configs,omitempty"`
	OfferDetails *IssuanceOfferDetails        `json:"offer_details,omitempty"`
	Nonce        string                       `json:"nonce,omitempty"`
	ResponseURI  string                       `json:"response_uri,omitempty"`
	DCQLQuery    map[string]any               `json:"dcql_query,omitempty"`
	// Findings are the checks on the verifier or issuer that failed in debug
	// mode. The consent dialog shows them in a collapsed list.
	Findings []string `json:"findings,omitempty"`
	// Purposes and privacy policy links from the request's registration
	// certificates, for the consent dialog.
	Purposes        []string `json:"purposes,omitempty"`
	PrivacyPolicies []string `json:"privacy_policies,omitempty"`
	// Alternatives for the Edit view. MatchedCreds retains the automatic selection.
	CredentialOptions *ConsentCredentialOptions `json:"credential_options,omitempty"`
	// Never serialize the owner because another caller could use it to claim the
	// request. Empty means the request is unowned.
	Owner string `json:"-"`
	// Keep the offer shown at consent in case its URL cannot be fetched again after
	// approval.
	ResolvedOffer *oid4vc.CredentialOffer `json:"-"`
	// True when the Request Object signature verifies against the key material it
	// carries. This does not establish trust in the verifier.
	ClientAuthSigned bool `json:"-"`
	// Empty when ClientAuthSigned is true. Otherwise explains why verification was
	// unavailable or failed.
	ClientAuthDetail string `json:"-"`
	// The unverified name from client_metadata.client_name. Empty if absent.
	ClientName string `json:"-"`
}

type CredentialMatch struct {
	QueryID      string         `json:"query_id"`
	CredentialID string         `json:"credential_id"`
	Format       string         `json:"format"`
	VCT          string         `json:"vct,omitempty"`
	DocType      string         `json:"doctype,omitempty"`
	Claims       map[string]any `json:"claims"`
	SelectedKeys []string       `json:"selected_keys"`
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
	// Debug mode offers credentials that do not match the query. Mismatches says why.
	Mismatches []string `json:"mismatches,omitempty"`
	// Debug mode lists the matching claim_sets options when there is more than
	// one. The first is the automatic selection.
	ClaimSets []ConsentClaimSet `json:"claim_sets,omitempty"`
}

// ConsentClaimSet is a matching claim_sets option of a credential. Index
// is its position in the query's claim_sets.
type ConsentClaimSet struct {
	Index  int            `json:"index"`
	Keys   []string       `json:"keys"`
	Claims map[string]any `json:"claims"`
}

// ConsentCredentialOptions defaults to the first set option and first candidate for each
// query. Unchanged consent therefore presents the same credentials as auto-accept.
type ConsentCredentialOptions struct {
	// Lists satisfiable credential_sets options in preference order. Without
	// credential_sets, every query is required.
	Sets    []ConsentSetOptions   `json:"sets,omitempty"`
	Queries []ConsentQueryOptions `json:"queries"`
}

type ConsentSetOptions struct {
	// Each option lists the query IDs that jointly satisfy the set.
	Options [][]string `json:"options"`
	// required: false lets the user skip the entire set.
	Optional bool `json:"optional,omitempty"`
	// Unmatched lists the options where only non-matching credentials fit (debug
	// mode).
	Unmatched []int `json:"unmatched,omitempty"`
}

type ConsentQueryOptions struct {
	ID string `json:"id"`
	// With multiple, every candidate is sent by default. The user can deselect all
	// but one.
	Multiple   bool              `json:"multiple,omitempty"`
	Candidates []CredentialMatch `json:"candidates"`
	// Debug mode lists the credentials that do not match the query. The user can
	// pick them to test how the verifier handles a wrong answer.
	NonMatching []CredentialMatch `json:"non_matching,omitempty"`
}

type ConsentResult struct {
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
	// Deferred issuance is still pending. The wallet continues collecting in the
	// background.
	Pending       bool   `json:"pending,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
}

type LogEntry struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Detail  string    `json:"detail"`
	Success bool      `json:"success"`
	// Severity is empty or "warning". A warning records a violation that did not
	// fail the action.
	Severity string         `json:"severity,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
	// The CLI and default log endpoint omit the additional payload used by the activity view.
	Payload *LogPayload `json:"payload,omitempty"`
}

type LogPayload struct {
	Label     string `json:"label"`
	Body      any    `json:"body"`
	Encrypted bool   `json:"encrypted,omitempty"`
	Wire      any    `json:"wire,omitempty"`
}

const severityWarning = "warning"

// New creates a CA and signing leaf to provide an x5c chain for testing.
func New(holderKey, issuerKey *ecdsa.PrivateKey, autoAccept bool) *Wallet {
	w := &Wallet{
		HolderKey:           holderKey,
		IssuerKey:           issuerKey,
		AutoAccept:          autoAccept,
		ConformanceSettings: ConformanceSettings{ValidationMode: ValidationModeDebug, VCIVersion: VCIVersion10},
		runtime:             newWalletRuntime(),
	}

	caKey, err := mock.GenerateKey()
	if err != nil {
		log.Printf("[Wallet] Warning: failed to generate CA key: %v", err)
		return w
	}

	caCert, err := mock.GenerateRootCACert(caKey)
	if err != nil {
		log.Printf("[Wallet] Warning: failed to generate CA cert: %v", err)
		return w
	}

	if err := w.SetCertificateAuthority(caKey, caCert); err != nil {
		log.Printf("[Wallet] Warning: failed to generate leaf cert: %v", err)
		return w
	}

	return w
}

// SetCertificateAuthority replaces the CA and certificate chain. The issuer key
// stays.
func (w *Wallet) SetCertificateAuthority(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) error {
	return w.setCertificateAuthority(caKey, caCert, false)
}

func (w *Wallet) setCertificateAuthority(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, renew bool) error {
	if w == nil || w.IssuerKey == nil || caKey == nil || caCert == nil {
		return fmt.Errorf("wallet CA configuration requires issuer key, CA key, and CA certificate")
	}
	opts := mock.LeafCertOptions{}
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(w.IssuerURL)
	leafCert, err := w.signingStore().certificate(caKey, caCert, &w.IssuerKey.PublicKey, opts, renew)
	if err != nil {
		return fmt.Errorf("generating issuer leaf certificate: %w", err)
	}
	// Slice header writes are not atomic. Without the lock a reader could see the
	// pointer of one chain and the length of another.
	w.mu.Lock()
	defer w.mu.Unlock()
	w.CAKey = caKey
	w.CertChain = []*x509.Certificate{leafCert, caCert}
	return nil
}

// RefreshSigningCertificate issues a new leaf. It keeps the CA and issuer key so
// published trust material stays valid.
func (w *Wallet) RefreshSigningCertificate() error {
	if w == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return nil
	}
	return w.setCertificateAuthority(w.CAKey, w.CertChain[len(w.CertChain)-1], true)
}

// SigningCertificateExpiry returns the zero time when no chain exists.
func (w *Wallet) SigningCertificateExpiry() time.Time {
	if w == nil || len(w.CertChain) == 0 || w.CertChain[0] == nil {
		return time.Time{}
	}
	return w.CertChain[0].NotAfter
}

// A long running wallet renews its signing certificate this long before expiry.
const signingCertificateRenewBefore = 30 * 24 * time.Hour

func (w *Wallet) RefreshSigningCertificateIfExpiring(now time.Time) (bool, error) {
	expiry := w.SigningCertificateExpiry()
	if expiry.IsZero() || now.Add(signingCertificateRenewBefore).Before(expiry) {
		return false, nil
	}
	if err := w.RefreshSigningCertificate(); err != nil {
		return false, err
	}
	return true, nil
}

// GenerateDefaultCredentials merges claimOverrides with PID template claims. vct selects
// the PID templates of that type, and an empty vct uses the EUDI PID. A type without
// templates uses the EUDI claim set under that type.
func (w *Wallet) GenerateDefaultCredentials(claimOverrides map[string]any, vct string) error {
	return w.generateDefaultCredentials(claimOverrides, vct, true)
}

// dropExisting replaces existing defaults of the same type. Baseline generation
// passes false because it removes its protected credentials itself.
func (w *Wallet) generateDefaultCredentials(claimOverrides map[string]any, vct string, dropExisting bool) error {
	sdName, mdocName, _ := credtemplate.PIDTemplateNames(vct, w.Templates)
	sdTpl, err := credtemplate.Load(sdName, w.Templates)
	if err != nil {
		return fmt.Errorf("loading %s template: %w", sdName, err)
	}
	mdocTpl, err := credtemplate.Load(mdocName, w.Templates)
	if err != nil {
		return fmt.Errorf("loading %s template: %w", mdocName, err)
	}
	vct = firstNonEmpty(vct, sdTpl.VCT, mock.DefaultPIDVCT)
	mdocDocType := firstNonEmpty(mdocTpl.DocType, mock.PIDNamespace)
	mdocNamespace := firstNonEmpty(mdocTpl.Namespace, mdocDocType)
	log.Printf("[Wallet] Generating default PID credentials: vct=%s overrides=%d", vct, len(claimOverrides))

	// A protected default stays and is not generated again.
	var keptSD, keptMDoc bool
	if dropExisting {
		mdocNamespaces := splitClaimsByNamespace(credtemplate.MergeClaims(mdocTpl.Claims, claimOverrides), mdocNamespace)
		keptSD = w.removeByType("dc+sd-jwt", vct) > 0
		keptMDoc = w.removeMDocsByNamespace(mdocDocType, namespaceNames(mdocNamespaces)) > 0
		if keptSD || keptMDoc {
			log.Printf("[Wallet] Keeping protected PID credentials: sdjwt=%t mdoc=%t", keptSD, keptMDoc)
		}
	}
	if !keptSD {
		if _, err := w.IssueCredential(IssueOptions{Template: sdName, Format: "sdjwt", VCT: vct, Claims: claimOverrides}); err != nil {
			return fmt.Errorf("issuing the SD-JWT PID: %w", err)
		}
	}
	if !keptMDoc {
		if _, err := w.IssueCredential(IssueOptions{Template: mdocName, Format: "mdoc", Claims: claimOverrides}); err != nil {
			return fmt.Errorf("issuing the mdoc PID: %w", err)
		}
	}
	return nil
}

// Protected credentials stay. Returns how many were kept.
func (w *Wallet) removeByType(format, vct string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var keptProtected int
	filtered := w.Credentials[:0]
	for _, c := range w.Credentials {
		if c.Format == format && (vct == "" || c.VCT == vct) {
			if !c.Protected {
				continue
			}
			keptProtected++
		}
		filtered = append(filtered, c)
	}
	w.Credentials = filtered
	return keptProtected
}

// German and EUDI PIDs share a doctype and differ in namespaces. Matching both
// keeps one PID when the other is regenerated. Protected credentials stay.
func (w *Wallet) removeMDocsByNamespace(docType string, namespaces []string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	wanted := namespaceKey(namespaces)
	var keptProtected int
	filtered := w.Credentials[:0]
	for _, c := range w.Credentials {
		if c.Format == "mso_mdoc" && c.DocType == docType && namespaceKey(credentialNamespaces(c)) == wanted {
			if !c.Protected {
				continue
			}
			keptProtected++
		}
		filtered = append(filtered, c)
	}
	w.Credentials = filtered
	return keptProtected
}

// NameSpaces comes first because claim keys in older wallet files may lack the
// namespace prefix.
func credentialNamespaces(c StoredCredential) []string {
	if len(c.NameSpaces) > 0 {
		names := make([]string, 0, len(c.NameSpaces))
		for ns := range c.NameSpaces {
			names = append(names, ns)
		}
		return names
	}
	seen := make(map[string]bool)
	var names []string
	for key := range c.Claims {
		ns, _, found := strings.Cut(key, ":")
		if !found || seen[ns] {
			continue
		}
		seen[ns] = true
		names = append(names, ns)
	}
	return names
}

func namespaceNames(claims map[string]map[string]any) []string {
	names := make([]string, 0, len(claims))
	for ns := range claims {
		names = append(names, ns)
	}
	return names
}

// Namespace order must not affect identity.
func namespaceKey(namespaces []string) string {
	sorted := append([]string(nil), namespaces...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\x00")
}

func (w *Wallet) removeProtected() {
	w.mu.Lock()
	defer w.mu.Unlock()
	kept := w.Credentials[:0]
	for _, c := range w.Credentials {
		if !c.Protected {
			kept = append(kept, c)
		}
	}
	w.Credentials = kept
}

func (w *Wallet) ClearCredentials() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	kept := make([]StoredCredential, 0, len(w.Credentials))
	for _, c := range w.Credentials {
		if c.Protected {
			kept = append(kept, c)
		}
	}
	removed := len(w.Credentials) - len(kept)
	w.Credentials = kept
	return removed
}

// RemoveCredential refuses to remove a protected credential.
func (w *Wallet) RemoveCredential(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	full := w.resolveIDLocked(id)
	// The UI treats a batch as one credential, so deleting it removes every copy.
	group := ""
	for _, c := range w.Credentials {
		if c.ID == full {
			if c.Protected {
				return false
			}
			group = c.BatchGroup
			break
		}
	}
	// One protected copy protects the whole batch.
	if group != "" {
		for _, c := range w.Credentials {
			if c.BatchGroup == group && c.Protected {
				return false
			}
		}
	}
	kept := w.Credentials[:0]
	removed := false
	for _, c := range w.Credentials {
		if c.ID == full || (group != "" && c.BatchGroup == group) {
			removed = true
			continue
		}
		kept = append(kept, c)
	}
	w.Credentials = kept
	return removed
}

// renameCredential moves a credential and its status entry to a new ID. It runs
// before the credential is first saved.
func (w *Wallet) renameCredential(oldID, newID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == oldID {
			w.Credentials[i].ID = newID
		}
	}
	if entry, ok := w.StatusEntries[oldID]; ok {
		delete(w.StatusEntries, oldID)
		w.StatusEntries[newID] = entry
	}
}

func (w *Wallet) IsProtected(id string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	full := w.resolveIDLocked(id)
	for _, c := range w.Credentials {
		if c.ID == full {
			return c.Protected
		}
	}
	return false
}

// BaselinePIDTemplates lists the SD-JWT templates of the baseline PIDs. The
// German PID extends the EUDI PID, so together they show type inheritance.
var BaselinePIDTemplates = []string{"pid-sdjwt", "german-pid-sdjwt"}

// GenerateProtectedDefaults marks the newly generated defaults as protected.
func (w *Wallet) GenerateProtectedDefaults() error {
	// A stored baseline can hold types that BaselinePIDTemplates leaves out.
	w.removeProtected()

	existing := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		existing[c.ID] = true
	}
	for _, name := range BaselinePIDTemplates {
		tpl, err := credtemplate.Load(name, w.Templates)
		if err != nil {
			return fmt.Errorf("loading %s template: %w", name, err)
		}
		if err := w.generateDefaultCredentials(nil, tpl.VCT, false); err != nil {
			return err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if !existing[w.Credentials[i].ID] {
			w.Credentials[i].Protected = true
		}
	}
	return nil
}

func (w *Wallet) RegisterIssuedAttestation(spec IssuedAttestationSpec) error {
	_, err := w.EnsureIssuedAttestation(spec)
	return err
}

// EnsureIssuedAttestation registers the attestation type and reports whether
// the wallet changed.
func (w *Wallet) EnsureIssuedAttestation(spec IssuedAttestationSpec) (bool, error) {
	normalized, err := NormalizeIssuedAttestationSpec(spec, "")
	if err != nil {
		return false, err
	}
	key := normalized.Format + "|" + normalized.VCT + "|" + normalized.DocType

	w.mu.Lock()
	defer w.mu.Unlock()
	for i, existing := range w.IssuedAttestations {
		existingKey := existing.Format + "|" + existing.VCT + "|" + existing.DocType
		if existingKey == key {
			if reflect.DeepEqual(existing, normalized) {
				return false, nil
			}
			w.IssuedAttestations[i] = normalized
			return true, nil
		}
	}
	w.IssuedAttestations = append(w.IssuedAttestations, normalized)
	w.IssuedAttestations = dedupeIssuedAttestations(w.IssuedAttestations)
	return true, nil
}

func (w *Wallet) GetCredentials() []StoredCredential {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]StoredCredential, len(w.Credentials))
	copy(out, w.Credentials)
	return out
}

// Conformance returns the current settings. A flow reads them once, so a
// change in the middle of the flow doesn't mix two settings.
func (w *Wallet) Conformance() ConformanceSettings {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ConformanceSettings
}

// Mode takes the lock because the mode can change at runtime.
func (w *Wallet) Mode() ValidationMode {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ValidationMode
}

// VCIFeatureVersion returns 1.0 when no version is set.
func (w *Wallet) VCIFeatureVersion() VCIVersion {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.VCIVersion == "" {
		return VCIVersion10
	}
	return w.VCIVersion
}

// HolderKeyPair takes the lock because a concurrent reload can replace the key.
func (w *Wallet) HolderKeyPair() *ecdsa.PrivateKey {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.HolderKey
}

// HAIPChecks reports whether --haip is on.
func (w *Wallet) HAIPChecks() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.RequireHAIP
}

// ARFChecks reports whether --arf is on.
func (w *Wallet) ARFChecks() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.RequireARF
}

// KeyAttestationLevelSetting takes the lock because the level can change during a
// flow.
func (w *Wallet) KeyAttestationLevelSetting() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.KeyAttestationLevel
}

// Caller must hold w.mu. An exact ID wins over a prefix match. A missing or
// ambiguous prefix returns "".
func (w *Wallet) resolveIDLocked(idOrPrefix string) string {
	if idOrPrefix == "" {
		return ""
	}
	var prefixMatch string
	prefixCount := 0
	for _, c := range w.Credentials {
		if c.ID == idOrPrefix {
			return c.ID
		}
		if strings.HasPrefix(c.ID, idOrPrefix) {
			prefixMatch = c.ID
			prefixCount++
		}
	}
	if prefixCount == 1 {
		return prefixMatch
	}
	return ""
}

func (w *Wallet) GetCredential(id string) (StoredCredential, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	full := w.resolveIDLocked(id)
	for _, c := range w.Credentials {
		if c.ID == full {
			return c, true
		}
	}
	return StoredCredential{}, false
}

func (w *Wallet) SetLogSink(fn func(LogEntry)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logSink = fn
}

func (w *Wallet) AddLog(action, detail string, success bool) {
	w.AddLogDetails(action, detail, success, nil)
}

func (w *Wallet) AddLogDetails(action, detail string, success bool, details map[string]any) {
	w.AddLogPayload(action, detail, success, details, nil)
}

func (w *Wallet) AddLogPayload(action, detail string, success bool, details map[string]any, payload *LogPayload) {
	w.appendLogEntry(LogEntry{
		Time:    time.Now(),
		Action:  action,
		Detail:  detail,
		Success: success,
		Details: cloneLogDetails(details),
		Payload: payload,
	})
}

// AddWarning logs a successful action with a warning severity.
func (w *Wallet) AddWarning(action, detail string, details map[string]any) {
	w.appendLogEntry(LogEntry{
		Time:     time.Now(),
		Action:   action,
		Detail:   detail,
		Success:  true,
		Severity: severityWarning,
		Details:  cloneLogDetails(details),
	})
}

// Several findings share one log entry with the full list in its details.
func (w *Wallet) warnFindings(action, summary string, findings []string) {
	switch len(findings) {
	case 0:
		return
	case 1:
		w.AddWarning(action, findings[0], nil)
	default:
		w.AddWarning(action, findingsSummary(summary, findings), map[string]any{"findings": findings})
	}
}

// findingsSummary is the log line of several findings. One finding is its own
// line.
func findingsSummary(summary string, findings []string) string {
	if len(findings) == 1 {
		return findings[0]
	}
	return fmt.Sprintf("%s (%d findings, see details)", summary, len(findings))
}

// deviation is a failed check of the other party. Strict mode refuses the
// flow with refusal, or with detail when refusal is nil. Debug mode records
// a warning and goes on.
type deviation struct {
	action, event, detail string
	details               map[string]any
	refusal               error
}

func (w *Wallet) reportDeviation(d deviation) error {
	if w.Mode() == ValidationModeStrict {
		w.addProtocolLog(d.action, d.event, d.detail, false, d.details)
		if d.refusal != nil {
			return d.refusal
		}
		return errors.New(d.detail)
	}
	w.addProtocolWarning(d.action, d.event, d.detail, d.details)
	log.Printf("[Wallet] WARNING: %s", d.detail)
	return nil
}

// The log is bounded because every reload reads it. logTrimSlack lets the log
// grow a little so trimming copies once per batch of entries. An entry is
// bounded too, because a remote party controls the bodies it records.
const (
	maxLogEntries    = 1000
	logTrimSlack     = 256
	maxLogEntryBytes = 64 << 10
)

func (w *Wallet) appendLogEntry(entry LogEntry) {
	entry = boundedLogEntry(entry)
	w.mu.Lock()
	w.Log = append(w.Log, entry)
	if len(w.Log) >= maxLogEntries+logTrimSlack {
		// A fresh slice lets the trimmed entries be garbage collected.
		trimmed := make([]LogEntry, maxLogEntries)
		copy(trimmed, w.Log[len(w.Log)-maxLogEntries:])
		w.Log = trimmed
	}
	sink := w.logSink
	w.mu.Unlock()
	if sink != nil {
		sink(entry)
	}
}

// boundedLogEntry truncates the detail and the payload of an entry larger
// than maxLogEntryBytes. The truncated values say how long they were.
func boundedLogEntry(entry LogEntry) LogEntry {
	if raw, err := json.Marshal(entry); err == nil && len(raw) <= maxLogEntryBytes {
		return entry
	}
	limit := maxLogEntryBytes / 4
	entry.Detail = truncatedLogValue(entry.Detail, limit).(string)
	if entry.Payload != nil {
		payload := *entry.Payload
		payload.Body = truncatedLogValue(payload.Body, limit)
		payload.Wire = truncatedLogValue(payload.Wire, limit)
		entry.Payload = &payload
	}
	return entry
}

func truncatedLogValue(value any, limit int) any {
	text, ok := value.(string)
	if !ok {
		if value == nil {
			return nil
		}
		raw, err := json.Marshal(value)
		if err != nil || len(raw) <= limit {
			return value
		}
		text = string(raw)
	}
	if len(text) <= limit {
		return value
	}
	return fmt.Sprintf("%s… (truncated, %d bytes)", strings.ToValidUTF8(text[:limit], ""), len(text))
}

func cloneLogDetails(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	out := make(map[string]any, len(details))
	for key, value := range details {
		out[key] = value
	}
	return out
}

func (w *Wallet) ClearLog() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Log = nil
}

func (w *Wallet) GetLog() []LogEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]LogEntry, len(w.Log))
	copy(out, w.Log)
	return out
}

func LoadKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	privKey, err := keys.LoadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be an EC private key (P-256)")
	}
	return ecKey, nil
}

func credentialLabel(c StoredCredential) string {
	if c.VCT != "" {
		return c.VCT
	}
	if c.DocType != "" {
		return c.DocType
	}
	return c.ID
}

func userClaimCount(claims map[string]any) int {
	n := 0
	for key := range claims {
		if !sdjwt.IsProtocolClaim(key) {
			n++
		}
	}
	return n
}

func CredentialSummary(c StoredCredential) map[string]any {
	summary := map[string]any{
		"id":          c.ID,
		"format":      c.Format,
		"claims":      c.Claims,
		"claim_count": userClaimCount(c.Claims),
		"raw":         c.Raw,
	}
	if c.VCT != "" {
		summary["vct"] = c.VCT
	}
	if c.DocType != "" {
		summary["doctype"] = c.DocType
	}
	if c.Protected {
		summary["protected"] = true
	}
	// The UI shows a batch as one credential.
	if c.BatchGroup != "" {
		summary["batch"] = true
	}
	if disp := displayForListing(c); disp != nil {
		summary["display"] = disp
	}
	notBefore, expiry := CredentialValidity(c)
	if !notBefore.IsZero() {
		summary["valid_from"] = notBefore.UTC().Format(time.RFC3339)
	}
	if !expiry.IsZero() {
		summary["expires_at"] = expiry.UTC().Format(time.RFC3339)
	}
	if issued := CredentialIssuedAt(c); !issued.IsZero() {
		summary["issued_at"] = issued.UTC().Format(time.RFC3339)
	}
	if issuer := credentialIssuerIdentity(c); issuer != nil {
		summary["issuer"] = issuer
	}
	if signature := credentialSignatureState(c); signature != nil {
		summary["signature"] = signature
	}
	// Listings may be printed or logged, so they never carry the refresh token.
	if c.CanRenew() {
		summary["can_renew"] = true
	}
	// Set when the issuer key is a DID. The signature then stays unchecked.
	if did := credentialIssuerDID(c.Raw); did != "" {
		summary["issuer_key_did"] = did
	}
	return summary
}

func MarshalConsentRequest(r *ConsentRequest) map[string]any {
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
	if r.Type == ConsentTypePresentation || r.Type == ConsentTypeIssuancePresentation {
		m["client_auth"] = map[string]any{
			"signed": r.ClientAuthSigned,
			"detail": r.ClientAuthDetail,
		}
	}
	if r.ClientName != "" {
		m["client_name"] = r.ClientName
	}
	return m
}

func (w *Wallet) CredentialsJSON() ([]byte, error) {
	return w.CredentialsJSONWindow(0, 0)
}

// ListedCredentials lists each batch once.
func (w *Wallet) ListedCredentials() []StoredCredential {
	creds := w.GetCredentials()
	out := make([]StoredCredential, 0, len(creds))
	seen := make(map[string]bool)
	for _, c := range creds {
		if c.BatchGroup == "" {
			out = append(out, c)
			continue
		}
		if seen[c.BatchGroup] {
			continue
		}
		seen[c.BatchGroup] = true
		out = append(out, batchRepresentative(creds, c))
	}
	return out
}

// The copy bound to the wallet holder key represents its batch, so the listed ID
// stays stable while other copies rotate.
func batchRepresentative(creds []StoredCredential, member StoredCredential) StoredCredential {
	if member.BindingKeyPEM == "" {
		return member
	}
	for _, c := range creds {
		if c.BatchGroup == member.BatchGroup && c.BindingKeyPEM == "" {
			return c
		}
	}
	return member
}

// CredentialsJSONWindow returns all remaining credentials when limit is zero. An
// offset past the end returns an empty array.
func (w *Wallet) CredentialsJSONWindow(offset, limit int) ([]byte, error) {
	return json.Marshal(w.listedSummaries(offset, limit))
}

// CredentialsListingWindow omits raw credentials and claims to keep UI refreshes
// small.
func (w *Wallet) CredentialsListingWindow(offset, limit int) []map[string]any {
	summaries := w.listedSummaries(offset, limit)
	for _, s := range summaries {
		TrimCredentialListing(s)
	}
	return summaries
}

// TrimCredentialListing removes raw credentials and claims from a summary.
func TrimCredentialListing(summary map[string]any) {
	delete(summary, "raw")
	delete(summary, "claims")
}

func (w *Wallet) listedSummaries(offset, limit int) []map[string]any {
	creds := w.ListedCredentials()
	SortCredentialsNewestFirst(creds)
	if offset > len(creds) {
		offset = len(creds)
	}
	creds = creds[offset:]
	if limit > 0 && limit < len(creds) {
		creds = creds[:limit]
	}
	summaries := make([]map[string]any, len(creds))
	for i, c := range creds {
		summaries[i] = w.CredentialSummaryWithBatch(c)
	}
	return summaries
}

func (w *Wallet) BatchGroupSize(group string) int {
	if group == "" {
		return 0
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	n := 0
	for _, c := range w.Credentials {
		if c.BatchGroup == group {
			n++
		}
	}
	return n
}

// RestoreCredential puts back an import that a concurrent reload dropped. It keeps
// an existing copy with the same ID.
func (w *Wallet) RestoreCredential(cred StoredCredential) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, existing := range w.Credentials {
		if existing.ID == cred.ID {
			return
		}
	}
	w.Credentials = append(w.Credentials, cred)
}

// PutCredential replaces a credential with the same ID.
func (w *Wallet) PutCredential(cred StoredCredential) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == cred.ID {
			w.Credentials[i] = cred
			return
		}
	}
	w.makeCredentialRoomLocked()
	w.Credentials = append(w.Credentials, cred)
}

// Capacity bounds a wallet that visitors share, such as a public demo. Zero
// means no bound. Credentials and deferred issuances make room by dropping
// the oldest entry, so a flood doesn't lock out other visitors. Added
// providers and lists are refused when full, because each one changes what
// every check trusts.
type Capacity struct {
	Credentials, Deferred, TrustedEntities, TrustedLists int
}

func (w *Wallet) SetCapacity(c Capacity) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.capacity = c
}

// makeCredentialRoomLocked removes the oldest credentials that aren't
// protected until one more fits.
func (w *Wallet) makeCredentialRoomLocked() {
	if w.capacity.Credentials <= 0 {
		return
	}
	for len(w.Credentials) >= w.capacity.Credentials {
		i := slices.IndexFunc(w.Credentials, func(c StoredCredential) bool { return !c.Protected })
		if i < 0 {
			return
		}
		w.Credentials = slices.Delete(w.Credentials, i, i+1)
	}
}
