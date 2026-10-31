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
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

const (
	issuancePath                   = "/api/issuance"
	sourceInteractiveAuthorization = "interactive_authorization"
	// maxIssuanceConfigurations bounds the credential requests of one call.
	maxIssuanceConfigurations = 16
	// maxListedConfigurations limits what the list keeps of one issuer.
	maxListedConfigurations = 256
	maxListedDisplays       = 64
	maxListedText           = 1024
)

// KnownIssuer is a Credential Issuer that the wallet can request credentials from.
// The ARF ISSU_23 note leaves that choice to the Wallet Provider.
type KnownIssuer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// operator is the demo issuer or an issuer of the operator's catalogue.
	operator bool
}

// IssuableCredential is an attestation type of the catalogue with the issuers
// that offer it. Each issuer lists one credential configuration per format.
type IssuableCredential struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Category string           `json:"category,omitempty"`
	Issuers  []IssuableIssuer `json:"issuers"`
}

// IssuableIssuer is an issuer of an IssuableCredential.
type IssuableIssuer struct {
	KnownIssuer
	Configurations []string `json:"credential_configuration_ids"`
	Formats        []string `json:"formats"`
}

// SetDemoIssuer makes the demo issuer a known issuer. url returns its Credential
// Issuer Identifier.
func (w *Wallet) SetDemoIssuer(url func() string) {
	w.demoIssuerURL = url
}

// knownIssuers are the demo issuer, the registered services with a Credential
// Issuer Identifier and the issuers named in the catalogue.
func (w *Wallet) knownIssuers() []KnownIssuer {
	var issuers []KnownIssuer
	add := func(name, issuer string) {
		if issuer != "" && !slices.ContainsFunc(issuers, func(k KnownIssuer) bool { return k.URL == issuer }) {
			issuers = append(issuers, KnownIssuer{Name: name, URL: issuer})
		}
	}
	if w.demoIssuerURL != nil {
		issuers = append(issuers, KnownIssuer{Name: DemoIssuerName, URL: w.demoIssuerURL(), operator: true})
	}
	if !w.sharedRegistrar {
		for _, party := range w.Registrar().RegisteredRelyingParties() {
			for _, service := range party.Services {
				if service.CredentialIssuer != "" {
					add(strings.TrimSpace(service.ServiceTradeName+" ("+issuerHost(service.CredentialIssuer)+")"), service.CredentialIssuer)
				}
			}
		}
	}
	for _, entry := range w.Registrar().CatalogAttestations() {
		add(issuerHost(entry.CredentialIssuer), entry.CredentialIssuer)
		if i := slices.IndexFunc(issuers, func(k KnownIssuer) bool { return k.URL == entry.CredentialIssuer }); i >= 0 && entry.Operator {
			issuers[i].operator = true
		}
	}
	return issuers
}

// issuerHost names an issuer by its address, because anyone can choose a trade
// name on a shared registrar. Several issuers can share a host.
func issuerHost(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return issuer
	}
	return parsed.Host + parsed.Path
}

// IssuableCredentials matches the catalogue against the metadata of the known
// issuers. Every entry is listed, also without an issuer. The CredentialIssuer of
// an entry is always listed. Without metadata for the type it has no
// configurations, and a request uses the ID of the entry. loading is set while
// metadata is on its way, and a later call can list more.
func (w *Wallet) IssuableCredentials() (credentials []IssuableCredential, loading bool) {
	issuers := w.knownIssuers()
	offered, loading := w.issuerOffers.read(issuers, w.fetchListedOffer)
	credentials = []IssuableCredential{}
	for _, entry := range w.Registrar().CatalogAttestations() {
		credential := IssuableCredential{ID: entry.Schema.ID, Name: entry.Name, Category: entry.Category, Issuers: []IssuableIssuer{}}
		for i, issuer := range issuers {
			// Visitors of a public demo choose their issuers and the metadata, so
			// one can't attach itself to the entries of others.
			if w.sharedRegistrar && !issuer.operator && issuer.URL != entry.CredentialIssuer {
				continue
			}
			if ids := matchingConfigurations(offered[i], entry); len(ids) > 0 {
				credential.Issuers = append(credential.Issuers, IssuableIssuer{KnownIssuer: issuer, Configurations: ids, Formats: configurationFormats(offered[i], ids)})
			}
		}
		named := slices.IndexFunc(issuers, func(k KnownIssuer) bool { return k.URL == entry.CredentialIssuer })
		if named >= 0 && !slices.ContainsFunc(credential.Issuers, func(i IssuableIssuer) bool { return i.URL == entry.CredentialIssuer }) {
			credential.Issuers = append(credential.Issuers, IssuableIssuer{KnownIssuer: issuers[named], Configurations: []string{}, Formats: []string{}})
		}
		credentials = append(credentials, credential)
	}
	return credentials, loading
}

// fetchIssuerOffer reads the configurations of an issuer. It writes no activity
// log, because the list reads issuers without any issuance.
func (w *Wallet) fetchIssuerOffer(issuer string) (map[string]any, error) {
	ignoreProblem := func(findings.Finding) error { return nil }
	metadata, _, err := fetchIssuerMetadataDocument(w.HTTPClient(), issuer, w.ARFChecks(), ignoreProblem)
	if err != nil {
		return nil, err
	}
	return jsonutil.GetMap(metadata, "credential_configurations_supported"), nil
}

// matchingConfigurations returns the configurations of an entry. ARF ISSU_12a:
// the wallet requests an attestation "in all formats offered". National PIDs
// share one mdoc doctype, so a format with several configurations keeps the ones
// with the display name of the entry.
func matchingConfigurations(configurations map[string]any, entry registrar.CatalogAttestation) []string {
	byFormat := map[string][]string{}
	for id, value := range configurations {
		configuration, ok := value.(map[string]any)
		if !ok {
			continue
		}
		format := jsonutil.GetString(configuration, "format")
		typ := jsonutil.GetString(configuration, "vct")
		if format == credtype.FormatMDOC {
			typ = jsonutil.GetString(configuration, "doctype")
		}
		if slices.ContainsFunc(entry.Credentials, func(c registrar.CatalogCredential) bool { return c.Format == format && c.Type == typ }) {
			byFormat[format] = append(byFormat[format], id)
		}
	}
	var ids []string
	for _, candidates := range byFormat {
		named := slices.DeleteFunc(slices.Clone(candidates), func(id string) bool {
			return !hasDisplayName(jsonutil.GetMap(configurations, id), entry.Name)
		})
		if len(named) > 0 {
			candidates = named
		}
		ids = append(ids, candidates...)
	}
	slices.Sort(ids)
	return ids
}

func configurationFormats(configurations map[string]any, ids []string) []string {
	var formats []string
	for _, id := range ids {
		if format := jsonutil.GetString(jsonutil.GetMap(configurations, id), "format"); !slices.Contains(formats, format) {
			formats = append(formats, format)
		}
	}
	return formats
}

// hasDisplayName reads the display of OpenID4VCI 1.0 §12.2.4.
func hasDisplayName(configuration map[string]any, name string) bool {
	display, _ := jsonutil.GetMap(configuration, "credential_metadata")["display"].([]any)
	return slices.ContainsFunc(display, func(value any) bool {
		entry, _ := value.(map[string]any)
		return jsonutil.GetString(entry, "name") == name
	})
}

// walletInitiatedOffer builds an offer without issuer_state for the wallet's own
// request. OpenID4VCI 1.0 §3.4 step (1a) starts the Authorization Code Flow in the
// Wallet. After that the steps are the same as for an offer.
func walletInitiatedOffer(issuer string, configurationIDs []string) (string, error) {
	offer, err := json.Marshal(map[string]any{
		"credential_issuer":            issuer,
		"credential_configuration_ids": configurationIDs,
		"grants":                       map[string]any{"authorization_code": map[string]any{}},
	})
	if err != nil {
		return "", err
	}
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offer)), nil
}

func (s *Server) handleListIssuable(w http.ResponseWriter, _ *http.Request) {
	credentials, loading := s.wallet.IssuableCredentials()
	writeJSON(w, http.StatusOK, map[string]any{"credentials": credentials, "loading": loading})
}

// handleStartIssuance requests the credential configurations of an issuer under
// one authorization.
func (s *Server) handleStartIssuance(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Issuer           string   `json:"issuer"`
		ConfigurationIDs []string `json:"credential_configuration_ids"`
		Attestation      string   `json:"attestation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	if body.Issuer == "" || (len(body.ConfigurationIDs) == 0) == (body.Attestation == "") {
		apierror.WriteStatus(w, http.StatusBadRequest, "issuer and either credential_configuration_ids or attestation are required")
		return
	}
	if len(slices.Compact(slices.Sorted(slices.Values(body.ConfigurationIDs)))) != len(body.ConfigurationIDs) {
		apierror.WriteStatus(w, http.StatusBadRequest, "credential_configuration_ids lists a configuration twice")
		return
	}
	if body.Attestation != "" {
		ids, status, err := s.wallet.configurationsOf(body.Issuer, body.Attestation)
		if err != nil {
			apierror.WriteStatusErr(w, status, err)
			return
		}
		body.ConfigurationIDs = ids
	}
	if len(body.ConfigurationIDs) > maxIssuanceConfigurations {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("a request can list %d credential configurations", maxIssuanceConfigurations))
		return
	}
	uri, err := walletInitiatedOffer(body.Issuer, body.ConfigurationIDs)
	if err != nil {
		apierror.WriteStatusErr(w, http.StatusInternalServerError, err)
		return
	}
	s.wallet.Consents().ClearLastError(callerOwners(r))
	// The caller opens the sign-in URL itself, so the wallet page keeps its place
	// in a running presentation.
	s.processOfferDirectly(w, uri, OfferOptions{
		Owner:                    requestOwner(r),
		ConfigurationID:          body.ConfigurationIDs[0],
		AdditionalConfigurations: body.ConfigurationIDs[1:],
		CallerNavigates:          true,
	}, false)
}

func (w *Wallet) fetchListedOffer(issuer string) (map[string]any, error) {
	configurations, err := w.fetchIssuerOffer(issuer)
	return listedConfigurations(configurations), err
}

// listedConfigurations keeps what matching needs. Visitors of a public demo choose
// the issuers, so the cache must not hold their full metadata.
func listedConfigurations(configurations map[string]any) map[string]any {
	listed := make(map[string]any, min(len(configurations), maxListedConfigurations))
	for _, id := range slices.Sorted(maps.Keys(configurations)) {
		if len(listed) == maxListedConfigurations {
			break
		}
		configuration, ok := configurations[id].(map[string]any)
		if !ok {
			continue
		}
		kept := map[string]any{}
		for _, field := range []string{"format", "vct", "doctype"} {
			if value, ok := configuration[field].(string); ok && len(value) <= maxListedText {
				kept[field] = value
			}
		}
		var display []any
		metadata, _ := jsonutil.GetMap(configuration, "credential_metadata")["display"].([]any)
		for _, value := range metadata[:min(len(metadata), maxListedDisplays)] {
			entry, _ := value.(map[string]any)
			if name := jsonutil.GetString(entry, "name"); len(name) <= maxListedText {
				display = append(display, map[string]any{"name": name})
			}
		}
		kept["credential_metadata"] = map[string]any{"display": display}
		listed[id] = kept
	}
	return listed
}

// configurationsOf asks the issuer for the configurations of a catalogue entry.
// Unlike the list, this waits for the issuer, because the user just clicked
// Request.
func (w *Wallet) configurationsOf(issuer, attestation string) ([]string, int, error) {
	entry, ok := w.Registrar().CatalogAttestation(attestation)
	if !ok || entry.CredentialIssuer != issuer {
		return nil, http.StatusBadRequest, fmt.Errorf("the catalogue has no attestation %s with the issuer %s", attestation, issuer)
	}
	configurations, err := w.fetchIssuerOffer(issuer)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("the wallet can't read the metadata of %s: %w", issuer, err)
	}
	ids := matchingConfigurations(configurations, entry)
	if len(ids) == 0 {
		return nil, http.StatusUnprocessableEntity, fmt.Errorf("the issuer %s doesn't offer %s", issuer, entry.Name)
	}
	return ids, 0, nil
}

// flagObtainableCredentials marks the queries without a credential whose type is
// in the catalogue. It reads the catalogue only, so the consent dialog never
// waits for an issuer.
func (w *Wallet) flagObtainableCredentials(query map[string]any, options *consent.CredentialOptions) {
	if options == nil {
		return
	}
	queries, _ := query["credentials"].([]any)
	for i := range options.Queries {
		option := &options.Queries[i]
		if len(option.Candidates) > 0 {
			continue
		}
		for _, value := range queries {
			entry, _ := value.(map[string]any)
			if jsonutil.GetString(entry, "id") == option.ID {
				option.Obtainable = w.obtainableCredentials(entry)
			}
		}
	}
}

// offersIssuance says whether a presentation dialog can request a missing
// credential. A Digital Credentials API request runs its dialog in a separate
// window, and the issuer sign-in would hide that window. A presentation for an
// issuer runs during a request, and only one runs at a time.
func offersIssuance(authReq *oid4vp.Request) bool {
	return authReq.Source != oid4vp.SourceDCAPI && authReq.Source != sourceInteractiveAuthorization
}

// obtainableOptions builds the dialog options for a wallet without a matching
// credential. It returns nil unless the catalogue can answer the request. The
// credential then appears in the dialog, and matching applies the credential sets.
func (w *Wallet) obtainableOptions(query map[string]any) *consent.CredentialOptions {
	queries, _ := query["credentials"].([]any)
	options := &consent.CredentialOptions{}
	for _, value := range queries {
		entry, _ := value.(map[string]any)
		options.Queries = append(options.Queries, consent.QueryOptions{ID: jsonutil.GetString(entry, "id"), Multiple: entry["multiple"] == true, Candidates: []consent.Match{}})
	}
	w.flagObtainableCredentials(query, options)
	obtainable := map[string]bool{}
	for _, option := range options.Queries {
		obtainable[option.ID] = len(option.Obtainable) > 0
	}
	if !canBeAnswered(query, obtainable) {
		return nil
	}
	return options
}

// canBeAnswered applies OpenID4VP 1.0 §6.4.2 to the queries that can get a
// credential. Without credential_sets every query is required. A request with
// optional sets only still needs one query that can get a credential.
func canBeAnswered(query map[string]any, obtainable map[string]bool) bool {
	values := slices.Collect(maps.Values(obtainable))
	sets, _ := query["credential_sets"].([]any)
	if len(sets) == 0 {
		return len(values) > 0 && !slices.Contains(values, false)
	}
	if !slices.Contains(values, true) {
		return false
	}
	for _, value := range sets {
		set, _ := value.(map[string]any)
		if required, present := set["required"].(bool); present && !required {
			continue
		}
		options, _ := set["options"].([]any)
		if !slices.ContainsFunc(options, func(option any) bool {
			ids, _ := option.([]any)
			return len(ids) > 0 && !slices.ContainsFunc(ids, func(id any) bool {
				text, _ := id.(string)
				return !obtainable[text]
			})
		}) {
			return false
		}
	}
	return true
}

func (w *Wallet) obtainableCredentials(query map[string]any) []consent.Obtainable {
	meta := jsonutil.GetMap(query, "meta")
	types, _ := meta["vct_values"].([]any)
	if doctype := jsonutil.GetString(meta, "doctype_value"); doctype != "" {
		types = append(types, doctype)
	}
	format := jsonutil.GetString(query, "format")
	var obtainable []consent.Obtainable
	for _, entry := range w.Registrar().CatalogAttestations() {
		if slices.ContainsFunc(entry.Credentials, func(c registrar.CatalogCredential) bool {
			return c.Format == format && slices.Contains(types, any(c.Type))
		}) {
			obtainable = append(obtainable, consent.Obtainable{ID: entry.Schema.ID, Name: entry.Name})
		}
	}
	return obtainable
}

// refreshWaitingPresentations matches the open presentation dialogs again after
// an issuance. A dialog changes only when a query gets its first credential, so
// the user's selection in the other queries stays.
func (w *Wallet) refreshWaitingPresentations() {
	for _, req := range w.Consents().Pending() {
		if req.DCQLQuery == nil || req.Type == consent.TypeIssuance {
			continue
		}
		matches, options := w.matchDCQL(req.DCQLQuery)
		if options == nil || !answersMoreQueries(w.Consents().Options(req), options) {
			continue
		}
		w.flagRevokedCertificates(matches, options)
		if !req.NoIssuance {
			w.flagObtainableCredentials(req.DCQLQuery, options)
		}
		w.Consents().UpdateOptions(req.ID, matches, options)
	}
}

func answersMoreQueries(before, after *consent.CredentialOptions) bool {
	if before == nil {
		return true
	}
	return slices.ContainsFunc(after.Queries, func(query consent.QueryOptions) bool {
		return len(query.Candidates) > 0 && slices.ContainsFunc(before.Queries, func(old consent.QueryOptions) bool {
			return old.ID == query.ID && len(old.Candidates) == 0
		})
	})
}
