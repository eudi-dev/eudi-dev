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
	"log"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

const (
	issuancePath = "/api/issuance"
	// maxIssuanceConfigurations bounds the credential requests of one call.
	maxIssuanceConfigurations = 16
)

// KnownIssuer is a Credential Issuer this wallet can request credentials from.
// The ARF ISSU_23 note leaves that choice to the Wallet Provider.
type KnownIssuer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
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
// Issuer Identifier and the issuers named in the catalogue. Visitors of a public
// demo share the registrar, so there only the operator names issuers.
func (w *Wallet) knownIssuers() []KnownIssuer {
	var issuers []KnownIssuer
	add := func(name, issuer string) {
		if issuer != "" && !slices.ContainsFunc(issuers, func(k KnownIssuer) bool { return k.URL == issuer }) {
			issuers = append(issuers, KnownIssuer{Name: name, URL: issuer})
		}
	}
	if w.demoIssuerURL != nil {
		add(DemoIssuerName, w.demoIssuerURL())
	}
	if !w.operatorIssuersOnly {
		for _, party := range w.Registrar().RegisteredRelyingParties() {
			for _, service := range party.Services {
				add(service.ServiceTradeName, service.CredentialIssuer)
			}
		}
	}
	for _, entry := range w.Registrar().CatalogAttestations() {
		if parsed, err := url.Parse(entry.CredentialIssuer); err == nil && (entry.Operator || !w.operatorIssuersOnly) {
			add(parsed.Host, entry.CredentialIssuer)
		}
	}
	return issuers
}

// IssuableCredentials matches the catalogue against the metadata of the known
// issuers. An entry without an issuer is listed too, so the list shows every
// type of the registrar. Reading a list is no issuance, so it writes no log.
func (w *Wallet) IssuableCredentials() []IssuableCredential {
	issuers := w.knownIssuers()
	offered := make([]map[string]any, len(issuers))
	ignoreProblem := func(findings.Finding) error { return nil }
	var fetches sync.WaitGroup
	for i, issuer := range issuers {
		fetches.Go(func() {
			metadata, _, err := fetchIssuerMetadataDocument(w.HTTPClient(), issuer.URL, w.ARFChecks(), ignoreProblem)
			if err != nil {
				log.Printf("[VCI] Skipping issuer %s: %v", issuer.URL, err)
				return
			}
			offered[i] = jsonutil.GetMap(metadata, "credential_configurations_supported")
		})
	}
	fetches.Wait()
	credentials := []IssuableCredential{}
	for _, entry := range w.Registrar().CatalogAttestations() {
		credential := IssuableCredential{ID: entry.Schema.ID, Name: entry.Name, Category: entry.Category, Issuers: []IssuableIssuer{}}
		for i, issuer := range issuers {
			if ids := matchingConfigurations(offered[i], entry); len(ids) > 0 {
				credential.Issuers = append(credential.Issuers, IssuableIssuer{KnownIssuer: issuer, Configurations: ids, Formats: configurationFormats(offered[i], ids)})
			}
		}
		credentials = append(credentials, credential)
	}
	return credentials
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

// walletInitiatedOffer describes a request the wallet starts itself as an offer
// without issuer_state. OpenID4VCI 1.0 §3.4 step (1a) starts the Authorization
// Code Flow in the Wallet, and the offer path then does the same steps.
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
	writeJSON(w, http.StatusOK, s.wallet.IssuableCredentials())
}

// handleStartIssuance requests the credential configurations of an issuer under
// one authorization. On a public demo the issuer must be a known one, because
// visitors share this list.
func (s *Server) handleStartIssuance(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Issuer           string   `json:"issuer"`
		ConfigurationIDs []string `json:"credential_configuration_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	if body.Issuer == "" || len(body.ConfigurationIDs) == 0 {
		apierror.WriteStatus(w, http.StatusBadRequest, "issuer and credential_configuration_ids are required")
		return
	}
	if len(body.ConfigurationIDs) > maxIssuanceConfigurations {
		apierror.WriteStatus(w, http.StatusBadRequest, fmt.Sprintf("a request can list %d credential configurations", maxIssuanceConfigurations))
		return
	}
	if len(slices.Compact(slices.Sorted(slices.Values(body.ConfigurationIDs)))) != len(body.ConfigurationIDs) {
		apierror.WriteStatus(w, http.StatusBadRequest, "credential_configuration_ids lists a configuration twice")
		return
	}
	known := slices.ContainsFunc(s.wallet.knownIssuers(), func(k KnownIssuer) bool { return k.URL == body.Issuer })
	if s.demo != nil && !known {
		apierror.WriteStatus(w, http.StatusBadRequest, "this wallet doesn't know the issuer")
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

// flagObtainableCredentials marks the queries without a credential whose type is
// in the catalogue. It reads the catalogue only, so the consent dialog waits for
// no issuer.
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

// obtainableOptions lets a wallet without any credential ask for what the query
// needs. Without an entry in the catalogue there is nothing to offer.
func (w *Wallet) obtainableOptions(query map[string]any) *consent.CredentialOptions {
	queries, _ := query["credentials"].([]any)
	options := &consent.CredentialOptions{}
	for _, value := range queries {
		entry, _ := value.(map[string]any)
		options.Queries = append(options.Queries, consent.QueryOptions{ID: jsonutil.GetString(entry, "id"), Multiple: entry["multiple"] == true, Candidates: []consent.Match{}})
	}
	w.flagObtainableCredentials(query, options)
	if !slices.ContainsFunc(options.Queries, func(q consent.QueryOptions) bool { return len(q.Obtainable) > 0 }) {
		return nil
	}
	return options
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
// an issuance. Only a dialog with a query that gains its first credential
// changes, so a selection the user made elsewhere stays.
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
		w.flagObtainableCredentials(req.DCQLQuery, options)
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
