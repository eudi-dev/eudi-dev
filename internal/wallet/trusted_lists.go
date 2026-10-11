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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

// The wallet publishes the providers of access certificates and of
// registration certificates on lists of their own (ARF RPACANot_05 and
// RPACANot_05a). The URIs come from ETSI TS 119 602 V1.1.1 Annexes F and G.
// Annex G spells its status determination URI "WRPRCrovidersList", and the
// constant keeps that spelling.
const (
	accessCAListType              = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"
	accessCAStatusDetermination   = "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU"
	accessCASchemeCommunityRules  = "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU"
	accessCAIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
	accessCARevocationServiceType = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation"

	registrarListType              = "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList"
	registrarStatusDetermination   = "http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU"
	registrarSchemeCommunityRules  = "http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU"
	registrarIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance"
	registrarRevocationServiceType = "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation"

	accessCAListID  = "access-ca"
	registrarListID = "registrar"
	// trustedListCAID takes the CAs of trusted list operators, like
	// --trusted-list-ca. The wallet doesn't publish it.
	trustedListCAID  = "trusted-list-ca"
	walletProviderID = "wallet-provider"
	// listOfListsID is the list that points to all of the wallet's trusted
	// lists (ETSI TS 119 602 V1.1.1 §6.3.13).
	listOfListsID          = ListOfTrustedListsID
	listOfTrustedListsType = "https://eudi-test.dev/LoTEType/ListOfTrustedLists"
	listOperatorName       = "EUDI Dev Wallet"
)

// ListOfTrustedListsID is the ID of the wallet's list of trusted lists.
const ListOfTrustedListsID = "lists"

// listsCredentialProviders reports whether the group lists the providers of
// credentials, as opposed to wallet providers, access CAs and registrars.
func (g TrustListGroup) listsCredentialProviders() bool {
	switch g.Profile.LoTEType {
	case walletProviderTrustListType, accessCAListType, registrarListType:
		return false
	}
	return true
}

func accessCATrustListProfile() trustListProfile {
	return trustListProfile{
		LoTEType:                    accessCAListType,
		StatusDeterminationApproach: accessCAStatusDetermination,
		SchemeTypeCommunityRules:    accessCASchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         accessCAIssuanceServiceType,
		RevocationServiceType:       accessCARevocationServiceType,
		IssuanceServiceName:         "Access Certificate Issuance",
		RevocationServiceName:       "Access Certificate Revocation",
		EntityName:                  "EUDI Dev Relying Party Access CA",
	}
}

func registrarTrustListProfile() trustListProfile {
	return trustListProfile{
		LoTEType:                    registrarListType,
		StatusDeterminationApproach: registrarStatusDetermination,
		SchemeTypeCommunityRules:    registrarSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         registrarIssuanceServiceType,
		RevocationServiceType:       registrarRevocationServiceType,
		IssuanceServiceName:         "Registration Certificate Issuance",
		RevocationServiceName:       "Registration Certificate Revocation",
		EntityName:                  "EUDI Dev Registrar",
	}
}

// TrustedEntity is a provider added by a user to one of the wallet's trusted
// lists. The wallet signs the list with the entity on it, so the entity's
// certificates anchor the --arf checks.
type TrustedEntity struct {
	ID   string `json:"id"`
	List string `json:"list"`
	Name string `json:"name"`
	// Certificates are base64 DER certificates of the provider's CAs or
	// signers.
	Certificates []string `json:"certificates"`
}

// ErrTrustNotFound reports a trusted entity or list that the wallet does not
// have.
var ErrTrustNotFound = errors.New("not on the wallet's trusted lists")

// ErrTrustFull reports that the wallet holds as many added providers or lists
// as its capacity allows.
var ErrTrustFull = errors.New("the wallet is full")

// TrustedEntityLists are the wallet lists that take trusted entities.
func TrustedEntityLists() []string {
	return append(slices.Clone(credtemplate.Categories), walletProviderID, accessCAListID, registrarListID, trustedListCAID)
}

// AddTrustedEntity puts a provider with the certificates in PEM on the list.
// The same certificates on the same list replace the earlier entry.
func (w *Wallet) AddTrustedEntity(list, name, certificatesPEM string) (TrustedEntity, error) {
	entity, err := NewTrustedEntity(list, name, certificatesPEM)
	if err != nil {
		return TrustedEntity{}, err
	}
	return entity, w.storeTrustedEntity(entity)
}

// NewTrustedEntity reads the provider with the certificates in PEM. Its ID
// follows from the list and the certificates.
func NewTrustedEntity(list, name, certificatesPEM string) (TrustedEntity, error) {
	list, name = strings.TrimSpace(list), strings.TrimSpace(name)
	if !slices.Contains(TrustedEntityLists(), list) {
		return TrustedEntity{}, fmt.Errorf("list %q is not one of %s", list, strings.Join(TrustedEntityLists(), ", "))
	}
	certs, err := keys.ParseCertificatesPEM([]byte(certificatesPEM))
	if err != nil {
		return TrustedEntity{}, fmt.Errorf("the certificates: %w", err)
	}
	entity := TrustedEntity{List: list, Name: firstNonEmpty(name, certs[0].Subject.CommonName, "Trusted provider")}
	digest := sha256.New()
	digest.Write([]byte(list))
	for _, cert := range certs {
		entity.Certificates = append(entity.Certificates, base64.StdEncoding.EncodeToString(cert.Raw))
		digest.Write(cert.Raw)
	}
	entity.ID = hex.EncodeToString(digest.Sum(nil)[:8])
	return entity, nil
}

// certificates decodes the stored base64 DER certificates.
func (e TrustedEntity) certificates() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(e.Certificates))
	for _, encoded := range e.Certificates {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (w *Wallet) storeTrustedEntity(entity TrustedEntity) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	others := slices.DeleteFunc(slices.Clone(w.TrustedEntities), func(e TrustedEntity) bool { return e.ID == entity.ID })
	if limit := w.capacity.TrustedEntities; limit > 0 && len(others) >= limit {
		return fmt.Errorf("%w: it holds at most %d added providers. Remove one first", ErrTrustFull, limit)
	}
	w.TrustedEntities = append(others, entity)
	return nil
}

// RemoveTrustedEntity takes a provider off its list.
func (w *Wallet) RemoveTrustedEntity(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.TrustedEntities)
	w.TrustedEntities = slices.DeleteFunc(w.TrustedEntities, func(e TrustedEntity) bool { return e.ID == id })
	if len(w.TrustedEntities) == before {
		return fmt.Errorf("%w: %q", ErrTrustNotFound, id)
	}
	return nil
}

// ListTrustedEntities returns the entities added by users.
func (w *Wallet) ListTrustedEntities() []TrustedEntity {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return slices.Clone(w.TrustedEntities)
}

// trustListEntities returns the entities on a wallet list besides the
// wallet's own provider: those added by users and, on the access-ca and
// registrar lists, the CAs from --relying-party-ca. Their CAs anchor both the
// issued certificates and the status lists.
func (w *Wallet) trustListEntities(listID string) []trustListEntity {
	var out []trustListEntity
	for _, entity := range w.ListTrustedEntities() {
		if entity.List == listID {
			out = append(out, trustListEntity{Name: entity.Name, Issuance: entity.Certificates, Revocation: entity.Certificates})
		}
	}
	if listID == accessCAListID || listID == registrarListID {
		w.mu.RLock()
		configured, err := keys.ParseCertificatesPEM(w.RelyingPartyCAPEM)
		w.mu.RUnlock()
		if err == nil {
			for _, cert := range configured {
				encoded := base64.StdEncoding.EncodeToString(cert.Raw)
				out = append(out, trustListEntity{Name: firstNonEmpty(cert.Subject.CommonName, "Relying party CA"), Issuance: []string{encoded}, Revocation: []string{encoded}})
			}
		}
	}
	return out
}

// AddTrustedList puts an external list of trusted entities on the wallet's
// list of trusted lists. The --arf checks then take anchors from it. Strict
// mode refuses an unreadable list. Debug mode adds it and reports why it can't
// be read.
func (w *Wallet) AddTrustedList(rawURL string) (TrustedListLink, error) {
	if err := w.trustedListRoom(rawURL); err != nil {
		return TrustedListLink{}, err
	}
	link, err := w.CheckTrustedList(rawURL)
	if err != nil {
		return TrustedListLink{}, err
	}
	return link, w.storeTrustedList(link.URL)
}

// CheckTrustedList reads an external list before it is added. Strict mode
// refuses a list the wallet can't read. Debug mode reports why in the link.
func (w *Wallet) CheckTrustedList(rawURL string) (TrustedListLink, error) {
	rawURL = strings.TrimSpace(rawURL)
	if !format.IsWebURL(rawURL) {
		return TrustedListLink{}, fmt.Errorf("%q is not an http or https URL", rawURL)
	}
	w.listCacheMu.Lock()
	delete(w.listCache, rawURL)
	w.listCacheMu.Unlock()
	link := TrustedListLink{URL: rawURL}
	if _, err := w.readTrustedList(rawURL); err != nil {
		if w.Mode() == ValidationModeStrict {
			return TrustedListLink{}, fmt.Errorf("the wallet can't use %s: %w", rawURL, err)
		}
		link.Error = err.Error()
	}
	return link, nil
}

// listCacheBound keeps every list the wallet reads itself in the cache,
// together with the lists they point to.
func (w *Wallet) listCacheBound() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return (len(w.ConfiguredTrustedListURLs)+len(w.AddedTrustedLists))*(1+maxFollowedPointers) + requestedListSlots
}

// trustedListRoom reports whether the wallet can add the list. A list it
// already has always fits.
func (w *Wallet) trustedListRoom(rawURL string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.trustedListRoomLocked(strings.TrimSpace(rawURL))
}

func (w *Wallet) trustedListRoomLocked(rawURL string) error {
	limit := w.capacity.TrustedLists
	if limit <= 0 || slices.Contains(w.AddedTrustedLists, rawURL) || len(w.AddedTrustedLists) < limit {
		return nil
	}
	return fmt.Errorf("%w: it holds at most %d added lists. Remove one first", ErrTrustFull, limit)
}

func (w *Wallet) storeTrustedList(rawURL string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.trustedListRoomLocked(rawURL); err != nil {
		return err
	}
	if !slices.Contains(w.AddedTrustedLists, rawURL) {
		w.AddedTrustedLists = append(w.AddedTrustedLists, rawURL)
	}
	return nil
}

// RemoveTrustedList takes an external list off the list of trusted lists.
func (w *Wallet) RemoveTrustedList(rawURL string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.AddedTrustedLists)
	w.AddedTrustedLists = slices.DeleteFunc(w.AddedTrustedLists, func(u string) bool { return u == strings.TrimSpace(rawURL) })
	if len(w.AddedTrustedLists) == before {
		return fmt.Errorf("%w: %q", ErrTrustNotFound, rawURL)
	}
	return nil
}

// ExternalTrustedLists are the external lists on the list of trusted lists:
// the ones from --trusted-list and the ones users added.
func (w *Wallet) ExternalTrustedLists() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := slices.Clone(w.ConfiguredTrustedListURLs)
	for _, u := range w.AddedTrustedLists {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// ownTrustListURL is where the wallet publishes one of its lists.
func (w *Wallet) ownTrustListURL(id string) string {
	return w.RegistrarBase() + "/api/trustlists/" + id
}

// The wallet reuses a fetched list for listCacheTTL, because an operator can
// publish a list before its next update (ETSI TS 119 602 V1.1.1 §6.3.15). A
// failed fetch is reused for failedListCacheTTL, so an unreachable list can't
// slow down every check.
const (
	listCacheTTL       = 5 * time.Minute
	failedListCacheTTL = time.Minute
	// requestedListSlots is the room in the list cache for lists that
	// requests name, besides the lists the wallet reads itself. Any visitor
	// can name a list URL.
	requestedListSlots = 16
	// maxFollowedPointers caps the lists the wallet reads from one external
	// list of trusted lists.
	maxFollowedPointers = 20
)

type cachedList struct {
	raw     string
	err     error
	fetched time.Time
}

// ownTrustListID returns the ID of one of the wallet's own lists. The URL
// compares like sameURL, so another spelling of the wallet's origin matches.
func (w *Wallet) ownTrustListID(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	base, err := url.Parse(w.RegistrarBase())
	if err != nil || !sameOrigin(u, base) {
		return "", false
	}
	return strings.CutPrefix(u.Path, strings.TrimSuffix(base.Path, "/")+"/api/trustlists/")
}

// rawTrustedList builds one of the wallet's own lists in process, because the
// wallet may not serve them over HTTP. It fetches every other list.
func (w *Wallet) rawTrustedList(rawURL string) (string, error) {
	if id, ok := w.ownTrustListID(rawURL); ok {
		group, found := FindTrustListGroupForWallet(w, id, "", "")
		if !found {
			return "", fmt.Errorf("the wallet has no trusted list %q", id)
		}
		return GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, "/api/trustlists/"+group.ID)
	}
	w.listCacheMu.Lock()
	cached, ok := w.listCache[rawURL]
	w.listCacheMu.Unlock()
	if ok && (cached.err == nil && time.Since(cached.fetched) < listCacheTTL || cached.err != nil && time.Since(cached.fetched) < failedListCacheTTL) {
		return cached.raw, cached.err
	}
	fetched, err, _ := w.listFetches.Do(rawURL, func() (any, error) {
		raw, err := format.FetchURL(rawURL, w.HTTPClient())
		bound := w.listCacheBound()
		w.listCacheMu.Lock()
		if w.listCache == nil {
			w.listCache = map[string]cachedList{}
		}
		for len(w.listCache) >= bound {
			oldest := ""
			for u, c := range w.listCache {
				if oldest == "" || c.fetched.Before(w.listCache[oldest].fetched) {
					oldest = u
				}
			}
			delete(w.listCache, oldest)
		}
		w.listCache[rawURL] = cachedList{raw: raw, err: err, fetched: time.Now()}
		w.listCacheMu.Unlock()
		return raw, err
	})
	if err != nil {
		return "", err
	}
	return fetched.(string), nil
}

// readTrustedList returns a list signed by a trusted list operator. Under the
// ARF, that signature is why the wallet accepts the trust anchors on the list
// (PPNot_05, TLPub_05, TLPub_07).
func (w *Wallet) readTrustedList(rawURL string) (*trustlist.TrustList, error) {
	operators, err := w.TrustListCAs()
	if err != nil {
		return nil, err
	}
	return w.readListSignedBy(rawURL, operators)
}

// readListSignedBy returns the list if its signer chains to one of the
// certificates and the list is current.
func (w *Wallet) readListSignedBy(rawURL string, signers []*x509.Certificate) (*trustlist.TrustList, error) {
	raw, err := w.rawTrustedList(rawURL)
	if err != nil {
		return nil, err
	}
	if err := verifyTrustListSigner(raw, signers); err != nil {
		return nil, err
	}
	list, err := trustlist.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing the trusted list: %w", err)
	}
	if err := list.Current(time.Now()); err != nil {
		return nil, err
	}
	return list, nil
}

// TrustedListURLs are the lists on the wallet's list of trusted lists: its
// own lists and the external ones.
func (w *Wallet) TrustedListURLs() []string {
	var urls []string
	for _, group := range TrustListGroupsForWallet(w) {
		urls = append(urls, w.ownTrustListURL(group.ID))
	}
	return append(urls, w.ExternalTrustedLists()...)
}

// trustedList is a list read by the wallet, or the error from reading it. Via
// is the list of trusted lists that points to it.
type trustedList struct {
	URL  string
	Via  string
	List *trustlist.TrustList
	Err  error
}

// trustedLists reads the wallet's own lists, the external lists, and the
// lists that an external list of trusted lists points to. An own or external
// list must be signed by a trusted list operator (ARF TLPub_07). A pointed-to
// list must be signed with a certificate from its pointer (ETSI TS 119 602
// V1.1.1 §6.3.13). The wallet follows pointers one level deep.
func (w *Wallet) trustedLists() []trustedList {
	urls := w.TrustedListURLs()
	seen := make(map[string]bool, len(urls))
	for _, u := range urls {
		seen[u] = true
	}
	operators, operatorsErr := w.TrustListCAs()
	out := make([]trustedList, len(urls))
	readAll(len(urls), func(i int) {
		if operatorsErr != nil {
			out[i] = trustedList{URL: urls[i], Err: operatorsErr}
			return
		}
		list, err := w.readListSignedBy(urls[i], operators)
		out[i] = trustedList{URL: urls[i], List: list, Err: err}
	})
	var pointed []trustedList
	var pointers []trustlist.Pointer
	for _, tl := range out {
		if tl.Err != nil || tl.List.SchemeInfo.LoTEType != listOfTrustedListsType {
			continue
		}
		followed := 0
		for _, pointer := range tl.List.SchemeInfo.Pointers {
			if pointer.Location == "" || seen[pointer.Location] || followed == maxFollowedPointers {
				continue
			}
			seen[pointer.Location] = true
			followed++
			pointed = append(pointed, trustedList{URL: pointer.Location, Via: tl.URL})
			pointers = append(pointers, pointer)
		}
	}
	readAll(len(pointed), func(i int) {
		signers, err := trustlist.Certificates(pointers[i].Certificates)
		if err != nil {
			pointed[i].Err = err
			return
		}
		list, err := w.readListSignedBy(pointed[i].URL, signers)
		if err == nil && pointers[i].LoTEType != "" && list.SchemeInfo.LoTEType != pointers[i].LoTEType {
			list, err = nil, fmt.Errorf("the list has the type %s, and its pointer names %s", list.SchemeInfo.LoTEType, pointers[i].LoTEType)
		}
		pointed[i].List, pointed[i].Err = list, err
	})
	return append(out, pointed...)
}

// anchors returns the certificates of the services of one kind on a readable
// list. trustedLists read the list as current, and a list that expired since
// then gives none (ETSI TS 119 602 V1.1.1 §6.3.15).
func (tl trustedList) anchors(kind string) []*x509.Certificate {
	certs, err := trustlist.Anchors(tl.List, kind, time.Now())
	if err != nil {
		return nil
	}
	return certs
}

// readAll runs read for every index in parallel and waits for all of them.
func readAll(n int, read func(i int)) {
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			read(i)
		}()
	}
	wg.Wait()
}

// listAnchors returns the certificates of all services of one kind on the
// readable lists of a list type.
func (w *Wallet) listAnchors(listType, kind string) []*x509.Certificate {
	return anchorsOf(w.trustedLists(), listType, kind)
}

func anchorsOf(lists []trustedList, listType, kind string) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, tl := range lists {
		if tl.Err == nil && tl.List.SchemeInfo.LoTEType == listType {
			anchors = append(anchors, tl.anchors(kind)...)
		}
	}
	return anchors
}

// GenerateListOfTrustedLists signs the list that points to the wallet's own
// lists and to the readable external ones (ETSI TS 119 602 V1.1.1 §6.3.13).
// A pointer names the list's location, the certificate of its signer and the
// qualifiers of §6.3.13 c).
func GenerateListOfTrustedLists(w *Wallet, issuer string) (string, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	key, chain, err := w.TrustListSigningMaterial(listOperatorName, mock.DefaultCertificateCountry)
	if err != nil {
		return "", err
	}
	var pointers []map[string]any
	for _, tl := range w.trustedLists() {
		if tl.Err != nil || tl.Via != "" {
			continue
		}
		signers, err := validate.X5CCertificates(tl.List.Header)
		if err != nil || len(signers) == 0 {
			continue
		}
		location := tl.URL
		if id, own := w.ownTrustListID(tl.URL); own && issuer != "" {
			location = issuer + "/api/trustlists/" + id
		}
		pointers = append(pointers, listPointer(location, tl.List.SchemeInfo, base64.StdEncoding.EncodeToString(signers[0].Raw)))
	}
	content, err := json.Marshal(pointers)
	if err != nil {
		return "", err
	}
	dir := w.signingStore().trustListDir(firstNonEmpty(issuer, w.RegistrarBase()), "/api/trustlists/"+listOfListsID)
	return w.signingStore().sequencedList(dir, chain[0], content, func(sequence int) (string, error) {
		now := time.Now().UTC().Truncate(time.Second)
		payload := map[string]any{
			"LoTE": map[string]any{
				"ListAndSchemeInformation": map[string]any{
					"LoTEVersionIdentifier": 1,
					"LoTESequenceNumber":    sequence,
					"LoTEType":              listOfTrustedListsType,
					"SchemeOperatorName":    []map[string]string{{"lang": "en", "value": listOperatorName}},
					"SchemeTerritory":       "EU",
					"ListIssueDateTime":     now.Format(time.RFC3339),
					"NextUpdate":            now.Add(24 * time.Hour).Format(time.RFC3339),
					"PointersToOtherLoTE":   pointers,
				},
				"TrustedEntitiesList": []map[string]any{},
			},
		}
		digest := sha256.Sum256(chain[0].Raw)
		header := map[string]any{
			"alg":      "ES256",
			"typ":      "JWT",
			"x5c":      []string{base64.StdEncoding.EncodeToString(chain[0].Raw)},
			"iat":      now.Unix(),
			"x5t#S256": base64.RawURLEncoding.EncodeToString(digest[:]),
		}
		return jws.Sign(header, payload, key)
	})
}

// listPointer is an OtherLoTEPointer of ETSI TS 119 602 V1.1.1 §6.3.13.
func listPointer(location string, scheme *trustlist.SchemeInfo, signer string) map[string]any {
	return map[string]any{
		"LoTELocation":             location,
		"ServiceDigitalIdentities": []map[string]any{{"X509Certificates": []map[string]string{{"val": signer}}}},
		"LoTEQualifiers": []map[string]any{{
			"LoTEType":           scheme.LoTEType,
			"SchemeOperatorName": []map[string]string{{"lang": "en", "value": scheme.SchemeOperatorName}},
			"SchemeTerritory":    scheme.SchemeTerritory,
			"MimeType":           "application/jwt",
		}},
	}
}

// CredentialProviderAnchors returns the certificates of one service kind on
// all credential provider lists. The demo verifier trusts the issuance
// services for credentials and the revocation services for status lists.
func (w *Wallet) CredentialProviderAnchors(kind string) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, tl := range w.trustedLists() {
		if tl.Err != nil {
			continue
		}
		switch tl.List.SchemeInfo.LoTEType {
		case walletProviderTrustListType, accessCAListType, registrarListType, listOfTrustedListsType:
			continue
		}
		anchors = append(anchors, tl.anchors(kind)...)
	}
	return anchors
}

// Service kinds for CredentialProviderAnchors.
const (
	IssuanceServices   = trustlist.IssuanceServices
	RevocationServices = trustlist.RevocationServices
)

// WalletProviderAnchors are the issuance certificates of the wallet provider
// lists, which anchor wallet and key attestations (ETSI TS 119 602 V1.1.1
// Annex E).
func (w *Wallet) WalletProviderAnchors() []*x509.Certificate {
	return w.listAnchors(walletProviderTrustListType, trustlist.IssuanceServices)
}
