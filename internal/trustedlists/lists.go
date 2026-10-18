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

package trustedlists

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// CheckList reads an external list before it is added. Strict mode refuses an
// unreadable list. Debug mode reports the reason in the link.
func (t *Set) CheckList(rawURL string) (Link, error) {
	rawURL = strings.TrimSpace(rawURL)
	if !format.IsWebURL(rawURL) {
		return Link{}, fmt.Errorf("%q is not an http or https URL", rawURL)
	}
	t.cache.mu.Lock()
	delete(t.cache.lists, rawURL)
	t.cache.mu.Unlock()
	link := Link{URL: rawURL}
	if _, err := t.ReadList(rawURL); err != nil {
		if t.env.Strict() {
			return Link{}, fmt.Errorf("the wallet can't use %s: %w", rawURL, err)
		}
		link.Error = err.Error()
	}
	return link, nil
}

// cacheBound keeps every list read by the wallet itself in the cache,
// together with the lists they point to.
func (t *Set) cacheBound() int {
	configured := len(t.settings.ConfiguredLists)
	t.mu.RLock()
	defer t.mu.RUnlock()
	return (configured+len(t.additions.AddedTrustedLists))*(1+maxFollowedPointers) + requestedListSlots
}

// ListRoom reports whether the wallet can add the list. A list already held by
// the wallet always fits.
func (t *Set) ListRoom(rawURL string) error {
	limit := t.settings.MaxLists
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.listRoomLocked(strings.TrimSpace(rawURL), limit)
}

func (t *Set) listRoomLocked(rawURL string, limit int) error {
	if limit <= 0 || slices.Contains(t.additions.AddedTrustedLists, rawURL) || len(t.additions.AddedTrustedLists) < limit {
		return nil
	}
	return fmt.Errorf("%w: it holds at most %d added lists. Remove one first", ErrFull, limit)
}

// StoreList puts the list on the list of trusted lists, unless the wallet is
// full.
func (t *Set) StoreList(rawURL string) error {
	limit := t.settings.MaxLists
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.listRoomLocked(rawURL, limit); err != nil {
		return err
	}
	if !slices.Contains(t.additions.AddedTrustedLists, rawURL) {
		t.additions.AddedTrustedLists = append(t.additions.AddedTrustedLists, rawURL)
	}
	return nil
}

// RemoveList takes an external list off the list of trusted lists.
func (t *Set) RemoveList(rawURL string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	before := len(t.additions.AddedTrustedLists)
	t.additions.AddedTrustedLists = slices.DeleteFunc(t.additions.AddedTrustedLists, func(u string) bool { return u == strings.TrimSpace(rawURL) })
	if len(t.additions.AddedTrustedLists) == before {
		return fmt.Errorf("%w: %q", ErrNotFound, rawURL)
	}
	return nil
}

// externalLists are the external lists on the list of trusted lists: those
// from --trusted-list and those added by users.
func (t *Set) externalLists() []string {
	out := slices.Clone(t.settings.ConfiguredLists)
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, u := range t.additions.AddedTrustedLists {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// OwnListURL is where the wallet publishes one of its lists.
func (t *Set) OwnListURL(id string) string {
	return t.env.RegistrarBase() + provider.TrustedListPath(id)
}

// The wallet reuses a fetched list for listCacheTTL, because an operator can
// publish a list before its next update (ETSI TS 119 602 V1.1.1 §6.3.15). A
// failed fetch is reused for failedListCacheTTL, so an unreachable list can't
// slow down every check.
const (
	listCacheTTL       = 5 * time.Minute
	failedListCacheTTL = time.Minute
	// requestedListSlots is the room in the list cache for lists from
	// requests. Lists read by the wallet itself come on top. Any visitor can
	// put a list URL into a request.
	requestedListSlots = 16
	// maxFollowedPointers caps how many lists the wallet reads from one
	// external list of trusted lists.
	maxFollowedPointers = 20
)

// ListCache holds the external lists fetched by a wallet. It lives as long as
// the wallet in memory and is never saved.
type ListCache struct {
	mu      sync.Mutex
	lists   map[string]cachedList
	fetches singleflight.Group
}

type cachedList struct {
	raw     string
	err     error
	fetched time.Time
	expires time.Time
}

// cacheExpiry ends the reuse of a fetched list at its next update, when the
// list expires (ETSI TS 119 602 V1.1.1 §6.3.15).
func cacheExpiry(raw string, err error, fetched time.Time) time.Time {
	if err != nil {
		return fetched.Add(failedListCacheTTL)
	}
	expires := fetched.Add(listCacheTTL)
	if list, err := lote.Parse(raw); err == nil && list.SchemeInfo != nil {
		if next, err := time.Parse(time.RFC3339, list.SchemeInfo.NextUpdate); err == nil && next.Before(expires) {
			return next
		}
	}
	return expires
}

// ownListID returns the ID of one of the wallet's own lists. The URL
// compares like format.SameURL, so another spelling of the wallet's origin
// matches.
func (t *Set) ownListID(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	base, err := url.Parse(t.env.RegistrarBase())
	if err != nil || !format.SameOrigin(u, base) {
		return "", false
	}
	return strings.CutPrefix(u.Path, strings.TrimSuffix(base.Path, "/")+provider.TrustedListPath(""))
}

// rawList builds one of the wallet's own lists in process, because the
// wallet may not serve them over HTTP. It fetches every other list.
func (t *Set) rawList(rawURL string) (string, error) {
	if id, ok := t.ownListID(rawURL); ok {
		group, found := t.FindGroup(id, "", "")
		if !found {
			return "", fmt.Errorf("the wallet has no trusted list %q", id)
		}
		return t.SignedGroupList(t.env.IssuerURL(), group, provider.TrustedListPath(group.ID))
	}
	c := t.cache
	c.mu.Lock()
	cached, ok := c.lists[rawURL]
	c.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.raw, cached.err
	}
	fetched, err, _ := c.fetches.Do(rawURL, func() (any, error) {
		raw, err := format.FetchURL(rawURL, t.env.HTTPClient())
		bound := t.cacheBound()
		c.mu.Lock()
		if c.lists == nil {
			c.lists = map[string]cachedList{}
		}
		for len(c.lists) >= bound {
			oldest := ""
			for u, cl := range c.lists {
				if oldest == "" || cl.fetched.Before(c.lists[oldest].fetched) {
					oldest = u
				}
			}
			delete(c.lists, oldest)
		}
		fetched := time.Now()
		c.lists[rawURL] = cachedList{raw: raw, err: err, fetched: fetched, expires: cacheExpiry(raw, err, fetched)}
		c.mu.Unlock()
		return raw, err
	})
	if err != nil {
		return "", err
	}
	return fetched.(string), nil
}

// ReadList returns a list signed by a trusted list operator. Under the ARF,
// that signature is why the wallet accepts the trust anchors on the list
// (PPNot_05, TLPub_05, TLPub_07).
func (t *Set) ReadList(rawURL string) (*lote.List, error) {
	operators, err := t.ListCAs()
	if err != nil {
		return nil, err
	}
	return t.readListSignedBy(rawURL, operators)
}

// readListSignedBy returns the list if its signer chains to one of the
// certificates and the list is current.
func (t *Set) readListSignedBy(rawURL string, signers []*x509.Certificate) (*lote.List, error) {
	raw, err := t.rawList(rawURL)
	if err != nil {
		return nil, err
	}
	if err := VerifyListSigner(raw, signers); err != nil {
		return nil, err
	}
	list, err := lote.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing the trusted list: %w", err)
	}
	if err := list.Current(time.Now()); err != nil {
		return nil, err
	}
	return list, nil
}

// VerifyListSigner checks the JAdES signature of a trusted list (ETSI TS 119
// 602 V1.1.1 Annexes D.4 to H.4) and that its signer chains to one of the
// certificates: a trusted list operator, or the signer given in a pointer. The
// ARF has the wallet accept the provider trust anchors because of the list's
// signature (PPNot_05, TLPub_05, TLPub_07).
func VerifyListSigner(raw string, operators []*x509.Certificate) error {
	header, _, _, err := format.ParseJWTParts(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("reading the trusted list: %w", err)
	}
	chain, err := validate.X5CCertificates(header)
	if err != nil || len(chain) == 0 {
		return errors.New("the trusted list has no x5c signer certificate")
	}
	if _, err := jws.Verify(strings.TrimSpace(raw), chain[0].PublicKey); err != nil {
		return errors.New("the trusted list's signature does not verify")
	}
	if _, err := certchain.Verify(chain, operators); err != nil {
		return fmt.Errorf("the list's signer does not chain to a trusted list CA. Add the list operator's CA to trusted-list-ca, or start the wallet with --trusted-list-ca: %w", err)
	}
	return nil
}

// listURLs are the lists on the wallet's list of trusted lists: its own lists
// and the external ones.
func (t *Set) listURLs() []string {
	var urls []string
	own := map[string]bool{}
	for _, group := range t.Groups() {
		urls = append(urls, t.OwnListURL(group.ID))
		own[group.ID] = true
	}
	for _, u := range t.externalLists() {
		// An external URL can point to one of the wallet's own lists.
		if id, ok := t.ownListID(u); !ok || !own[id] {
			urls = append(urls, u)
		}
	}
	return urls
}

// List is a list read by the wallet, or the error from reading it. Via is the
// list of trusted lists that points to it.
type List struct {
	URL  string
	Via  string
	List *lote.List
	Err  error
}

// Lists reads the wallet's own lists, the external lists, and the lists that
// an external list of trusted lists points to. An own or external list must
// be signed by a trusted list operator (ARF TLPub_07). A pointed-to list must
// be signed with a certificate from its pointer (ETSI TS 119 602 V1.1.1
// §6.3.13). The wallet follows pointers one level deep.
func (t *Set) Lists() []List {
	urls := t.listURLs()
	seen := make(map[string]bool, len(urls))
	for _, u := range urls {
		seen[u] = true
	}
	operators, operatorsErr := t.ListCAs()
	out := make([]List, len(urls))
	readAll(len(urls), func(i int) {
		if operatorsErr != nil {
			out[i] = List{URL: urls[i], Err: operatorsErr}
			return
		}
		list, err := t.readListSignedBy(urls[i], operators)
		out[i] = List{URL: urls[i], List: list, Err: err}
	})
	var pointed []List
	var pointers []lote.Pointer
	for _, tl := range out {
		if tl.Err != nil || tl.List.SchemeInfo.LoTEType != ListOfListsType {
			continue
		}
		followed := 0
		for _, pointer := range tl.List.SchemeInfo.Pointers {
			if pointer.Location == "" || seen[pointer.Location] || followed == maxFollowedPointers {
				continue
			}
			seen[pointer.Location] = true
			followed++
			pointed = append(pointed, List{URL: pointer.Location, Via: tl.URL})
			pointers = append(pointers, pointer)
		}
	}
	readAll(len(pointed), func(i int) {
		signers, err := lote.Certificates(pointers[i].Certificates)
		if err != nil {
			pointed[i].Err = err
			return
		}
		list, err := t.readListSignedBy(pointed[i].URL, signers)
		if err == nil && pointers[i].LoTEType != "" && list.SchemeInfo.LoTEType != pointers[i].LoTEType {
			list, err = nil, fmt.Errorf("the list has the type %s, but its pointer gives the type %s", list.SchemeInfo.LoTEType, pointers[i].LoTEType)
		}
		pointed[i].List, pointed[i].Err = list, err
	})
	return append(out, pointed...)
}

// Anchors returns the certificates of the services of one kind on a readable
// list. Lists read the list as current, and a list that expired since then
// gives none (ETSI TS 119 602 V1.1.1 §6.3.15).
func (tl List) Anchors(kind string) []*x509.Certificate {
	certs, err := lote.Anchors(tl.List, kind, time.Now())
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

// AnchorsOf returns the certificates of all services of one kind on the
// readable lists of a list type.
func AnchorsOf(lists []List, listType, kind string) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, tl := range lists {
		if tl.Err == nil && tl.List.SchemeInfo.LoTEType == listType {
			anchors = append(anchors, tl.Anchors(kind)...)
		}
	}
	return anchors
}

// ListOfLists signs the list that points to the wallet's own lists and to the
// readable external ones (ETSI TS 119 602 V1.1.1 §6.3.13).
func (t *Set) ListOfLists(issuer string) (string, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	signer := t.env.Signer()
	key, chain, err := signer.TrustList(config.WalletName, listOfListsTerritory)
	if err != nil {
		return "", err
	}
	var pointers []map[string]any
	for _, tl := range t.Lists() {
		if tl.Err != nil || tl.Via != "" {
			continue
		}
		signers, err := validate.X5CCertificates(tl.List.Header)
		if err != nil || len(signers) == 0 {
			continue
		}
		location := tl.URL
		if id, own := t.ownListID(tl.URL); own && issuer != "" {
			location = issuer + provider.TrustedListPath(id)
		}
		pointers = append(pointers, lote.PointerEntry(location, tl.List.SchemeInfo.LoTEType, tl.List.SchemeInfo.SchemeOperatorName, tl.List.SchemeInfo.SchemeTerritory, base64.StdEncoding.EncodeToString(signers[0].Raw)))
	}
	content, err := json.Marshal(pointers)
	if err != nil {
		return "", err
	}
	return signer.Keys().SequencedList(jsonutil.FirstNonEmpty(issuer, t.env.RegistrarBase()), provider.TrustedListPath(ListOfListsID), chain[0], content, func(sequence int, issued time.Time, _ string) (string, error) {
		scheme := map[string]any{
			"LoTEVersionIdentifier": 1,
			"LoTESequenceNumber":    sequence,
			"LoTEType":              ListOfListsType,
			"SchemeOperatorName":    []map[string]string{{"lang": "en", "value": config.WalletName}},
			"SchemeTerritory":       listOfListsTerritory,
			"ListIssueDateTime":     issued.Format(time.RFC3339),
			"NextUpdate":            issued.Add(lote.UpdateInterval).Format(time.RFC3339),
		}
		// ETSI TS 119 602 V1.1.1 §6.3.13 needs one or more pointers. A list of
		// lists approves no trusted entity, so it has no TrustedEntitiesList
		// (§6.4.0).
		if len(pointers) > 0 {
			scheme["PointersToOtherLoTE"] = pointers
		}
		return lote.SignList(key, chain[0], issued, map[string]any{"ListAndSchemeInformation": scheme})
	})
}

// CredentialProviderAnchors returns the certificates of one service kind on
// all credential provider lists. The demo verifier trusts the issuance
// services for credentials and the revocation services for status lists.
func (t *Set) CredentialProviderAnchors(kind string) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, tl := range t.Lists() {
		if tl.Err != nil {
			continue
		}
		switch tl.List.SchemeInfo.LoTEType {
		case lote.WalletProvidersListType, lote.AccessCertProvidersListType, lote.RegistrationCertProvidersListType, ListOfListsType:
			continue
		}
		anchors = append(anchors, tl.Anchors(kind)...)
	}
	return anchors
}

// WalletProviderAnchors are the issuance certificates of the wallet provider
// lists. They anchor wallet and key attestations (ETSI TS 119 602 V1.1.1
// Annex E).
func (t *Set) WalletProviderAnchors() []*x509.Certificate {
	return AnchorsOf(t.Lists(), lote.WalletProvidersListType, lote.IssuanceServices)
}

// RelyingPartyCAs are the anchors for access certificates under --arf: the
// issuance services of the lists of access certificate providers (ARF RPA_04
// and PPNot_06, ETSI TS 119 602 V1.1.1 Annex F).
func (t *Set) RelyingPartyCAs() []*x509.Certificate {
	return AnchorsOf(t.Lists(), lote.AccessCertProvidersListType, lote.IssuanceServices)
}

// RegistrarCAs are the anchors for registration certificates under --arf:
// the issuance services of the lists of registration certificate providers
// (ARF RPRC_02a and RPACANot_04, ETSI TS 119 602 V1.1.1 Annex G).
func (t *Set) RegistrarCAs() []*x509.Certificate {
	return AnchorsOf(t.Lists(), lote.RegistrationCertProvidersListType, lote.IssuanceServices)
}

// RegistrationStatusCAs are the anchors of the status lists of registration
// certificates: the revocation services of the same lists (ARF
// RPACANot_03b).
func (t *Set) RegistrationStatusCAs() []*x509.Certificate {
	return AnchorsOf(t.Lists(), lote.RegistrationCertProvidersListType, lote.RevocationServices)
}
