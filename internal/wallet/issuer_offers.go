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
	"log"
	"maps"
	"slices"
	"sync"
	"time"
)

const (
	// operatorOfferMaxAge is short, so a new template reaches the list soon.
	operatorOfferMaxAge = 5 * time.Second
	issuerOfferMaxAge   = time.Minute
	// maxIssuerOfferFetches limits parallel requests, because visitors of a
	// public demo can fill the catalogue.
	maxIssuerOfferFetches = 8
)

// issuerOfferCache holds the configurations offered by each issuer. Reading it never
// waits for an issuer. A missing or old entry is fetched in the background.
type issuerOfferCache struct {
	mu      sync.Mutex
	entries map[string]issuerOffer
	slots   chan struct{}
}

type issuerOfferFetch func(issuer string) (map[string]any, error)

type issuerOffer struct {
	configurations map[string]any
	retryAt        time.Time
	fetching       bool
}

// read returns the known configurations per issuer. loading is set during the
// first fetch of an issuer and during each fetch of an operator's issuer.
func (c *issuerOfferCache) read(issuers []KnownIssuer, fetch issuerOfferFetch) (offered []map[string]any, loading bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]issuerOffer{}
		c.slots = make(chan struct{}, maxIssuerOfferFetches)
	}
	maps.DeleteFunc(c.entries, func(url string, entry issuerOffer) bool {
		return !entry.fetching && !slices.ContainsFunc(issuers, func(k KnownIssuer) bool { return k.URL == url })
	})
	offered = make([]map[string]any, len(issuers))
	for i, issuer := range issuers {
		entry := c.entries[issuer.URL]
		if !entry.fetching && !time.Now().Before(entry.retryAt) {
			entry.fetching = true
			c.entries[issuer.URL] = entry
			go c.refresh(issuer, fetch)
		}
		offered[i] = entry.configurations
		loading = loading || (entry.fetching && (entry.configurations == nil || issuer.operator))
	}
	return offered, loading
}

// refresh fetches outside the slots for the operator's issuers, so slow issuers
// of visitors don't hold them up.
func (c *issuerOfferCache) refresh(issuer KnownIssuer, fetch issuerOfferFetch) {
	if !issuer.operator {
		c.slots <- struct{}{}
		defer func() { <-c.slots }()
	}
	configurations, err := fetch(issuer.URL)
	c.mu.Lock()
	defer c.mu.Unlock()
	wait := issuerOfferMaxAge
	if issuer.operator {
		wait = operatorOfferMaxAge
	}
	if err != nil {
		log.Printf("[VCI] Keeping the last offer of issuer %s: %v", issuer.URL, err)
		configurations = c.entries[issuer.URL].configurations
	}
	c.entries[issuer.URL] = issuerOffer{configurations: configurations, retryAt: time.Now().Add(wait)}
}
