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

// Package demorp runs a demo OpenID4VCI issuer and OpenID4VP verifier on the wallet
// server. The issuer supports pre-authorized and authorization code grants with a
// built-in demo account. The verifier serves signed request objects by reference and
// checks encrypted direct_post.jwt responses. Both use the wallet CA.
package demorp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/jws"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

const (
	// entryTTL is how long offers, tokens and verification requests stay valid.
	entryTTL = 10 * time.Minute
	// maxEntries caps each state map. Anonymous visitors could otherwise grow
	// memory without limit between TTL sweeps.
	maxEntries   = 500
	maxBodyBytes = 64 << 10
)

type DemoRP struct {
	wallet  *wallet.Wallet
	baseURL func() string
	// onWalletChange persists the wallet after the issuer changes it, for
	// example when it reserves a status list index.
	onWalletChange func()
	// clientAuth is the client authentication the demo authorization server
	// requires from a wallet. The zero value is ClientAuthRequired.
	clientAuth ClientAuthMode
	// verifierTrustAnchors lets the demo verifier accept credentials from other
	// issuers, such as the conformance suite. The wallet CA is always trusted.
	verifierTrustAnchors []*x509.Certificate

	mu       sync.Mutex
	offers   map[string]*offerState
	tokens   map[string]*offerState
	requests map[string]*requestState
	// authRequests holds pushed authorization requests by request_uri. codes
	// holds the codes issued from them after the user signs in.
	authRequests map[string]*authRequestState
	codes        map[string]*authRequestState
	// interactive holds the Authorization Challenge conversations of
	// OpenID4VCI 1.1 §6, keyed by auth_session.
	interactive map[string]*interactiveSession
	// nonces keeps Nonce Endpoint challenges until they expire. A wallet can
	// use one nonce for a whole batch of proofs.
	nonces map[string]time.Time
	// deferred holds accepted issuances that are not delivered yet. The key is
	// the transaction id the wallet polls with.
	deferred map[string]*deferredTicket
}

// New creates the demo issuer and verifier. baseURL returns the public origin
// of the wallet server, for example https://eudi-test.dev.
func New(w *wallet.Wallet, baseURL func() string) *DemoRP {
	return &DemoRP{
		wallet:       w,
		baseURL:      func() string { return strings.TrimRight(baseURL(), "/") },
		offers:       make(map[string]*offerState),
		tokens:       make(map[string]*offerState),
		requests:     make(map[string]*requestState),
		authRequests: make(map[string]*authRequestState),
		codes:        make(map[string]*authRequestState),
		interactive:  make(map[string]*interactiveSession),
		nonces:       make(map[string]time.Time),
		deferred:     make(map[string]*deferredTicket),
	}
}

// SetOnWalletChange registers the callback that persists the wallet after the
// demo issuer changed it. Call before serving.
func (d *DemoRP) SetOnWalletChange(fn func()) {
	d.onWalletChange = fn
}

// SetClientAuthMode sets the client authentication the demo authorization
// server requires at its PAR and token endpoints. Call it before serving
// because the authorization server metadata publishes the mode.
func (d *DemoRP) SetClientAuthMode(mode ClientAuthMode) {
	d.clientAuth = mode
}

// SetVerifierTrustAnchors sets extra CAs for issuer certificate chains. The
// demo verifier always trusts the wallet CA as well. Call it before serving.
func (d *DemoRP) SetVerifierTrustAnchors(anchors []*x509.Certificate) {
	d.verifierTrustAnchors = anchors
}

func (d *DemoRP) saveWallet() {
	if d.onWalletChange != nil {
		d.onWalletChange()
	}
}

func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("reading random bytes: %v", err))
	}
	return hex.EncodeToString(b)
}

// pruneLocked removes expired entries. Callers hold d.mu.
func (d *DemoRP) pruneLocked() {
	now := time.Now()
	for id, o := range d.offers {
		if now.After(o.expires) {
			delete(d.offers, id)
		}
	}
	for tok, o := range d.tokens {
		if now.After(o.expires) {
			delete(d.tokens, tok)
		}
	}
	for txID, t := range d.deferred {
		if now.After(t.expires) {
			delete(d.deferred, txID)
		}
	}
	for id, r := range d.requests {
		if now.After(r.expires) {
			delete(d.requests, id)
		}
	}
	for uri, a := range d.authRequests {
		if now.After(a.expires) {
			delete(d.authRequests, uri)
		}
	}
	for code, a := range d.codes {
		if now.After(a.expires) || a.codeUsed {
			delete(d.codes, code)
		}
	}
	for nonce, expires := range d.nonces {
		if now.After(expires) {
			delete(d.nonces, nonce)
		}
	}
	for id, session := range d.interactive {
		if now.After(session.expires) {
			delete(d.interactive, id)
		}
	}
}

type compactJWT struct {
	header       map[string]any
	payload      map[string]any
	signature    []byte
	signingInput string
}

func parseCompactJWT(raw string) (*compactJWT, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT")
	}
	decode := func(part string, target *map[string]any) error {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}
	jwt := &compactJWT{signingInput: parts[0] + "." + parts[1]}
	if err := decode(parts[0], &jwt.header); err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	if err := decode(parts[1], &jwt.payload); err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT signature: %w", err)
	}
	jwt.signature = sig
	return jwt, nil
}

// jws.Valid only accepts a compact JWT, so the signature is encoded again.
func verifyES256(pub *ecdsa.PublicKey, signingInput string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	return jws.Valid(signingInput+"."+base64.RawURLEncoding.EncodeToString(sig), pub)
}

func holderKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	data, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	pub, err := keys.ParseJWK(data)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only EC keys are supported")
	}
	return ecPub, nil
}

func writeJSON(w http.ResponseWriter, status int, doc any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(doc)
}
