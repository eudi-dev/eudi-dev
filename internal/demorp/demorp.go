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
// checks encrypted direct_post.jwt responses. The issuer signs with the
// wallet's certificates, and the verifier trusts the wallet's trusted lists.
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

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

const (
	// entryTTL is how long offers, tokens and verification requests stay valid.
	entryTTL = 10 * time.Minute
	// maxEntries caps each state map. Anonymous visitors could otherwise grow
	// memory without limit between TTL sweeps (see makeRoom).
	maxEntries = 500
	// maxBodyBytes leaves room for a form-encoded presentation with a portrait.
	maxBodyBytes = 256 << 10
)

// limitBodies caps every request body, since anonymous visitors call these
// endpoints.
func limitBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

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
	// issuers, such as the conformance suite. The wallet's credential provider
	// lists are always trusted.
	verifierTrustAnchors []*x509.Certificate

	mu       sync.Mutex
	offers   map[string]*offerState
	tokens   map[string]*tokenState
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
	// deferred holds accepted issuances that are not delivered yet, keyed by
	// the transaction id. The wallet polls with that id.
	deferred map[string]*deferredTicket
}

// New creates the demo issuer and verifier. baseURL returns the public origin
// of the wallet server, for example https://eudi-test.dev.
func New(w *wallet.Wallet, baseURL func() string) *DemoRP {
	return &DemoRP{
		wallet:       w,
		baseURL:      func() string { return strings.TrimRight(baseURL(), "/") },
		offers:       make(map[string]*offerState),
		tokens:       make(map[string]*tokenState),
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
// demo verifier also trusts the wallet's credential provider lists. Call it
// before serving.
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

// freshnessWindow is how far the iat of a JWT made for one request may lie
// from now: DPoP proofs (RFC 9449 §11.1), key proofs (OpenID4VCI 1.0
// Appendix F.4), attestation PoPs and key binding JWTs (RFC 9901 §7.3). None
// of them sets a value. It covers the round trip plus clock drift between two
// machines.
const freshnessWindow = 5 * time.Minute

// clockSkew is the drift accepted on nbf.
const clockSkew = time.Minute

// checkTimeClaims checks the time claims of a JWT payload. fresh requires an
// iat within freshnessWindow of now, and requireExp requires an exp. An exp
// or nbf that is present is always checked.
func checkTimeClaims(payload map[string]any, fresh, requireExp bool) error {
	now := time.Now()
	if fresh {
		iat, ok := payload["iat"].(float64)
		if !ok {
			return fmt.Errorf("has no numeric iat claim")
		}
		if age := now.Sub(time.Unix(int64(iat), 0)); age > freshnessWindow || age < -freshnessWindow {
			return fmt.Errorf("iat is %s away from now, outside the accepted %s window", age.Round(time.Second), freshnessWindow)
		}
	}
	exp, hasExp := payload["exp"].(float64)
	if requireExp && !hasExp {
		return fmt.Errorf("has no exp claim")
	}
	if hasExp && now.After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("expired")
	}
	if nbf, ok := payload["nbf"].(float64); ok && now.Add(clockSkew).Before(time.Unix(int64(nbf), 0)) {
		return fmt.Errorf("not valid yet")
	}
	return nil
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

// holderKeyFromJWK parses the public key of a JWK header or cnf claim. Such a
// JWK must not carry a private key: RFC 9449 §4.3 for a DPoP proof, OpenID4VCI
// 1.0 Appendix F.4 for a key proof and
// draft-ietf-oauth-attestation-based-client-auth-10 §7.1 for the attested key.
func holderKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	if _, private := jwk["d"]; private {
		return nil, fmt.Errorf("the jwk carries private key material, it must hold a public key only")
	}
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

// makeRoom evicts the entries that expire first until a state map has room
// for one more. Visitors share the maps, so a full map must not lock out
// everyone else.
func makeRoom[V any](m map[string]V, expires func(V) time.Time) {
	for len(m) >= maxEntries {
		first, at := "", time.Time{}
		for key, value := range m {
			if e := expires(value); first == "" || e.Before(at) {
				first, at = key, e
			}
		}
		delete(m, first)
	}
}
