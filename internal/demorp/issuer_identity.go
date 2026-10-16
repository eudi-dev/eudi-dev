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

package demorp

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Wallets fetch the issuer metadata from the Credential Issuer Identifier,
// and the request does not say which offer it is for (OpenID4VCI 1.0
// §12.2.2). So each identity has its own identifier below /issuer. Visitors
// of a shared demo choose an identity without changing it for anyone else.
const (
	identityRegistered   = "registered"
	identityUnregistered = "unregistered"
	identityOwn          = "own"
	identityUnsigned     = "unsigned"

	unregisteredPath = "/unregistered"
	unsignedPath     = "/unsigned"
	ownPathPrefix    = "/own/"
)

// issuerIdentity is how the demo issuer presents itself: the access
// certificate that signs its metadata and the registration certificate in its
// issuer_info (ETSI TS 119 472-3 V1.1.1 §4.2).
type issuerIdentity struct {
	kind string
	// path follows /issuer in the Credential Issuer Identifier.
	path string
	// signingKey, chain and issuerInfo come from the visitor for an own
	// identity.
	signingKey *ecdsa.PrivateKey
	chain      []*x509.Certificate
	issuerInfo []any
	// expires moves forward with every request, so an own identity lasts as
	// long as a wallet uses it.
	expires time.Time
}

var (
	registeredIssuer   = &issuerIdentity{kind: identityRegistered}
	unregisteredIssuer = &issuerIdentity{kind: identityUnregistered, path: unregisteredPath}
	// unsignedIssuer answers every metadata request with plain JSON, like an
	// issuer without an access certificate.
	unsignedIssuer = &issuerIdentity{kind: identityUnsigned, path: unsignedPath}
)

// signsMetadata reports whether the identity serves signed metadata to a
// wallet that asks for it (OpenID4VCI 1.0 §12.2.3).
func (id *issuerIdentity) signsMetadata() bool {
	return id.kind != identityUnsigned
}

// rootPath leads from a page directly below the issuer identifier to the
// wallet root.
func (id *issuerIdentity) rootPath() string {
	return "../" + strings.Repeat("../", strings.Count(id.path, "/"))
}

type identityContextKey struct{}

func withIssuerIdentity(r *http.Request, id *issuerIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityContextKey{}, id))
}

// issuerOf returns the identity of the request path.
func issuerOf(r *http.Request) *issuerIdentity {
	if id, ok := r.Context().Value(identityContextKey{}).(*issuerIdentity); ok {
		return id
	}
	return registeredIssuer
}

// issuerURL is the Credential Issuer Identifier of an identity.
func (d *DemoRP) issuerURL(id *issuerIdentity) string {
	return d.issuerID() + id.path
}

// requestIssuerURL is the Credential Issuer Identifier of the request path.
func (d *DemoRP) requestIssuerURL(r *http.Request) string {
	return d.issuerURL(issuerOf(r))
}

// issuerInfo is the issuer_info of an identity. Without a registration
// certificate a wallet with ARF checks reports RPRC_22a.
func (d *DemoRP) issuerInfo(id *issuerIdentity) ([]any, error) {
	switch id.kind {
	case identityRegistered:
		return d.wallet.DemoIssuerInfo()
	case identityOwn:
		return id.issuerInfo, nil
	}
	return nil, nil
}

// accessSigningMaterial is the key and access certificate chain that sign the
// identity's metadata.
func (d *DemoRP) accessSigningMaterial(id *issuerIdentity) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if id.kind == identityOwn {
		return id.signingKey, id.chain, nil
	}
	return d.wallet.AccessSigningMaterial()
}

// ownIdentityBody is the material of an own identity.
type ownIdentityBody struct {
	// SigningKey is a PEM bundle with an EC private key and its access
	// certificate chain. The chain goes into the x5c of the signed metadata.
	SigningKey string `json:"signing_key"`
	// IssuerInfo is the issuer_info array. Empty publishes none.
	IssuerInfo []any `json:"issuer_info"`
}

// offerBody is the JSON body of an offer request with an own identity or an
// own identity check.
type offerBody struct {
	ownIdentityBody
	IdentityCheck identityCheckBody `json:"identity_check"`
}

// identityCheckBody is the material of an own identity check, like the own
// certificates of the demo verifier.
type identityCheckBody struct {
	// SigningKey is a PEM bundle with an EC private key and its access
	// certificate chain. The chain goes into the x5c of the request.
	SigningKey string `json:"signing_key"`
	// VerifierInfo is the verifier_info array (OpenID4VP 1.0 §5.1). Empty
	// sends none.
	VerifierInfo []any `json:"verifier_info"`
}

// identityCheck is how the issuer identifies itself in the identity check,
// the PID presentation during interactive authorization. It is chosen apart
// from the issuer identity, like the identity of the demo verifier.
type identityCheck struct {
	kind         string
	signingKey   *ecdsa.PrivateKey
	chain        []*x509.Certificate
	verifierInfo []any
}

var (
	registeredIdentityCheck   = &identityCheck{kind: identityRegistered}
	unregisteredIdentityCheck = &identityCheck{kind: identityUnregistered}
)

func newIdentityCheck(kind string, body identityCheckBody) (*identityCheck, error) {
	switch kind {
	case "", identityRegistered:
		return registeredIdentityCheck, nil
	case identityUnregistered:
		return unregisteredIdentityCheck, nil
	case identityOwn:
		key, chain, err := parseOwnSigningKey("identity_check.signing_key", body.SigningKey)
		if err != nil {
			return nil, err
		}
		return &identityCheck{kind: identityOwn, signingKey: key, chain: chain, verifierInfo: body.VerifierInfo}, nil
	default:
		return nil, fmt.Errorf("identity_check must be %q, %q or %q, not %q", identityRegistered, identityUnregistered, identityOwn, kind)
	}
}

// parseOwnSigningKey reads the PEM bundle of an own identity from field.
func parseOwnSigningKey(field, pemBundle string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if strings.TrimSpace(pemBundle) == "" {
		return nil, nil, fmt.Errorf("%s is required: an EC private key and its access certificate chain as PEM", field)
	}
	return parseSigningKeyBundle(pemBundle)
}

// identityCheckSigningMaterial is the key and access certificate chain that
// sign the presentation request of the identity check.
func (d *DemoRP) identityCheckSigningMaterial(check *identityCheck) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if check.kind == identityOwn {
		return check.signingKey, check.chain, nil
	}
	return d.wallet.AccessSigningMaterial()
}

// identityCheckVerifierInfo is the verifier_info of the identity check. Only
// the registered demo issuer has a registration for that intended use.
func (d *DemoRP) identityCheckVerifierInfo(check *identityCheck) ([]any, error) {
	switch check.kind {
	case identityRegistered:
		return d.wallet.DemoIdentityCheckVerifierInfo()
	case identityOwn:
		return check.verifierInfo, nil
	}
	return nil, nil
}

// newOwnIssuer stores an identity with the visitor's access certificate and
// issuer_info under an identifier of its own.
func (d *DemoRP) newOwnIssuer(body ownIdentityBody) (*issuerIdentity, error) {
	key, chain, err := parseOwnSigningKey("signing_key", body.SigningKey)
	if err != nil {
		return nil, err
	}
	id := &issuerIdentity{
		kind:       identityOwn,
		path:       ownPathPrefix + randToken(),
		signingKey: key,
		chain:      chain,
		issuerInfo: body.IssuerInfo,
		expires:    time.Now().Add(entryTTL),
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	makeRoom(d.ownIssuers, func(o *issuerIdentity) time.Time { return o.expires })
	d.ownIssuers[id.path] = id
	return id, nil
}

// identityAt splits a path below /issuer into the identity and the path
// below its identifier. An unknown or expired own identity is not found.
func (d *DemoRP) identityAt(path string) (*issuerIdentity, string, bool) {
	if rest, ok := cutPathPrefix(path, unregisteredPath); ok {
		return unregisteredIssuer, rest, true
	}
	if rest, ok := cutPathPrefix(path, unsignedPath); ok {
		return unsignedIssuer, rest, true
	}
	tail, ok := strings.CutPrefix(path, ownPathPrefix)
	if !ok {
		return registeredIssuer, path, true
	}
	token, _, _ := strings.Cut(tail, "/")
	idPath := ownPathPrefix + token
	rest, _ := cutPathPrefix(path, idPath)
	d.mu.Lock()
	defer d.mu.Unlock()
	id, known := d.ownIssuers[idPath]
	if !known || time.Now().After(id.expires) {
		delete(d.ownIssuers, idPath)
		return nil, "", false
	}
	id.expires = time.Now().Add(entryTTL)
	return id, rest, true
}

// cutPathPrefix removes prefix when it is a whole path segment.
func cutPathPrefix(path, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", false
	}
	return rest, true
}

// identityHandler serves the registered identity with the issuer page and
// the other identities with the protocol endpoints only.
func (d *DemoRP) identityHandler(page, protocol http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, rest, ok := d.identityAt(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if id == registeredIssuer {
			page.ServeHTTP(w, withIssuerIdentity(r, id))
			return
		}
		if rest == "" {
			rest = "/"
		}
		inner := withIssuerIdentity(r, id)
		u := *r.URL
		u.Path, u.RawPath = rest, ""
		inner.URL = &u
		protocol.ServeHTTP(w, inner)
	})
}

// HandleWellKnown registers the issuer and authorization server metadata of
// every identity at the server root, because OpenID4VCI 1.0 §12.2.2 and
// RFC 8414 §3.1 put the well-known segment before the issuer path.
func (d *DemoRP) HandleWellKnown(handle func(pattern string, h http.Handler)) {
	for _, entry := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"openid-credential-issuer", d.handleIssuerMetadata},
		{"oauth-authorization-server", d.handleAuthorizationServerMetadata},
	} {
		prefix := "/.well-known/" + entry.name + "/issuer"
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, rest, ok := d.identityAt(strings.TrimPrefix(r.URL.Path, prefix))
			if !ok || rest != "" {
				http.NotFound(w, r)
				return
			}
			entry.handler(w, withIssuerIdentity(r, id))
		})
		handle("GET "+prefix, h)
		handle("GET "+prefix+"/", h)
	}
}
