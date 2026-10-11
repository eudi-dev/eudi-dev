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
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
)

// RegistrationStatusClient fetches the status lists of registration
// certificates. The wallet's own list is answered in process, so strict TLS
// doesn't have to trust the wallet's self-signed HTTPS port. Other lists go
// through the outbound client.
func (w *Wallet) RegistrationStatusClient() *http.Client {
	outbound := w.HTTPClient()
	return &http.Client{Timeout: outbound.Timeout, Transport: ownStatusListTransport{wallet: w, next: outbound}}
}

type ownStatusListTransport struct {
	wallet *Wallet
	next   *http.Client
}

func (t ownStatusListTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !sameURL(req.URL, t.wallet.Registrar().RegistrationStatusListURL()) {
		if t.next.Transport == nil {
			return nil, errors.New("the wallet has no outbound transport")
		}
		return t.next.Transport.RoundTrip(req)
	}
	token, err := t.wallet.Registrar().RegistrationStatusListToken()
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": []string{statuslist.MediaTypeJWT}},
		Body:          io.NopCloser(strings.NewReader(token)),
		ContentLength: int64(len(token)),
		Request:       req,
	}, nil
}

// PrepareARFChecks adds what --arf needs to a request: a client for the status
// lists of registration certificates, and the anchors for access and
// registration certificates and their status lists.
func (w *Wallet) PrepareARFChecks(params *AuthorizationRequestParams) {
	if !w.ARFChecks() {
		return
	}
	params.StatusClient = w.RegistrationStatusClient()
	// The three anchor sets come from the same lists, which are read once.
	lists := w.trustedLists()
	params.RelyingPartyCAs = anchorsOf(lists, accessCAListType, trustlist.IssuanceServices)
	params.RegistrarCAs = anchorsOf(lists, registrarListType, trustlist.IssuanceServices)
	params.RegistrationStatusCAs = anchorsOf(lists, registrarListType, trustlist.RevocationServices)
}

// RelyingPartyCAs are the anchors --arf trusts for access certificates: the
// issuance services of the lists of access certificate providers (ARF RPA_04
// and PPNot_06, ETSI TS 119 602 V1.1.1 Annex F).
func (w *Wallet) RelyingPartyCAs() []*x509.Certificate {
	return w.listAnchors(accessCAListType, trustlist.IssuanceServices)
}

// RegistrarCAs are the anchors --arf trusts for registration certificates:
// the issuance services of the lists of registration certificate providers
// (ARF RPRC_02a and RPACANot_04, ETSI TS 119 602 V1.1.1 Annex G).
func (w *Wallet) RegistrarCAs() []*x509.Certificate {
	return w.listAnchors(registrarListType, trustlist.IssuanceServices)
}

// RegistrationStatusCAs are the anchors of the status lists of registration
// certificates: the revocation services of the same lists (ARF
// RPACANot_03b).
func (w *Wallet) RegistrationStatusCAs() []*x509.Certificate {
	return w.listAnchors(registrarListType, trustlist.RevocationServices)
}

// TrustListCAs are the CAs --arf trusts for the signer of a trusted list. The
// wallet's list operator key, certified by the wallet CA, signs the wallet's
// own lists, like the seal of the Commission on the lists it compiles (ARF
// TLPub_07). --trusted-list-ca and the trusted-list-ca entities add others.
func (w *Wallet) TrustListCAs() ([]*x509.Certificate, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var cas []*x509.Certificate
	if len(w.CertChain) > 0 {
		cas = append(cas, w.CertChain[len(w.CertChain)-1])
	}
	if len(w.TrustListCAPEM) > 0 {
		configured, err := keys.ParseCertificatesPEM(w.TrustListCAPEM)
		if err != nil {
			return nil, fmt.Errorf("the trusted list CAs: %w", err)
		}
		cas = append(cas, configured...)
	}
	for _, entity := range w.TrustedEntities {
		if entity.List != trustedListCAID {
			continue
		}
		certs, err := entity.certificates()
		if err != nil {
			return nil, fmt.Errorf("the trusted list CA %s: %w", entity.Name, err)
		}
		cas = append(cas, certs...)
	}
	return cas, nil
}

// sameURL compares scheme, host with its default port, and path. Host and
// scheme are case insensitive (RFC 3986 §6.2.2.1).
func sameURL(u *url.URL, raw string) bool {
	other, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return sameOrigin(u, other) && strings.TrimSuffix(u.Path, "/") == strings.TrimSuffix(other.Path, "/")
}

func sameOrigin(u, other *url.URL) bool {
	hostPort := func(v *url.URL) string {
		port := v.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(v.Scheme)]
		}
		return strings.ToLower(v.Hostname()) + ":" + port
	}
	return strings.EqualFold(u.Scheme, other.Scheme) && hostPort(u) == hostPort(other)
}

// RegistrarBase is the base URL of the registrar's default contact URLs and
// registry URIs.
func (w *Wallet) RegistrarBase() string {
	return firstNonEmpty(strings.TrimRight(w.IssuerURL, "/"), strings.TrimRight(w.BaseURL, "/"), "https://issuer.example")
}

// Registrar is the wallet's registrar. It works on the registrar state stored
// in the wallet.
func (w *Wallet) Registrar() *registrar.Registrar {
	return registrar.New(&w.mu, &w.State, registrarEnv{w})
}

// registrarEnv implements registrar.Env for the wallet.
type registrarEnv struct{ w *Wallet }

func (e registrarEnv) RegistrarBase() string { return e.w.RegistrarBase() }
func (e registrarEnv) RegistrarSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return e.w.RegistrarSigningMaterial()
}
func (e registrarEnv) RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return e.w.RelyingPartyAccessCA()
}
func (e registrarEnv) TemplateLocation() credtemplate.Location { return e.w.Templates }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
