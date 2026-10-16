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
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

// RegistrationStatusClient fetches the status lists of registration
// certificates and the CRLs of access and registrar certificates. The
// wallet's own list and CRLs are answered in process, so strict TLS doesn't
// have to trust the wallet's self-signed HTTPS port. Other URLs go through
// the outbound client.
func (w *Wallet) RegistrationStatusClient() *http.Client {
	outbound := w.HTTPClient()
	return &http.Client{Timeout: outbound.Timeout, Transport: ownPublicationsTransport{wallet: w, next: outbound}}
}

type ownPublicationsTransport struct {
	wallet *Wallet
	next   *http.Client
}

func (t ownPublicationsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && format.SameURL(req.URL, t.wallet.Registrar().RegistrationStatusListURL()) {
		token, err := t.wallet.Registrar().RegistrationStatusListToken()
		if err != nil {
			return nil, err
		}
		return inProcessResponse(req, statuslist.MediaTypeJWT, []byte(token)), nil
	}
	if path, ok := t.wallet.ownCRLPath(req.URL); ok && req.Method == http.MethodGet {
		der, err := t.wallet.CRL(path)
		if err != nil {
			return nil, err
		}
		return inProcessResponse(req, "application/pkix-crl", der), nil
	}
	if t.next.Transport == nil {
		return nil, errors.New("the wallet has no outbound transport")
	}
	return t.next.Transport.RoundTrip(req)
}

func inProcessResponse(req *http.Request, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// PrepareARFChecks adds what --arf needs to a request: a client for the status
// lists of registration certificates, and the anchors for access and
// registration certificates and their status lists.
func (w *Wallet) PrepareARFChecks(params *oid4vp.Request) {
	if !w.ARFChecks() {
		return
	}
	params.StatusClient = w.RegistrationStatusClient()
	// Read the lists once for all three anchor sets.
	lists := w.TrustedLists().Lists()
	params.RelyingPartyCAs = trustedlists.AnchorsOf(lists, lote.AccessCertProvidersListType, lote.IssuanceServices)
	params.RegistrarCAs = trustedlists.AnchorsOf(lists, lote.RegistrationCertProvidersListType, lote.IssuanceServices)
	params.RegistrationStatusCAs = trustedlists.AnchorsOf(lists, lote.RegistrationCertProvidersListType, lote.RevocationServices)
}

// RegistrarBase is the base URL of the registrar's default contact URLs and
// registry URIs.
func (w *Wallet) RegistrarBase() string {
	return jsonutil.FirstNonEmpty(strings.TrimRight(w.IssuerURL, "/"), strings.TrimRight(w.BaseURL, "/"), mock.DefaultIssuer)
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
	return e.w.Signer().Registrar()
}
func (e registrarEnv) RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return e.w.Signer().RelyingPartyAccessCA()
}
func (e registrarEnv) AccessCACRLDistributionPoints() []string {
	return e.w.Signer().CRLDistributionPoints(provider.AccessCACRLPath)
}
func (e registrarEnv) TemplateLocation() credtemplate.Location { return e.w.Templates }
func (e registrarEnv) MaxRelyingParties() int {
	e.w.mu.RLock()
	defer e.w.mu.RUnlock()
	return e.w.capacity.RelyingParties
}
func (e registrarEnv) TrustedListURL(category string) string {
	return e.w.RegistrarBase() + provider.TrustedListPath(category)
}

// TrustedLists is the wallet's set of trusted lists. It works on the
// additions stored in the wallet.
func (w *Wallet) TrustedLists() *trustedlists.Set {
	w.mu.RLock()
	settings := w.TrustSettings
	w.mu.RUnlock()
	return trustedlists.New(&w.mu, &w.Additions, &w.listCache, settings, trustEnv{w})
}

// trustEnv implements trustedlists.Env for the wallet.
type trustEnv struct{ w *Wallet }

func (e trustEnv) Signer() *provider.Signer { return e.w.Signer() }
func (e trustEnv) IssuedAttestationSpecs() []provider.IssuedAttestationSpec {
	return e.w.issuedAttestationSpecs()
}
func (e trustEnv) TemplateLocation() credtemplate.Location { return e.w.Templates }
func (e trustEnv) IssuerURL() string                       { return e.w.IssuerURL }
func (e trustEnv) RegistrarBase() string                   { return e.w.RegistrarBase() }
func (e trustEnv) HTTPClient() *http.Client                { return e.w.HTTPClient() }
func (e trustEnv) Strict() bool                            { return e.w.Mode() == ValidationModeStrict }
func (e trustEnv) ListedProviderName() string              { return listedProviderName }

// The listed provider is the demo issuer. Its certificates carry its EUID as
// NTRNL-NLTEST.00000000 (ETSI EN 319 412-1 V1.6.1 LEG-5.1.4-07 b).
var listedProviderName = demoIssuer().LegalPerson.LegalName[0]
