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
	"encoding/json"
	"fmt"
	"log"
	"path"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/defaults"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// The demo issuer and the demo verifier are registered with the wallet's
// registrar like any relying party. Their registrations are TS05 files in the
// defaults tree with one service each. The wallet adds what depends on its
// templates. Each party is identified by the organizationIdentifier of its
// access certificate (ETSI TS 119 475 V1.2.1 §5.1.1).
var (
	demoIssuer   = demoRegistrationFile("demo-issuer.json")
	demoVerifier = demoRegistrationFile("demo-verifier.json")

	// DemoIssuerName and DemoVerifierName are the trade names of the demo
	// parties.
	DemoIssuerName   = demoIssuer().TradeName
	DemoVerifierName = demoVerifier().TradeName
)

// demoRegistrationFile reads a registration of the defaults tree. Each call
// of the result returns a fresh copy.
func demoRegistrationFile(name string) func() registrar.WalletRelyingParty {
	data, err := defaults.ReadFile(path.Join("registrations", name))
	if err != nil {
		panic(fmt.Sprintf("reading the demo registration %s: %v", name, err))
	}
	return func() registrar.WalletRelyingParty {
		var rp registrar.WalletRelyingParty
		if err := json.Unmarshal(data, &rp); err != nil || len(rp.Identifier) == 0 || len(rp.Services) != 1 || len(rp.Services[0].IntendedUses) != 1 {
			panic(fmt.Sprintf("the demo registration %s needs an identifier and one service with one intended use: %v", name, err))
		}
		return rp
	}
}

func demoIdentifier(registration func() registrar.WalletRelyingParty) string {
	return registration().Identifier[0].Identifier
}

// IdentityCheckClaims are the PID claims that the demo issuer's identity
// check asks for, as registered for its intended use.
func IdentityCheckClaims() []string {
	var claims []string
	for _, c := range demoIssuer().Services[0].IntendedUses[0].Credentials {
		if c.Format != credtype.FormatSDJWT {
			continue
		}
		for _, claim := range c.Claims {
			if name, ok := claim.Path[0].(string); ok && len(claim.Path) == 1 {
				claims = append(claims, name)
			}
		}
	}
	return claims
}

// DemoVerifierAccessSigningMaterial is the access certificate of the demo
// verifier. The demo verifier is a relying party of its own, so its
// certificate identifies a different organization from the demo issuer.
func (w *Wallet) DemoVerifierAccessSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.demoAccessSigningMaterial("demo-verifier-access", demoVerifier())
}

// demoAccessSigningMaterial has the registrar sign the access certificate of
// a demo relying party, with a key from the signing store. The wallet keeps
// the certificate until it is about to expire. The DNS name of the issuer URL
// makes x509_san_dns client identifiers work (OpenID4VP 1.0 §5.9.3).
func (w *Wallet) demoAccessSigningMaterial(keyName string, registration registrar.WalletRelyingParty) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	key, err := w.signingStore().key(keyName)
	if err != nil {
		return nil, nil, err
	}
	service := registration.Services[0]
	tradeName, serviceID := service.ServiceTradeName, service.ServiceIdentifier
	registration.Services = []registrar.WalletRelyingPartyService{{ServiceTradeName: tradeName, ServiceIdentifier: serviceID}}
	rp, err := w.Registrar().NormalizedRelyingParty(registration)
	if err != nil {
		return nil, nil, err
	}
	_, ca, err := w.RelyingPartyAccessCA()
	if err != nil {
		return nil, nil, err
	}
	dnsNames, _, _ := issuerSubjectAltNames(w.IssuerURL)
	subject, err := json.Marshal([]any{rp.Identifier[0].Identifier, rp.LegalPerson.LegalName, rp.Country, tradeName, serviceID, rp.Services[0].SupportURI, dnsNames})
	if err != nil {
		return nil, nil, err
	}
	leaf, err := w.signingStore().cachedCertificate(subject, ca, &key.PublicKey, false, func() (*x509.Certificate, error) {
		chain, err := w.Registrar().AccessCertificateFor(rp, serviceID, &key.PublicKey, dnsNames, registrar.MaxAccessCertificateValidity)
		if err != nil {
			return nil, err
		}
		return chain[0], nil
	})
	if err != nil {
		return nil, nil, err
	}
	return key, []*x509.Certificate{leaf, ca}, nil
}

// EnsureDemoRegistrations registers the demo issuer and the demo verifier, or
// updates them to the wallet's templates, and makes sure both have a current
// certificate for each of their registered uses. It reports whether the
// registrar state changed.
func (w *Wallet) EnsureDemoRegistrations() (bool, error) {
	return w.registerDemoParties(true)
}

// RegisterMissingDemoParties registers the demo issuer and verifier when the
// registrar has no registration for them, and keeps an existing one. Both get
// a current certificate for each of their registered uses.
func (w *Wallet) RegisterMissingDemoParties() (bool, error) {
	return w.registerDemoParties(false)
}

func (w *Wallet) registerDemoParties(overwrite bool) (bool, error) {
	changed := false
	for _, build := range []demoRegistration{w.demoIssuerRegistration, w.demoVerifierRegistration} {
		updated, err := w.ensureDemoRegistration(build, overwrite)
		if err != nil {
			return changed, err
		}
		changed = changed || updated
	}
	return changed, nil
}

// DemoIssuerInfo is the issuer_info of the demo issuer (ETSI TS 119 472-3
// V1.1.1 §4.2.3): its registrar dataset and its registration certificate.
func (w *Wallet) DemoIssuerInfo() ([]any, error) {
	result, err := w.demoCertificate(w.demoIssuerRegistration, registrar.RegistrationCertificateRequest{ServiceIdentifier: demoIssuer().Services[0].ServiceIdentifier})
	if err != nil || result == nil {
		return nil, err
	}
	return decodeInfo(result.IssuerInfo, "issuer_info")
}

// DemoVerifierInfo is the verifier_info of the demo verifier (OpenID4VP 1.0
// §5.1): the registration certificate of its intended use.
func (w *Wallet) DemoVerifierInfo() ([]any, error) {
	result, err := w.demoCertificate(w.demoVerifierRegistration, registrar.RegistrationCertificateRequest{IntendedUseIdentifier: demoVerifier().Services[0].IntendedUses[0].IntendedUseIdentifier})
	if err != nil || result == nil {
		return nil, err
	}
	return decodeInfo(result.VerifierInfo, "verifier_info")
}

// DemoIdentityCheckVerifierInfo is the verifier_info of the demo issuer's
// identity check. The demo issuer asks for a PID before it issues, and this
// is the registration certificate of that intended use.
func (w *Wallet) DemoIdentityCheckVerifierInfo() ([]any, error) {
	result, err := w.demoCertificate(w.demoIssuerRegistration, registrar.RegistrationCertificateRequest{IntendedUseIdentifier: demoIssuer().Services[0].IntendedUses[0].IntendedUseIdentifier})
	if err != nil || result == nil {
		return nil, err
	}
	return decodeInfo(result.VerifierInfo, "verifier_info")
}

type demoRegistration func() (registrar.WalletRelyingParty, error)

// demoCertificate returns the current certificate that req names in a demo
// registration and issues one when there is none or it expires soon. The
// registration fills in the identifier. A deleted registration has no
// certificate, and the result is nil. A running server saves a new
// certificate.
func (w *Wallet) demoCertificate(build demoRegistration, req registrar.RegistrationCertificateRequest) (*registrar.RegistrationCertificateResult, error) {
	var result *registrar.RegistrationCertificateResult
	var err error
	change := func() bool {
		w.demoRegistrationMu.Lock()
		defer w.demoRegistrationMu.Unlock()
		var issued bool
		rp, buildErr := build()
		if buildErr != nil {
			err = buildErr
			return false
		}
		req.Identifier = rp.Identifier[0].Identifier
		result, issued, err = w.Registrar().CurrentRegistrationCertificate(req)
		return issued
	}
	w.saveChange(change)
	if registrar.IsNotRegistered(err) {
		return nil, nil
	}
	return result, err
}

func (w *Wallet) ensureDemoRegistration(build demoRegistration, overwrite bool) (bool, error) {
	w.demoRegistrationMu.Lock()
	defer w.demoRegistrationMu.Unlock()
	rp, err := build()
	if err != nil {
		return false, err
	}
	var updated bool
	if stored, exists := w.Registrar().RelyingParty(rp.Identifier[0].Identifier); exists && !overwrite {
		updated, err = w.rebaseDemoParty(stored)
		rp = stored
	} else {
		_, updated, err = w.Registrar().EnsureRelyingParty(rp)
	}
	if err != nil {
		return false, err
	}
	for _, req := range registrar.CertificateRequests(rp) {
		_, issued, err := w.Registrar().CurrentRegistrationCertificate(req)
		if err != nil {
			return updated, err
		}
		updated = updated || issued
	}
	return updated, nil
}

func decodeInfo(value, name string) ([]any, error) {
	var info []any
	if err := json.Unmarshal([]byte(value), &info); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	return info, nil
}

// demoIssuerRegistration registers the demo issuer as a provider of the
// credential types it issues, with the entitlements of their categories (ETSI
// TS 119 475 V1.2.1 Table 8). A type gets its category from its template or
// its catalogue entry. A type without one is an EAA, and an unlisted type is
// left out. Its identity check asks for a PID before it issues, so it
// registers that intended use too.
func (w *Wallet) demoIssuerRegistration() (registrar.WalletRelyingParty, error) {
	catalogue := w.Registrar().CatalogAttestations()
	var entitlements, vcts, docTypes []string
	add := func(category, format, vct, docType string) {
		if entry, ok := catalogueEntryIn(catalogue, format, []string{vct, docType}); ok && category == "" {
			category = entry.Category
		}
		switch category {
		case UnlistedCategory:
			return
		case "":
			category = credtemplate.CategoryEAA
		}
		switch format {
		case credtype.FormatSDJWT:
			vcts = append(vcts, vct)
		case credtype.FormatMDOC:
			docTypes = append(docTypes, docType)
		default:
			return
		}
		entitlements = append(entitlements, registrar.CategoryOf(category).Entitlement)
	}
	templates, err := credtemplate.List(w.Templates)
	if err != nil {
		log.Printf("[Wallet] WARNING: the demo issuer is registered without the templates the wallet can't read: %v", err)
	}
	for _, t := range templates {
		switch format, _ := credtemplate.NormalizeFormat(t.Format); {
		case format == "sdjwt" && t.VCT != "":
			add(t.Category, credtype.FormatSDJWT, t.VCT, "")
		case format == "mdoc" && t.DocType != "":
			add(t.Category, credtype.FormatMDOC, "", t.DocType)
		}
	}
	for _, spec := range w.issuedAttestationSpecs() {
		add(spec.Category, spec.Format, spec.VCT, spec.DocType)
	}
	var provides []registrar.ProvidedAttestation
	for _, vct := range sortedUnique(vcts) {
		provides = append(provides, registrar.ProvidedAttestation{Format: credtype.FormatSDJWT, Type: vct})
	}
	for _, docType := range sortedUnique(docTypes) {
		provides = append(provides, registrar.ProvidedAttestation{Format: credtype.FormatMDOC, Type: docType})
	}
	rp := demoIssuer()
	rp.Services[0].Entitlements = sortedUnique(entitlements)
	rp.Services[0].ProvidesAttestations = provides
	return rp, nil
}

// demoVerifierRegistration registers the demo verifier with one intended use.
// It covers the claims of every predefined credential template, so the demo
// requests ask only for registered claims (ARF RPRC_21).
func (w *Wallet) demoVerifierRegistration() (registrar.WalletRelyingParty, error) {
	var credentials []registrar.RegisteredCredential
	for _, entry := range w.Registrar().CatalogAttestations() {
		if !entry.Template {
			continue
		}
		for _, c := range entry.Credentials {
			meta := map[string]any{"vct_values": []string{c.Type}}
			if c.Format == credtype.FormatMDOC {
				meta = map[string]any{"doctype_value": c.Type}
			}
			rc := registrar.RegisteredCredential{Format: c.Format, Meta: meta}
			for _, path := range c.Claims {
				rc.Claims = append(rc.Claims, registrar.RegisteredClaim{Path: path})
			}
			credentials = append(credentials, rc)
		}
	}
	rp := demoVerifier()
	rp.Services[0].IntendedUses[0].Credentials = credentials
	return rp, nil
}

func sortedUnique(values []string) []string {
	out := slices.DeleteFunc(slices.Clone(values), func(v string) bool { return strings.TrimSpace(v) == "" })
	slices.Sort(out)
	return slices.Compact(out)
}

// rebaseDemoParty moves the URLs of a kept demo registration to the wallet's
// current base URL, for a wallet that restarts on another port or base URL.
// The registry URI shows the base the registration was made under.
func (w *Wallet) rebaseDemoParty(stored registrar.WalletRelyingParty) (bool, error) {
	previous := strings.TrimSuffix(stored.RegistryURI, "/api/registrar/wrp/"+stored.Identifier[0].Identifier)
	current := w.RegistrarBase()
	if previous == stored.RegistryURI || previous == current {
		return false, nil
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return false, err
	}
	quoted := func(base string) []byte { b, _ := json.Marshal(base); return b[:len(b)-1] }
	var rebased registrar.WalletRelyingParty
	if err := json.Unmarshal(bytes.ReplaceAll(raw, quoted(previous), quoted(current)), &rebased); err != nil {
		return false, err
	}
	if _, err := w.Registrar().UpdateRelyingParty(rebased); err != nil {
		return false, err
	}
	return true, nil
}
