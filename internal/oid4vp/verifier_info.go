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

package oid4vp

import (
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// Unsigned requests carry verifier_info as a parameter. Signed requests use only the
// Request Object (OID4VP 1.0 §5.10.1).
func requestVerifierInfo(authReq *Request) map[string]any {
	payload := authReq.RequestPayload
	if payload == nil && authReq.RequestObject == nil && strings.TrimSpace(authReq.FullParams["verifier_info"]) != "" {
		payload = map[string]any{"verifier_info": authReq.FullParams["verifier_info"]}
	}
	return payload
}

// ConsentRegistration returns the purposes and privacy policy links for the
// consent dialog (ARF RPA_10). It uses only registration certificates bound to
// the access certificate that signed the request, because OpenID4VP 1.0 §5.1
// requires the wallet to "validate the signature and ensure binding" of
// information it uses from verifier_info.
func ConsentRegistration(authReq *Request) (purposes, privacyPolicies []string) {
	return regcert.Purposes(boundRegistrations(authReq))
}

// RegisteredName returns the relying party name of the bound registration
// certificates, or "" without one.
func RegisteredName(authReq *Request) string {
	for _, claims := range boundRegistrations(authReq) {
		if name := jsonutil.Text(claims["name"]); name != "" {
			return name
		}
	}
	return ""
}

func boundRegistrations(authReq *Request) []map[string]any {
	if authReq == nil {
		return nil
	}
	accessChain := requestAccessChain(authReq)
	if len(accessChain) == 0 {
		return nil
	}
	registrations, _ := regcert.Verify(regcert.InfoEntries(requestVerifierInfo(authReq), "verifier_info"))
	var bound []map[string]any
	for _, r := range registrations {
		if regcert.Bound(r.Claims, accessChain[0]) {
			bound = append(bound, r.Claims)
		}
	}
	return bound
}

// ARFFindings checks the relying party authentication of a request against
// the ARF and ETSI TS 119 475. --arf turns these checks on. The ARF leaves
// refusing to the Wallet Provider (RPA_06a, RPRC_17, RPRC_21), and strict mode
// refuses.
func ARFFindings(authReq *Request) findings.List {
	if authReq == nil {
		return nil
	}
	registrations, problems := regcert.Verify(regcert.InfoEntries(requestVerifierInfo(authReq), "verifier_info"))
	var list findings.List
	for _, problem := range problems {
		list = append(list, findings.ARF.Registration("RPRC_17").New("the registration certificate "+problem))
	}
	if count := len(registrations) + len(problems); count > 1 {
		list = append(list, findings.ARF.Registration("RPRC_19").Newf("the request carries %d registration certificates. It must carry exactly one", count))
	}
	accessChain := requestAccessChain(authReq)
	if len(accessChain) == 0 {
		list = append(list, findings.ARF.Registration("RPA_03").New("the request is not signed with a relying party access certificate in x5c"))
	} else if path, err := certchain.VerifiedPath(accessChain, authReq.RelyingPartyCAs); err != nil {
		list = append(list, findings.ARF.Registration("RPA_04").Newf("the access certificate %q does not chain to a trusted access certificate authority: %v", accessChain[0].Subject.String(), err))
	} else {
		// CIR (EU) 2024/2982 Article 3(1) and 5(2) require the wallet to validate
		// the relying party with its access certificate. A revoked certificate
		// fails RFC 5280 §6.1.3 (a)(3).
		list = append(list, certchain.RevocationFindings(path, authReq.StatusClient, findings.ARF.Registration("RPA_06a").Cited("ARF RPA_06a and CIR (EU) 2024/2982 Article 3(1) and 5(2)"))...)
	}
	for _, r := range registrations {
		cert := r.Claims
		name := jsonutil.FirstNonEmpty(jsonutil.Text(cert["name"]), jsonutil.Text(cert["sub"]), "the relying party")
		list = append(list, regcert.ContentFindings(cert)...)
		if len(accessChain) > 0 {
			list = append(list, regcert.BindingFindings(cert, accessChain[0], findings.ARF.Registration("RPRC_17a"))...)
		}
		if _, err := certchain.Verify(r.Chain, authReq.RegistrarCAs); err != nil {
			list = append(list, findings.ARF.Registration("RPRC_02a").Newf("the registration certificate of %s does not chain to a trusted registrar: %v", name, err))
		}
		list = append(list, regcert.StatusFindings(cert, authReq.StatusClient, authReq.RegistrationStatusCAs, findings.ARF.Registration("RPRC_17"))...)
	}
	// RPRC_21 compares the request with "the registration certificate included
	// in the same request".
	if len(registrations) == 1 {
		list = append(list, regcert.OverAskingFindings(registrations[0].Claims, authReq.DCQLQuery)...)
	}
	return list
}

// RegistrationDeadline is the date from which wallets must authenticate and
// validate registration certificates. CIR (EU) 2026/1731 defers Article 3(4)
// of CIR (EU) 2024/2982 to it.
const RegistrationDeadline = "11 August 2028"

// ARFAdvisories warns about a request without a registration certificate and
// about a revoked registrar certificate. Wallets must check
// registration certificates only from RegistrationDeadline, so these are
// warnings in every mode.
func ARFAdvisories(authReq *Request) findings.List {
	if authReq == nil {
		return nil
	}
	registrations, problems := regcert.Verify(regcert.InfoEntries(requestVerifierInfo(authReq), "verifier_info"))
	if len(registrations)+len(problems) == 0 {
		rule := findings.ARF.Registration("RPRC_19").Cited("ARF RPRC_19 and ETSI TS 119 472-2 V1.2.1 OIDFVP-HAIP-COMMON-REQ-RO-13 as adapted by CIR (EU) 2026/1731 Annex XII, CIR (EU) 2024/2982 Article 3(4)")
		return findings.List{rule.New("the request carries no registration certificate (typ rc-wrp+jwt) in verifier_info. Wallets must check registration certificates from " + RegistrationDeadline)}
	}
	return RegistrarRevocationAdvisories(registrations, authReq.RegistrarCAs, authReq.StatusClient, findings.ARF.Registration("RPRC_17").Cited("ARF RPRC_17 and CIR (EU) 2024/2982 Annex II WRP-VALIDATION-02 as added by CIR (EU) 2026/1731, CIR (EU) 2024/2982 Article 3(4)"))
}

// RegistrarRevocationAdvisories checks the registrar chain of each
// registration certificate against its CRLs. Only chains to a trusted
// registrar are checked. WRP-VALIDATION-02 counts a revoked certificate as a
// failed validation. It applies from RegistrationDeadline (CIR (EU) 2024/2982
// Article 3(4)).
func RegistrarRevocationAdvisories(registrations []regcert.Registration, registrarCAs []*x509.Certificate, client *http.Client, rule findings.Rule) findings.List {
	var advisories findings.List
	for _, r := range registrations {
		path, err := certchain.VerifiedPath(r.Chain, registrarCAs)
		if err != nil {
			continue
		}
		name := jsonutil.FirstNonEmpty(jsonutil.Text(r.Claims["name"]), jsonutil.Text(r.Claims["sub"]), "the relying party")
		for _, finding := range certchain.RevocationFindings(path, client, rule) {
			finding.Text += ". It signs the registration certificate of " + name + ". Wallets must check registration certificates from " + RegistrationDeadline
			advisories = append(advisories, finding)
		}
	}
	return advisories
}

// relyingPartyAuthenticated reports whether a trusted access certificate
// signed the request (ARF RPA_03 and RPA_04). ARF RPA_06a: with a revoked
// access certificate, "Relying Party authentication fails".
func relyingPartyAuthenticated(authReq *Request) bool {
	path, err := certchain.VerifiedPath(requestAccessChain(authReq), authReq.RelyingPartyCAs)
	if err != nil {
		return false
	}
	for _, problem := range certchain.CheckRevocation(path, authReq.StatusClient, time.Now()) {
		if problem.Revoked {
			return false
		}
	}
	return true
}

// requestAccessChain returns the request object's x5c chain, leaf first, if the
// leaf key verifies the signature. A chain whose leaf didn't sign the request
// proves nothing about the relying party.
func requestAccessChain(authReq *Request) []*x509.Certificate {
	reqObj := authReq.RequestObject
	if reqObj == nil || jsonutil.Text(reqObj.Header["alg"]) == "none" || strings.Count(reqObj.Raw, ".") != 2 {
		return nil
	}
	chain, err := validate.X5CCertificates(reqObj.Header)
	if err != nil || len(chain) == 0 {
		return nil
	}
	if _, err := jws.Verify(reqObj.Raw, chain[0].PublicKey); err != nil {
		return nil
	}
	return chain
}
