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
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
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

// ConsentRegistration returns the purposes and privacy policy links the consent
// dialog shows (ARF RPA_10). It uses only registration certificates bound to
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
func ARFFindings(authReq *Request) []string {
	if authReq == nil {
		return nil
	}
	registrations, problems := regcert.Verify(regcert.InfoEntries(requestVerifierInfo(authReq), "verifier_info"))
	var findings []string
	for _, problem := range problems {
		findings = append(findings, "ARF RPRC_17: the registration certificate "+problem)
	}
	switch count := len(registrations) + len(problems); {
	case count == 0:
		findings = append(findings, "ARF RPRC_17 and RPRC_19 and ETSI TS 119 472-2 OIDFVP-HAIP-COMMON-REQ-RO-13 as adapted by CIR (EU) 2026/1731 Annex XII: the request carries no registration certificate (typ rc-wrp+jwt) in verifier_info")
	case count > 1:
		findings = append(findings, fmt.Sprintf("ARF RPRC_19: the request carries %d registration certificates. It must carry exactly one", count))
	}
	accessChain := requestAccessChain(authReq)
	if len(accessChain) == 0 {
		findings = append(findings, "ARF RPA_03: the request is not signed with a relying party access certificate in x5c")
	} else if _, err := certchain.Verify(accessChain, authReq.RelyingPartyCAs); err != nil {
		findings = append(findings, fmt.Sprintf("ARF RPA_04: the access certificate %q does not chain to a trusted access certificate authority: %v", accessChain[0].Subject.String(), err))
	}
	for _, r := range registrations {
		cert := r.Claims
		name := jsonutil.FirstNonEmpty(jsonutil.Text(cert["name"]), jsonutil.Text(cert["sub"]), "the relying party")
		findings = append(findings, regcert.ContentFindings(cert)...)
		if len(accessChain) > 0 {
			findings = append(findings, regcert.BindingFindings(cert, accessChain[0], "ARF RPRC_17a")...)
		}
		if _, err := certchain.Verify(r.Chain, authReq.RegistrarCAs); err != nil {
			findings = append(findings, fmt.Sprintf("ARF RPRC_02a: the registration certificate of %s does not chain to a trusted registrar: %v", name, err))
		}
		findings = append(findings, regcert.StatusFindings(cert, authReq.StatusClient, authReq.RegistrationStatusCAs, "ARF RPRC_17")...)
	}
	// RPRC_21 compares the request with "the registration certificate included
	// in the same request".
	if len(registrations) == 1 {
		findings = append(findings, regcert.OverAskingFindings(registrations[0].Claims, authReq.DCQLQuery)...)
	}
	return findings
}

// relyingPartyAuthenticated reports whether a trusted access certificate
// signed the request (ARF RPA_03 and RPA_04).
func relyingPartyAuthenticated(authReq *Request) bool {
	chain := requestAccessChain(authReq)
	_, err := certchain.Verify(chain, authReq.RelyingPartyCAs)
	return err == nil
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
