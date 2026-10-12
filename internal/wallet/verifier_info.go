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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/jws"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
)

// ETSI TS 119 475 identifies registration certificates by rc-wrp+jwt. Select by this
// typ even though the verifier_info format is registration_cert (ETSI TS 119 472-2).
const registrationCertificateTyp = "rc-wrp+jwt"

// Read registered purposes from verifier_info for the consent dialog (OpenID4VP 1.0
// §5.1). Only rc-wrp+jwt certificates whose signature verifies against their own x5c
// leaf contribute purposes. Their sub identifies a legal entity and may differ from
// client_id.
func verifierInfoPurposes(payload map[string]any) (purposes []string, findings []string) {
	certs, findings := verifiedRegistrationCertificates(payload)
	for _, cert := range certs {
		for _, purpose := range purposeStrings(cert["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
	}
	return purposes, findings
}

// Verify signatures against each certificate's own x5c leaf. This does not establish
// trust in the signer. See SECURITY.md.
func verifiedRegistrationCertificates(payload map[string]any) (certs []map[string]any, findings []string) {
	for _, entry := range verifierInfoEntries(payload) {
		data, _ := entry["data"].(string)
		if strings.Count(data, ".") != 2 {
			continue
		}
		header, claims, err := decodeCompactJWT(data)
		if err != nil {
			continue
		}
		if typ, _ := header["typ"].(string); typ != registrationCertificateTyp {
			continue
		}
		key, err := validate.ExtractX5CLeafKey(header)
		if err != nil || key == nil {
			findings = append(findings, "The registration certificate carries no readable x5c certificate, so its signature cannot be checked and its purpose is not shown")
			continue
		}
		if _, err := jws.Verify(data, key); err != nil {
			findings = append(findings, fmt.Sprintf("The registration certificate signature does not verify with its x5c leaf, so its purpose is not shown: %v", err))
			continue
		}
		certs = append(certs, claims)
	}
	return certs, findings
}

// Unsigned requests carry verifier_info as a parameter. Signed requests use only the
// Request Object (OID4VP 1.0 §5.10.1). Certificate content checks follow ETSI TS 119
// 475 and ARF RPRC_19. They stay warnings in every mode because strict mode covers
// only OpenID4VP and HAIP.
func (w *Wallet) consentPurposes(scope string, authReq *AuthorizationRequestParams) []string {
	if authReq == nil {
		return nil
	}
	payload := authReq.RequestPayload
	if payload == nil && authReq.RequestObject == nil && strings.TrimSpace(authReq.FullParams["verifier_info"]) != "" {
		payload = map[string]any{"verifier_info": authReq.FullParams["verifier_info"]}
	}

	certs, findings := verifiedRegistrationCertificates(payload)
	if len(certs) == 0 {
		findings = append(findings, "ARF RPRC_19: the request carries no relying party registration certificate (verifier_info entry with typ rc-wrp+jwt), required in every presentation request")
	}

	var purposes []string
	for _, cert := range certs {
		findings = append(findings, registrationCertificateContentFindings(cert)...)
		findings = append(findings, overAskingFindings(cert, authReq.DCQLQuery)...)
		for _, purpose := range purposeStrings(cert["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
	}
	w.warnFindings(scope, "The relying party registration certificate does not follow the ARF and ETSI TS 119 475", findings)
	return purposes
}

// Check required content from ETSI TS 119 475 V1.2.1 §5.2.4 and ARF Topic 44. Missing
// fields produce warnings.
func registrationCertificateContentFindings(cert map[string]any) []string {
	var findings []string
	miss := func(field, rule string) {
		findings = append(findings, fmt.Sprintf("%s: the registration certificate has no %s", rule, field))
	}
	if stringClaim(cert["name"]) == "" {
		miss("name (trade name)", "ARF RPRC_06")
	}
	if stringClaim(cert["sub"]) == "" {
		miss("sub (relying party identifier)", "ARF RPRC_07")
	}
	if stringClaim(cert["privacy_policy"]) == "" {
		miss("privacy_policy", "ETSI TS 119 475 §5.2.4")
	}
	if len(purposeStrings(cert["srv_description"])) == 0 {
		miss("srv_description", "ETSI TS 119 475 §5.2.4")
	}
	if !nonEmptyList(cert["entitlements"]) {
		miss("entitlements (at least one)", "ETSI TS 119 475 GEN-5.2.4-03")
	}
	if !hasContact(cert["support_uri"]) {
		miss("support_uri (data deletion contact)", "ARF RPRC_11")
	}
	if !hasSupervisoryAuthority(cert["supervisory_authority"]) {
		miss("supervisory_authority contact", "ARF RPRC_12")
	}
	if !nonEmptyList(cert["credentials"]) {
		miss("credentials (the registered attestations and attributes)", "ETSI TS 119 475 GEN-5.2.4-06")
	}
	return append(findings, registrationValidityFindings(cert)...)
}

// ETSI TS 119 475 GEN-5.2.4-08 and ARF RPRC_17 require iat. If exp is present, it must
// be in the future and within 12 months of iat.
func registrationValidityFindings(cert map[string]any) []string {
	var findings []string
	iat, hasIat := numberClaim(cert["iat"])
	if !hasIat {
		findings = append(findings, "ETSI TS 119 475 §5.2.4: the registration certificate has no iat")
	}
	exp, hasExp := numberClaim(cert["exp"])
	if !hasExp {
		return findings
	}
	expTime := time.Unix(int64(exp), 0)
	if expTime.Before(time.Now()) {
		findings = append(findings, "ARF RPRC_17: the registration certificate has expired")
	}
	if hasIat && expTime.After(time.Unix(int64(iat), 0).AddDate(1, 0, 0)) {
		findings = append(findings, "ETSI TS 119 475 GEN-5.2.4-08: the registration certificate is valid for more than 12 months")
	}
	return findings
}

// ARF RPRC_21 requires requested claims to be registered. Report one finding for an
// unregistered credential type, or one per unregistered attribute of a registered
// type.
func overAskingFindings(cert map[string]any, dcql map[string]any) []string {
	registered := registeredCredentials(cert)
	if len(registered) == 0 {
		// A missing credentials list already has a content finding and provides
		// nothing to compare.
		return nil
	}
	var findings []string
	overAsk := func(what string) {
		findings = append(findings, fmt.Sprintf("ARF RPRC_21: the request asks for %s, which the registration certificate does not register (over-asking)", what))
	}
	for _, cq := range listOfMaps(dcql["credentials"]) {
		format, _ := cq["format"].(string)
		types := credentialTypes(cq["meta"])
		if !registersCredential(registered, format, types) {
			overAsk(credentialTypeName(format, types))
			continue
		}
		for _, claim := range listOfMaps(cq["claims"]) {
			path := toAnyList(claim["path"])
			if len(path) == 0 {
				continue
			}
			if !registeredCovers(registered, format, types, path) {
				overAsk(describeClaim(format, types, path))
			}
		}
	}
	return findings
}

func registersCredential(registered []registeredCredential, format string, types []string) bool {
	for _, rc := range registered {
		if rc.matches(format, types) {
			return true
		}
	}
	return false
}

// Without a claim list, the entry registers the credential without an attribute
// restriction (ETSI TS 119 475 §5.2.4 Table 9).
type registeredCredential struct {
	format          string
	types           []string
	paths           [][]any
	anyClaimAllowed bool
}

// An omitted format or type on either side does not restrict matching.
func (rc registeredCredential) matches(format string, types []string) bool {
	if format != "" && rc.format != "" && rc.format != format {
		return false
	}
	return typesOverlap(types, rc.types)
}

func registeredCredentials(cert map[string]any) []registeredCredential {
	var out []registeredCredential
	for _, entry := range listOfMaps(cert["credentials"]) {
		format, _ := entry["format"].(string)
		rc := registeredCredential{format: format, types: credentialTypes(entry["meta"])}
		claims := listOfMaps(entry["claim"])
		if len(claims) == 0 {
			// ETSI TS 119 475 §5.2.4 Table 9 allows omitting specific attributes.
			// Treat this as registration without an attribute restriction.
			rc.anyClaimAllowed = true
		}
		for _, claim := range claims {
			if path := toAnyList(claim["path"]); len(path) > 0 {
				rc.paths = append(rc.paths, path)
			}
		}
		out = append(out, rc)
	}
	return out
}

func registeredCovers(registered []registeredCredential, format string, types []string, path []any) bool {
	for _, rc := range registered {
		if !rc.matches(format, types) {
			continue
		}
		if rc.anyClaimAllowed {
			return true
		}
		for _, registeredPath := range rc.paths {
			if pathPrefix(registeredPath, path) {
				return true
			}
		}
	}
	return false
}

// An empty type list does not restrict matching.
func typesOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Registering a parent path such as address also covers children such as
// address.street_address.
func pathPrefix(registered, requested []any) bool {
	if len(registered) > len(requested) {
		return false
	}
	for i := range registered {
		if fmt.Sprint(registered[i]) != fmt.Sprint(requested[i]) {
			return false
		}
	}
	return true
}

// SD-JWT VC uses vct_values. mdoc uses doctype_value.
func credentialTypes(meta any) []string {
	m, ok := meta.(map[string]any)
	if !ok {
		return nil
	}
	var types []string
	for _, v := range toAnyList(m["vct_values"]) {
		if s, ok := v.(string); ok {
			types = append(types, s)
		}
	}
	if s, ok := m["doctype_value"].(string); ok && s != "" {
		types = append(types, s)
	}
	return types
}

func describeClaim(format string, types []string, path []any) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprint(p)
	}
	claim := strings.Join(parts, ".")
	label := credentialTypeName(format, types)
	if label == "" {
		return claim
	}
	return fmt.Sprintf("%s of %s", claim, label)
}

func credentialTypeName(format string, types []string) string {
	if len(types) > 0 {
		return types[0]
	}
	return format
}

func stringClaim(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func numberClaim(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func nonEmptyList(v any) bool {
	list, ok := v.([]any)
	return ok && len(list) > 0
}

// ETSI TS 119 475 permits one or more contact addresses.
func hasContact(v any) bool {
	if stringClaim(v) != "" {
		return true
	}
	return nonEmptyList(v)
}

func hasSupervisoryAuthority(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return stringClaim(m["email"]) != "" || stringClaim(m["phone"]) != "" || stringClaim(m["uri"]) != ""
}

func listOfMaps(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toAnyList(v any) []any {
	list, _ := v.([]any)
	return list
}

// SignRegistrationCertificateJWT includes the leaf in x5c so wallets can verify the
// registered purpose.
func SignRegistrationCertificateJWT(claims map[string]any, signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": registrationCertificateTyp,
	}
	if x5c := buildJWSX5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
		digest := sha256.Sum256(signerCerts[0].Raw)
		header["x5t#S256"] = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	// TS 119 475 V1.2.1 §5.2.1 requires JAdES B-B. TS 119 182-1 V1.2.1 §5.1.11 requires iat after July 2025.
	header["iat"] = time.Now().Unix()
	return signJSONWebSignature(claims, signingKey, header)
}

// Plain request parameters carry verifier_info as a JSON string.
func verifierInfoEntries(payload map[string]any) []map[string]any {
	if payload == nil {
		return nil
	}
	raw := payload["verifier_info"]
	if encoded, ok := raw.(string); ok && encoded != "" {
		var decoded any
		if err := json.Unmarshal([]byte(encoded), &decoded); err == nil {
			raw = decoded
		}
	}
	list, _ := raw.([]any)
	entries := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// Prefer English, then the first available translation. Certificate entries use value.
// The TS5 data model uses content. Plain strings pass through unchanged.
func purposeStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		if v := strings.TrimSpace(value); v != "" {
			return []string{v}
		}
	case []any:
		var plain []string
		var first, english string
		for _, item := range value {
			switch entry := item.(type) {
			case string:
				if v := strings.TrimSpace(entry); v != "" {
					plain = append(plain, v)
				}
			case map[string]any:
				text, _ := entry["value"].(string)
				if text == "" {
					text, _ = entry["content"].(string)
				}
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}
				if first == "" {
					first = text
				}
				if lang, _ := entry["lang"].(string); strings.HasPrefix(strings.ToLower(lang), "en") && english == "" {
					english = text
				}
			}
		}
		if english != "" {
			return append(plain, english)
		}
		if first != "" {
			return append(plain, first)
		}
		return plain
	}
	return nil
}

func containsPurpose(purposes []string, purpose string) bool {
	for _, p := range purposes {
		if p == purpose {
			return true
		}
	}
	return false
}

// Decoding does not verify the signature. The caller must verify it where possible.
func decodeCompactJWT(compact string) (header, payload map[string]any, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWT")
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return header, payload, nil
}
