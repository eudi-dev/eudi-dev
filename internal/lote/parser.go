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

package lote

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// Parse parses the JWT of a list of trusted entities (ETSI TS 119 602).
func Parse(raw string) (*List, error) {
	raw = strings.TrimSpace(raw)

	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing payload: %w", err)
	}

	tl := &List{
		Raw:    raw,
		Header: header,
	}

	lote, ok := payload["LoTE"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parsing payload: missing top-level LoTE object")
	}

	if lsi, ok := lote["ListAndSchemeInformation"].(map[string]any); ok {
		tl.SchemeInfo = parseSchemeInfo(lsi, &tl.Findings)
	}

	if tel, ok := lote["TrustedEntitiesList"].([]any); ok {
		for i, entry := range tel {
			entryMap, ok := entry.(map[string]any)
			if !ok {
				tl.Findings = append(tl.Findings, fmt.Sprintf("trusted entity %d is not an object, so it is ignored", i+1))
				continue
			}
			tl.Entities = append(tl.Entities, parseTrustedEntity(entryMap, i+1, &tl.Findings))
		}
	}

	return tl, nil
}

func parseSchemeInfo(lsi map[string]any, findings *[]string) *SchemeInfo {
	info := &SchemeInfo{}

	if lt, ok := lsi["LoTEType"].(string); ok {
		info.LoTEType = lt
	}

	info.SchemeOperatorName = firstMultiLangValue(lsi["SchemeOperatorName"])

	// Lists in the wild spell the key both "ListIssueDateTime" and
	// "ListIssueDatetime".
	for _, key := range []string{"ListIssueDateTime", "ListIssueDatetime"} {
		if lid, ok := lsi[key].(string); ok {
			info.ListIssueDatetime = lid
			break
		}
	}
	if next, ok := lsi["NextUpdate"].(string); ok {
		info.NextUpdate = next
	}
	info.SchemeTerritory, _ = lsi["SchemeTerritory"].(string)
	pointers, _ := lsi["PointersToOtherLoTE"].([]any)
	for _, raw := range pointers {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		pointer := Pointer{}
		pointer.Location, _ = entry["LoTELocation"].(string)
		if qualifiers, ok := entry["LoTEQualifiers"].([]any); ok && len(qualifiers) > 0 {
			if q, ok := qualifiers[0].(map[string]any); ok {
				pointer.LoTEType, _ = q["LoTEType"].(string)
				pointer.SchemeOperatorName = firstMultiLangValue(q["SchemeOperatorName"])
				pointer.SchemeTerritory, _ = q["SchemeTerritory"].(string)
			}
		}
		identities, _ := entry["ServiceDigitalIdentities"].([]any)
		for _, identity := range identities {
			if m, ok := identity.(map[string]any); ok {
				pointer.Certificates = append(pointer.Certificates, parseCertificates(m["X509Certificates"], "the pointer to "+pointer.Location, findings)...)
			}
		}
		info.Pointers = append(info.Pointers, pointer)
	}

	return info
}

// parseCertificates reads the X509Certificates of a digital identity (ETSI TS
// 119 602 V1.1.1 §6.6.3). An unreadable certificate is left out with a
// finding, because it cannot anchor anything.
func parseCertificates(raw any, owner string, findings *[]string) []CertInfo {
	certs, _ := raw.([]any)
	var out []CertInfo
	for i, cert := range certs {
		certMap, _ := cert.(map[string]any)
		val, ok := certMap["val"].(string)
		if !ok {
			*findings = append(*findings, fmt.Sprintf("certificate %d of %s has no val string, so it is ignored", i+1, owner))
			continue
		}
		info, err := parseCertificate(val)
		if err != nil {
			*findings = append(*findings, fmt.Sprintf("certificate %d of %s is ignored: %v", i+1, owner, err))
			continue
		}
		out = append(out, info)
	}
	return out
}

func parseTrustedEntity(entry map[string]any, position int, findings *[]string) TrustedEntity {
	entity := TrustedEntity{}

	if tei, ok := entry["TrustedEntityInformation"].(map[string]any); ok {
		if names, ok := tei["TEName"].([]any); ok && len(names) > 0 {
			if name, ok := names[0].(map[string]any); ok {
				if v, ok := name["value"].(string); ok {
					entity.Name = v
				}
			}
		}
	}

	owner := fmt.Sprintf("trusted entity %d", position)
	if entity.Name != "" {
		owner = fmt.Sprintf("the trusted entity %q", entity.Name)
	}
	if tes, ok := entry["TrustedEntityServices"].([]any); ok {
		for i, svc := range tes {
			svcMap, _ := svc.(map[string]any)
			si, ok := svcMap["ServiceInformation"].(map[string]any)
			if !ok {
				*findings = append(*findings, fmt.Sprintf("service %d of %s has no ServiceInformation, so it is ignored", i+1, owner))
				continue
			}
			entity.Services = append(entity.Services, parseTrustedService(si, fmt.Sprintf("service %d of %s", i+1, owner), findings))
		}
	}

	return entity
}

func parseTrustedService(si map[string]any, owner string, findings *[]string) TrustedService {
	service := TrustedService{}
	service.ServiceType, _ = si["ServiceTypeIdentifier"].(string)
	service.ServiceStatus, _ = si["ServiceStatus"].(string)
	if sdi, ok := si["ServiceDigitalIdentity"].(map[string]any); ok {
		service.Certificates = parseCertificates(sdi["X509Certificates"], owner, findings)
	}
	return service
}

func parseCertificate(b64 string) (CertInfo, error) {
	der, err := format.DecodeBase64Std(b64)
	if err != nil {
		return CertInfo{}, fmt.Errorf("decoding certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertInfo{}, fmt.Errorf("parsing certificate: %w", err)
	}
	return newCertInfo(cert), nil
}

// newCertInfo describes a certificate as a trusted list entry.
func newCertInfo(cert *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.Format("2006-01-02"),
		NotAfter:  cert.NotAfter.Format("2006-01-02"),
		PublicKey: cert.PublicKey,
		Raw:       cert.Raw,
	}
}

// CertInfos describes parsed certificates as trusted list entries.
func CertInfos(certs []*x509.Certificate) []CertInfo {
	infos := make([]CertInfo, 0, len(certs))
	for _, cert := range certs {
		infos = append(infos, newCertInfo(cert))
	}
	return infos
}

// Certificates parses the entries back into certificates. An entry that is
// not a certificate is an error.
func Certificates(infos []CertInfo) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(infos))
	for i, info := range infos {
		cert, err := x509.ParseCertificate(info.Raw)
		if err != nil {
			return nil, fmt.Errorf("trust anchor %d is not a certificate: %w", i+1, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Current checks that the list is not past its NextUpdate. ETSI TS 119 602
// V1.1.1 §6.3.15: "LoTE with a Next update occurring in the past shall be
// discarded as expired". A closed list has a null NextUpdate, and its
// services are expired too.
func (tl *List) Current(now time.Time) error {
	var next string
	if tl.SchemeInfo != nil {
		next = tl.SchemeInfo.NextUpdate
	}
	at, err := time.Parse(time.RFC3339, next)
	switch {
	case err != nil:
		return fmt.Errorf("the trusted list has no NextUpdate date, so it is closed or malformed (ETSI TS 119 602 V1.1.1 §6.3.15)")
	case at.Before(now):
		return fmt.Errorf("the trusted list expired at %s (ETSI TS 119 602 V1.1.1 §6.3.15)", next)
	}
	return nil
}

// Anchors returns the certificates of the services of one kind on a current
// list. See ServiceCertificates for the kinds.
func Anchors(tl *List, kind string, now time.Time) ([]*x509.Certificate, error) {
	if err := tl.Current(now); err != nil {
		return nil, err
	}
	return Certificates(ServiceCertificates(tl, kind))
}

// Service kinds of ServiceCertificates. In ETSI TS 119 602 V1.1.1 the service
// types of each list end in these suffixes, such as
// http://uri.etsi.org/19602/SvcType/PID/Issuance and .../PID/Revocation.
const (
	IssuanceServices   = "Issuance"
	RevocationServices = "Revocation"
)

// ServiceCertificates returns the certificates of the services of one kind:
// the issuance services anchor credentials, the revocation services their
// status lists (ETSI TS 119 602 V1.1.1 Table D.3). Withdrawn services don't
// count. If no service of a list has either kind, every service counts.
func ServiceCertificates(tl *List, kind string) []CertInfo {
	typed := false
	for _, entity := range tl.Entities {
		for _, svc := range entity.Services {
			typed = typed || strings.HasSuffix(svc.ServiceType, "/"+IssuanceServices) || strings.HasSuffix(svc.ServiceType, "/"+RevocationServices)
		}
	}
	var certs []CertInfo
	for _, entity := range tl.Entities {
		for _, svc := range entity.Services {
			if strings.HasSuffix(svc.ServiceStatus, "/withdrawn") || (typed && !strings.HasSuffix(svc.ServiceType, "/"+kind)) {
				continue
			}
			certs = append(certs, svc.Certificates...)
		}
	}
	return certs
}

// firstMultiLangValue is the first value of a sequence of multilingual
// strings (ETSI TS 119 602 V1.1.1 §6.1.4).
func firstMultiLangValue(raw any) string {
	values, _ := raw.([]any)
	if len(values) == 0 {
		return ""
	}
	entry, _ := values[0].(map[string]any)
	value, _ := entry["value"].(string)
	return value
}
