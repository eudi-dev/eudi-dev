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

package trustlist

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
)

// Parse parses an ETSI TS 119 602 trust list JWT.
func Parse(raw string) (*TrustList, error) {
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

	tl := &TrustList{
		Raw:    raw,
		Header: header,
	}

	lote, ok := payload["LoTE"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parsing payload: missing top-level LoTE object")
	}

	if lsi, ok := lote["ListAndSchemeInformation"].(map[string]any); ok {
		tl.SchemeInfo = parseSchemeInfo(lsi)
	}

	if tel, ok := lote["TrustedEntitiesList"].([]any); ok {
		for _, entry := range tel {
			entryMap, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			entity, err := parseTrustedEntity(entryMap)
			if err != nil {
				continue
			}
			tl.Entities = append(tl.Entities, *entity)
		}
	}

	return tl, nil
}

func parseSchemeInfo(lsi map[string]any) *SchemeInfo {
	info := &SchemeInfo{}

	if lt, ok := lsi["LoTEType"].(string); ok {
		info.LoTEType = lt
	}

	if son, ok := lsi["SchemeOperatorName"].([]any); ok && len(son) > 0 {
		if entry, ok := son[0].(map[string]any); ok {
			if v, ok := entry["value"].(string); ok {
				info.SchemeOperatorName = v
			}
		}
	}

	// Trust lists in the wild spell the key both "ListIssueDateTime" and
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

	return info
}

func parseTrustedEntity(entry map[string]any) (*TrustedEntity, error) {
	entity := &TrustedEntity{}

	if tei, ok := entry["TrustedEntityInformation"].(map[string]any); ok {
		if names, ok := tei["TEName"].([]any); ok && len(names) > 0 {
			if name, ok := names[0].(map[string]any); ok {
				if v, ok := name["value"].(string); ok {
					entity.Name = v
				}
			}
		}
	}

	if tes, ok := entry["TrustedEntityServices"].([]any); ok {
		for _, svc := range tes {
			svcMap, ok := svc.(map[string]any)
			if !ok {
				continue
			}
			service, err := parseTrustedService(svcMap)
			if err != nil {
				continue
			}
			entity.Services = append(entity.Services, *service)
		}
	}

	return entity, nil
}

func parseTrustedService(svc map[string]any) (*TrustedService, error) {
	service := &TrustedService{}

	si, ok := svc["ServiceInformation"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no ServiceInformation")
	}

	if st, ok := si["ServiceTypeIdentifier"].(string); ok {
		service.ServiceType = st
	}

	if sdi, ok := si["ServiceDigitalIdentity"].(map[string]any); ok {
		if certs, ok := sdi["X509Certificates"].([]any); ok {
			for _, cert := range certs {
				certMap, ok := cert.(map[string]any)
				if !ok {
					continue
				}
				val, ok := certMap["val"].(string)
				if !ok {
					continue
				}
				certInfo, err := parseCertificate(val)
				if err != nil {
					continue
				}
				service.Certificates = append(service.Certificates, *certInfo)
			}
		}
	}

	return service, nil
}

func parseCertificate(b64 string) (*CertInfo, error) {
	der, err := format.DecodeBase64Std(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return &CertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.Format("2006-01-02"),
		NotAfter:  cert.NotAfter.Format("2006-01-02"),
		PublicKey: cert.PublicKey,
		Raw:       der,
	}, nil
}

func ExtractPublicKeys(tl *TrustList) []CertInfo {
	var keys []CertInfo
	for _, entity := range tl.Entities {
		for _, svc := range entity.Services {
			keys = append(keys, svc.Certificates...)
		}
	}
	return keys
}
