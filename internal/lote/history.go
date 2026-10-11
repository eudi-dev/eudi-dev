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
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 derives the key identifier with SHA-1.
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"maps"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
)

// PubEAAWithdrawnStatus marks a service the provider may no longer use (ETSI
// TS 119 602 V1.1.1 Table H.3).
const PubEAAWithdrawnStatus = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn"

// keepPubEAAHistory dates the services of a Pub-EAA providers list and keeps
// the services of the previous list that this one no longer names. The list
// keeps its history forever (ETSI TS 119 602 V1.1.1 Table H.1 and §6.3.12),
// so a removed service stays with the status withdrawn (Table H.3) and its
// earlier status in ServiceHistory (§6.4.4).
func keepPubEAAHistory(previous string, built []map[string]any, issued time.Time) ([]any, error) {
	entities, err := jsonArray(built)
	if err != nil {
		return nil, err
	}
	stamp := issued.Format(time.RFC3339)
	previousEntities := previousTrustedEntities(previous)
	since := map[string]string{}
	for _, entity := range previousEntities {
		for _, info := range serviceInformation(entity) {
			if info["ServiceStatus"] == PubEAANotifiedStatus {
				since[serviceKey(info)], _ = info["StatusStartingTime"].(string)
			}
		}
	}
	current := map[string]bool{}
	byName := map[string]map[string]any{}
	for _, entity := range objects(entities) {
		byName[entityName(entity)] = entity
		for _, info := range serviceInformation(entity) {
			key := serviceKey(info)
			current[key] = true
			info["StatusStartingTime"] = jsonutil.FirstNonEmpty(since[key], stamp)
		}
	}
	for _, entity := range previousEntities {
		var kept []any
		for _, svc := range objects(entity["TrustedEntityServices"]) {
			info, _ := svc["ServiceInformation"].(map[string]any)
			if info == nil || current[serviceKey(info)] {
				continue
			}
			if info["ServiceStatus"] == PubEAANotifiedStatus {
				svc = withdraw(info, stamp)
			}
			kept = append(kept, svc)
		}
		if len(kept) == 0 {
			continue
		}
		if listed, ok := byName[entityName(entity)]; ok {
			listed["TrustedEntityServices"] = append(listed["TrustedEntityServices"].([]any), kept...)
			continue
		}
		entity["TrustedEntityServices"] = kept
		byName[entityName(entity)] = entity
		entities = append(entities, entity)
	}
	return entities, nil
}

// withdraw turns a notified service into a withdrawn one. Its history names
// the key by X509SKI and carries no certificate (Table H.3).
func withdraw(info map[string]any, stamp string) map[string]any {
	earlier := map[string]any{
		"ServiceName":        info["ServiceName"],
		"ServiceStatus":      PubEAANotifiedStatus,
		"StatusStartingTime": info["StatusStartingTime"],
	}
	if serviceType, ok := info["ServiceTypeIdentifier"]; ok {
		earlier["ServiceTypeIdentifier"] = serviceType
	}
	if ski := subjectKeyIdentifier(firstCertificate(info)); ski != "" {
		earlier["ServiceDigitalIdentity"] = map[string]any{"X509SKIs": []any{ski}}
	}
	withdrawn := maps.Clone(info)
	withdrawn["ServiceStatus"] = PubEAAWithdrawnStatus
	withdrawn["StatusStartingTime"] = stamp
	return map[string]any{"ServiceInformation": withdrawn, "ServiceHistory": []any{earlier}}
}

func previousTrustedEntities(previous string) []map[string]any {
	if previous == "" {
		return nil
	}
	_, payload, _, err := format.ParseJWTParts(previous)
	if err != nil {
		return nil
	}
	list, _ := payload["LoTE"].(map[string]any)
	return objects(list["TrustedEntitiesList"])
}

// jsonArray gives the entities Sign builds the types of a decoded list.
func jsonArray(value any) ([]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out []any
	return out, json.Unmarshal(encoded, &out)
}

func objects(value any) []map[string]any {
	items, _ := value.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func serviceInformation(entity map[string]any) []map[string]any {
	var out []map[string]any
	for _, svc := range objects(entity["TrustedEntityServices"]) {
		if info, ok := svc["ServiceInformation"].(map[string]any); ok {
			out = append(out, info)
		}
	}
	return out
}

func entityName(entity map[string]any) string {
	information, _ := entity["TrustedEntityInformation"].(map[string]any)
	return firstMultiLangValue(information["TEName"])
}

func serviceKey(info map[string]any) string {
	serviceType, _ := info["ServiceTypeIdentifier"].(string)
	return serviceType + " " + firstCertificate(info)
}

func firstCertificate(info map[string]any) string {
	identity, _ := info["ServiceDigitalIdentity"].(map[string]any)
	for _, cert := range objects(identity["X509Certificates"]) {
		value, _ := cert["val"].(string)
		return value
	}
	return ""
}

// subjectKeyIdentifier is the certificate's key identifier extension, or the
// SHA-1 of its public key (RFC 5280 §4.2.1.2 method 1).
func subjectKeyIdentifier(encoded string) string {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	if len(cert.SubjectKeyId) > 0 {
		return base64.StdEncoding.EncodeToString(cert.SubjectKeyId)
	}
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return ""
	}
	digest := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // See the import.
	return base64.StdEncoding.EncodeToString(digest[:])
}
