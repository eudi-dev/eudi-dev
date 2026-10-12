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

package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/fatih/color"
)

var (
	headerColor  = color.New(color.FgCyan, color.Bold)
	labelColor   = color.New(color.FgYellow)
	valueColor   = color.New(color.FgWhite)
	dimColor     = color.New(color.Faint)
	successColor = color.New(color.FgGreen)
	errorColor   = color.New(color.FgRed)
	classColor   = color.New(color.FgMagenta, color.Bold)
)

type TerminalWriter struct {
	AllTraffic   bool
	DashboardURL string // if set, print /decode links
}

type renderedField struct {
	key string
	val any
}

type renderedSection struct {
	title  string
	fields []renderedField
}

func (tw *TerminalWriter) WriteEntry(entry *TrafficEntry) {
	if entry.Class == ClassUnknown && !tw.AllTraffic {
		return
	}
	PrintEntry(entry, tw.DashboardURL)
}

// PrintEntry uses the remote dashboard origin in decode links. The CLI may
// not reach the dashboard's localhost address. Without a dashboard it prints a CLI command.
func PrintEntry(entry *TrafficEntry, decodeBase string) {
	ts := entry.Timestamp.Format("15:04:05")

	statusFn := successColor.Sprintf
	if entry.StatusCode >= 400 {
		statusFn = errorColor.Sprintf
	}

	fmt.Printf("%s %s %s %s  %s  %s\n",
		dimColor.Sprint("━━━"),
		dimColor.Sprintf("[%s]", ts),
		headerColor.Sprintf("%s %s", entry.Method, entry.URL),
		statusFn("%s", responseSummary(entry)),
		dimColor.Sprintf("(%dms)", entry.DurationMS),
		classColor.Sprintf("[%s]", entryTitle(entry)),
	)

	sections := buildRenderedSections(entry)
	if len(sections) > 0 {
		fmt.Println()
		for i, section := range sections {
			printSection(section)
			if i < len(sections)-1 {
				fmt.Println()
			}
		}
	}

	if len(entry.Credentials) > 0 {
		if len(sections) > 0 {
			fmt.Println()
		}
		printDecodeSection(entry.Credentials, entry.CredentialLabels, decodeBase)
	}

	fmt.Println()
	fmt.Println()
}

func responseSummary(entry *TrafficEntry) string {
	return fmt.Sprintf("%d", entry.StatusCode)
}

func entryTitle(entry *TrafficEntry) string {
	if entry.FlowID == "" {
		return entry.ClassLabel
	}
	return entry.FlowID + " / " + entry.ClassLabel
}

func buildRenderedSections(entry *TrafficEntry) []renderedSection {
	var sections []renderedSection
	if shouldRenderRawRequest(entry) {
		sections = appendSection(sections, "request headers", sortedRenderedFields(headerFieldsForDisplay(entry.RequestHeaders), entry.Class, "request_headers"))
		sections = appendSection(sections, "request body", sortedRenderedFields(rawBodyFields(entry.RequestBody), entry.Class, "request_body"))
	}
	if redirect := redirectResponseHeaderFields(entry); len(redirect) > 0 {
		sections = appendSection(sections, "response headers", sortedRenderedFields(redirect, entry.Class, "response_headers"))
	}

	if entry.Decoded != nil {
		switch entry.Class {
		case ClassVCITokenRequest, ClassOIDCTokenRequest:
			sections = appendSection(sections, "request", sortedRenderedFields(filterMap(entry.Decoded, "response"), entry.Class, "request"))
			sections = appendSection(sections, "response", sortedRenderedFields(mapValue(entry.Decoded, "response"), entry.Class, "response"))
		case ClassVCICredentialRequest:
			sections = appendSection(sections, "request", sortedRenderedFields(mapValue(entry.Decoded, "request"), entry.Class, "request"))
			sections = appendSection(sections, "response", sortedRenderedFields(mapValue(entry.Decoded, "response"), entry.Class, "response"))
			sections = appendSection(sections, "derived", sortedRenderedFields(filterMap(entry.Decoded, "request", "response"), entry.Class, "derived"))
		case ClassVCINonceRequest:
			sections = appendSection(sections, "response", sortedRenderedFields(mapValue(entry.Decoded, "response"), entry.Class, "response"))
			sections = appendSection(sections, "derived", sortedRenderedFields(filterMap(entry.Decoded, "response", "c_nonce"), entry.Class, "derived"))
		case ClassVCIMetadata, ClassOIDCMetadata:
			sections = appendSection(sections, "response", sortedRenderedFields(mapValue(entry.Decoded, "metadata"), entry.Class, "response"))
		case ClassVPRequestObject:
			sections = appendSection(sections, "request", sortedRenderedFields(pickKeys(entry.Decoded, "wallet_metadata", "wallet_nonce"), entry.Class, "request"))
			sections = appendSection(sections, "response", sortedRenderedFields(pickKeys(entry.Decoded, "header", "payload", "encrypted", "encryption_alg", "encryption_enc", "encryption_jwks", "wallet_nonce_in_response"), entry.Class, "response"))
			sections = appendSection(sections, "derived", sortedRenderedFields(excludeKeys(entry.Decoded, "wallet_metadata", "wallet_nonce", "header", "payload", "encrypted", "encryption_alg", "encryption_enc", "encryption_jwks", "wallet_nonce_in_response"), entry.Class, "derived"))
		case ClassVPAuthResponse:
			sections = appendSection(sections, "request", sortedRenderedFields(pickKeys(entry.Decoded, "response_preview", "vp_token_preview", "id_token_preview", "state", "presentation_submission"), entry.Class, "request"))
			sections = appendSection(sections, "derived", sortedRenderedFields(excludeKeys(entry.Decoded, "response_preview", "vp_token_preview", "id_token_preview", "state", "presentation_submission"), entry.Class, "derived"))
		case ClassVPAuthRequest, ClassOIDCAuthRequest, ClassVCICredentialOffer, ClassOIDCCallback:
			sections = appendSection(sections, "request", sortedRenderedFields(entry.Decoded, entry.Class, "request"))
		default:
			sections = appendSection(sections, "derived", sortedRenderedFields(entry.Decoded, entry.Class, "derived"))
		}
	}

	return sections
}

func redirectResponseHeaderFields(entry *TrafficEntry) map[string]any {
	if entry.StatusCode < 300 || entry.StatusCode >= 400 || entry.ResponseHeaders == nil {
		return nil
	}
	location := entry.ResponseHeaders.Get("Location")
	if location == "" {
		return nil
	}
	return map[string]any{"Location": location}
}

func appendSection(sections []renderedSection, title string, fields []renderedField) []renderedSection {
	if len(fields) == 0 {
		return sections
	}
	return append(sections, renderedSection{title: title, fields: fields})
}

func printSection(section renderedSection) {
	labelColor.Printf("  %s:\n", section.title)
	for _, field := range section.fields {
		printDecodedField(field.key, field.val, 2)
	}
}

func printDecodeSection(credentials, labels []string, decodeBase string) {
	labelColor.Printf("  decode:\n")
	for i, credential := range credentials {
		label := ""
		if i < len(labels) {
			label = labels[i]
		}
		printDecodeHint(credential, label, decodeBase)
	}
}

func sortedRenderedFields(fields map[string]any, class TrafficClass, section string) []renderedField {
	if len(fields) == 0 {
		return nil
	}
	keys := sortedFieldKeys(fields, class, section)
	rendered := make([]renderedField, 0, len(keys))
	for _, key := range keys {
		rendered = append(rendered, renderedField{key: key, val: fields[key]})
	}
	return rendered
}

func sortedFieldKeys(fields map[string]any, class TrafficClass, section string) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi := fieldPriority(keys[i], class, section)
		pj := fieldPriority(keys[j], class, section)
		if pi != pj {
			return pi < pj
		}
		return keys[i] < keys[j]
	})
	return keys
}

func fieldPriority(key string, class TrafficClass, section string) int {
	priorities := map[string]int{
		"Host":                    5,
		"Authorization":           6,
		"DPoP":                    7,
		"Content-Type":            8,
		"grant_type":              10,
		"client_id":               20,
		"code":                    30,
		"pre-authorized_code":     40,
		"tx_code":                 50,
		"code_verifier":           60,
		"redirect_uri":            70,
		"scope":                   80,
		"state":                   90,
		"nonce":                   100,
		"response_type":           110,
		"response_mode":           120,
		"token_type":              130,
		"expires_in":              140,
		"refresh_expires_in":      150,
		"c_nonce":                 160,
		"authorization_details":   170,
		"access_token":            180,
		"refresh_token":           190,
		"id_token":                200,
		"credential":              210,
		"credentials":             220,
		"credential_decoded":      230,
		"vp_token_preview":        240,
		"id_token_preview":        250,
		"response_preview":        260,
		"presentation_submission": 270,
		"response_payload":        280,
		"vp_token_decoded":        290,
		"id_token_header":         300,
		"id_token_payload":        310,
		"header":                  320,
		"payload":                 330,
		"metadata":                340,
	}

	if priority, ok := priorities[key]; ok {
		if section == "response" && (class == ClassVCIMetadata || class == ClassOIDCMetadata) {
			return priority - 200
		}
		return priority
	}

	return 1000
}

func shouldRenderRawRequest(entry *TrafficEntry) bool {
	switch entry.Method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return entry.RequestBody != ""
	}
}

func headerFieldsForDisplay(headers http.Header) map[string]any {
	if len(headers) == 0 {
		return nil
	}
	fields := make(map[string]any)
	for key, values := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-proxy-") {
			continue
		}
		if len(values) == 1 {
			fields[key] = values[0]
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		fields[key] = copied
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func rawBodyFields(body string) map[string]any {
	if body == "" {
		return nil
	}
	return map[string]any{"body": body}
}

func filterMap(m map[string]any, skipKeys ...string) map[string]any {
	skip := make(map[string]struct{}, len(skipKeys))
	for _, key := range skipKeys {
		skip[key] = struct{}{}
	}

	filtered := make(map[string]any)
	for key, value := range m {
		if _, ok := skip[key]; ok {
			continue
		}
		filtered[key] = value
	}
	return filtered
}

func pickKeys(m map[string]any, wantedKeys ...string) map[string]any {
	picked := make(map[string]any)
	for _, key := range wantedKeys {
		if value, ok := m[key]; ok {
			picked[key] = value
		}
	}
	return picked
}

func excludeKeys(m map[string]any, excludedKeys ...string) map[string]any {
	return filterMap(m, excludedKeys...)
}

func mapValue(m map[string]any, key string) map[string]any {
	if value, ok := m[key].(map[string]any); ok {
		return value
	}
	return nil
}

func printDecodedField(key string, val any, depth int) {
	prefix := strings.Repeat("  ", depth)

	switch v := val.(type) {
	case map[string]any:
		labelColor.Printf("%s┌ %s:\n", prefix, key)
		for _, k := range sortedFieldKeys(v, ClassUnknown, "nested") {
			printDecodedField(k, v[k], depth+1)
		}
	case string:
		labelColor.Printf("%s┌ ", prefix)
		labelColor.Printf("%s: ", key)
		valueColor.Println(v)
	default:
		labelColor.Printf("%s┌ ", prefix)
		labelColor.Printf("%s: ", key)
		if b, err := json.MarshalIndent(val, prefix+"  ", "  "); err == nil {
			valueColor.Println(string(b))
		} else {
			valueColor.Println(fmt.Sprintf("%v", val))
		}
	}
}

func printDecodeHint(credential, label, decodeBase string) {
	prefix := strings.Repeat("  ", 2)

	if decodeBase != "" {
		decodeURL := fmt.Sprintf("%s/decode/#credential=%s", strings.TrimRight(decodeBase, "/"), url.QueryEscape(credential))
		dimColor.Printf("%s┌ ", prefix)
		if label != "" {
			dimColor.Printf("%s: ", label)
		} else {
			dimColor.Print("link: ")
		}
		fmt.Println(decodeURL)
		return
	}

	dimColor.Printf("%s┌ ", prefix)
	if label != "" {
		dimColor.Printf("%s: ", label)
	} else {
		dimColor.Print("link: ")
	}
	dimColor.Println("eudi decode")
}
