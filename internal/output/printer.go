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

package output

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

var (
	headerColor  = color.New(color.FgCyan, color.Bold)
	labelColor   = color.New(color.FgYellow)
	valueColor   = color.New(color.FgWhite)
	dimColor     = color.New(color.Faint)
	successColor = color.New(color.FgGreen)
	errorColor   = color.New(color.FgRed)
	warnColor    = color.New(color.FgYellow)

	// Tests replace timeNow to control time-dependent output.
	timeNow = time.Now
)

func relativeTime(t time.Time) string {
	return validity.Relative(t, timeNow())
}

func addTokenNotes(out map[string]any, token *sdjwt.Token) {
	if len(token.Warnings) > 0 {
		out["warnings"] = token.Warnings
	}
	if len(token.Deviations) > 0 {
		out["deviations"] = token.Deviations
	}
}

func printTokenNotes(token *sdjwt.Token) {
	if len(token.Warnings) > 0 {
		printSection("Warnings")
		for _, w := range token.Warnings {
			warnColor.Printf("  ⚠ %s\n", w)
		}
	}
	if len(token.Deviations) > 0 {
		printSection("Deviations")
		for _, d := range token.Deviations {
			warnColor.Printf("  ⚠ %s\n", d)
		}
	}
}

func BuildSDJWTJSON(token *sdjwt.Token) map[string]any {
	out := map[string]any{
		"format":         credtype.FormatSDJWT,
		"header":         token.Header,
		"payload":        token.Payload,
		"disclosures":    formatDisclosuresJSON(token, token.Disclosures),
		"resolvedClaims": token.ResolvedClaims,
	}
	addTokenNotes(out, token)
	if token.KeyBindingJWT != nil {
		out["keyBindingJWT"] = map[string]any{
			"header":  token.KeyBindingJWT.Header,
			"payload": token.KeyBindingJWT.Payload,
		}
	}
	return out
}

func PrintSDJWT(token *sdjwt.Token, opts Options) {
	if opts.JSON {
		PrintJSON(BuildSDJWTJSON(token))
		return
	}

	headerColor.Println("SD-JWT Credential")
	headerColor.Println(strings.Repeat("─", 50))

	printSection("Header")
	printMapFiltered(token.Header, 1, opts.Verbose, "x5c")

	printSection("Payload (signed claims)")
	printMap(token.Payload, 1)

	if len(token.Disclosures) > 0 {
		printSection(fmt.Sprintf("Disclosed Claims (%d)", len(token.Disclosures)))
		for i, d := range token.Disclosures {
			if d.IsArrayEntry {
				dimColor.Printf("  [%d] ", i+1)
				labelColor.Print("(array element) ")
				fmt.Println(formatValue(d.Value))
			} else {
				dimColor.Printf("  [%d] ", i+1)
				labelColor.Printf("%s: ", d.Name)
				fmt.Println(formatValue(d.Value))
			}
			if opts.Verbose {
				dimColor.Printf("       salt=%s digest=%s\n", d.Salt, d.Digest)
			}
		}
	}

	printTokenNotes(token)

	if token.KeyBindingJWT != nil {
		printSection("Key Binding JWT")
		printMap(token.KeyBindingJWT.Payload, 1)
	}

	if cnf, ok := token.Payload["cnf"].(map[string]any); ok {
		printSection("Holder Key (cnf)")
		printMap(cnf, 1)
	}

	fmt.Println()
}

func BuildJWTJSON(token *sdjwt.Token) map[string]any {
	out := map[string]any{
		"format":  "jwt",
		"header":  token.Header,
		"payload": token.Payload,
	}
	addTokenNotes(out, token)
	return out
}

func PrintJWT(token *sdjwt.Token, opts Options) {
	if opts.JSON {
		PrintJSON(BuildJWTJSON(token))
		return
	}

	headerColor.Println("JWT")
	headerColor.Println(strings.Repeat("─", 50))

	printSection("Header")
	printMapFiltered(token.Header, 1, opts.Verbose, "x5c")

	printSection("Payload")
	printMap(token.Payload, 1)

	printTokenNotes(token)

	fmt.Println()
}

func BuildMDOCJSON(doc *mdoc.Document) map[string]any {
	out := map[string]any{
		"format":  credtype.FormatMDOC,
		"docType": doc.DocType,
		"claims":  formatMDOCClaimsJSON(doc),
	}
	if len(doc.Deviations) > 0 {
		out["deviations"] = doc.Deviations
	}
	if doc.IsDeviceResponse {
		out["isDeviceResponse"] = true
		if doc.ResponseVersion != "" {
			out["responseVersion"] = doc.ResponseVersion
		}
		if doc.ResponseStatus != nil {
			out["responseStatus"] = *doc.ResponseStatus
		}
	}
	if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil {
		mso := doc.IssuerAuth.MSO
		msoOut := map[string]any{
			"version":         mso.Version,
			"digestAlgorithm": mso.DigestAlgorithm,
			"docType":         mso.DocType,
		}
		if mso.ValidityInfo != nil {
			vi := map[string]any{}
			if mso.ValidityInfo.Signed != nil {
				vi["signed"] = mso.ValidityInfo.Signed.Format(time.RFC3339)
			}
			if mso.ValidityInfo.ValidFrom != nil {
				vi["validFrom"] = mso.ValidityInfo.ValidFrom.Format(time.RFC3339)
			}
			if mso.ValidityInfo.ValidUntil != nil {
				vi["validUntil"] = mso.ValidityInfo.ValidUntil.Format(time.RFC3339)
			}
			msoOut["validityInfo"] = vi
		}
		if mso.Status != nil {
			msoOut["status"] = mso.Status
		}
		if len(mso.ValueDigests) > 0 {
			digests := make(map[string]any, len(mso.ValueDigests))
			for ns, byID := range mso.ValueDigests {
				entries := make(map[string]any, len(byID))
				for id, digest := range byID {
					entries[strconv.FormatUint(id, 10)] = base64.RawURLEncoding.EncodeToString(digest)
				}
				digests[ns] = entries
			}
			msoOut["valueDigests"] = digests
		}
		if mso.DeviceKeyInfo != nil {
			msoOut["deviceKeyInfo"] = mso.DeviceKeyInfo
		}
		out["mso"] = msoOut
	}
	// Raw COSE integer labels and bytes are hard to read, so the holder key is summarized.
	out["deviceKey"] = buildDeviceKeyJSON(doc)
	out["issuerAuth"] = buildIssuerAuthJSON(doc)
	out["issuerSignedItems"] = buildIssuerSignedItemsJSON(doc)
	if doc.DeviceSigned != nil && doc.DeviceSigned.DeviceAuth != nil {
		out["deviceAuth"] = doc.DeviceSigned.DeviceAuth
		out["deviceAuthType"] = deviceAuthType(doc)
	}
	return out
}

func buildIssuerAuthJSON(doc *mdoc.Document) map[string]any {
	if doc.IssuerAuth == nil {
		return nil
	}
	out := map[string]any{
		"structure": "COSE_Sign1 [protected, unprotected, payload, signature]",
	}
	if named := mdoc.NameCOSEHeader(cborKeyedMap(doc.IssuerAuth.ProtectedHeader)); named != nil {
		out["protected"] = named
	}
	if named := mdoc.NameCOSEHeader(cborKeyedMap(doc.IssuerAuth.UnprotectedHeader)); named != nil {
		out["unprotected"] = named
	}
	out["payload"] = "the Mobile Security Object, below"
	out["payloadBytes"] = len(doc.IssuerAuth.Payload)
	out["signatureBytes"] = len(doc.IssuerAuth.Signature)
	return out
}

func cborKeyedMap(m map[any]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[fmt.Sprintf("%v", k)] = v
	}
	return out
}

func buildIssuerSignedItemsJSON(doc *mdoc.Document) map[string]any {
	if len(doc.NameSpaces) == 0 {
		return nil
	}
	out := make(map[string]any, len(doc.NameSpaces))
	for namespace, items := range doc.NameSpaces {
		entries := make([]map[string]any, 0, len(items))
		for _, item := range items {
			entry := map[string]any{
				"elementIdentifier": item.ElementIdentifier,
				"elementValue":      item.ElementValue,
				"digestID":          item.DigestID,
				"random":            base64.RawURLEncoding.EncodeToString(item.Random),
				"randomBytes":       len(item.Random),
			}
			got, want, err := mdoc.ItemDigest(doc, namespace, item)
			switch {
			case err != nil:
				entry["digestError"] = err.Error()
			case want == nil:
				entry["digestMatches"] = false
				entry["digestError"] = "the MSO lists no digest for this id"
			default:
				entry["digest"] = base64.RawURLEncoding.EncodeToString(got)
				entry["signedDigest"] = base64.RawURLEncoding.EncodeToString(want)
				entry["digestMatches"] = bytes.Equal(got, want)
			}
			entries = append(entries, entry)
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i]["elementIdentifier"].(string) < entries[j]["elementIdentifier"].(string)
		})
		out[namespace] = entries
	}
	return out
}

func buildDeviceKeyJSON(doc *mdoc.Document) map[string]any {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.DeviceKeyInfo == nil {
		return map[string]any{"bound": false}
	}
	out := map[string]any{"bound": true}
	if named := mdoc.NameCOSEKey(deviceKeyMap(doc)); named != nil {
		out["coseKey"] = named
	}
	key, err := mdoc.DeviceKey(doc)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["type"] = "EC"
	out["curve"] = key.Curve.Params().Name
	out["thumbprint"] = mdoc.DeviceKeyThumbprint(key)
	return out
}

func deviceKeyMap(doc *mdoc.Document) map[string]any {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return nil
	}
	key, _ := doc.IssuerAuth.MSO.DeviceKeyInfo["deviceKey"].(map[string]any)
	return key
}

func deviceAuthType(doc *mdoc.Document) string {
	switch {
	case doc.DeviceSigned == nil:
		return ""
	case len(doc.DeviceSigned.RawDeviceSignature) > 0:
		return "deviceSignature"
	case doc.DeviceSigned.DeviceAuth["deviceMac"] != nil:
		return "deviceMac"
	default:
		return "unknown"
	}
}

// A credential without a device key cannot be presented with device authentication.
func printDeviceKey(doc *mdoc.Document, mso *mdoc.MSO, opts Options) {
	if mso.DeviceKeyInfo == nil {
		printSection("Device Key")
		dimColor.Println("  none (the credential is not bound to a holder key)")
		return
	}
	printSection("Device Key (holder binding)")
	key, err := mdoc.DeviceKey(doc)
	if err != nil {
		printKV("Key", dimColor.Sprintf("unreadable: %v", err), 1)
		printMap(mso.DeviceKeyInfo, 1)
		return
	}
	printKV("Type", "EC "+key.Curve.Params().Name, 1)
	if thumbprint := mdoc.DeviceKeyThumbprint(key); thumbprint != "" {
		printKV("Thumbprint", thumbprint, 1)
	}
	if opts.Verbose {
		printMap(mso.DeviceKeyInfo, 1)
	}
}

// Only a DeviceResponse carries holder authentication.
func printDeviceAuth(doc *mdoc.Document, opts Options) {
	if !doc.IsDeviceResponse {
		return
	}
	printSection("Device Authentication")
	if doc.DeviceSigned == nil || len(doc.DeviceSigned.DeviceAuth) == 0 {
		dimColor.Println("  none (the response carries no holder signature)")
		return
	}
	switch {
	case len(doc.DeviceSigned.RawDeviceSignature) > 0:
		printKV("Type", "deviceSignature (COSE_Sign1)", 1)
		dimColor.Println("    signed over the session transcript of the request it answers")
	case doc.DeviceSigned.DeviceAuth["deviceMac"] != nil:
		printKV("Type", "deviceMac (COSE_Mac0)", 1)
	default:
		dimColor.Println("  present, but neither deviceSignature nor deviceMac")
	}
}

func PrintMDOC(doc *mdoc.Document, opts Options) {
	if opts.JSON {
		PrintJSON(BuildMDOCJSON(doc))
		return
	}

	headerColor.Println("mdoc Credential")
	headerColor.Println(strings.Repeat("─", 50))

	if doc.IsDeviceResponse {
		dimColor.Println("  (parsed from DeviceResponse)")
	}

	if len(doc.Deviations) > 0 {
		printSection("Deviations")
		for _, d := range doc.Deviations {
			warnColor.Printf("  ⚠ %s\n", d)
		}
	}

	printSection("Document Info")
	printKV("DocType", doc.DocType, 1)

	if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil {
		mso := doc.IssuerAuth.MSO
		if mso.Version != "" {
			printKV("MSO Version", mso.Version, 1)
		}
		printKV("Digest Algorithm", mso.DigestAlgorithm, 1)
		if mso.ValidityInfo != nil {
			if mso.ValidityInfo.Signed != nil {
				printKV("Signed", mso.ValidityInfo.Signed.Format(time.RFC3339), 1)
			}
			if mso.ValidityInfo.ValidFrom != nil {
				printKV("Valid From", mso.ValidityInfo.ValidFrom.Format(time.RFC3339), 1)
			}
			if mso.ValidityInfo.ValidUntil != nil {
				printKV("Valid Until", mso.ValidityInfo.ValidUntil.Format(time.RFC3339)+dimColor.Sprintf(" (%s)", relativeTime(*mso.ValidityInfo.ValidUntil)), 1)
			}
		}

		if mso.Status != nil {
			printSection("Status")
			printMap(mso.Status, 1)
		}

		printDeviceKey(doc, mso, opts)
	}

	printDeviceAuth(doc, opts)

	namespaces := sortedKeys(doc.NameSpaces)
	for _, ns := range namespaces {
		items := doc.NameSpaces[ns]
		printSection(fmt.Sprintf("Namespace: %s (%d claims)", ns, len(items)))
		// Sorting in place reorders the caller's document.
		items = append([]mdoc.IssuerSignedItem(nil), items...)
		sort.Slice(items, func(i, j int) bool {
			return items[i].ElementIdentifier < items[j].ElementIdentifier
		})
		for _, item := range items {
			labelColor.Printf("  %s: ", item.ElementIdentifier)
			fmt.Println(formatValue(item.ElementValue))
			if opts.Verbose {
				dimColor.Printf("    digestID=%d\n", item.DigestID)
			}
		}
	}

	if doc.DeviceSigned != nil && doc.DeviceSigned.DeviceAuth != nil {
		printSection("Device Auth")
		printMap(doc.DeviceSigned.DeviceAuth, 1)
	}

	fmt.Println()
}

func PrintVerifyResultSDJWT(r *sdjwt.VerifyResult, opts Options) {
	if opts.JSON {
		PrintJSON(r)
		return
	}

	printSection("Signature Verification")
	if r.SignatureValid {
		successColor.Println("  ✓ Signature valid")
	} else {
		errorColor.Println("  ✗ Signature invalid")
	}

	printKV("Algorithm", r.Algorithm, 1)
	if r.KeyID != "" {
		printKV("Key ID", r.KeyID, 1)
	}
	if r.Issuer != "" {
		printKV("Issuer", r.Issuer, 1)
	}

	if r.IssuedAt != nil {
		printKV("Issued", r.IssuedAt.Format(time.RFC3339), 1)
	}
	printTimeValidity(r.ExpiresAt, r.NotBefore, r.Expired, r.NotYetValid)

	for _, e := range r.Errors {
		errorColor.Printf("  ✗ %s\n", e)
	}
}

func PrintVerifyResultMDOC(r *mdoc.VerifyResult, opts Options) {
	if opts.JSON {
		PrintJSON(r)
		return
	}

	printSection("Signature Verification")
	if r.SignatureValid {
		successColor.Println("  ✓ Signature valid")
	} else {
		errorColor.Println("  ✗ Signature invalid")
	}

	printKV("Algorithm", r.Algorithm, 1)
	printKV("DocType", r.DocType, 1)

	printTimeValidity(r.ValidUntil, r.ValidFrom, r.Expired, r.NotYetValid)

	for _, w := range r.Warnings {
		warnColor.Printf("  ⚠ %s\n", w)
	}
	for _, e := range r.Errors {
		errorColor.Printf("  ✗ %s\n", e)
	}
}

func printTimeValidity(expires *time.Time, validFrom *time.Time, expired, notYetValid bool) {
	if validFrom != nil {
		printKV("Valid From", validFrom.Format(time.RFC3339), 1)
	}
	if expires != nil {
		label := "Expires"
		rel := dimColor.Sprintf(" (%s)", relativeTime(*expires))
		if expired {
			label = "Expired"
			warnColor.Printf("  ⚠ %s: %s%s\n", label, expires.Format(time.RFC3339), rel)
		} else {
			printKV(label, expires.Format(time.RFC3339)+rel, 1)
		}
	}
	if notYetValid {
		warnColor.Println("  ⚠ Credential not yet valid")
	}
}

func printSection(title string) {
	fmt.Println()
	headerColor.Printf("┌ %s\n", title)
}

func printKV(key, value string, indent int) {
	prefix := strings.Repeat("  ", indent)
	labelColor.Printf("%s%s: ", prefix, key)
	valueColor.Println(value)
}

func printMapFiltered(m map[string]any, indent int, verbose bool, hiddenKeys ...string) {
	if verbose {
		printMap(m, indent)
		return
	}
	hidden := make(map[string]bool, len(hiddenKeys))
	for _, k := range hiddenKeys {
		hidden[k] = true
	}
	keys := sortedKeys(m)
	prefix := strings.Repeat("  ", indent)
	for _, k := range keys {
		if hidden[k] {
			if arr, ok := m[k].([]any); ok {
				dimColor.Printf("%s%s: (%d entries, use -v to show)\n", prefix, k, len(arr))
			}
			continue
		}
		labelColor.Printf("%s%s: ", prefix, k)
		fmt.Println(formatValue(m[k]))
	}
}

func printMap(m map[string]any, indent int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	prefix := strings.Repeat("  ", indent)
	for _, k := range keys {
		labelColor.Printf("%s%s: ", prefix, k)
		fmt.Println(formatValue(m[k]))
	}
}

func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	case []byte:
		return fmt.Sprintf("(%d bytes)", len(val))
	case map[string]any:
		b, _ := json.MarshalIndent(val, "    ", "  ")
		return string(b)
	case []any:
		if isSimpleArray(val) {
			b, _ := json.Marshal(val)
			return string(b)
		}
		b, _ := json.MarshalIndent(val, "    ", "  ")
		return string(b)
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

func isSimpleArray(arr []any) bool {
	for _, v := range arr {
		switch v.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func formatDisclosuresJSON(token *sdjwt.Token, disclosures []sdjwt.Disclosure) []map[string]any {
	// A disclosure with an unreferenced digest belongs to another credential.
	referenced := sdjwt.ReferencedDigests(token)
	result := make([]map[string]any, len(disclosures))
	for i, d := range disclosures {
		result[i] = map[string]any{
			"name":         d.Name,
			"value":        d.Value,
			"salt":         d.Salt,
			"digest":       d.Digest,
			"isArrayEntry": d.IsArrayEntry,
			"referenced":   referenced[d.Digest],
		}
	}
	return result
}

func formatMDOCClaimsJSON(doc *mdoc.Document) map[string]any {
	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		nsClaims := make(map[string]any)
		for _, item := range items {
			nsClaims[item.ElementIdentifier] = item.ElementValue
		}
		claims[ns] = nsClaims
	}
	return claims
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func BuildCredentialOfferJSON(offer *oid4vc.CredentialOffer) map[string]any {
	out := map[string]any{
		"type":                         "OID4VCI Credential Offer",
		"credential_issuer":            offer.CredentialIssuer,
		"credential_configuration_ids": offer.CredentialConfigurationIDs,
	}
	grants := map[string]any{}
	if offer.Grants.PreAuthorizedCode != "" {
		preAuth := map[string]any{
			"pre-authorized_code": offer.Grants.PreAuthorizedCode,
		}
		if offer.Grants.TxCode != nil {
			preAuth["tx_code"] = offer.Grants.TxCode
		}
		grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = preAuth
	}
	if offer.Grants.AuthorizationCode != "" || offer.Grants.IssuerState != "" {
		authCode := map[string]any{}
		if offer.Grants.AuthorizationCode != "" {
			authCode["authorization_code"] = offer.Grants.AuthorizationCode
		}
		if offer.Grants.IssuerState != "" {
			authCode["issuer_state"] = offer.Grants.IssuerState
		}
		grants["authorization_code"] = authCode
	}
	if len(grants) > 0 {
		out["grants"] = grants
	}
	return out
}

func PrintCredentialOffer(offer *oid4vc.CredentialOffer, opts Options) {
	if opts.JSON {
		PrintJSON(BuildCredentialOfferJSON(offer))
		return
	}

	headerColor.Println("OID4VCI Credential Offer")
	headerColor.Println(strings.Repeat("─", 50))

	printSection("Issuer")
	printKV("Credential Issuer", offer.CredentialIssuer, 1)

	if len(offer.CredentialConfigurationIDs) > 0 {
		printSection("Credential Configurations")
		for i, id := range offer.CredentialConfigurationIDs {
			dimColor.Printf("  [%d] ", i+1)
			valueColor.Println(id)
		}
	}

	hasGrants := offer.Grants.PreAuthorizedCode != "" || offer.Grants.AuthorizationCode != "" || offer.Grants.IssuerState != ""
	if hasGrants {
		printSection("Grants")
		if offer.Grants.PreAuthorizedCode != "" {
			printKV("Pre-Authorized Code", offer.Grants.PreAuthorizedCode, 1)
			if offer.Grants.TxCode != nil {
				parts := []string{}
				if mode, ok := offer.Grants.TxCode["input_mode"].(string); ok {
					parts = append(parts, "input_mode="+mode)
				}
				if length, ok := offer.Grants.TxCode["length"].(float64); ok {
					parts = append(parts, fmt.Sprintf("length=%d", int(length)))
				}
				if desc, ok := offer.Grants.TxCode["description"].(string); ok {
					parts = append(parts, "description="+desc)
				}
				printKV("TX Code", strings.Join(parts, ", "), 1)
			}
		}
		if offer.Grants.AuthorizationCode != "" {
			printKV("Authorization Code", offer.Grants.AuthorizationCode, 1)
		}
		if offer.Grants.IssuerState != "" {
			printKV("Issuer State", offer.Grants.IssuerState, 1)
		}
	}

	if opts.Verbose && offer.FullJSON != nil {
		printSection("Full JSON")
		printMap(offer.FullJSON, 1)
	}

	fmt.Println()
}

func BuildAuthorizationRequestJSON(req *oid4vc.AuthorizationRequest) map[string]any {
	out := map[string]any{
		"type": "OID4VP Authorization Request",
	}
	if req.ClientID != "" {
		out["client_id"] = req.ClientID
	}
	if req.ResponseType != "" {
		out["response_type"] = req.ResponseType
	}
	if req.ResponseMode != "" {
		out["response_mode"] = req.ResponseMode
	}
	if req.Nonce != "" {
		out["nonce"] = req.Nonce
	}
	if req.State != "" {
		out["state"] = req.State
	}
	if req.RedirectURI != "" {
		out["redirect_uri"] = req.RedirectURI
	}
	if req.ResponseURI != "" {
		out["response_uri"] = req.ResponseURI
	}
	if req.Scope != "" {
		out["scope"] = req.Scope
	}
	if req.RequestObject != nil {
		out["request_object"] = map[string]any{
			"header":  req.RequestObject.Header,
			"payload": req.RequestObject.Payload,
		}
	}
	if req.RequestObject == nil {
		if req.DCQLQuery != nil {
			out["dcql_query"] = req.DCQLQuery
		}
	}
	return out
}

func PrintAuthorizationRequest(req *oid4vc.AuthorizationRequest, opts Options) {
	if opts.JSON {
		PrintJSON(BuildAuthorizationRequestJSON(req))
		return
	}

	headerColor.Println("OID4VP Authorization Request")
	headerColor.Println(strings.Repeat("─", 50))

	printSection("Client")
	if req.ClientID != "" {
		printKV("Client ID", req.ClientID, 1)
	}
	if req.ResponseType != "" {
		printKV("Response Type", req.ResponseType, 1)
	}
	if req.ResponseMode != "" {
		printKV("Response Mode", req.ResponseMode, 1)
	}
	if req.RedirectURI != "" {
		printKV("Redirect URI", req.RedirectURI, 1)
	}
	if req.ResponseURI != "" {
		printKV("Response URI", req.ResponseURI, 1)
	}
	if req.Scope != "" {
		printKV("Scope", req.Scope, 1)
	}

	if req.Nonce != "" || req.State != "" {
		printSection("Session")
		if req.Nonce != "" {
			printKV("Nonce", req.Nonce, 1)
		}
		if req.State != "" {
			printKV("State", req.State, 1)
		}
	}

	if req.RequestObject != nil {
		printSection("Request Object (JWT)")
		labelColor.Println("  Header:")
		printMap(req.RequestObject.Header, 2)
		labelColor.Println("  Payload:")
		printMap(req.RequestObject.Payload, 2)
	}

	// The request object payload already contains these fields.
	if req.RequestObject == nil {
		if req.DCQLQuery != nil {
			printSection("DCQL Query")
			b, _ := json.MarshalIndent(req.DCQLQuery, "  ", "  ")
			fmt.Printf("  %s\n", string(b))
		}
	}

	if opts.Verbose && len(req.FullParams) > 0 {
		printSection("All Parameters")
		for _, k := range sortedKeys(req.FullParams) {
			printKV(k, req.FullParams[k], 1)
		}
	}

	fmt.Println()
}

func BuildTrustListJSON(tl *lote.List) map[string]any {
	out := map[string]any{
		"format": "trusted-list",
		"header": tl.Header,
	}
	if tl.SchemeInfo != nil {
		out["schemeInfo"] = map[string]any{
			"loTEType":           tl.SchemeInfo.LoTEType,
			"schemeOperatorName": tl.SchemeInfo.SchemeOperatorName,
			"listIssueDatetime":  tl.SchemeInfo.ListIssueDatetime,
			"nextUpdate":         tl.SchemeInfo.NextUpdate,
		}
	}
	entities := make([]map[string]any, 0)
	for _, e := range tl.Entities {
		entity := map[string]any{"name": e.Name}
		services := make([]map[string]any, 0)
		for _, s := range e.Services {
			svc := map[string]any{"serviceType": s.ServiceType}
			certs := make([]map[string]any, 0)
			for _, c := range s.Certificates {
				certs = append(certs, map[string]any{
					"subject":   c.Subject,
					"issuer":    c.Issuer,
					"notBefore": c.NotBefore,
					"notAfter":  c.NotAfter,
				})
			}
			svc["certificates"] = certs
			services = append(services, svc)
		}
		entity["services"] = services
		entities = append(entities, entity)
	}
	out["entities"] = entities
	return out
}

func PrintTrustList(tl *lote.List, opts Options) {
	if opts.JSON {
		PrintJSON(BuildTrustListJSON(tl))
		return
	}

	fmt.Println("ETSI TS 119 602 trusted list")
	fmt.Println("──────────────────────────────────────────────────")

	if tl.SchemeInfo != nil {
		fmt.Printf("\n  Operator:  %s\n", tl.SchemeInfo.SchemeOperatorName)
		fmt.Printf("  Type:      %s\n", tl.SchemeInfo.LoTEType)
		fmt.Printf("  Issued:    %s\n", tl.SchemeInfo.ListIssueDatetime)
		if tl.SchemeInfo.NextUpdate != "" {
			fmt.Printf("  Next:      %s\n", tl.SchemeInfo.NextUpdate)
		}
	}

	if alg, ok := tl.Header["alg"].(string); ok {
		fmt.Printf("  Algorithm: %s\n", alg)
	}

	fmt.Printf("\n  Trusted Entities (%d):\n", len(tl.Entities))
	for _, e := range tl.Entities {
		fmt.Printf("\n  ┌ %s\n", e.Name)
		for _, s := range e.Services {
			fmt.Printf("  │ Service: %s\n", s.ServiceType)
			for _, c := range s.Certificates {
				fmt.Printf("  │   Subject: %s\n", c.Subject)
				fmt.Printf("  │   Issuer:  %s\n", c.Issuer)
				fmt.Printf("  │   Valid:   %s → %s\n", c.NotBefore, c.NotAfter)
			}
		}
	}
	fmt.Println()
}

func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "%s %s\n", errorColor.Sprint("Error:"), msg)
}
