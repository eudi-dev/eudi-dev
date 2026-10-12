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

package web

import (
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/output"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

type ValidateOpts struct {
	Key          string
	TrustListURL string
	TrustListRaw string
	CheckStatus  bool
	// Offline skips network checks and marks them NeedsNetwork. The UI shows
	// offline results first.
	Offline bool
	// WalletStore provides the CA and issuer key for locally issued credentials. Nil
	// selects the default wallet.
	WalletStore *wallet.WalletStore
	// HTTPClient fetches status lists, trusted lists and issuer metadata. Nil
	// selects the shared developer client.
	HTTPClient *http.Client
}

// Validate adds a validation object to the decoded result.
func Validate(input string, opts ValidateOpts) (map[string]any, error) {
	detected := format.DetectEncoding(input)

	var checks []CheckResult

	switch detected {
	case format.FormatSDJWT:
		// Inspect keeps a malformed credential and records its deviations, so the decoder
		// can still show it.
		token, err := sdjwt.Inspect(input)
		if err != nil {
			return nil, fmt.Errorf("parsing SD-JWT: %w", err)
		}
		result := output.BuildSDJWTJSON(token)

		checks = append(checks, CheckSDJWTType(token))
		checks = append(checks, checkSDJWTExpiry(token))
		checks = append(checks, CheckSDJWTIntegrity(token))
		checks = append(checks, checkSDJWTSignature(token, opts))
		checks = append(checks, checkSDJWTStatus(token, opts)...)

		result["validation"] = map[string]any{
			"checks": checks,
		}
		return result, nil

	case format.FormatJWT:
		token, err := sdjwt.Inspect(input)
		if err != nil {
			return nil, fmt.Errorf("parsing JWT: %w", err)
		}
		result := output.BuildJWTJSON(token)

		checks = append(checks, checkSDJWTExpiry(token))
		checks = append(checks, CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: "Not applicable for plain JWT",
		})
		checks = append(checks, checkSDJWTSignature(token, opts))
		checks = append(checks, CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "Not applicable for plain JWT",
		})

		result["validation"] = map[string]any{
			"checks": checks,
		}
		return result, nil

	case format.FormatMDOC:
		doc, err := mdoc.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing mdoc: %w", err)
		}
		result := output.BuildMDOCJSON(doc)

		checks = append(checks, checkMDOCExpiry(doc))
		checks = append(checks, CheckMDOCIntegrity(doc))
		checks = append(checks, checkMDOCSignature(doc, opts))
		checks = append(checks, checkMDOCStatus(doc, opts)...)

		result["validation"] = map[string]any{
			"checks": checks,
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mdoc)")
	}
}

func checkSDJWTExpiry(token *sdjwt.Token) CheckResult {
	now := time.Now()

	if nbf, ok := token.Payload["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if now.Before(nbfTime) {
			return CheckResult{
				Name:   "expiry",
				Status: "fail",
				Detail: fmt.Sprintf("not yet valid (valid from %s)", nbfTime.Format(time.RFC3339)),
			}
		}
	}

	exp, ok := token.Payload["exp"].(float64)
	if !ok {
		return CheckResult{
			Name:   "expiry",
			Status: "skipped",
			Detail: "No exp claim present",
		}
	}

	expTime := time.Unix(int64(exp), 0)
	if now.After(expTime) {
		return CheckResult{
			Name:   "expiry",
			Status: "fail",
			Detail: fmt.Sprintf("expired %s", relativeTimeGo(expTime)),
		}
	}

	return CheckResult{
		Name:   "expiry",
		Status: "pass",
		Detail: fmt.Sprintf("expires %s", relativeTimeGo(expTime)),
	}
}

func checkMDOCExpiry(doc *mdoc.Document) CheckResult {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.ValidityInfo == nil {
		return CheckResult{
			Name:   "expiry",
			Status: "skipped",
			Detail: "No validity info in MSO",
		}
	}

	vi := doc.IssuerAuth.MSO.ValidityInfo
	now := time.Now()

	if vi.ValidFrom != nil && now.Before(*vi.ValidFrom) {
		return CheckResult{
			Name:   "expiry",
			Status: "fail",
			Detail: fmt.Sprintf("not yet valid (valid from %s)", vi.ValidFrom.Format(time.RFC3339)),
		}
	}

	if vi.ValidUntil == nil {
		return CheckResult{
			Name:   "expiry",
			Status: "skipped",
			Detail: "No validUntil in MSO",
		}
	}

	if now.After(*vi.ValidUntil) {
		return CheckResult{
			Name:   "expiry",
			Status: "fail",
			Detail: fmt.Sprintf("expired %s", relativeTimeGo(*vi.ValidUntil)),
		}
	}

	return CheckResult{
		Name:   "expiry",
		Status: "pass",
		Detail: fmt.Sprintf("expires %s", relativeTimeGo(*vi.ValidUntil)),
	}
}

func checkSDJWTSignature(token *sdjwt.Token, opts ValidateOpts) CheckResult {
	pubKeys, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return CheckResult{
			Name:   "signature",
			Status: "fail",
			Detail: err.Error(),
		}
	}

	// Without explicit keys, credentials issued by the local wallet validate
	// against its CA with a full chain.
	if len(pubKeys) == 0 && len(tlCerts) == 0 {
		if anchors := localWalletTrustAnchors(opts.WalletStore); len(anchors) > 0 {
			if caKey, err := validate.ExtractAndValidateX5C(token.Header, anchors); err == nil && caKey != nil {
				result := sdjwt.Verify(token, caKey)
				if result.SignatureValid {
					return CheckResult{
						Name:   "signature",
						Status: "pass",
						Detail: fmt.Sprintf("Valid (%s, via local wallet CA, chain verified)", result.Algorithm),
					}
				}
			}
		}
	}

	if opts.Offline {
		return offlineSDJWTSignature(token, pubKeys, tlCerts, opts)
	}

	result, source, err := validate.VerifyJWTSignature(token, pubKeys, tlCerts, opts.HTTPClient)
	if err != nil {
		if len(pubKeys) == 0 && len(tlCerts) == 0 {
			if localResult, localSource := verifyWithLocalWalletIssuerKey(token, opts.WalletStore); localResult != nil {
				result = localResult
				source = localSource
				err = nil
			}
		}
		if err != nil && len(pubKeys) == 0 && len(tlCerts) == 0 && validate.CanResolveJWTIssuerMetadata(token) {
			return CheckResult{
				Name:   "signature",
				Status: "skipped",
				Detail: fmt.Sprintf("Issuer metadata lookup failed: %v", err),
			}
		}
		if err != nil {
			return CheckResult{
				Name:   "signature",
				Status: "fail",
				Detail: err.Error(),
			}
		}
	}
	if result == nil {
		if len(pubKeys) == 0 && len(tlCerts) == 0 {
			if localResult, localSource := verifyWithLocalWalletIssuerKey(token, opts.WalletStore); localResult != nil {
				result = localResult
				source = localSource
			}
		}
	}
	if result == nil {
		detail := "No key provided"
		if validate.CanResolveJWTIssuerMetadata(token) {
			detail = "Issuer metadata verification unavailable"
		}
		return CheckResult{
			Name:   "signature",
			Status: "skipped",
			Detail: detail,
		}
	}
	if result.SignatureValid {
		if source != "" {
			return CheckResult{
				Name:   "signature",
				Status: "pass",
				Detail: fmt.Sprintf("Valid (%s, via %s)", result.Algorithm, source),
			}
		}
		return CheckResult{
			Name:   "signature",
			Status: "pass",
			Detail: fmt.Sprintf("Valid (%s)", result.Algorithm),
		}
	}
	detail := "Signature verification failed"
	if source != "" {
		detail = fmt.Sprintf("Signature verification failed via %s", source)
	}
	return CheckResult{
		Name:   "signature",
		Status: "fail",
		Detail: detail,
	}
}

// offlineSDJWTSignature verifies with supplied or embedded keys. A check that needs
// issuer metadata is marked as pending network access.
func offlineSDJWTSignature(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []trustlist.CertInfo, opts ValidateOpts) CheckResult {
	result, source, err := validate.VerifyJWTSignatureOffline(token, pubKeys, tlCerts)
	if err != nil {
		return CheckResult{
			Name:   "signature",
			Status: "fail",
			Detail: err.Error(),
		}
	}
	if result == nil && len(pubKeys) == 0 && len(tlCerts) == 0 {
		if localResult, localSource := verifyWithLocalWalletIssuerKey(token, opts.WalletStore); localResult != nil {
			result = localResult
			source = localSource
		}
	}
	if result == nil {
		if validate.CanResolveJWTIssuerMetadata(token) || opts.TrustListURL != "" {
			return CheckResult{
				Name:         "signature",
				Status:       "skipped",
				Detail:       "Needs an issuer key that is only reachable over the network",
				NeedsNetwork: true,
			}
		}
		return CheckResult{
			Name:   "signature",
			Status: "skipped",
			Detail: "No key provided",
		}
	}
	if result.SignatureValid {
		if source != "" {
			return CheckResult{
				Name:   "signature",
				Status: "pass",
				Detail: fmt.Sprintf("Valid (%s, via %s)", result.Algorithm, source),
			}
		}
		return CheckResult{
			Name:   "signature",
			Status: "pass",
			Detail: fmt.Sprintf("Valid (%s)", result.Algorithm),
		}
	}
	// Issuer metadata can provide another key after a local key mismatch.
	if validate.CanResolveJWTIssuerMetadata(token) {
		return CheckResult{
			Name:         "signature",
			Status:       "skipped",
			Detail:       "Needs an issuer key that is only reachable over the network",
			NeedsNetwork: true,
		}
	}
	detail := "Signature verification failed"
	if source != "" {
		detail = fmt.Sprintf("Signature verification failed via %s", source)
	}
	return CheckResult{
		Name:   "signature",
		Status: "fail",
		Detail: detail,
	}
}

func checkMDOCSignature(doc *mdoc.Document, opts ValidateOpts) CheckResult {
	pubKeys, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return CheckResult{
			Name:   "signature",
			Status: "fail",
			Detail: err.Error(),
		}
	}

	if len(pubKeys) == 0 && len(tlCerts) == 0 {
		// Credentials issued by the local wallet validate against its CA
		// with a full chain.
		if anchors := localWalletTrustAnchors(opts.WalletStore); len(anchors) > 0 {
			if caKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, anchors); err == nil && caKey != nil {
				result := mdoc.Verify(doc, caKey)
				if result.SignatureValid {
					return CheckResult{
						Name:   "signature",
						Status: "pass",
						Detail: fmt.Sprintf("Valid (%s, via local wallet CA, chain verified)", result.Algorithm),
					}
				}
			}
		}
		if leafKey, err := validate.ExtractMDOCX5ChainLeafKey(doc); err == nil && leafKey != nil {
			result := mdoc.Verify(doc, leafKey)
			if result.SignatureValid {
				return CheckResult{
					Name:   "signature",
					Status: "pass",
					Detail: fmt.Sprintf("Valid (%s, via %s)", result.Algorithm, validate.SourceX5CLeaf),
				}
			}
			return CheckResult{
				Name:   "signature",
				Status: "fail",
				Detail: "Signature invalid (embedded x5chain leaf key)",
			}
		}
		return CheckResult{
			Name:   "signature",
			Status: "skipped",
			Detail: "No key provided",
		}
	}

	if len(tlCerts) > 0 {
		if x5cKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts); err == nil && x5cKey != nil {
			result := mdoc.Verify(doc, x5cKey)
			if result.SignatureValid {
				return CheckResult{
					Name:   "signature",
					Status: "pass",
					Detail: fmt.Sprintf("Valid (%s, chain verified)", result.Algorithm),
				}
			}
			return CheckResult{
				Name:   "signature",
				Status: "fail",
				Detail: "Signature invalid (chain-derived key)",
			}
		}
	}

	for _, key := range pubKeys {
		result := mdoc.Verify(doc, key)
		if result.SignatureValid {
			return CheckResult{
				Name:   "signature",
				Status: "pass",
				Detail: fmt.Sprintf("Valid (%s)", result.Algorithm),
			}
		}
	}

	return CheckResult{
		Name:   "signature",
		Status: "fail",
		Detail: "Signature verification failed",
	}
}

func checkSDJWTStatus(token *sdjwt.Token, opts ValidateOpts) []CheckResult {
	if nonStandard := validate.NonStatusListFormat(token.ResolvedClaims); nonStandard != "" {
		return []CheckResult{{
			Name:   "status",
			Status: "warning",
			Detail: nonStandard + ". HAIP 1.0 §6.1 asks for status_list, so this status is not checked.",
		}}
	}
	ref := statuslist.ExtractStatusRef(token.ResolvedClaims)
	if skip, ok := statusCheckNotRun(ref, opts); ok {
		return []CheckResult{skip}
	}

	_, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return []CheckResult{{Name: "status", Status: "fail", Detail: err.Error()}}
	}
	return checkStatusRef(ref, tlCerts, opts.HTTPClient)
}

func checkMDOCStatus(doc *mdoc.Document, opts ValidateOpts) []CheckResult {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.Status == nil {
		return []CheckResult{{Name: "status", Status: "skipped", Detail: "No status reference in credential"}}
	}

	// ExtractStatusRef expects {"status": {"status_list": ...}}. MSO.Status is
	// already the inner status object.
	ref := statuslist.ExtractStatusRef(map[string]any{"status": doc.IssuerAuth.MSO.Status})
	if skip, ok := statusCheckNotRun(ref, opts); ok {
		return []CheckResult{skip}
	}

	_, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return []CheckResult{{Name: "status", Status: "fail", Detail: err.Error()}}
	}
	return checkStatusRef(ref, tlCerts, opts.HTTPClient)
}

// A credential without a status reference needs no network check. A reference stays
// unresolved until its list is fetched.
func statusCheckNotRun(ref *statuslist.StatusRef, opts ValidateOpts) (CheckResult, bool) {
	if ref == nil {
		return CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "No status list reference in credential",
		}, true
	}
	if opts.Offline {
		return CheckResult{
			Name:         "status",
			Status:       "skipped",
			Detail:       "Needs the status list, which is fetched from the issuer",
			NeedsNetwork: true,
		}, true
	}
	if !opts.CheckStatus {
		return CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "Not requested",
		}, true
	}
	return CheckResult{}, false
}

// The credential status is reported apart from trust in the status list signature.
func checkStatusRef(ref *statuslist.StatusRef, tlCerts []trustlist.CertInfo, client *http.Client) []CheckResult {
	if ref == nil {
		return []CheckResult{{Name: "status", Status: "skipped", Detail: "No status list reference in credential"}}
	}
	if ref.Invalid != "" {
		return []CheckResult{{Name: "status", Status: "fail", Detail: fmt.Sprintf("Malformed status list reference: %s", ref.Invalid)}}
	}

	checkOpts := statuslist.CheckOptions{HTTPClient: client}
	for _, ci := range tlCerts {
		if len(ci.Raw) > 0 {
			checkOpts.TrustListCerts = append(checkOpts.TrustListCerts, statuslist.TrustCert{Raw: ci.Raw})
		}
	}

	result, err := statuslist.CheckWithOptions(ref, checkOpts)
	if err != nil {
		return []CheckResult{{Name: "status", Status: "fail", Detail: fmt.Sprintf("Status check error: %v", err)}}
	}

	statusDetail := fmt.Sprintf("index %d, status=%d %s, %s",
		result.Index, result.Status, result.StatusName, strings.ToUpper(result.Format))
	if !result.IsValid {
		return []CheckResult{{Name: "status", Status: "fail", Detail: fmt.Sprintf("%s (%s)", result.StatusName, statusDetail)}}
	}

	status := CheckResult{Name: "status", Status: "pass", Detail: fmt.Sprintf("Valid (%s)", statusDetail)}

	sigDetail := result.SignatureInfo
	if len(result.Warnings) > 0 {
		sigDetail = strings.Join(result.Warnings, ". ")
	}
	signature := CheckResult{Name: "status list signature", Status: "warning", Detail: sigDetail}
	if result.TrustAnchored {
		signature.Status = "pass"
	}
	return []CheckResult{status, signature}
}

func resolveKeys(opts ValidateOpts) ([]crypto.PublicKey, []trustlist.CertInfo, error) {
	var pubKeys []crypto.PublicKey
	var tlCerts []trustlist.CertInfo

	if opts.Key != "" {
		key, err := keys.ParsePublicKey([]byte(opts.Key))
		if err != nil {
			return nil, nil, fmt.Errorf("parsing key: %w", err)
		}
		pubKeys = append(pubKeys, key)
	}

	if opts.TrustListRaw != "" {
		tl, err := trustlist.Parse(opts.TrustListRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing trust list: %w", err)
		}
		tlCerts = trustlist.ExtractPublicKeys(tl)
		for _, ci := range tlCerts {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	if opts.TrustListURL != "" && !opts.Offline {
		// The URL is caller-supplied, and ReadRemoteInput cannot read local files.
		tlRaw, err := format.ReadRemoteInput(opts.TrustListURL, opts.HTTPClient)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching trust list: %w", err)
		}
		tl, err := trustlist.Parse(tlRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing trust list: %w", err)
		}
		certs := trustlist.ExtractPublicKeys(tl)
		tlCerts = append(tlCerts, certs...)
		for _, ci := range certs {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	return pubKeys, tlCerts, nil
}

func relativeTimeGo(t time.Time) string {
	diff := time.Until(t)
	future := diff > 0
	if diff < 0 {
		diff = -diff
	}

	days := int(diff.Hours() / 24)
	hours := int(diff.Hours())
	minutes := int(diff.Minutes())
	months := days / 30

	var str string
	if months >= 2 {
		str = fmt.Sprintf("%d months", months)
	} else if months == 1 {
		str = "1 month"
	} else if days >= 2 {
		str = fmt.Sprintf("%d days", days)
	} else if days == 1 {
		str = "1 day"
	} else if hours >= 2 {
		str = fmt.Sprintf("%d hours", hours)
	} else if hours == 1 {
		str = "1 hour"
	} else if minutes >= 2 {
		str = fmt.Sprintf("%d minutes", minutes)
	} else {
		str = "1 minute"
	}

	if future {
		return "in " + str
	}
	return str + " ago"
}
