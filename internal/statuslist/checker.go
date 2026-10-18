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

package statuslist

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/issuermetadata"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// ExtractStatusRef extracts the status list reference from SD-JWT claims or
// mdoc MSO status. It returns nil without a status claim. Section 6.2 requires
// idx and uri. Without either the reference has Invalid set.
func ExtractStatusRef(claims map[string]any) *StatusRef {
	status, ok := claims["status"].(map[string]any)
	if !ok {
		return nil
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		return nil
	}

	uri, _ := sl["uri"].(string)
	if uri == "" {
		return &StatusRef{Invalid: "the status_list reference has no uri claim"}
	}

	rawIdx, present := sl["idx"]
	if !present {
		return &StatusRef{URI: uri, Invalid: "the status_list reference has no idx claim"}
	}
	idx, ok := asInt(rawIdx)
	if !ok {
		return &StatusRef{URI: uri, Invalid: fmt.Sprintf("the status_list idx claim is not an integer (%T)", rawIdx)}
	}
	if idx < 0 {
		return &StatusRef{URI: uri, Invalid: fmt.Sprintf("the status_list idx claim is %d, which is not a non-negative integer", idx)}
	}
	return &StatusRef{URI: uri, Idx: idx}
}

// JSON decodes numbers as float64. CBOR decodes them as int64 or uint64.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		if n > 1<<62 {
			return 0, false
		}
		return int(n), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func Check(ref *StatusRef) (*StatusResult, error) {
	return CheckWithOptions(ref, CheckOptions{})
}

// CheckWithOptions fetches the Status List Token referenced by a credential
// and reports the status at the credential's index.
//
// Every step of Section 8.3 runs here. "If any of these checks fails, no
// statement about the status of the Referenced Token can be made and the
// Referenced Token SHOULD be rejected."
func CheckWithOptions(ref *StatusRef, opts CheckOptions) (*StatusResult, error) {
	if ref == nil {
		return nil, fmt.Errorf("no status list reference")
	}
	if ref.Invalid != "" {
		return nil, fmt.Errorf("invalid status list reference: %s", ref.Invalid)
	}
	if ref.URI == "" {
		return nil, fmt.Errorf("status list reference has no uri")
	}
	if ref.Idx < 0 {
		return nil, fmt.Errorf("status list index %d is negative", ref.Idx)
	}

	body, contentType, err := fetchStatusListToken(ref.URI, acceptHeader(opts.Prefer), opts.HTTPClient)
	if err != nil {
		return nil, err
	}

	tokenFormat, formatWarning := detectFormat(contentType, body)

	var tok *statusListToken
	switch tokenFormat {
	case FormatCWT:
		tok, err = parseCWTStatusListToken(body, opts)
	default:
		tok, err = parseJWTStatusListToken(body, opts)
	}
	if err != nil {
		return nil, err
	}
	if formatWarning != "" {
		tok.warnings = append(tok.warnings, formatWarning)
	}

	if err := tok.validate(ref, opts); err != nil {
		return nil, err
	}

	decompressed, rawDeflate, err := zlibDecompress(tok.lst)
	if err != nil {
		return nil, fmt.Errorf("decompressing status list: %w", err)
	}
	if rawDeflate {
		// Section 4.1 requires the ZLIB data format around the DEFLATE
		// stream. A bare DEFLATE stream is read with a warning.
		tok.warnings = append(tok.warnings, "the status list is raw DEFLATE without the ZLIB header required by section 4.1")
	}

	status, err := extractStatus(decompressed, ref.Idx, tok.bits)
	if err != nil {
		return nil, err
	}

	signatureValid := true
	return &StatusResult{
		URI:            ref.URI,
		Index:          ref.Idx,
		Status:         status,
		StatusName:     StatusName(status),
		IsValid:        status == 0,
		BitsPerEntry:   tok.bits,
		Format:         tok.format,
		Subject:        tok.subject,
		SignatureValid: &signatureValid,
		SignatureInfo:  tok.signatureInfo,
		TrustAnchored:  tok.trustAnchored,
		Warnings:       tok.warnings,
		HAIPFindings:   tok.haipFindings,
	}, nil
}

// acceptHeader asks for the preferred representation first and for the other
// one with a lower weight.
func acceptHeader(prefer string) string {
	switch prefer {
	case FormatJWT:
		return MediaTypeJWT + ", " + MediaTypeCWT + ";q=0.5"
	case FormatCWT:
		return MediaTypeCWT + ", " + MediaTypeJWT + ";q=0.5"
	}
	return MediaTypeJWT + ", " + MediaTypeCWT
}

// FormatForCredential is the status list format that matches a credential
// format: CWT for an mdoc and JWT for every JWT-based format.
func FormatForCredential(credentialFormat string) string {
	switch credentialFormat {
	case credtype.FormatMDOC, "mdoc":
		return FormatCWT
	}
	return FormatJWT
}

// fetchStatusListToken performs the Section 8.1 request. It returns the raw
// token body and the declared content type.
func fetchStatusListToken(uri, accept string, clients ...*http.Client) ([]byte, string, error) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", accept)

	resp, err := format.HTTPClient(clients...).Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetching status list: %w", err)
	}
	defer resp.Body.Close()

	// Section 8.2: "A successful response that contains a Status List Token
	// MUST use an HTTP status code in the 2xx range." A cache or a proxy
	// can answer 203 or 206.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", fmt.Errorf("status list returned HTTP %d", resp.StatusCode)
	}

	body, err := format.ReadRemoteBody(resp.Body, "status list")
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// detectFormat picks the representation from the response content type or
// else from the shape of the body. Section 8.2 makes the content type
// mandatory, so any other one is a warning.
func detectFormat(contentType string, body []byte) (string, string) {
	mediaType := ""
	if contentType != "" {
		if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
			mediaType = strings.ToLower(strings.TrimSpace(parsed))
		}
	}
	switch mediaType {
	case MediaTypeJWT:
		return FormatJWT, ""
	case MediaTypeCWT:
		return FormatCWT, ""
	}

	sniffed := FormatCWT
	if looksLikeCompactJWS(body) {
		sniffed = FormatJWT
	}
	if contentType == "" {
		return sniffed, fmt.Sprintf("the status list response declared no Content-Type. Section 8.2 requires %s or %s", MediaTypeJWT, MediaTypeCWT)
	}
	return sniffed, fmt.Sprintf("the status list response declared Content-Type %q. Section 8.2 requires %s or %s", contentType, MediaTypeJWT, MediaTypeCWT)
}

func looksLikeCompactJWS(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if bytes.Count(trimmed, []byte(".")) != 2 {
		return false
	}
	for _, b := range trimmed {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

type statusListToken struct {
	format        string
	subject       string
	issuedAt      *time.Time
	expiresAt     *time.Time
	notBefore     *time.Time
	bits          int
	lst           []byte
	signatureInfo string
	trustAnchored bool
	warnings      []string
	haipFindings  []string
}

func (t *statusListToken) validate(ref *StatusRef, opts CheckOptions) error {
	// Section 8.3: "The subject claim (sub or 2) of the Status List Token
	// MUST be equal to the uri claim in the status_list object of the
	// Referenced Token".
	if t.subject == "" {
		return fmt.Errorf("the status list token has no subject claim, which section 5.1 and 5.2 require")
	}
	if t.subject != ref.URI {
		return fmt.Errorf("the status list token's subject is %q, but the credential references the uri %q", t.subject, ref.URI)
	}

	// Section 5.1: "iat: REQUIRED. ... The iat (issued at) claim MUST specify
	// the time at which the Status List Token was issued."
	if t.issuedAt == nil {
		return fmt.Errorf("the status list token has no issued at claim, which section 5.1 and 5.2 require")
	}

	// Section 8.3: "If the expiration time is defined (exp or 4), it MUST be
	// checked if the Status List Token is expired".
	now := opts.now()
	if t.expiresAt != nil {
		if validity.Expired(t.expiresAt, now) {
			return fmt.Errorf("the status list token expired at %s", t.expiresAt.UTC().Format(time.RFC3339))
		}
	} else {
		t.warnings = append(t.warnings, "the status list token has no exp claim, which section 5.1 and 5.2 recommend")
	}
	// RFC 7519 §4.1.5: "The nbf (not before) claim identifies the time before
	// which the JWT MUST NOT be accepted for processing." RFC 8392 §3.1.5
	// gives claim 5 the same meaning in a CWT.
	if validity.NotYet(t.notBefore, now) {
		return fmt.Errorf("the status list token is not valid before %s", t.notBefore.UTC().Format(time.RFC3339))
	}
	if validity.NotYet(t.issuedAt, now) {
		t.warnings = append(t.warnings, fmt.Sprintf("the status list token is issued at %s, which is in the future", t.issuedAt.UTC().Format(time.RFC3339)))
	}

	// Section 4.2 and 4.3: "bits: REQUIRED ... The allowed values for bits are
	// 1, 2, 4, and 8." A wrong width reads other credentials' entries, so a
	// missing bits value has no default.
	switch t.bits {
	case 1, 2, 4, 8:
	case 0:
		return fmt.Errorf("the status list has no bits member, which section 4.2 and 4.3 require")
	default:
		return fmt.Errorf("the status list declares %d bits per entry, which is not one of 1, 2, 4 or 8", t.bits)
	}
	if len(t.lst) == 0 {
		return fmt.Errorf("the status list has no lst member, which section 4.2 and 4.3 require")
	}
	return nil
}

type keyCandidates struct {
	keys     []crypto.PublicKey
	info     string
	anchored bool
	warning  string
}

// resolveKeys picks the verification keys for a Status List Token.
// Sections 5.1 and 5.2 say "Relying Parties MUST reject JWTs with an invalid
// signature", so verification runs even without a trusted list. A trust anchor
// only decides whether the key is trusted, and that is reported separately.
func resolveKeys(certs []*x509.Certificate, embedded []crypto.PublicKey, named, iss string, opts CheckOptions) (*keyCandidates, error) {
	if len(opts.TrustListCerts) > 0 {
		if len(certs) == 0 {
			return nil, fmt.Errorf("the status list token carries no certificate chain to validate against the trusted list")
		}
		leaf, err := verifyChain(certs, opts.TrustListCerts)
		if err != nil {
			return nil, err
		}
		return &keyCandidates{
			keys:     []crypto.PublicKey{leaf.PublicKey},
			info:     "signed by " + leaf.Subject.CommonName,
			anchored: true,
		}, nil
	}

	if len(opts.Keys) > 0 {
		return &keyCandidates{
			keys:     opts.Keys,
			info:     "signed by a supplied key",
			anchored: true,
		}, nil
	}

	if len(opts.CandidateAnchors) > 0 && len(certs) > 0 {
		if leaf, err := verifyChain(certs, opts.CandidateAnchors); err == nil {
			return &keyCandidates{
				keys:     []crypto.PublicKey{leaf.PublicKey},
				info:     "signed by " + leaf.Subject.CommonName,
				anchored: true,
			}, nil
		}
	}

	if len(certs) > 0 {
		return &keyCandidates{
			keys:    []crypto.PublicKey{certs[0].PublicKey},
			info:    "signed by " + certs[0].Subject.CommonName,
			warning: "the status list token's certificate chain was not validated against a trusted list",
		}, nil
	}

	if len(embedded) > 0 {
		return &keyCandidates{
			keys:    embedded,
			info:    "signed by the key in its own header",
			warning: "the status list token was verified with its own embedded key, so its issuer is not verified",
		}, nil
	}

	// Section 11.3 leaves key resolution to the ecosystem. The EUDI ecosystem
	// resolves a Status Issuer through x5c. A DID kid gets its own error.
	if did := keys.DIDReference(named); did != "" {
		return nil, fmt.Errorf("the status list token identifies its key by the DID %s. This tool does not resolve DIDs. Section 11.3 leaves key resolution to the ecosystem, and the EUDI ecosystem identifies a Status Issuer by the certificate chain in the x5c header", did)
	}

	// Section 11.3 allows a kid that refers to web-based key resolution. No
	// specification defines that resolution for a Status List Token, so the
	// JWT VC Issuer Metadata of SD-JWT VC §4 is used. A key found there is
	// never trust anchored.
	if iss != "" {
		keys, err := issuerMetadataKeys(iss, named, opts)
		if err != nil {
			return nil, fmt.Errorf("no key to verify the status list token with: it has no x5c and no jwk header, and its kid could not be resolved through the issuer metadata of %s: %w", iss, err)
		}
		return &keyCandidates{keys: keys, info: "signed by a key from the issuer metadata of " + iss}, nil
	}

	return nil, fmt.Errorf("no key to verify the status list token with: it carries no certificate chain and no public key, and no trusted list or key was supplied")
}

// issuerMetadataKeys returns the keys of the JWT VC Issuer Metadata of iss
// that match kid.
func issuerMetadataKeys(iss, kid string, opts CheckOptions) ([]crypto.PublicKey, error) {
	jwks, err := issuermetadata.JWKs(iss, kid, opts.HTTPClient)
	if err != nil {
		return nil, err
	}
	var keys []crypto.PublicKey
	var parseErr error
	for _, jwk := range jwks {
		key, err := publicKeyFromJWK(jwk)
		if err != nil {
			parseErr = err
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("parsing the issuer metadata key: %w", parseErr)
	}
	return keys, nil
}

// verifyChain checks the token's chain against the trust anchors. An anchor
// that is not a certificate is an error.
func verifyChain(certs []*x509.Certificate, trustCerts []TrustCert) (*x509.Certificate, error) {
	anchors := make([]*x509.Certificate, 0, len(trustCerts))
	for i, tc := range trustCerts {
		anchor, err := x509.ParseCertificate(tc.Raw)
		if err != nil {
			return nil, fmt.Errorf("trust anchor %d is not a certificate: %w", i+1, err)
		}
		anchors = append(anchors, anchor)
	}
	leaf, err := certchain.Verify(certs, anchors)
	if err != nil {
		return nil, fmt.Errorf("the status list token's certificate chain is not trusted: %w", err)
	}
	return leaf, nil
}

// parseJWTStatusListToken parses and verifies a Status List Token in JWT
// format (Section 5.1).
func parseJWTStatusListToken(body []byte, opts CheckOptions) (*statusListToken, error) {
	compact := strings.TrimSpace(string(body))
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("the status list token is not a JWS compact serialization")
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding status list header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing status list header: %w", err)
	}

	// Section 5.1: "typ: REQUIRED. The JWT type MUST be statuslist+jwt."
	typ, _ := header["typ"].(string)
	if !format.JOSETypeIs(typ, TypJWT) {
		if typ == "" {
			return nil, fmt.Errorf("the status list token has no typ header. Section 5.1 requires %q", TypJWT)
		}
		return nil, fmt.Errorf("the status list token has typ %q. Section 5.1 requires %q", typ, TypJWT)
	}

	certs, err := certchain.FromX5C(header["x5c"])
	if err != nil {
		return nil, err
	}
	var embedded []crypto.PublicKey
	if jwkMap, ok := header["jwk"]; ok {
		if key, err := publicKeyFromJWK(jwkMap); err == nil {
			embedded = append(embedded, key)
		}
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding status list payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing status list payload: %w", err)
	}

	kid, _ := header["kid"].(string)
	iss, _ := payload["iss"].(string)
	candidates, err := resolveKeys(certs, embedded, kid, iss, opts)
	if err != nil {
		return nil, err
	}

	// Status lists accept fewer algorithms than the toolkit's shared set.
	alg, _ := header["alg"].(string)
	switch alg {
	case jws.AlgES256, "ES384":
	default:
		return nil, fmt.Errorf("the status list token is signed with %q, which is not one of the accepted algorithms ES256 and ES384", alg)
	}

	verified := false
	for _, key := range candidates.keys {
		if jws.Valid(compact, key) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("the status list token's %s signature does not verify", alg)
	}

	tok := &statusListToken{
		format:        FormatJWT,
		signatureInfo: candidates.info,
		trustAnchored: candidates.anchored,
	}
	if candidates.warning != "" {
		tok.warnings = append(tok.warnings, candidates.warning)
	}
	// HAIP 1.0 §6.1: "The public key used to validate the signature on the
	// Status List Token [...] MUST be included in the x5c JOSE header of the
	// Token."
	if len(certs) == 0 {
		tok.haipFindings = append(tok.haipFindings, "HAIP 1.0 §6.1: the status list token has no x5c header. HAIP requires the signing certificate there")
	}
	tok.subject, _ = payload["sub"].(string)
	tok.issuedAt = unixClaim(payload["iat"])
	tok.expiresAt = unixClaim(payload["exp"])
	tok.notBefore = unixClaim(payload["nbf"])
	if ttl, present := payload["ttl"]; present {
		if n, ok := asInt(ttl); !ok || n <= 0 {
			tok.warnings = append(tok.warnings, "the status list token's ttl claim is not a positive number, which section 5.1 requires")
		}
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the status list token has no status_list claim, which section 5.1 requires")
	}
	if b, present := sl["bits"]; present {
		if n, ok := asInt(b); ok {
			tok.bits = n
		} else {
			return nil, fmt.Errorf("the status list bits member is not an integer (%T)", b)
		}
	}
	if lst, ok := sl["lst"].(string); ok {
		decoded, err := format.DecodeBase64URL(lst)
		if err != nil {
			return nil, fmt.Errorf("decoding lst: %w", err)
		}
		tok.lst = decoded
	}
	return tok, nil
}

func publicKeyFromJWK(raw any) (crypto.PublicKey, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return keys.ParseJWK(data)
}

// unixClaim reads a NumericDate. RFC 7519 §2 and RFC 8392 §2 allow a
// non-integer value.
func unixClaim(v any) *time.Time {
	if f, ok := v.(float64); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil
		}
		sec, frac := math.Modf(f)
		t := time.Unix(int64(sec), int64(frac*float64(time.Second)))
		return &t
	}
	n, ok := asInt(v)
	if !ok {
		return nil
	}
	t := time.Unix(int64(n), 0)
	return &t
}

// maxBitstringBytes limits the memory used by an untrusted status list.
const maxBitstringBytes = 16 << 20

// zlibDecompress limits the output size. It reports a raw DEFLATE stream without the
// ZLIB header that Section 4.1 requires.
func zlibDecompress(data []byte) ([]byte, bool, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err == nil {
		defer r.Close()
		out, err := readBounded(r)
		return out, false, err
	}

	fr := flate.NewReader(bytes.NewReader(data))
	defer fr.Close()
	out, err := readBounded(fr)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func readBounded(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxBitstringBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxBitstringBytes {
		return nil, fmt.Errorf("status list decompresses to more than %d bytes", maxBitstringBytes)
	}
	return out, nil
}

// idx and bits come from untrusted documents. idx*bits can overflow, so idx is
// checked on its own.
func extractStatus(bitstring []byte, idx, bits int) (int, error) {
	if idx < 0 {
		return 0, fmt.Errorf("status list index %d is negative", idx)
	}
	switch bits {
	case 1, 2, 4, 8:
	default:
		return 0, fmt.Errorf("status list declares %d bits per entry, which is not one of 1, 2, 4 or 8", bits)
	}

	entries := len(bitstring) * 8 / bits
	if idx >= entries {
		return 0, fmt.Errorf("index %d is out of range. The status list holds %d entries in %d bytes", idx, entries, len(bitstring))
	}

	bitPos := idx * bits
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	mask := (1 << bits) - 1
	return (int(bitstring[byteIdx]) >> bitOffset) & mask, nil
}
