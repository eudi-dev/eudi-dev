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

package mock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"maps"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// SplitClaimsByNamespace groups claims by namespace. A key of the form
// "namespace:element" goes into that namespace. Every other key goes into
// defaultNamespace. The German PID puts its national additions in
// eu.europa.ec.eudi.pid.de.1.
func SplitClaimsByNamespace(claims map[string]any, defaultNamespace string) map[string]map[string]any {
	out := make(map[string]map[string]any)
	for key, value := range claims {
		ns, name := defaultNamespace, key
		if i := strings.Index(key, ":"); i > 0 {
			ns, name = key[:i], key[i+1:]
		}
		if out[ns] == nil {
			out[ns] = make(map[string]any)
		}
		out[ns][name] = value
	}
	if len(out) == 0 {
		out[defaultNamespace] = map[string]any{}
	}
	return out
}

var fullDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// EU PID Rulebook v1.7 §3.1.2 and ISO/IEC 18013-5:2021 Table 5 define date attributes.
func mdocClaimValue(namespace, name string, value any) any {
	value = cborValue(value)
	if namespace == "org.iso.18013.5.1" && name == "driving_privileges" {
		if privileges, ok := value.([]any); ok {
			out := make([]any, len(privileges))
			for i, privilege := range privileges {
				if fields, ok := privilege.(map[string]any); ok {
					copy := maps.Clone(fields)
					for _, date := range []string{"issue_date", "expiry_date"} {
						if field, ok := fields[date]; ok {
							copy[date] = mdocDateValue(field, true, false)
						}
					}
					out[i] = copy
				} else {
					out[i] = privilege
				}
			}
			return out
		}
	}
	switch namespace {
	case PIDNamespace, "org.iso.18013.5.1", "org.iso.23220.photoid.1":
		switch name {
		case "birth_date":
			return mdocDateValue(value, true, false)
		case "expiry_date", "issuance_date", "issue_date":
			return mdocDateValue(value, true, true)
		case "portrait_capture_date":
			return mdocDateValue(value, false, true)
		}
	}
	return value
}

// cborValue encodes claims that come from JSON with their CBOR types. A
// whole number is an integer, and a base64 data URI is a byte string, such as
// the ISO 18013-5 portrait.
func cborValue(value any) any {
	switch v := value.(type) {
	case float64:
		if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
			return int64(v)
		}
	case string:
		if meta, payload, ok := strings.Cut(v, ","); ok && strings.HasPrefix(meta, "data:") && strings.HasSuffix(meta, ";base64") {
			if data, err := base64.StdEncoding.DecodeString(payload); err == nil {
				return data
			}
		}
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = cborValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cborValue(item)
		}
		return out
	}
	return value
}

func mdocDateValue(value any, fullDate, dateTime bool) any {
	text, ok := value.(string)
	if !ok {
		return value
	}
	if fullDate && fullDatePattern.MatchString(text) {
		if _, err := time.Parse(time.DateOnly, text); err == nil {
			return cbor.Tag{Number: 1004, Content: text}
		}
	}
	if dateTime {
		if _, err := time.Parse(time.RFC3339, text); err == nil {
			return cbor.Tag{Number: 0, Content: text}
		}
	}
	return value
}

type MDOCConfig struct {
	CertificateIssuer string
	DocType           string
	Namespace         string
	// Claims go into Namespace, except a key "namespace:element" (see
	// SplitClaimsByNamespace).
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	HolderKey     *ecdsa.PublicKey    // optional: adds deviceKeyInfo to MSO
	ExpiresIn     time.Duration       // Validity duration. Defaults to 30 days when zero.
	ValidFrom     *time.Time          // optional: override validFrom (defaults to now)
	StatusListURI string              // optional: status list URI for revocation
	StatusListIdx int                 // optional: index in the status list
	CertChain     []*x509.Certificate // optional: x5chain certificate chain [leaf, CA]
	// KeepTrustAnchor embeds the chain as given, including a terminal
	// self-signed root.
	KeepTrustAnchor bool
	// OmitValidityInfo drops the MSO validityInfo required by ISO 18013-5.
	// Tests use it to check verifiers.
	OmitValidityInfo bool
	// OmitDigestAlgorithm drops the MSO digestAlgorithm required by ISO
	// 18013-5. The digests still use SHA-256.
	OmitDigestAlgorithm bool
}

func GenerateMDOC(cfg MDOCConfig) (string, error) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresIn := cfg.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 30 * 24 * time.Hour
	}
	validFrom := now
	if cfg.ValidFrom != nil {
		validFrom = cfg.ValidFrom.UTC().Truncate(time.Second)
	}
	validUntil := now.Add(expiresIn)

	namespaceClaims := SplitClaimsByNamespace(cfg.Claims, cfg.Namespace)

	// Digest IDs are unique across namespaces.
	tag24ItemsByNS := make(map[string]any, len(namespaceClaims))
	valueDigestsByNS := make(map[string]any, len(namespaceClaims))

	var digestID uint64
	for ns, claims := range namespaceClaims {
		var tag24Items []cbor.RawMessage
		valueDigests := make(map[uint64][]byte)
		for name, value := range claims {
			random := make([]byte, 16)
			if _, err := rand.Read(random); err != nil {
				return "", fmt.Errorf("generating random: %w", err)
			}

			item := map[string]any{
				"digestID":          digestID,
				"random":            random,
				"elementIdentifier": name,
				"elementValue":      mdocClaimValue(ns, name, value),
			}

			itemBytes, err := cbor.Marshal(item)
			if err != nil {
				return "", fmt.Errorf("encoding IssuerSignedItem: %w", err)
			}

			tag24 := cbor.Tag{
				Number:  24,
				Content: itemBytes,
			}
			tag24Bytes, err := cbor.Marshal(tag24)
			if err != nil {
				return "", fmt.Errorf("encoding Tag-24: %w", err)
			}

			tag24Items = append(tag24Items, tag24Bytes)

			digest := sha256.Sum256(tag24Bytes)
			valueDigests[digestID] = digest[:]
			digestID++
		}
		tag24ItemsByNS[ns] = tag24Items
		valueDigestsByNS[ns] = valueDigests
	}

	mso := map[string]any{
		"version":      "1.0",
		"docType":      cfg.DocType,
		"valueDigests": valueDigestsByNS,
	}
	if !cfg.OmitDigestAlgorithm {
		mso["digestAlgorithm"] = "SHA-256"
	}
	if !cfg.OmitValidityInfo {
		mso["validityInfo"] = map[string]any{
			"signed":     cbor.Tag{Number: 0, Content: now.Format(time.RFC3339)},
			"validFrom":  cbor.Tag{Number: 0, Content: validFrom.Format(time.RFC3339)},
			"validUntil": cbor.Tag{Number: 0, Content: validUntil.Format(time.RFC3339)},
		}
	}

	if cfg.StatusListURI != "" {
		mso["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	if cfg.HolderKey != nil {
		xBytes, yBytes, err := format.ECPublicCoords(cfg.HolderKey)
		if err != nil {
			return "", fmt.Errorf("encoding holder key: %w", err)
		}

		crv, err := coseCurve(cfg.HolderKey)
		if err != nil {
			return "", err
		}
		// COSE_Key labels 1=kty, -1=crv, -2=x, -3=y (RFC 9053 §7.1.1).
		coseKey := map[any]any{
			int64(1):  int64(2), // kty: EC2
			int64(-1): crv,
			int64(-2): xBytes,
			int64(-3): yBytes,
		}

		mso["deviceKeyInfo"] = map[string]any{
			"deviceKey": coseKey,
		}
	}

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return "", fmt.Errorf("encoding MSO: %w", err)
	}

	taggedMSOBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: msoBytes})
	if err != nil {
		return "", fmt.Errorf("encoding Tag-24 MSO: %w", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, cfg.Key)
	if err != nil {
		return "", fmt.Errorf("creating COSE signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Payload = taggedMSOBytes

	// Verifiers take the root from their trust list, so x5chain holds the leaf
	// and intermediates.
	chain := cfg.CertChain
	if !cfg.KeepTrustAnchor {
		chain = certchain.WithoutSelfSignedAnchor(chain)
	}
	if len(chain) > 0 {
		// CIR (EU) 2026/1731 Annex I §4.1 requires protected PID certificate references.
		if strings.HasPrefix(cfg.DocType, "eu.europa.ec.eudi.pid.") && !cfg.KeepTrustAnchor {
			if reference := SigningCertificateURL(cfg.CertificateIssuer, chain[0], "der"); reference != "" {
				digest := sha256.Sum256(chain[0].Raw)
				msg.Headers.Protected[int64(35)] = reference
				msg.Headers.Protected[int64(34)] = []any{int64(-16), digest[:]}
			}
		}
		if len(chain) == 1 {
			msg.Headers.Unprotected[int64(33)] = chain[0].Raw
		} else {
			certDERs := make([][]byte, 0, len(chain))
			for _, cert := range chain {
				certDERs = append(certDERs, cert.Raw)
			}
			msg.Headers.Unprotected[int64(33)] = certDERs
		}
	}

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return "", fmt.Errorf("COSE signing: %w", err)
	}

	issuerAuthBytes, err := msg.MarshalCBOR()
	if err != nil {
		return "", fmt.Errorf("encoding COSE_Sign1: %w", err)
	}
	issuerAuthBytes, err = format.StripCBORTag(issuerAuthBytes, 18)
	if err != nil {
		return "", fmt.Errorf("normalizing COSE_Sign1 tag: %w", err)
	}

	issuerSigned := map[string]any{
		"nameSpaces": tag24ItemsByNS,
		"issuerAuth": cbor.RawMessage(issuerAuthBytes),
	}

	issuerSignedBytes, err := cbor.Marshal(issuerSigned)
	if err != nil {
		return "", fmt.Errorf("encoding IssuerSigned: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(issuerSignedBytes), nil
}

// coseCurve is the COSE Elliptic Curve identifier of an EC2 key (RFC 9053
// §7.1).
func coseCurve(key *ecdsa.PublicKey) (int64, error) {
	switch key.Curve {
	case elliptic.P256():
		return 1, nil
	case elliptic.P384():
		return 2, nil
	case elliptic.P521():
		return 3, nil
	}
	return 0, fmt.Errorf("the holder key curve %s has no COSE identifier", key.Curve.Params().Name)
}
