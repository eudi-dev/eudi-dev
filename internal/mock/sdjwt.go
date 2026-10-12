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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/jws"
)

type SDJWTConfig struct {
	CertificateIssuer string
	Issuer            string
	VCT               string
	ExpiresIn         time.Duration
	// IssuedAt overrides the issuance time of iat, which exp counts from. An
	// issuer of several copies rounds it, so the copies are not linkable by the
	// issuance second (RFC 9901 §10.1). Nil issues at now.
	IssuedAt      *time.Time
	NotBefore     *time.Time // optional: sets nbf claim
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	HolderKey     *ecdsa.PublicKey    // optional: adds cnf claim for holder binding
	StatusListURI string              // optional: status list URI for revocation
	StatusListIdx int                 // optional: index in the status list
	CertChain     []*x509.Certificate // optional: x5c certificate chain [leaf, CA]
	// KeepTrustAnchor embeds the chain as given, including a terminal
	// self-signed root.
	KeepTrustAnchor bool
	// AlwaysDisclosed lists claims that stay in plain text, as top-level names
	// ("family_name") or dotted paths ("address.country"). Entries that match no
	// claim are ignored.
	AlwaysDisclosed []string
}

// GenerateSDJWT creates a mock SD-JWT credential. By default all claims are
// selectively disclosable. Claims in AlwaysDisclosed stay in plain text. Map
// values produce nested disclosures with their own _sd array. Slice values
// produce array element disclosures.
func GenerateSDJWT(cfg SDJWTConfig) (string, error) {
	if cfg.Key == nil {
		return "", fmt.Errorf("signing key is required")
	}

	now := time.Now()
	if cfg.IssuedAt != nil {
		now = *cfg.IssuedAt
	}

	always := make(map[string]bool, len(cfg.AlwaysDisclosed))
	for _, path := range cfg.AlwaysDisclosed {
		if p := strings.TrimSpace(path); p != "" {
			always[p] = true
		}
	}

	var disclosures []string
	var digests []string
	plain := make(map[string]any)

	for name, value := range cfg.Claims {
		if err := checkClaimName(name); err != nil {
			return "", err
		}
		if always[name] || forcePlainClaims[name] {
			plain[name] = value
			continue
		}

		claimDisclosures, claimValue, err := makeDisclosure(name, value, name, always)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, claimDisclosures...)

		topDisc, topDigest, err := createDisclosure(name, claimValue)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, topDisc)
		digests = append(digests, topDigest)
	}

	payload := map[string]any{
		"iss":     cfg.Issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(cfg.ExpiresIn).Unix(),
		"vct":     cfg.VCT,
		"_sd_alg": "sha-256",
	}
	// RFC 9901 §4.2.4.1 allows an empty _sd array but recommends omitting the
	// key, and SD-JWT VC §2.2.2.5 requires it: "An SD-JWT VC MAY have no
	// selectively disclosable claims. In that case, the SD-JWT VC MUST NOT
	// contain the _sd claim in the JWT body."
	if len(digests) > 0 {
		payload["_sd"] = hideDigestOrder(digests)
	}
	for name, value := range plain {
		payload[name] = value
	}

	if cfg.NotBefore != nil {
		payload["nbf"] = cfg.NotBefore.Unix()
	}

	if cfg.HolderKey != nil {
		payload["cnf"] = map[string]any{
			"jwk": PublicKeyJWKMap(cfg.HolderKey),
		}
	}

	if cfg.StatusListURI != "" {
		payload["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	// SD-JWT VC §2.2.1: "The Issuer MUST include the typ header parameter in
	// the SD-JWT. The typ value MUST use dc+sd-jwt."
	header := map[string]any{
		"alg": "ES256",
		"typ": "dc+sd-jwt",
		"kid": KeyIDForPublicKey(&cfg.Key.PublicKey),
	}

	if len(cfg.CertChain) > 0 {
		chain := cfg.CertChain
		if !cfg.KeepTrustAnchor {
			chain = WithoutSelfSignedTrustAnchor(chain)
		}
		var x5c []string
		for _, cert := range chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		if len(x5c) > 0 {
			header["x5c"] = x5c
			if strings.HasPrefix(cfg.VCT, "urn:eudi:pid:") && !cfg.KeepTrustAnchor {
				if reference := SigningCertificateURL(cfg.CertificateIssuer, chain[0], "pem"); reference != "" {
					digest := sha256.Sum256(chain[0].Raw)
					header["x5u"] = reference
					header["x5t#S256"] = base64.RawURLEncoding.EncodeToString(digest[:])
					header["iat"] = time.Now().Unix()
				}
			}
		}
	}

	jwt, err := jws.Sign(header, payload, cfg.Key)
	if err != nil {
		return "", err
	}

	// RFC 9901 §4 orders the parts JWT, tilde, disclosures each followed by a
	// tilde, then the optional KB-JWT. Its ABNF permits no empty component, so
	// a credential with no disclosures is jwt~.
	var serialized strings.Builder
	serialized.WriteString(jwt)
	serialized.WriteString("~")
	for _, d := range disclosures {
		serialized.WriteString(d)
		serialized.WriteString("~")
	}
	return serialized.String(), nil
}

// forcePlainClaims always stay in plain text. SD-JWT VC §2.2.2.3 lists iss, nbf,
// exp, cnf, vct, vct#integrity, aka_vcts and status. This generator writes iat
// itself, and RFC 9901 §7.1 rejects a disclosure for a claim already present
// next to _sd.
var forcePlainClaims = map[string]bool{
	"iss":           true,
	"nbf":           true,
	"exp":           true,
	"cnf":           true,
	"vct":           true,
	"vct#integrity": true,
	"aka_vcts":      true,
	"status":        true,
	"iat":           true,
}

// checkClaimName refuses the keys RFC 9901 reserves. A disclosure name "MUST
// NOT be _sd, ..., or a claim name existing in the object as a permanently
// disclosed claim" (§4.2.1). §4.1.1 reserves _sd_alg for the top level.
func checkClaimName(name string) error {
	switch name {
	case "_sd", "_sd_alg", "...":
		return fmt.Errorf("claim name %q is reserved by RFC 9901 and cannot be used as a credential claim", name)
	}
	return nil
}

// hideDigestOrder returns the digests in an order independent of the claim
// order. RFC 9901 §4.2.4.1: "The Issuer MUST hide the original order of the
// claims in the array [...] e.g., by sorting it alphanumerically or randomly".
func hideDigestOrder(digests []string) []string {
	sorted := make([]string, len(digests))
	copy(sorted, digests)
	sort.Strings(sorted)
	return sorted
}

// makeDisclosure returns the sub-disclosures and the value for the parent
// disclosure. A plain value stays unchanged. A map becomes an object with _sd
// and a slice becomes an array of {"...": digest}. Subclaims whose dotted path
// is in always stay in plain text.
func makeDisclosure(name string, value any, path string, always map[string]bool) (subDisclosures []string, transformedValue any, err error) {
	switch v := value.(type) {
	case map[string]any:
		var subDigests []string
		obj := make(map[string]any)
		for subName, subValue := range v {
			if err := checkClaimName(subName); err != nil {
				return nil, nil, err
			}
			subPath := path + "." + subName
			if always[subPath] {
				obj[subName] = subValue
				continue
			}
			subSub, transformed, err := makeDisclosure(subName, subValue, subPath, always)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, subSub...)
			disc, digest, err := createDisclosure(subName, transformed)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, disc)
			subDigests = append(subDigests, digest)
		}
		if len(subDigests) > 0 {
			obj["_sd"] = hideDigestOrder(subDigests)
		}
		return subDisclosures, obj, nil

	case []any:
		var elements []any
		for _, item := range v {
			disc, digest, err := createArrayElementDisclosure(item)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, disc)
			elements = append(elements, map[string]any{"...": digest})
		}
		transformedValue = elements
		return subDisclosures, transformedValue, nil

	default:
		return nil, value, nil
	}
}

func createDisclosure(name string, value any) (encoded string, digest string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}

	disclosure := []any{format.EncodeBase64URL(salt), name, value}
	discJSON, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", fmt.Errorf("marshaling disclosure: %w", err)
	}

	enc := format.EncodeBase64URL(discJSON)
	h := sha256.Sum256([]byte(enc))
	return enc, format.EncodeBase64URL(h[:]), nil
}

func createArrayElementDisclosure(value any) (encoded string, digest string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}

	disclosure := []any{format.EncodeBase64URL(salt), value}
	discJSON, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", fmt.Errorf("marshaling disclosure: %w", err)
	}

	enc := format.EncodeBase64URL(discJSON)
	h := sha256.Sum256([]byte(enc))
	return enc, format.EncodeBase64URL(h[:]), nil
}
