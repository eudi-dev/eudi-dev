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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// The provider regenerates the list on each request. The expiry ends a cached copy.
const tokenLifetime = 24 * time.Hour

// defaultTTL is the ttl claim in seconds. Section 5.1 RECOMMENDS the claim, and
// its example uses 12 hours.
const defaultTTL = 43200

type StatusListConfig struct {
	// URI is the status list token URI, used as the "sub" claim. Section 5.1:
	// "The sub (subject) claim MUST specify the URI of the Status List Token.
	// The value MUST be equal to that of the uri claim contained in the
	// status_list claim of the Referenced Token."
	URI    string
	Issuer string
	// Bits is the number of bits per entry. Section 4.1 allows 1, 2, 4 and 8.
	// Zero means 1.
	Bits int
	// TTL is the caching time-to-live in seconds (RECOMMENDED by Section 5.1).
	// Defaults to 43200 (12h).
	TTL int
	// CertChain is included as x5c (JWT) or x5chain (CWT) when set.
	CertChain []*x509.Certificate
	// IssuedAt overrides the iat claim. The zero value means time.Now().
	IssuedAt time.Time
}

func (c StatusListConfig) issuer() string {
	if c.Issuer == "" {
		return "https://issuer.example"
	}
	return c.Issuer
}

func (c StatusListConfig) ttl() int {
	if c.TTL <= 0 {
		return defaultTTL
	}
	return c.TTL
}

func (c StatusListConfig) issuedAt() time.Time {
	if c.IssuedAt.IsZero() {
		return time.Now()
	}
	return c.IssuedAt
}

// normalizeBits maps the configured width to one of the four widths of
// Section 4.1.
func normalizeBits(bits int) (int, error) {
	switch bits {
	case 0, 1:
		return 1, nil
	case 2, 4, 8:
		return bits, nil
	default:
		return 0, fmt.Errorf("a status list cannot use %d bits per entry, section 4.1 allows 1, 2, 4 and 8", bits)
	}
}

// GenerateStatusListJWT creates a signed Status List Token in JWT format
// (Section 5.1) from a bitstring.
func GenerateStatusListJWT(bitstring []byte, signingKey *ecdsa.PrivateKey, cfg StatusListConfig) (string, error) {
	compressed, err := compressBitstring(bitstring)
	if err != nil {
		return "", err
	}
	bits, err := normalizeBits(cfg.Bits)
	if err != nil {
		return "", err
	}

	now := cfg.issuedAt()
	payload := map[string]any{
		"sub": cfg.URI,
		"iss": cfg.issuer(),
		"iat": now.Unix(),
		"exp": now.Add(tokenLifetime).Unix(),
		"ttl": cfg.ttl(),
		"status_list": map[string]any{
			"bits": bits,
			"lst":  format.EncodeBase64URL(compressed),
		},
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": TypJWT,
	}

	// The public signing key lets a relying party verify without a certificate
	// path. Token Status List leaves key resolution to the deployment (§11.3)
	// and requires only `typ` in the header (§5.1).
	header["jwk"] = mock.PublicKeyJWKMap(&signingKey.PublicKey)

	// HAIP 6.1 excludes the trust anchor from x5c.
	if chain := mock.WithoutSelfSignedTrustAnchor(cfg.CertChain); len(chain) > 0 {
		x5c := make([]string, 0, len(chain))
		for _, cert := range chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		header["x5c"] = x5c
	}

	return jws.Sign(header, payload, signingKey)
}
