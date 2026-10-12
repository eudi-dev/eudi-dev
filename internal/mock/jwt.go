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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/jws"
)

type JWTConfig struct {
	Issuer        string
	VCT           string
	ExpiresIn     time.Duration
	NotBefore     *time.Time // optional: sets nbf claim
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	StatusListURI string              // optional: status list URI for revocation
	StatusListIdx int                 // optional: index in the status list
	CertChain     []*x509.Certificate // optional: x5c certificate chain [leaf, CA]
}

// GenerateJWT creates a mock JWT VC credential with all claims in the payload.
func GenerateJWT(cfg JWTConfig) (string, error) {
	if cfg.Key == nil {
		return "", fmt.Errorf("signing key is required")
	}

	now := time.Now()

	payload := map[string]any{
		"iss": cfg.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(cfg.ExpiresIn).Unix(),
		"vct": cfg.VCT,
	}

	if cfg.NotBefore != nil {
		payload["nbf"] = cfg.NotBefore.Unix()
	}

	for name, value := range cfg.Claims {
		payload[name] = value
	}

	if cfg.StatusListURI != "" {
		payload["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "vc+jwt",
	}

	if len(cfg.CertChain) > 0 {
		var x5c []string
		for _, cert := range cfg.CertChain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		header["x5c"] = x5c
	}

	return jws.Sign(header, payload, cfg.Key)
}
