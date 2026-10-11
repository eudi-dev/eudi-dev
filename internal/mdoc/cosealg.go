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

package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/veraison/go-cose"
)

// AlgorithmESP256 is ECDSA using P-256 and SHA-256 (RFC 9864 §2.1). HAIP 1.0
// §7 names it with -7 as the COSE identifiers of the mandatory ECDSA P-256
// suite.
const AlgorithmESP256 cose.Algorithm = -9

// coseAlgorithms names the COSE algorithms by IANA value. verifiable marks the
// ones a signature check accepts.
var coseAlgorithms = map[cose.Algorithm]struct {
	name       string
	verifiable bool
}{
	cose.AlgorithmES256: {"ES256", true},
	AlgorithmESP256:     {"ESP256", true},
	cose.AlgorithmES384: {"ES384", true},
	cose.AlgorithmES512: {"ES512", true},
	cose.AlgorithmPS256: {"PS256", true},
	cose.AlgorithmEdDSA: {"EdDSA", false},
	cose.AlgorithmRS256: {"RS256", false},
	cose.AlgorithmRS384: {"RS384", false},
	cose.AlgorithmRS512: {"RS512", false},
	cose.AlgorithmPS384: {"PS384", false},
	cose.AlgorithmPS512: {"PS512", false},
}

// COSEAlgorithmName returns the registered name of a COSE algorithm.
func COSEAlgorithmName(alg cose.Algorithm) string {
	if a, ok := coseAlgorithms[alg]; ok {
		return a.name
	}
	return fmt.Sprintf("unknown(%d)", int64(alg))
}

// NewCOSEVerifier returns a verifier for a COSE algorithm this toolkit accepts.
func NewCOSEVerifier(alg cose.Algorithm, key crypto.PublicKey) (cose.Verifier, error) {
	if !coseAlgorithms[alg].verifiable {
		return nil, fmt.Errorf("unsupported COSE algorithm %s", COSEAlgorithmName(alg))
	}
	if alg != AlgorithmESP256 {
		return cose.NewVerifier(alg, key)
	}
	// go-cose has no ESP256. It computes the same signature as ES256, which
	// leaves the curve open, so the key must be on P-256.
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("ESP256 needs a P-256 key")
	}
	inner, err := cose.NewVerifier(cose.AlgorithmES256, key)
	if err != nil {
		return nil, err
	}
	return esp256Verifier{inner}, nil
}

type esp256Verifier struct{ cose.Verifier }

// Algorithm matches the protected header, which go-cose compares before it
// verifies.
func (esp256Verifier) Algorithm() cose.Algorithm { return AlgorithmESP256 }
