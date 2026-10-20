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

package demorp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
)

// ConfiguredIdentity is signing material given at startup, such as the
// access certificate of a member state sandbox. It takes the place of the
// registered identity of the demo issuer or the demo verifier.
type ConfiguredIdentity struct {
	Key   *ecdsa.PrivateKey
	Chain []*x509.Certificate
	// Info is the issuer_info or verifier_info that goes with the access
	// certificate. Empty publishes none.
	Info []any
}

// ParseConfiguredIdentity reads a PEM bundle with an EC private key and its
// access certificate chain, leaf first.
func ParseConfiguredIdentity(pemBundle string, info []any) (*ConfiguredIdentity, error) {
	key, chain, err := parseSigningKeyBundle(pemBundle)
	if err != nil {
		return nil, err
	}
	leaf, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !leaf.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("the first certificate does not belong to the private key")
	}
	return &ConfiguredIdentity{Key: key, Chain: chain, Info: info}, nil
}

// SetIssuerIdentity makes id the registered identity of the demo issuer: it
// signs the metadata and its Info is the issuer_info. The identity without
// registration signs with it too. Call it before serving.
func (d *DemoRP) SetIssuerIdentity(id *ConfiguredIdentity) {
	d.configuredIssuer = id
}

// SetVerifierIdentity makes id the registered identity of the demo verifier:
// it signs the request objects and its Info is the verifier_info. The
// identity without registration signs with it too. Call it before serving.
func (d *DemoRP) SetVerifierIdentity(id *ConfiguredIdentity) {
	d.configuredVerifier = id
}
