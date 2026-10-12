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

package wallet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"slices"

	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// providerKeys are the provider keys of the store that loaded the wallet. A
// wallet without a store keeps them in memory.
func (w *Wallet) providerKeys() *provider.Keys {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.signers == nil {
		w.signers = provider.NewKeys(storage.NewMemory(), "", nil)
	}
	return w.signers
}

// Signer issues the signing material of the wallet's providers.
func (w *Wallet) Signer() *provider.Signer {
	return provider.NewSigner(w.providerKeys(), walletRoot{w})
}

// walletRoot implements provider.Env for the wallet.
type walletRoot struct{ w *Wallet }

func (r walletRoot) Root() provider.Root {
	r.w.mu.RLock()
	defer r.w.mu.RUnlock()
	return provider.Root{IssuerKey: r.w.IssuerKey, CAKey: r.w.CAKey, Chain: slices.Clone(r.w.CertChain), IssuerURL: r.w.IssuerURL}
}

// AccessSigningMaterial is the access certificate of the wallet's issuer, the
// demo issuer. The registrar issues it like the access certificate of any
// relying party.
func (w *Wallet) AccessSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.demoAccessSigningMaterial("access", demoIssuer())
}
