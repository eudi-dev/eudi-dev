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
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

// A decoder that runs alone uses the default wallet.
func loadLocalWallet(store *wallet.WalletStore) (*wallet.Wallet, error) {
	if store == nil {
		store = wallet.NewWalletStore("")
	}
	return store.LoadOrCreate()
}

// The local CA verifies locally issued credentials without a trust list.
func localWalletTrustAnchors(store *wallet.WalletStore) []trustlist.CertInfo {
	w, err := loadLocalWallet(store)
	if err != nil || w == nil || len(w.CertChain) == 0 {
		return nil
	}
	ca := w.CertChain[len(w.CertChain)-1]
	return []trustlist.CertInfo{{Raw: ca.Raw, PublicKey: ca.PublicKey}}
}

func verifyWithLocalWalletIssuerKey(token *sdjwt.Token, store *wallet.WalletStore) (*sdjwt.VerifyResult, string) {
	if token == nil {
		return nil, ""
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return nil, ""
	}

	w, err := loadLocalWallet(store)
	if err != nil || w == nil || w.IssuerKey == nil {
		return nil, ""
	}
	if mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey) != strings.TrimSpace(kid) {
		return nil, ""
	}

	return sdjwt.Verify(token, &w.IssuerKey.PublicKey), "local wallet issuer key"
}
