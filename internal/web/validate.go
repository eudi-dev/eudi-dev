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
	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

// CheckResult is one check of the decoder's validation.
type CheckResult = validate.Check

type ValidateOpts struct {
	Key          string
	TrustListURL string
	TrustListRaw string
	CheckStatus  bool
	// Offline skips network checks and marks them NeedsNetwork. The UI shows
	// offline results first.
	Offline bool
	// WalletStore is a stored wallet. When it exists, its attestation
	// catalogue anchors credentials. The decoder never creates a wallet.
	WalletStore *wallet.WalletStore
	// Wallet is the running wallet, if the decoder runs inside one. It takes
	// precedence over WalletStore.
	Wallet *wallet.Wallet
}

// Validate decodes a credential and adds the checks of validate.Credential as
// its validation.
func Validate(input string, opts ValidateOpts) (map[string]any, error) {
	result, err := validate.Credential(input, resolveTrust(opts), validate.Options{Offline: opts.Offline, Status: opts.CheckStatus})
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	switch result.Format {
	case validate.FormatSDJWT:
		decoded = output.BuildSDJWTJSON(result.SDJWT)
	case validate.FormatJWT:
		decoded = output.BuildJWTJSON(result.SDJWT)
	case validate.FormatMDOC:
		decoded = output.BuildMDOCJSON(result.MDOC)
	}
	decoded["validation"] = map[string]any{"checks": result.Checks}
	return decoded, nil
}

// Decode decodes a credential and validates it offline without a wallet. The
// proxy calls it while it holds a response, so it reads nothing over the
// network.
func Decode(input string) (map[string]any, error) {
	return Validate(input, ValidateOpts{Offline: true})
}
