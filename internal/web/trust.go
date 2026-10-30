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
	"fmt"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// resolveTrust builds the trust of one validation: the supplied key and
// trusted lists, and the wallet's catalogue and HTTP client.
func resolveTrust(opts ValidateOpts) validate.Trust {
	trust := validate.Trust{CertificateProblems: validate.CRLReader(format.HTTPClient())}
	if !opts.Offline {
		w, err := decoderWallet(opts)
		trust.CatalogueErr = err
		if w != nil {
			trust.Catalogue = w
			trust.HTTPClient = w.HTTPClient()
			trust.CertificateProblems = w.CertificateProblems
		}
	}
	trust.Err = addSuppliedTrust(&trust, opts)
	return trust
}

// decoderWallet returns the running wallet, or the stored one when it exists.
func decoderWallet(opts ValidateOpts) (*wallet.Wallet, error) {
	if opts.Wallet != nil {
		return opts.Wallet, nil
	}
	if opts.WalletStore == nil {
		return nil, nil
	}
	if exists, err := opts.WalletStore.Exists(); err != nil || !exists {
		return nil, err
	}
	w, err := opts.WalletStore.LoadOrCreate()
	if err != nil {
		return nil, fmt.Errorf("loading the wallet: %w", err)
	}
	return w, nil
}

func addSuppliedTrust(trust *validate.Trust, opts ValidateOpts) error {
	if opts.Key != "" {
		key, err := keys.ParsePublicKey([]byte(opts.Key))
		if err != nil {
			return fmt.Errorf("parsing key: %w", err)
		}
		trust.AddKey(key)
	}
	if opts.TrustListRaw != "" {
		if err := trust.AddTrustedList(opts.TrustListRaw, time.Now()); err != nil {
			return err
		}
	}
	if opts.TrustListURL != "" {
		if opts.Offline {
			trust.Supplied, trust.Pending = true, true
			return nil
		}
		// The URL is caller-supplied, and ReadRemoteInput cannot read local files.
		raw, err := format.ReadRemoteInput(opts.TrustListURL, trust.HTTPClient)
		if err != nil {
			return fmt.Errorf("fetching trusted list: %w", err)
		}
		return trust.AddTrustedList(raw, time.Now())
	}
	return nil
}
