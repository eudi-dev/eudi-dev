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
	"crypto/x509"
	"net/http"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

func (w *Wallet) TLSVerification() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.tlsVerificationLocked()
}

func (w *Wallet) tlsVerificationLocked() bool {
	if w.TLSVerify != nil {
		return *w.TLSVerify
	}
	return w.ValidationMode == ValidationModeStrict
}

// OutboundConfig sets how the wallet reaches issuers and verifiers. A nil TLSVerify
// follows the validation mode. A nil Proxy uses the proxy environment variables.
type OutboundConfig struct {
	TLSVerify *bool
	TLSCAPEM  []byte
	Proxy     format.ProxyFunc
}

func (w *Wallet) ConfigureOutbound(cfg OutboundConfig) error {
	if _, err := format.TLSRoots(cfg.TLSCAPEM); err != nil {
		return err
	}
	var override *bool
	if cfg.TLSVerify != nil {
		value := *cfg.TLSVerify
		override = &value
	}
	w.mu.Lock()
	previous := w.outboundHTTP
	w.TLSVerify, w.outbound, w.outboundHTTP = override, cfg, nil
	w.mu.Unlock()
	if previous != nil {
		previous.CloseIdleConnections()
	}
	return nil
}

func (w *Wallet) HTTPClient() *http.Client {
	if w == nil {
		return format.HTTPClient()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.outboundHTTP == nil {
		roots := outboundRoots(w.outbound.TLSCAPEM, caCertificate(w.CertChain))
		w.outboundHTTP = format.NewHTTPClient(w.TLSVerification, roots, w.outbound.Proxy)
	}
	return w.outboundHTTP
}

// outboundRoots trusts the system roots, the --tls-ca bundle and the wallet
// CA. The wallet CA signs the certificate of the wallet's own HTTPS listener.
// It serves the status lists of the wallet's credentials, and the demo
// verifier fetches them. ConfigureOutbound has checked the bundle.
func outboundRoots(bundle []byte, ca *x509.Certificate) *x509.CertPool {
	roots, _ := format.TLSRoots(bundle)
	if ca == nil {
		return roots
	}
	if roots == nil {
		system, err := x509.SystemCertPool()
		if err != nil {
			return nil
		}
		roots = system
	}
	roots.AddCert(ca)
	return roots
}
