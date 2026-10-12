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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

func (s *Server) SetIssuerTLSCertificate(cert tls.Certificate) {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	s.issuerTLSCert = &cert
}

// SetIssuerListenPort accepts a negative port to disable TLS when an external server
// terminates it. Otherwise NewServer derives the port from IssuerURL.
func (s *Server) SetIssuerListenPort(port int) {
	s.issuerPort = port
}

func (s *Server) currentIssuerTLSCertificate() *tls.Certificate {
	s.tlsMu.RLock()
	defer s.tlsMu.RUnlock()
	return s.issuerTLSCert
}

func (s *Server) renewIssuerTLSCertificateIfNeeded(now time.Time) {
	current := s.currentIssuerTLSCertificate()
	if current == nil || len(current.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(current.Certificate[0])
	if err != nil || now.Add(provider.RenewBefore).Before(leaf.NotAfter) {
		return
	}
	caKey, chain := s.wallet.certificateAuthority()
	renewed, err := generateIssuerTLSCertificate(parseIssuerHost(s.wallet.IssuerURL), caKey, caCertificate(chain))
	if err != nil {
		s.log("  ERROR: re-issuing the HTTPS certificate: %v", err)
		return
	}
	s.SetIssuerTLSCertificate(renewed)
	s.log("  Renewed:       HTTPS certificate")
}

// Read the current signing certificate's expiry so renewal updates the published
// value.
func (s *Server) signingKeyExpiry() time.Time {
	if expiry := s.wallet.SigningCertificateExpiry(); !expiry.IsZero() {
		return expiry
	}
	return time.Now().Add(24 * time.Hour)
}

func (s *Server) startIssuerTLSServer() error {
	if s.issuerPort <= 0 || s.issuerSrv != nil {
		return nil
	}

	if s.currentIssuerTLSCertificate() == nil {
		caKey, chain := s.wallet.certificateAuthority()
		cert, err := generateIssuerTLSCertificate(parseIssuerHost(s.wallet.IssuerURL), caKey, caCertificate(chain))
		if err != nil {
			return fmt.Errorf("generating issuer TLS certificate: %w", err)
		}
		s.SetIssuerTLSCertificate(cert)
	}

	ln, err := net.Listen("tcp", netaddr.ListenAddr(s.listenHost, s.issuerPort))
	if err != nil {
		return fmt.Errorf("listening for issuer HTTPS server: %w", err)
	}

	s.issuerSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  config.ServerIdleTimeout,
	}

	go func() {
		tlsListener := tls.NewListener(ln, &tls.Config{
			// Read the certificate for each handshake so renewal takes effect without
			// restarting the listener.
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.currentIssuerTLSCertificate(), nil
			},
			MinVersion: tls.VersionTLS12,
			// RFC 9325 recommends these AEAD ECDHE suites for TLS 1.2 with ECDSA
			// certificates. Go fixes the TLS 1.3 suite list.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		})
		_ = s.issuerSrv.Serve(tlsListener)
	}()

	return nil
}
