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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

func LocalIssuerURL(port int, docker bool) string {
	host := "localhost"
	if docker {
		host = "host.docker.internal"
	}
	return fmt.Sprintf("https://%s:%d", host, port)
}

func IssuerURLFromBaseURL(baseURL string, issuerPort int) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("base URL must include a hostname")
	}
	return (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, strconv.Itoa(issuerPort)),
	}).String(), nil
}

func parseIssuerPort(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			return 443
		}
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return p
}

func parseIssuerHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func buildIssuerSigningJWK(w *Wallet, exp time.Time) map[string]any {
	if w == nil || w.IssuerKey == nil {
		return nil
	}
	jwk := mock.SigningJWKMap(&w.IssuerKey.PublicKey)
	if !exp.IsZero() {
		jwk["exp"] = exp.Unix()
	}
	chain := w.CertChain
	if derived, err := w.DefaultSigningCertChain(); err == nil && len(derived) > 0 {
		chain = derived
	}
	chain = mock.WithoutSelfSignedTrustAnchor(chain)
	if len(chain) > 0 {
		x5c := make([]string, 0, len(chain))
		for _, cert := range chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		jwk["x5c"] = x5c
	}
	return jwk
}

func generateIssuerTLSCertificate(serverName string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (tls.Certificate, error) {
	certPEM, keyPEM, err := generateIssuerTLSCertificatePEMWithCA(serverName, caKey, caCert)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading TLS certificate: %w", err)
	}
	return cert, nil
}

func generateIssuerTLSCertificatePEMWithCA(serverName string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating TLS key: %w", err)
	}
	return issuerTLSCertificatePEM(serverName, key, caKey, caCert)
}

func issuerTLSCertificatePEM(serverName string, key *ecdsa.PrivateKey, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) ([]byte, []byte, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generating TLS serial: %w", err)
	}
	if serverName == "" {
		serverName = "localhost"
	}
	dnsNames := []string{"localhost", "host.docker.internal"}
	if serverName != "localhost" && serverName != "host.docker.internal" {
		dnsNames = append(dnsNames, serverName)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	parent := tmpl
	signer := any(key)
	if caKey != nil && caCert != nil {
		parent = caCert
		signer = caKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("creating TLS certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if caCert != nil {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding TLS private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
