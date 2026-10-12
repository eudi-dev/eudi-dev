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

package format

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
)

type policyTransport struct {
	remote    *http.Transport
	remoteDev *http.Transport
	local     *http.Transport
	localDev  *http.Transport
	verify    func() bool
}

// NewHTTPClient sends remote requests through proxy, or through the proxy
// environment variables when proxy is nil. Local requests never use a proxy.
func NewHTTPClient(verify func() bool, roots *x509.CertPool, proxy ProxyFunc) *http.Client {
	remote := newPolicyTransport()
	remote.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	remoteDev := newPolicyTransport()
	if proxy != nil {
		remote.Proxy, remoteDev.Proxy = proxy, proxy
	}
	//nolint:gosec // The caller can explicitly disable TLS verification for development.
	remoteDev.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	local := newLocalPolicyTransport()
	local.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	localDev := newLocalPolicyTransport()
	//nolint:gosec // The caller can explicitly disable TLS verification for development.
	localDev.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout: remoteTimeout,
		Transport: &policyTransport{
			remote: remote, remoteDev: remoteDev, local: local, localDev: localDev, verify: verify,
		},
	}
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	local := netaddr.IsLocal(req.URL.Hostname())
	verify := !local
	if t.verify != nil {
		verify = t.verify()
	}
	if local {
		if verify {
			return t.local.RoundTrip(req)
		}
		return t.localDev.RoundTrip(req)
	}
	if verify {
		return t.remote.RoundTrip(req)
	}
	return t.remoteDev.RoundTrip(req)
}

func (t *policyTransport) CloseIdleConnections() {
	t.remote.CloseIdleConnections()
	t.remoteDev.CloseIdleConnections()
	t.local.CloseIdleConnections()
	t.localDev.CloseIdleConnections()
}

func TLSRoots(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading system TLS roots: %w", err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("TLS CA bundle contains no PEM certificates")
	}
	return roots, nil
}

// IsWebURL reports whether rawURL is an absolute http or https URL with a host.
// url.Parse also accepts javascript: and data: URLs. These must never reach a
// link or a browser.
func IsWebURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}

// SameURL compares scheme, host with its default port, and path. Host and
// scheme are case insensitive (RFC 3986 §6.2.2.1).
func SameURL(u *url.URL, raw string) bool {
	other, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return SameOrigin(u, other) && strings.TrimSuffix(u.Path, "/") == strings.TrimSuffix(other.Path, "/")
}

// SameOrigin compares scheme and host with its default port. Both are case
// insensitive (RFC 3986 §6.2.2.1).
func SameOrigin(u, other *url.URL) bool {
	hostPort := func(v *url.URL) string {
		port := v.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(v.Scheme)]
		}
		return strings.ToLower(v.Hostname()) + ":" + port
	}
	return strings.EqualFold(u.Scheme, other.Scheme) && hostPort(u) == hostPort(other)
}

// ValidateAbsoluteURI accepts an empty value or an absolute http or https
// URI. The error identifies the value by field. Only HTTP and HTTPS redirects are
// safe. url.Parse also treats javascript: and data: URLs as absolute, and
// navigating to them could run script on the wallet's origin.
func ValidateAbsoluteURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("%s must be an absolute URI", field)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("%s must use http or https, got scheme %q", field, u.Scheme)
	}
}
