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

package cmd

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/netaddr"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
	"github.com/dominikschlosser/eudi-dev/v3/internal/remote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

type dispatchOID4Opts struct {
	port              int
	portExplicit      bool
	autoAccept        bool
	sessionTranscript string
	txCode            string
	// conformance is what the conformance flags set. conformanceFlags names
	// the flags set on the command line. A running wallet refuses the ones
	// that differ from its own settings.
	conformance      walletConformance
	conformanceFlags []string
	// docker serves the presentation trust and status lists under
	// host.docker.internal. A verifier in a container can reach them there, and
	// the status list token subject matches the URI in the credential.
	docker bool
	// resolvedOffer holds the offer read for the transaction code prompt.
	// Issuance uses it when reading the URI again fails.
	resolvedOffer *oid4vc.CredentialOffer
}

func dispatchURI(uri string, opts dispatchOID4Opts) error {
	detected := format.Detect(uri)

	switch detected {
	case format.FormatOID4VP:
		w, store, err := loadWallet()
		if err != nil {
			return err
		}
		opts.conformance.apply(w)
		if opts.autoAccept {
			w.AutoAccept = true
		}
		if err := applySessionTranscriptMode(w, opts.sessionTranscript); err != nil {
			return err
		}
		if err := w.EnsureRequestEncryptionKey(); err != nil {
			return err
		}
		port, err := resolvePresentationPort(opts.port, opts.autoAccept, opts.portExplicit)
		if err != nil {
			return err
		}
		return runPresent(w, store, uri, port, opts.docker)

	case format.FormatOID4VCI:
		return processCredentialOffer(uri, opts)

	default:
		return fmt.Errorf("unable to detect URI type (expected openid4vp://, openid-credential-offer://, or similar): %s", format.Truncate(uri, 80))
	}
}

// runPresent answers a presentation request on a local wallet server. The
// request takes the flow of POST /api/presentations, the one every entry
// point uses (ADR-0012). The server also serves the trusted list the verifier
// reads and the consent dialog.
func runPresent(w *wallet.Wallet, store *wallet.WalletStore, uri string, port int, docker bool) error {
	setLocalPresentationIssuerURL(w, port, docker)
	srv := wallet.NewServer(w, port, nil)
	if err := configureIssuerTLSCertificate(srv, store, w.IssuerURL); err != nil {
		return err
	}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}
	defer srv.Shutdown()

	dim := color.New(color.Faint)
	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")
	fmt.Fprintf(humanOut(), "  Trusted list: %s/api/trustlist\n", addr)
	dim.Fprintf(humanOut(), "               http://host.docker.internal:%d/api/trustlist\n", port)

	c := remote.NewClient(addr)
	interactive := !w.AutoAccept
	if interactive {
		fmt.Fprintf(humanOut(), "  Consent UI: %s\n", addr)
		enlistBrowser(c)
	}
	result, err := c.Present(uri, interactive, "")
	if saveErr := store.Save(w); saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", saveErr)
	}
	if err != nil {
		return err
	}
	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")
	printPresentationResult(result, interactive)
	return remoteFlowError(result)
}

// printPresentationResult reports the outcome. With --json, stdout carries
// only the document (ADR 0020).
func printPresentationResult(result map[string]any, browserWaiting bool) {
	if jsonOutput {
		output.PrintJSON(result)
		return
	}
	status, _ := result["status"].(string)
	if response, ok := result["response"].(map[string]any); ok {
		if code, _ := response["status_code"].(float64); code > 0 {
			fmt.Fprintf(humanOut(), "  %s: HTTP %d\n", status, int(code))
		}
	} else {
		fmt.Fprintf(humanOut(), "  %s\n", status)
	}
	redirectURI, _ := result["redirect_uri"].(string)
	followVerifierRedirect(redirectURI, browserWaiting)
}

func setLocalPresentationIssuerURL(w *wallet.Wallet, port int, docker bool) {
	origin, _ := walletOrigin(effectivePresentationPort(port), "", docker)
	w.OverrideURLs(w.BaseURL, origin.Issuer)
}

func resolvePresentationPort(port int, autoAccept bool, portExplicit bool) (int, error) {
	port = effectivePresentationPort(port)

	if presentationPortPairAvailable(port) {
		return port, nil
	}

	if !portExplicit {
		fallbackPort, err := findFreePresentationPortPair(port + 1)
		if err != nil {
			return 0, err
		}
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(humanOut(), "  Note: port %d/%d is already in use (using temporary port %d)\n", port, port+1, fallbackPort)
		return fallbackPort, nil
	}

	if !autoAccept {
		return port, nil
	}

	fallbackPort, err := findFreePresentationPortPair(port + 1)
	if err != nil {
		return 0, fmt.Errorf("resolving temporary auto-accept port after %d was busy: %w", port, err)
	}
	yellow := color.New(color.FgYellow)
	yellow.Fprintf(humanOut(), "  Note: port %d is already in use (auto-accept uses temporary port %d)\n", port, fallbackPort)
	return fallbackPort, nil
}

func presentationPortPairAvailable(port int) bool {
	return portFree(port) && portFree(port+1)
}

// portFree checks the wildcard address the wallet server binds and the
// loopback address. Either bind can succeed while another server holds the
// other one.
func portFree(port int) bool {
	for _, host := range []string{"", "127.0.0.1"} {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return false
		}
		_ = ln.Close()
	}
	return true
}

func findFreePresentationPortPair(start int) (int, error) {
	for candidate := start; candidate <= start+100; candidate++ {
		if presentationPortPairAvailable(candidate) {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("could not find free adjacent presentation ports near %d", start)
}

func registeredWalletListenerBaseURL() string {
	raw, err := os.ReadFile(filepath.Join(config.BaseDir(), "url-handler.sh"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "LISTENER=") {
			continue
		}
		value := strings.TrimPrefix(line, "LISTENER=")
		value = strings.Trim(value, `"'`)
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			return value
		}
	}
	return ""
}

func registeredWalletListenerPort() int {
	raw := registeredWalletListenerBaseURL()
	if raw == "" {
		return 0
	}
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return port
}

func defaultWalletCommandPort() int {
	if port := registeredWalletListenerPort(); port > 0 {
		return port
	}
	return config.DefaultWalletPort
}

func walletPortFromBaseURL(raw string) int {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return port
}

// A Docker hostname may be intentional. Only realign localhost issuer URLs to the
// registered listener.
func isLocalhostIssuerURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && netaddr.IsLoopback(u.Hostname())
}

func effectivePresentationPort(port int) int {
	if port > 0 {
		return port
	}
	return config.DefaultWalletPort
}

func processCredentialOffer(uri string, opts dispatchOID4Opts) error {
	w, store, err := loadWallet()
	if err != nil {
		return err
	}
	opts.conformance.apply(w)

	result, err := w.ProcessCredentialOfferWithOptions(uri, wallet.OfferOptions{TxCode: opts.txCode, ResolvedOffer: opts.resolvedOffer})
	if err != nil {
		return fmt.Errorf("processing credential offer: %w", err)
	}

	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}

	printIssuanceResult(result)
	return nil
}

// printIssuanceResult reports a one-shot issuance. With --json, stdout carries
// only the result (ADR 0020).
func printIssuanceResult(result *wallet.IssuanceResult) {
	if result.Pending {
		// Without a wallet server nothing collects a deferred credential
		// later, so say so.
		fmt.Fprintf(humanOut(), "Issuer %s deferred the credential (transaction %s, retry every %s)\n",
			result.Issuer, result.TransactionID, result.RetryInterval)
		fmt.Fprintln(humanOut(), "Run 'eudi wallet serve' and accept the offer there to have the wallet collect it in the background.")
	} else {
		fmt.Fprintf(humanOut(), "Received %s credential from %s (ID: %s)\n", result.Format, result.Issuer, result.CredentialID)
		if result.VerificationDetail != "" {
			fmt.Fprintf(humanOut(), "Verification: %s", result.VerificationDetail)
			if result.VerificationStatus != "" {
				fmt.Fprintf(humanOut(), " [%s]", result.VerificationStatus)
			}
			fmt.Fprintln(humanOut())
		}
	}
	if jsonOutput {
		output.PrintJSON(result)
	}
}

// OpenID4VP 1.0 section 8.2 returns the browser to the verifier. Print the redirect
// URL, but open it only for an interactive CLI when the consent tab is not already
// navigating there.
func followVerifierRedirect(redirectURI string, browserWaiting bool) {
	if redirectURI == "" {
		return
	}
	fmt.Fprintf(humanOut(), "  Continue at: %s\n", redirectURI)
	if stdinIsTerminal() && navigatesHere(browserWaiting) {
		openBrowser(redirectURI)
	}
}

// Navigate only when no browser tab owns the flow. PAR request_uri values can be used
// once (RFC 9126 §4), and verifier redirect sessions are consumed after use (OpenID4VP
// 1.0 §13.3, steps 7 to 10). A second navigation can fail.
func navigatesHere(browserWaiting bool) bool {
	return !noOpen && !browserWaiting
}

// loadPEMCertificates reads the PEM files of a CA flag into one bundle.
func loadPEMCertificates(flag string, paths []string) ([]byte, error) {
	var bundle []byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading --%s: %w", flag, err)
		}
		if _, err := keys.ParseCertificatesPEM(data); err != nil {
			return nil, fmt.Errorf("--%s %s: %w", flag, path, err)
		}
		bundle = append(append(bundle, data...), '\n')
	}
	return bundle, nil
}
