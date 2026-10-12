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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/demorp"
	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/imprint"
	"github.com/eudi-dev/eudi-dev/v2/internal/news"
	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
	"github.com/eudi-dev/eudi-dev/v2/internal/serverlog"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v2/internal/web"
)

type walletServeOptions struct {
	Port                    int
	AutoAccept              bool
	CredFiles               []string
	PID                     bool
	KeyPath                 string
	IssuerKey               string
	SessionTranscript       string
	Register                bool
	NoRegister              bool
	StatusList              bool
	BaseURL                 string
	Docker                  bool
	PreferredFormat         string
	KeyAttestationLevel     string
	RequireEncryptedRequest bool
	HAIP                    bool
	VCIVersion              string
	ClientAttestation       bool
	AdhocDisplayImages      bool
	DemoIssuerClientAuth    string
	VCIClientID             string
	VCIRedirectURI          string
	Demo                    bool
	DemoReset               string
	ImprintFile             string
	NewsFile                string
	Detached                bool
	ServeTLS                bool
	DemoVerifierTrust       []string
	LogFormat               string
	AllowPrivateNetworks    bool
}

func walletServeCmd() *cobra.Command {
	cmd, _ := walletServeCmdWithOptions()
	return cmd
}

// Return the options so tests exercise the same flag parsing and demo defaults as the
// command.
func walletServeCmdWithOptions() (*cobra.Command, *walletServeOptions) {
	var opts walletServeOptions

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling",
		Long: `Start a persistent wallet server with a web UI for managing credentials and handling OID4VP/OID4VCI flows.

Capabilities:
  - Web UI for credential management, issuing, and consent
  - OID4VP authorization endpoint (/authorize)
  - Legacy PID-first trust list endpoint (/api/trustlist)
  - Trust-list index endpoint (/api/trustlists)
  - Request logging with timestamps
  - Browser-based consent UI for incoming requests

Use --register to also register OS URL scheme handlers (openid4vp://, eudi-openid4vp://, haip-vp://, openid-credential-offer://, haip-vci://, eu-eaa-offer://)
so the wallet automatically receives incoming protocol requests.

Every flag can also be set as EUDI_DEV_<FLAG>, such as EUDI_DEV_BASE_URL for --base-url. A flag on the command line wins.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := applyServeFlagEnv(cmd, &opts); err != nil {
				return err
			}
			// The root command applies --no-color before the environment is read.
			applyNoColor()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWalletServe(cmd, &opts)
		},
	}

	cmd.Flags().IntVar(&opts.Port, "port", config.DefaultWalletPort, "Wallet server port")
	cmd.Flags().BoolVar(&opts.AutoAccept, "auto-accept", false, "Headless mode: auto-accept presentations and credential offers. With --demo it counts only on the command line and EUDI_DEV_AUTO_ACCEPT is ignored")
	cmd.Flags().StringSliceVar(&opts.CredFiles, "credential", nil, "Import credential from file (repeatable)")
	cmd.Flags().BoolVar(&opts.PID, "pid", false, "Auto-generate default EUDI PID credentials (SD-JWT + mdoc)")
	cmd.Flags().StringVar(&opts.KeyPath, "key", "", "Holder private key file (PEM/JWK). Uses the stored key or auto-generates one if omitted")
	cmd.Flags().StringVar(&opts.IssuerKey, "issuer-key", "", "Issuer key for generated credentials (PEM/JWK)")
	cmd.Flags().StringVar(&opts.SessionTranscript, "session-transcript", "oid4vp", "mdoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().BoolVar(&opts.Register, "register", false, "Register OS URL scheme handlers (openid4vp://, eudi-openid4vp://, haip-vp://, openid-credential-offer://, haip-vci://, eu-eaa-offer://)")
	cmd.Flags().BoolVar(&opts.NoRegister, "no-register", false, "Skip URL scheme registration (overrides --register)")
	cmd.Flags().BoolVar(&opts.StatusList, "status-list", false, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&opts.BaseURL, "base-url", "", "Public URL of the wallet's HTTP endpoints, optionally with a path prefix such as https://example.com/eudi (its host is also reused for HTTPS wallet endpoints)")
	cmd.Flags().BoolVar(&opts.Docker, "docker", false, "Use host.docker.internal instead of localhost for both HTTP and HTTPS wallet endpoint URLs")
	cmd.Flags().StringVar(&opts.PreferredFormat, "preferred-format", "", "Preferred credential format when multiple match: 'dc+sd-jwt', 'mso_mdoc', or 'jwt_vc_json'")
	cmd.Flags().StringVar(&opts.KeyAttestationLevel, "key-attestation-level", "", "What the key attestation claims as key_storage and user_authentication (OpenID4VCI Appendix D.2): whatever the issuer requires (default), 'none', or one of iso_18045_high, iso_18045_moderate, iso_18045_enhanced-basic, iso_18045_basic for both. The wallet holds its keys in files and can prove none of them")
	cmd.Flags().BoolVar(&opts.RequireEncryptedRequest, "require-encrypted-request", false, "Reject a Verifier's Request Object that is not encrypted (the wallet always sends an encryption key in wallet_metadata, so this only requires the Verifier to use it)")
	cmd.Flags().BoolVar(&opts.ClientAttestation, "client-attestation", false, "Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise attest_jwt_client_auth (advertising it is only a SHOULD)")
	cmd.Flags().BoolVar(&opts.HAIP, "haip", false, "Enforce HAIP 1.0 on presentations (x509_hash, direct_post.jwt, DCQL, JAR, ES256) and on credential offers (https issuer, and authorization code offers also need PAR, PKCE S256, DPoP, client auth)")
	cmd.Flags().BoolVar(&opts.AdhocDisplayImages, "adhoc-display-images", false, "Keep an issuer's https display image URL and let the card fetch it on demand instead of fetching once and storing the image (nothing is stored but the issuer sees each render, while a data URI, template art, and http URLs are still embedded)")
	cmd.Flags().StringVar(&opts.VCIVersion, "vci-version", string(wallet.VCIVersion10), "OpenID4VCI feature level the wallet uses as a client: '1.0' (the published version, the default) or '1.1' (also uses what the 1.1 draft adds, where an issuer offers it)")
	cmd.Flags().StringVar(&opts.DemoIssuerClientAuth, "demo-issuer-client-auth", string(demorp.ClientAuthRequired), "What the demo issuer's authorization server demands at its PAR and token endpoints: 'required' (HAIP 1.0 §4.4.1, the default) or 'optional' (also serves wallets that send no wallet attestation, for testing against them)")
	cmd.Flags().StringVar(&opts.VCIClientID, "vci-client-id", "", "Client ID the wallet should use for OID4VCI authorization-code flows")
	cmd.Flags().StringVar(&opts.VCIRedirectURI, "vci-redirect-uri", "", "Redirect URI the wallet should use for OID4VCI authorization-code flows")
	cmd.Flags().BoolVar(&opts.Demo, "demo", false, "Public demo profile: implies --pid, --mode debug, --haip and --vci-version 1.1 (all overridable), disables process/filesystem endpoints, blocks fetches to internal networks unless --allow-private-networks is set. Auto-accepts only with --auto-accept on the command line")
	cmd.Flags().BoolVar(&opts.AllowPrivateNetworks, "allow-private-networks", false, "Let --demo reach private networks and loopback, for a demo on a local machine or test network. Without --demo the wallet reaches every address, so the flag changes nothing")
	cmd.Flags().StringVar(&opts.DemoReset, "demo-reset", "1h", "When to restore the clean demo baseline: an interval (24h), a daily wall-clock time (00:00), or one with a timezone (\"00:00 Europe/Berlin\"). 0 disables. Requires --demo")
	cmd.Flags().StringVar(&opts.ImprintFile, "imprint-file", "", "HTML snippet with the site operator's legal notice, served at /imprint (required for public EU hosting)")
	cmd.Flags().StringVar(&opts.NewsFile, "news-file", "", "HTML snippet with news for visitors of a public demo, shown once in a popup and again from the footer link. Requires --demo")
	cmd.Flags().BoolVar(&opts.ServeTLS, "serve-tls", false, "Serve an https --base-url locally with the wallet's own TLS certificate instead of expecting an external TLS terminator in front (the HTTP port stays bound as well)")
	cmd.Flags().StringArrayVar(&opts.DemoVerifierTrust, "demo-verifier-trust-anchor", nil, "CA certificate PEM file the demo verifier accepts issuer chains under, next to the wallet's own CA (repeatable). For presentations issued outside this wallet, such as an OIDF conformance suite run")
	cmd.Flags().StringVar(&opts.LogFormat, "log-format", "", "Console output format: 'text' (the default) or 'json' (one JSON record per line on stdout, for log collectors)")
	cmd.Flags().BoolVarP(&opts.Detached, "detached", "d", false, "Run the server as a background process and return once it responds. Output goes to <wallet-dir>/serve.log")
	return cmd, &opts
}

func validateServeTLSBaseURL(baseURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("requires an https --base-url with an explicit port, got %q", baseURL)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("requires an https --base-url, got %q", baseURL)
	}
	if parsed.Port() == "" {
		return fmt.Errorf("requires an explicit port in --base-url so the TLS listener knows where to bind, got %q", baseURL)
	}
	return nil
}

func loadVerifierTrustAnchors(paths []string) ([]*x509.Certificate, error) {
	var anchors []*x509.Certificate
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		found := 0
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			anchors = append(anchors, cert)
			found++
		}
		if found == 0 {
			return nil, fmt.Errorf("%s holds no PEM certificate", path)
		}
	}
	return anchors, nil
}

// applyServeFlagEnv sets the flags missing from the command line from the
// environment. A public demo auto-accepts only when --auto-accept is on the
// command line, so the image default EUDI_DEV_AUTO_ACCEPT=true keeps a demo
// asking for consent.
func applyServeFlagEnv(cmd *cobra.Command, opts *walletServeOptions) error {
	autoAcceptGiven := cmd.Flags().Changed("auto-accept")
	if err := applyFlagEnv(cmd.Flags()); err != nil {
		return err
	}
	if opts.Demo && !autoAcceptGiven {
		opts.AutoAccept = false
		cmd.Flags().Lookup("auto-accept").Changed = false
	}
	return nil
}

// demoWarnings names the demo settings that do not belong on a public host.
func demoWarnings(opts *walletServeOptions) []string {
	if !opts.Demo {
		return nil
	}
	var warnings []string
	if opts.AllowPrivateNetworks {
		warnings = append(warnings, "--allow-private-networks lets the public demo reach local and private addresses. Keep it off on a public host.")
	}
	if opts.AutoAccept {
		warnings = append(warnings, "--auto-accept lets the public demo accept every presentation and credential offer without consent. Keep it off on a public host.")
	}
	return warnings
}

// Apply demo defaults only where the user has not supplied an explicit flag.
func applyDemoProfileDefaults(cmd *cobra.Command, opts *walletServeOptions, w *wallet.Wallet) {
	if !cmd.Flags().Changed("pid") {
		opts.PID = true
	}
	if !cmd.Flags().Changed("mode") {
		w.ValidationMode = wallet.ValidationModeDebug
	}
	if !cmd.Flags().Changed("haip") {
		opts.HAIP = true
	}
	if !cmd.Flags().Changed("vci-version") {
		opts.VCIVersion = string(wallet.VCIVersion11)
	}
}

// servingConfigWarnings flags persisted serving config that cannot work in
// the current environment and credentials whose embedded URLs this server
// does not serve. Both situations come from serving config that changed
// after the URLs were persisted or issued.
func servingConfigWarnings(w *wallet.Wallet, port int, docker bool) []string {
	var warnings []string

	if !docker && !runningInDocker() {
		for _, u := range []string{w.BaseURL, w.IssuerURL} {
			if strings.Contains(u, "host.docker.internal") {
				warnings = append(warnings,
					fmt.Sprintf("%s uses a Docker hostname but this server does not run in Docker (start with --base-url or --docker to change it)", u))
				break
			}
		}
	}

	served := map[string]bool{
		fmt.Sprintf("localhost:%d", port):            true,
		fmt.Sprintf("127.0.0.1:%d", port):            true,
		fmt.Sprintf("host.docker.internal:%d", port): true,
	}
	for _, u := range []string{w.BaseURL, w.IssuerURL} {
		if hp := urlHostPort(u); hp != "" {
			served[hp] = true
		}
	}

	var stale []string
	for _, c := range w.GetCredentials() {
		mismatch := false
		if ref := wallet.CredentialStatusRef(c); ref != nil {
			if hp := urlHostPort(ref.URI); hp != "" && isLocalTestHostPort(hp) && !served[hp] {
				mismatch = true
			}
		}
		if iss, ok := c.Claims["iss"].(string); ok {
			if hp := urlHostPort(iss); hp != "" && isLocalTestHostPort(hp) && !served[hp] {
				mismatch = true
			}
		}
		if mismatch {
			stale = append(stale, credLabel(c))
		}
	}
	if len(stale) > 0 {
		warnings = append(warnings,
			fmt.Sprintf("%d credential(s) embed issuer or status list URLs this server does not serve (%s). Validation and status checks fail for them until they are issued again.", len(stale), strings.Join(stale, ", ")))
	}
	return warnings
}

func urlHostPort(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// isLocalTestHostPort reports whether the host is one this tool generates
// URLs for. Foreign issuers keep their own URLs and are never flagged.
func isLocalTestHostPort(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	switch host {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal":
		return true
	}
	return false
}

func runningInDocker() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func serializeWalletServeArgs(cmd *cobra.Command) ([]string, error) {
	args := []string{}
	// The flag set holds the persistent flags of the parents too. The seed
	// is a secret and travels in the environment.
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		switch flag.Name {
		case "register", "no-register", "detached", "seed":
			return
		}
		if values, ok := flag.Value.(pflag.SliceValue); ok {
			for _, value := range values.GetSlice() {
				args = append(args, "--"+flag.Name, value)
			}
			return
		}
		if flag.Value.Type() == "bool" {
			// Use --name=value to preserve explicit false values such as --haip=false
			// when starting the child.
			args = append(args, "--"+flag.Name+"="+flag.Value.String())
			return
		}
		args = append(args, "--"+flag.Name, flag.Value.String())
	})
	return args, nil
}

// demoFetchPolicy limits the outbound connections of a public demo to public
// addresses. The demo must still reach its own issuer and verifier, so the
// origins stay allowed at their exact address and port. Outside --demo, and
// with --allow-private-networks, the wallet reaches every address.
func demoFetchPolicy(opts *walletServeOptions, ownOrigins ...string) format.FetchPolicy {
	if !opts.Demo || opts.AllowPrivateNetworks {
		return nil
	}
	return format.AllowOwnOrigins(format.BlockPrivateAddresses, ownOrigins...)
}

// parseDemoReset interprets the --demo-reset value: a duration ("24h", "0"),
// a daily wall-clock time ("00:00"), or one with an explicit zone
// ("00:00 Europe/Berlin"). A wall-clock schedule resets at the same local time
// every day, independent of process restarts.
func parseDemoReset(value string) (wallet.DemoOptions, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return wallet.DemoOptions{}, nil
	}
	if strings.Contains(value, ":") {
		schedule, err := wallet.ParseDailySchedule(value)
		if err != nil {
			return wallet.DemoOptions{}, err
		}
		return wallet.DemoOptions{ResetDaily: schedule}, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil {
		return wallet.DemoOptions{}, err
	}
	if interval < 0 {
		return wallet.DemoOptions{}, fmt.Errorf("interval must not be negative")
	}
	return wallet.DemoOptions{ResetInterval: interval}, nil
}

func demoResetDescription(opts wallet.DemoOptions) string {
	switch {
	case opts.ResetDaily != nil:
		return fmt.Sprintf("resets daily at %s", opts.ResetDaily)
	case opts.ResetInterval > 0:
		return fmt.Sprintf("resets every %s", opts.ResetInterval)
	default:
		return ""
	}
}

func runWalletServe(cmd *cobra.Command, opts *walletServeOptions) error {
	if opts.Detached {
		return spawnDetachedServe(cmd, opts.Port, opts.Register, opts.NoRegister)
	}
	logFormat, err := serverlog.ParseFormat(opts.LogFormat)
	if err != nil {
		return fmt.Errorf("--log-format: %w", err)
	}
	if logFormat == serverlog.FormatJSON {
		restore, err := serverlog.RedirectProcessOutput(os.Stdout)
		if err != nil {
			return err
		}
		defer restore()
	}
	clientAuthMode, err := demorp.ParseClientAuthMode(opts.DemoIssuerClientAuth)
	if err != nil {
		return fmt.Errorf("--demo-issuer-client-auth: %w", err)
	}
	if opts.ServeTLS {
		if err := validateServeTLSBaseURL(opts.BaseURL); err != nil {
			return fmt.Errorf("--serve-tls: %w", err)
		}
	}
	verifierTrustAnchors, err := loadVerifierTrustAnchors(opts.DemoVerifierTrust)
	if err != nil {
		return fmt.Errorf("--demo-verifier-trust-anchor: %w", err)
	}
	store, err := openStore()
	if err != nil {
		return err
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}
	if templatesDir != "" {
		w.Templates = credtemplate.FileLocation(templatesDir)
	}
	if err := applyValidationMode(w, walletValidationMode); err != nil {
		return err
	}
	if err := applyWalletOutbound(w); err != nil {
		return err
	}

	if opts.KeyPath != "" {
		holderKey, err := loadWalletECKey(opts.KeyPath, "holder")
		if err != nil {
			return err
		}
		w.HolderKey = holderKey
	}
	if opts.IssuerKey != "" {
		ik, err := loadWalletECKey(opts.IssuerKey, "issuer")
		if err != nil {
			return err
		}
		w.IssuerKey = ik
	}

	if cmd.Flags().Changed("demo-reset") && !opts.Demo {
		return fmt.Errorf("--demo-reset requires --demo")
	}
	if opts.NewsFile != "" && !opts.Demo {
		return fmt.Errorf("--news-file requires --demo")
	}
	demoOpts, err := parseDemoReset(opts.DemoReset)
	if err != nil {
		return fmt.Errorf("invalid --demo-reset %q: %w", opts.DemoReset, err)
	}
	if opts.Demo {
		applyDemoProfileDefaults(cmd, opts, w)
	}

	if opts.AutoAccept {
		w.AutoAccept = true
	}

	if err := applySessionTranscriptMode(w, opts.SessionTranscript); err != nil {
		return err
	}

	if err := applyVCIVersion(w, opts.VCIVersion); err != nil {
		return fmt.Errorf("--vci-version: %w", err)
	}

	if opts.PreferredFormat != "" {
		w.PreferredFormat = opts.PreferredFormat
	}
	if w.KeyAttestationLevel, err = wallet.ParseKeyAttestationLevel(opts.KeyAttestationLevel); err != nil {
		return fmt.Errorf("--key-attestation-level: %w", err)
	}

	// Always hold a request object encryption key so wallet_metadata can offer
	// it. --require-encrypted-request decides whether the Verifier must use it.
	if err := w.EnsureRequestEncryptionKey(); err != nil {
		return err
	}
	w.RequireEncryptedRequest = opts.RequireEncryptedRequest

	if opts.HAIP {
		w.RequireHAIP = true
	}
	if opts.AdhocDisplayImages {
		w.AdhocDisplayImages = true
	}
	if opts.ClientAttestation {
		w.ForceClientAttestation = true
	}
	if opts.VCIClientID != "" {
		w.VCIClientID = opts.VCIClientID
	}
	if opts.VCIRedirectURI != "" {
		w.VCIRedirectURI = opts.VCIRedirectURI
	}

	if cmd.Flags().Changed("base-url") {
		w.BaseURL = opts.BaseURL
	} else if opts.StatusList && strings.TrimSpace(w.BaseURL) == "" {
		if opts.BaseURL == "" {
			if opts.Docker {
				opts.BaseURL = fmt.Sprintf("http://host.docker.internal:%d", opts.Port)
			} else {
				opts.BaseURL = fmt.Sprintf("http://localhost:%d", opts.Port)
			}
		}
		w.BaseURL = opts.BaseURL
	}

	if cmd.Flags().Changed("base-url") || cmd.Flags().Changed("docker") || strings.TrimSpace(w.IssuerURL) == "" {
		issuerBaseURL := opts.BaseURL
		if issuerBaseURL == "" && cmd.Flags().Changed("base-url") {
			issuerBaseURL = w.BaseURL
		}
		w.IssuerURL, err = deriveWalletIssuerURL(opts.Port, issuerBaseURL, opts.Docker)
		if err != nil {
			return err
		}
	}

	// Default the client ID and callback URI to this wallet's origin so authorization
	// code offers work without extra flags. Both are required before PAR, where the
	// wallet first sends its attestation.
	{
		base := strings.TrimRight(strings.TrimSpace(w.BaseURL), "/")
		if base == "" {
			if opts.Docker {
				base = fmt.Sprintf("http://host.docker.internal:%d", opts.Port)
			} else {
				base = fmt.Sprintf("http://localhost:%d", opts.Port)
			}
		}
		if w.VCIClientID == "" {
			w.VCIClientID = base
		}
		if w.VCIRedirectURI == "" {
			w.VCIRedirectURI = base + "/callback"
		}
		w.ServingOrigin = base
	}

	// Install the address exceptions after resolving the serving URLs.
	if policy := demoFetchPolicy(opts, w.BaseURL, w.IssuerURL, fmt.Sprintf("http://localhost:%d", opts.Port)); policy != nil {
		format.SetFetchPolicy(policy)
	}

	if opts.PID {
		// In demo mode the generated PIDs are the shared baseline and
		// must survive whatever visitors do to the wallet.
		generate := w.GenerateDefaultCredentials
		if opts.Demo {
			generate = func(map[string]any, string) error { return w.GenerateProtectedDefaults() }
		}
		if err := generate(nil, ""); err != nil {
			return fmt.Errorf("generating PID credentials: %w", err)
		}
		if err := store.Save(w); err != nil {
			return fmt.Errorf("saving wallet: %w", err)
		}
	}

	for _, path := range opts.CredFiles {
		if err := w.ImportCredentialFromFile(path); err != nil {
			return fmt.Errorf("importing credential %s: %w", path, err)
		}
	}
	if len(opts.CredFiles) > 0 {
		if err := store.Save(w); err != nil {
			return fmt.Errorf("saving wallet: %w", err)
		}
	}

	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)
	yellow := color.New(color.FgYellow)
	publicHTTPURL := fmt.Sprintf("http://localhost:%d", opts.Port)
	if opts.BaseURL != "" {
		publicHTTPURL = opts.BaseURL
	} else if opts.Docker {
		publicHTTPURL = fmt.Sprintf("http://host.docker.internal:%d", opts.Port)
	}
	httpsURL := w.IssuerURL
	issuerViaBaseURL := issuerServedByBaseURL(w.IssuerURL, w.BaseURL)

	cyan.Printf("EUDI Dev Wallet %s\n", Version)
	dim.Println("───────────────────────────────────────")
	fmt.Printf("  Server:      http://localhost:%d\n", opts.Port)
	if publicHTTPURL != fmt.Sprintf("http://localhost:%d", opts.Port) {
		dim.Printf("               %s\n", publicHTTPURL)
	}
	if issuerViaBaseURL {
		fmt.Printf("  Issuer:      %s (served via base URL, external TLS)\n", httpsURL)
		fmt.Printf("  Authorize:   %s/authorize\n", publicHTTPURL)
		fmt.Printf("  Trust List:  %s/api/trustlist\n", publicHTTPURL)
		fmt.Printf("  Trust Lists: %s/api/trustlists\n", publicHTTPURL)
	} else {
		fmt.Printf("  HTTPS:       %s\n", httpsURL)
		fmt.Printf("  Authorize:   %s/authorize\n", publicHTTPURL)
		dim.Printf("               %s/authorize\n", httpsURL)
		fmt.Printf("  Trust List:  %s/api/trustlist\n", publicHTTPURL)
		dim.Printf("               %s/api/trustlist\n", httpsURL)
		fmt.Printf("  Trust Lists: %s/api/trustlists\n", publicHTTPURL)
		dim.Printf("               %s/api/trustlists\n", httpsURL)
	}
	fmt.Printf("  Metadata:    %s/.well-known/jwt-vc-issuer\n", httpsURL)
	fmt.Printf("  Credentials: %d loaded\n", len(w.GetCredentials()))
	fmt.Printf("  Storage:     %s\n", store.Location())
	if source := store.SeedSource(); source != "" {
		fmt.Printf("  Keys:        derived from the %s\n", source)
	}
	if store.SeedSource() == wallet.BuiltInSeedSource && (opts.Demo || store.Backend().Kind() != storage.KindMemory) {
		fmt.Fprintln(os.Stderr, "warning: the keys derive from the public seed eudi-dev. Anyone can derive this wallet's CA. Set EUDI_DEV_SEED to a secret, or to an empty value for random keys.")
	}
	for _, warning := range demoWarnings(opts) {
		fmt.Fprintln(os.Stderr, "warning: "+warning)
	}
	fmt.Printf("  Validation:  %s\n", w.ValidationMode)
	if opts.Demo {
		details := []string{"admin API disabled"}
		if schedule := demoResetDescription(demoOpts); schedule != "" {
			details = append(details, schedule)
		}
		if w.AutoAccept {
			details = append(details, "auto-accept")
		}
		fmt.Printf("  Mode:        public demo (%s)\n", strings.Join(details, ", "))
	} else if w.AutoAccept {
		fmt.Printf("  Mode:        auto-accept\n")
	} else {
		fmt.Printf("  Mode:        interactive (consent UI)\n")
	}
	fmt.Printf("  Transcript:  %s\n", w.SessionTranscript)
	if w.VCIFeatureVersion() == wallet.VCIVersion11 {
		fmt.Printf("  OID4VCI:     1.1 draft features used where an issuer offers them\n")
	}
	if w.PreferredFormat != "" {
		fmt.Printf("  Preferred:   %s\n", w.PreferredFormat)
	}
	if w.BaseURL != "" {
		fmt.Printf("  Status List: %s/api/statuslist\n", publicHTTPURL)
		dim.Printf("               %s/api/statuslist\n", httpsURL)
	}
	if w.RequireEncryptedRequest {
		fmt.Printf("  Encrypted:   request object encryption required\n")
	}
	if w.RequireHAIP {
		fmt.Printf("  HAIP:        enforced (presentations: x509_hash, direct_post.jwt, DCQL, JAR, ES256)\n")
		fmt.Printf("               enforced (issuance needs an https issuer, authorization code offers also PAR, PKCE S256, DPoP and client auth)\n")
	}
	for _, warning := range servingConfigWarnings(w, opts.Port, opts.Docker) {
		yellow.Printf("  Warning:     %s\n", warning)
	}

	if opts.Register && !opts.NoRegister {
		serveArgs, err := serializeWalletServeArgs(cmd)
		if err != nil {
			return fmt.Errorf("serializing wallet serve flags for registration: %w", err)
		}
		if err := wallet.RegisterURLSchemes(wallet.RegisterOptions{
			ListenerPort: opts.Port,
			AutoAccept:   w.AutoAccept,
			ServeArgs:    serveArgs,
		}); err != nil {
			yellow.Printf("  Register:    skipped (%s)\n", err)
		} else if wallet.SupportsURLSchemeRegistration() {
			fmt.Printf("  Register:    URL scheme handlers registered\n")
		} else {
			yellow.Printf("  Register:    not supported on this platform (use 'wallet accept <uri>' for copied links)\n")
		}
	}

	dim.Println("───────────────────────────────────────")
	fmt.Println()

	if len(w.GetCredentials()) > 0 {
		for _, c := range w.GetCredentials() {
			fmt.Printf("  [%s] %s (%d claims)\n", c.Format, credLabel(c), len(c.Claims))
		}
		fmt.Println()
	}

	var imprintHTML []byte
	if opts.ImprintFile != "" {
		imprintHTML, err = imprint.Load(opts.ImprintFile)
		if err != nil {
			return err
		}
	}

	srv := wallet.NewServer(w, opts.Port, func() {
		if err := store.Save(w); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
		}
	})
	srv.SetStore(store)
	srv.SetVersion(Version)
	srv.SetImprint(imprintHTML)
	if opts.NewsFile != "" {
		n, err := news.Load(opts.NewsFile)
		if err != nil {
			return err
		}
		srv.SetNews(n)
	}
	if opts.Demo {
		srv.SetDemo(demoOpts)
	}
	// Embed the credential decoder UI so stored credentials can be inspected
	// from the wallet UI. Its links refer to a credential by id.
	srv.Mount("/decoder", web.NewMuxWithOptions(web.MuxOptions{
		Version:     Version,
		ImprintHTML: imprintHTML,
		Demo:        opts.Demo,
		WalletStore: store,
		HTTPClient:  w.HTTPClient,
		CredentialByID: func(id string) (string, bool) {
			cred, ok := w.GetCredential(id)
			if !ok {
				return "", false
			}
			return cred.Raw, true
		},
	}))
	demoRP := demorp.New(w, func() string {
		if base := strings.TrimSpace(w.BaseURL); base != "" {
			return base
		}
		return fmt.Sprintf("http://localhost:%d", opts.Port)
	})
	demoRP.SetClientAuthMode(clientAuthMode)
	demoRP.SetVerifierTrustAnchors(verifierTrustAnchors)
	// Persist the reserved status index before another request reloads wallet state.
	demoRP.SetOnWalletChange(func() {
		if err := store.Save(w); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
		}
	})
	srv.Mount("/issuer", demoRP.IssuerHandler())
	srv.Mount("/verifier", demoRP.VerifierHandler())
	// OID4VCI inserts the well-known segment before the issuer path,
	// so the metadata for the /issuer-mounted issuer lives at the
	// server root.
	srv.Handle("GET /.well-known/openid-credential-issuer/issuer", demoRP.IssuerMetadataHandler())
	// Same for the authorization server metadata of the demo issuer,
	// which is its own authorization server (RFC 8414 §3.1).
	srv.Handle("GET /.well-known/oauth-authorization-server/issuer", demoRP.AuthorizationServerMetadataHandler())
	if err := srv.CheckBasePath(); err != nil {
		return err
	}
	if err := configureIssuerTLSCertificate(srv, store, w.IssuerURL); err != nil {
		return err
	}
	if issuerViaBaseURL && !opts.ServeTLS {
		// The TLS terminator in front of the base URL serves the issuer
		// origin, so the derived port (443 for a port-less https URL) is
		// not bound locally. With --serve-tls the listener stays on the
		// base URL's own port with the wallet's certificate.
		srv.SetIssuerListenPort(-1)
	}

	srv.SetLogger(func(format string, args ...any) {
		if logFormat == serverlog.FormatJSON {
			log.Printf(format, args...)
			return
		}
		timestamp := time.Now().Format("15:04:05")
		dim.Printf("[%s] ", timestamp)
		fmt.Printf(format+"\n", args...)
	})

	// When an interactive request arrives, open the consent UI on a desktop or
	// print its URL on a headless host. A demo host does neither because
	// visitors reach it through the browser redirect.
	if !w.AutoAccept && !opts.Demo {
		srv.SetOnUIRequest(func(requestID string) {
			target := fmt.Sprintf("http://localhost:%d/?focus=overview", opts.Port)
			if requestID != "" {
				// Pass the request id so the tab answers this request and no other
				// pending one.
				target += "&request=" + url.QueryEscape(requestID)
			}
			// A tab already watching is told over its event stream, so no
			// second tab is opened. The address is printed either way.
			watched := w.AttachedUIs() > 0
			if !watched && !noOpen && hasDesktopSession() && openBrowser(target) {
				fmt.Printf("  Opening wallet UI: %s\n", target)
				return
			}
			fmt.Printf("  Waiting for consent at: %s\n", target)
		})
	}

	if opts.Register && !opts.NoRegister {
		fmt.Println("Listening for URL scheme dispatches...")
		fmt.Println()
	}

	// Record this instance so `wallet ps` can discover it and
	// `wallet kill` and POST /api/shutdown can stop it.
	processID := os.Getpid()
	if err := remote.RegisterInstance(remote.Instance{
		PID:       processID,
		Port:      opts.Port,
		URL:       fmt.Sprintf("http://localhost:%d", opts.Port),
		WalletDir: store.Dir,
		StartedAt: time.Now(),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: registering wallet instance: %v\n", err)
	}
	defer remote.UnregisterInstance(processID)
	srv.ShutdownFunc = func() {
		remote.UnregisterInstance(processID)
		os.Exit(0)
	}

	return srv.ListenAndServe()
}
