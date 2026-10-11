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
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/netaddr"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
	"github.com/dominikschlosser/eudi-dev/v3/internal/remote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
	"github.com/dominikschlosser/eudi-dev/v3/internal/urlhandler"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

var walletDir string
var templatesDir string

var storageSpec string

var keySeed string
var walletValidationMode string
var walletTLSVerify bool
var walletTLSCA string
var walletHTTPProxy string
var walletHTTPSProxy string
var walletNoProxy string

var noOpen bool

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Manage a testing wallet for OID4VP/OID4VCI flows",
	Long: "Stateful wallet, persisted to files by default. Supports credential management, OID4VP presentations, OID4VCI issuance, " +
		"QR scanning, and URL scheme registration. The management commands operate on the local store, on the remote " +
		"instance selected by `wallet use` or --remote, or through a running server for the same wallet directory.",
}

// walletFlags select and configure the wallet a command works on. The wallet
// commands and the top-level registrar, catalog and trust commands share the
// same flag values, so Changed reads the same on every path.
var walletFlags = newWalletFlags()

func newWalletFlags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("wallet", pflag.ContinueOnError)
	flags.StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory (default ~/.eudi-dev/wallet/)")
	flags.StringVar(&remoteFlag, "remote", "", "Manage a remote wallet server at this URL for this invocation (\"local\" forces the local store)")
	flags.StringVar(&templatesDir, "templates-dir", "", "Credential template directory (default <wallet-dir>/templates/)")
	flags.StringVar(&storageSpec, "storage", "", storageFlagUsage)
	flags.StringVar(&keySeed, "seed", "", seedFlagUsage)
	flags.StringVar(&walletValidationMode, "mode", string(wallet.ValidationModeDebug), "Wallet validation mode: debug or strict")
	flags.BoolVar(&walletTLSVerify, "tls-verify", false, "Verify certificates for every outbound HTTPS request (default: true in strict mode, false in debug mode)")
	flags.StringVar(&walletTLSCA, "tls-ca", "", "PEM CA bundle added to system trust for outbound HTTPS")
	flags.StringVar(&walletHTTPProxy, "http-proxy", "", "Forward proxy URL for outbound http:// requests (default $HTTP_PROXY)")
	flags.StringVar(&walletHTTPSProxy, "https-proxy", "", "Forward proxy URL for outbound https:// requests (default $HTTPS_PROXY)")
	flags.StringVar(&walletNoProxy, "no-proxy", "", "Comma-separated hosts, domains and CIDRs that bypass the proxy (default $NO_PROXY)")
	return flags
}

// addWalletCommand registers a command that works on the active wallet.
func addWalletCommand(cmd *cobra.Command) {
	cmd.PersistentFlags().AddFlagSet(walletFlags)
	rootCmd.AddCommand(cmd)
}

func init() {
	walletCmd.PersistentFlags().BoolVar(&noOpen, "no-open", false, "Never open a browser, only print the URL")
	walletCmd.AddCommand(walletServeCmd())
	walletCmd.AddCommand(walletListCmd())
	walletCmd.AddCommand(walletShowCmd())
	walletCmd.AddCommand(walletImportCmd())
	walletCmd.AddCommand(walletRemoveCmd())
	walletCmd.AddCommand(walletAcceptCmd())
	walletCmd.AddCommand(walletScanCmd())
	walletCmd.AddCommand(walletLogsCmd())
	walletCmd.AddCommand(walletDeferredCmd())
	walletCmd.AddCommand(walletRefreshCmd())
	walletCmd.AddCommand(walletRegisterCmd())
	walletCmd.AddCommand(walletUnregisterCmd())
	walletCmd.AddCommand(walletTLSCertCmd())
	walletCmd.AddCommand(walletInfoCmd())
	walletCmd.AddCommand(walletPsCmd())
	walletCmd.AddCommand(walletUseCmd())
	walletCmd.AddCommand(walletKillCmd())
	addWalletCommand(walletCmd)
	addWalletCommand(registrarCmd())
	addWalletCommand(catalogCmd())
	addWalletCommand(trustCmd())
	addMovedCommands()

	// Completions and annotations live on the shared flags, so they hold for
	// every command above.
	_ = walletCmd.RegisterFlagCompletionFunc("remote", completeRemoteFlag)
	_ = walletCmd.RegisterFlagCompletionFunc("mode", staticCompletion("debug", "strict"))
	_ = walletCmd.MarkPersistentFlagDirname("wallet-dir")
	_ = walletCmd.MarkPersistentFlagDirname("templates-dir")
}

const storageFlagUsage = "Where the wallet state lives: 'file', 'memory', 'auto' (files when a state directory was given or exists, memory otherwise) or a postgres:// URL (default $EUDI_DEV_STORAGE)"

func resolvedStorageSpec() string {
	if storageSpec != "" {
		return storageSpec
	}
	return os.Getenv(storage.EnvVar)
}

const seedFlagUsage = "Derive the wallet's generated keys from this string, so a wallet that stores nothing gets the same keys on every start. 'auto' seeds the memory backend only (default $EUDI_DEV_SEED)"

func openStore() (*wallet.WalletStore, error) {
	store, err := wallet.OpenWalletStore(walletDir, resolvedStorageSpec())
	if err != nil {
		return nil, err
	}
	if keySeed != "" {
		store.SetSeed(keySeed)
	}
	return store, nil
}

// resolvedWalletDir returns the absolute --wallet-dir, which identifies the
// wallet to the instance registry on every backend.
func resolvedWalletDir() string {
	return wallet.ResolveWalletDir(walletDir)
}

func loadWallet() (*wallet.Wallet, *wallet.WalletStore, error) {
	store, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		return nil, nil, fmt.Errorf("loading wallet: %w", err)
	}
	if templatesDir != "" {
		w.Templates = credtemplate.FileLocation(templatesDir)
	}
	if err := applyValidationMode(w, walletValidationMode); err != nil {
		return nil, nil, err
	}
	if err := applyWalletOutbound(w); err != nil {
		return nil, nil, err
	}
	return w, store, nil
}

func applyValidationMode(w *wallet.Wallet, raw string) error {
	mode, err := wallet.ParseValidationMode(raw)
	if err != nil {
		return err
	}
	w.ValidationMode = mode
	return nil
}

// After direct issuance, embedded issuer and status list URLs work only once a server
// runs for this wallet directory.
func warnIssuedEndpointsOffline(store *wallet.WalletStore, w *wallet.Wallet) {
	if strings.TrimSpace(w.IssuerURL) == "" {
		return
	}
	if remote.InstanceForWalletDir(store.Dir, 300*time.Millisecond) != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Note: the embedded issuer and status list URLs point at %s. They resolve once `%s wallet serve` runs.\n", w.IssuerURL, binaryName())
}

// walletURLs are the public URLs of a wallet server.
type walletURLs struct {
	Base   string
	Issuer string
}

// walletOrigin derives the URLs of a wallet server on port. baseURL is its
// --base-url. Without one, docker picks the Docker host name over localhost.
// The issuer URL is the HTTPS origin on the next port.
func walletOrigin(port int, baseURL string, docker bool) (walletURLs, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		host := "localhost"
		if docker {
			host = netaddr.DockerHost
		}
		return walletURLs{Base: fmt.Sprintf("http://%s:%d", host, port), Issuer: wallet.LocalIssuerURL(port+1, docker)}, nil
	}
	// An https base URL means a TLS terminator already serves the wallet on
	// that origin. Issuer metadata, status list and trusted list are served
	// there too.
	if u, err := url.Parse(baseURL); err == nil && strings.EqualFold(u.Scheme, "https") {
		return walletURLs{Base: baseURL, Issuer: baseURL}, nil
	}
	issuer, err := wallet.IssuerURLFromBaseURL(baseURL, port+1)
	if err != nil {
		return walletURLs{}, err
	}
	return walletURLs{Base: baseURL, Issuer: issuer}, nil
}

// An external TLS terminator can serve both the base and issuer URLs on one origin.
func issuerServedByBaseURL(issuerURL, baseURL string) bool {
	trim := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
	return trim(issuerURL) != "" && trim(issuerURL) == trim(baseURL)
}

func configureIssuerTLSCertificate(srv *wallet.Server, store *wallet.WalletStore, issuerURL string) error {
	cert, err := store.LoadOrCreateIssuerTLSCertificateForURL(issuerURL)
	if err != nil {
		return fmt.Errorf("loading issuer TLS certificate: %w", err)
	}
	srv.SetIssuerTLSCertificate(cert)
	return nil
}

func walletListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			creds, err := svc.Credentials()
			if err != nil {
				return err
			}
			// A deferred credential is not in the store yet but is on its way,
			// so it is listed too.
			deferred, err := svc.DeferredIssuances()
			if err != nil {
				return err
			}
			return printCredentialList(creds, deferred)
		},
	}
}

func walletShowCmd() *cobra.Command {
	var decoded bool
	cmd := &cobra.Command{
		Use:               "show <id>",
		Short:             "Show a stored credential",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeCredentialIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			// A deferred issuance has its own id. Show its state for that id.
			deferred, derr := svc.DeferredIssuances()
			if derr == nil {
				for _, entry := range deferred {
					if docString(entry, "id") == args[0] {
						return printDeferredDoc(entry)
					}
				}
			}
			cred, err := svc.Credential(args[0])
			if err != nil {
				return err
			}
			return printCredentialDoc(cred, decoded)
		},
	}
	cmd.Flags().BoolVar(&decoded, "decoded", false, "Show human-readable decoded output instead of raw")
	return cmd
}

func walletImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import [file-or-raw]",
		Short: "Import a credential into the wallet",
		Long:  "Imports an SD-JWT, JWT VC, or mdoc credential from a file, a raw string, or stdin (-, the default).",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := "-"
			if len(args) > 0 {
				input = args[0]
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			raw, err := format.ReadInputRaw(input)
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			imported, err := svc.ImportCredential(raw)
			if err != nil {
				return err
			}
			printResult(imported, func() {
				claims, _ := imported["claims"].(map[string]any)
				fmt.Printf("Imported %s credential (%s) with %d claims\n", docString(imported, "format"), docCredLabel(imported), len(claims))
			})
			warnAboutCredential(imported)
			return nil
		},
	}
}

func walletRemoveCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               "remove <id>",
		Short:             "Remove a credential by its ID",
		ValidArgsFunction: completeCredentialIDs,
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return fmt.Errorf("--all does not take a credential ID")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if all {
				removed, err := svc.RemoveAllCredentials()
				if err != nil {
					return err
				}
				printResult(map[string]any{"removed": removed.Deleted, "kept_protected": removed.KeptProtected}, func() {
					fmt.Printf("Removed %d credential(s)\n", removed.Deleted)
					if removed.KeptProtected > 0 {
						fmt.Printf("Kept %d protected credential(s)\n", removed.KeptProtected)
					}
				})
				return nil
			}
			if err := svc.RemoveCredential(args[0]); err != nil {
				return err
			}
			printResult(map[string]any{"removed": 1, "id": args[0]}, func() { fmt.Printf("Removed credential %s\n", args[0]) })
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Remove all stored credentials")
	return cmd
}

func walletRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register [wallet-serve-flags...]",
		Short: "Register the OS URL scheme handlers (macOS, a no-op elsewhere)",
		Long: `Registers this wallet as the OS handler for the OID4VP/OID4VCI URL schemes (macOS, a no-op elsewhere). The provided arguments are stored and replayed as 'wallet serve ...' when a clicked link needs to auto-start the wallet listener.

Supported schemes: openid4vp://, eudi-openid4vp://, haip-vp://,
openid-credential-offer://, haip-vci:// and eu-eaa-offer://.`,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if arg == "-h" || arg == "--help" {
					return cmd.Help()
				}
			}
			opts, err := walletRegisterOptions(args)
			if err != nil {
				return err
			}
			opts.ServeArgs = append(walletRegisterInheritedServeArgs(cmd), opts.ServeArgs...)
			reg, err := urlhandler.Register(opts)
			if err != nil {
				return err
			}
			printResult(reg, func() { printRegistration(reg) })
			return nil
		},
	}
	return cmd
}

func walletRegisterInheritedServeArgs(cmd *cobra.Command) []string {
	args := []string{}
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		switch flag.Name {
		case "tls-verify":
			args = append(args, "--tls-verify="+flag.Value.String())
		case "wallet-dir", "mode", "storage", "tls-ca", "http-proxy", "https-proxy", "no-proxy":
			args = append(args, "--"+flag.Name, flag.Value.String())
		}
	})
	return args
}

func walletRegisterOptions(args []string) (urlhandler.Options, error) {
	port := config.DefaultWalletPort
	autoAccept := false

	flags := pflag.NewFlagSet("wallet-register", pflag.ContinueOnError)
	flags.ParseErrorsWhitelist.UnknownFlags = true
	flags.IntVar(&port, "port", config.DefaultWalletPort, "")
	flags.BoolVar(&autoAccept, "auto-accept", false, "")
	if err := flags.Parse(args); err != nil {
		return urlhandler.Options{}, fmt.Errorf("parsing wallet serve arguments for registration: %w", err)
	}

	return urlhandler.Options{
		ListenerPort: port,
		AutoAccept:   autoAccept,
		ServeArgs:    append([]string(nil), args...),
	}, nil
}

func walletUnregisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unregister",
		Short: "Remove the OS URL scheme handlers (macOS, a no-op elsewhere)",
		RunE: func(cmd *cobra.Command, args []string) error {
			unreg, err := urlhandler.Unregister()
			if err != nil {
				return err
			}
			printResult(unreg, func() {
				if !unreg.Unregistered {
					fmt.Println("No URL scheme handlers were registered.")
					return
				}
				fmt.Printf("Unregistered URL scheme handlers and removed %s\n", unreg.AppBundle)
			})
			return nil
		},
	}
}

func printRegistration(reg urlhandler.Registration) {
	if !reg.Registered {
		fmt.Println("URL scheme registration is not available on this platform. Continue with 'eudi wallet accept <uri>' for copied offer or presentation links.")
		return
	}
	fmt.Println("Registered URL scheme handlers:")
	fmt.Printf("  App bundle: %s\n", reg.AppBundle)
	fmt.Printf("  Handler:    %s\n", reg.Handler)
	fmt.Printf("  Binary:     %s\n", reg.Binary)
	mode := "interactive UI"
	if reg.AutoAccept {
		mode = "auto-accept"
	}
	fmt.Printf("  Mode:       %s\n", mode)
	if len(reg.ServeArgs) > 0 {
		fmt.Printf("  Serve args: %s\n", strings.Join(reg.ServeArgs, " "))
	}
	schemes := make([]string, len(reg.Schemes))
	for i, scheme := range reg.Schemes {
		schemes[i] = scheme + "://"
	}
	fmt.Printf("  Schemes:    %s\n", strings.Join(schemes, ", "))
}

func certificateExportFormat(asPEM, asJWKS bool) (string, error) {
	if asPEM && asJWKS {
		return "", fmt.Errorf("--pem and --jwks are mutually exclusive")
	}
	if asJWKS {
		return "jwks", nil
	}
	return "pem", nil
}

// writeCertificateExport prints the certificate, or writes it to outPath and
// prints the path. With --json it prints {"path"} or {"pem"}. A JWKS is JSON
// already.
func writeCertificateExport(cmd *cobra.Command, kind, certFormat string, data []byte, outPath string) error {
	out := cmd.OutOrStdout()
	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return fmt.Errorf("writing wallet %s certificate: %w", kind, err)
		}
		if jsonOutput {
			return output.WriteJSON(out, map[string]string{"path": outPath})
		}
		if _, err := fmt.Fprintln(out, outPath); err != nil {
			return fmt.Errorf("writing wallet %s certificate path: %w", kind, err)
		}
		return nil
	}
	if jsonOutput && certFormat == "pem" {
		return output.WriteJSON(out, map[string]string{"pem": string(data)})
	}
	if _, err := fmt.Fprint(out, string(data)); err != nil {
		return fmt.Errorf("writing wallet %s certificate: %w", kind, err)
	}
	return nil
}

func walletTLSCertCmd() *cobra.Command {
	var (
		port    int
		baseURL string
		docker  bool
		outPath string
		asPEM   bool
		asJWKS  bool
	)

	cmd := &cobra.Command{
		Use:   "tls-cert",
		Short: "Print or export the wallet HTTPS leaf certificate",
		Long: `Loads or creates the HTTPS leaf certificate used by the wallet's HTTPS endpoints.
Use this to inspect or export the exact server certificate presented by the wallet.
Use 'trust ca-cert' for the one trust root shared by every wallet under the same base directory.

Use --jwks to export the certificate as a JWKS document (public key with x5c
chain).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			certFormat, err := certificateExportFormat(asPEM, asJWKS)
			if err != nil {
				return err
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			certData, err := svc.Certificate("tls", certFormat, walletCertOptions{port: port, baseURL: baseURL, docker: docker})
			if err != nil {
				return err
			}
			return writeCertificateExport(cmd, "TLS", certFormat, certData, outPath)
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Wallet server port (certificate will match HTTPS wallet endpoints on port+1)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL used to derive the HTTPS wallet host")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost when deriving the HTTPS wallet host")
	cmd.Flags().StringVar(&outPath, "out", "", "Write the wallet TLS certificate to a file instead of stdout")
	cmd.Flags().BoolVar(&asPEM, "pem", false, "Output as PEM (the default)")
	cmd.Flags().BoolVar(&asJWKS, "jwks", false, "Output as JWKS (public key with x5c chain)")
	return cmd
}

func typeLabel(vct, docType, fmt_ string) string {
	if vct != "" {
		return vct
	}
	if docType != "" {
		return docType
	}
	return fmt_
}

func credLabel(c wallet.StoredCredential) string {
	return typeLabel(c.VCT, c.DocType, c.Format)
}

func parseClaimsOverrides(flag string) (map[string]any, error) {
	if flag == "" {
		return nil, nil
	}
	var overrides map[string]any
	if err := json.Unmarshal([]byte(flag), &overrides); err != nil {
		return nil, fmt.Errorf("parsing --claims JSON: %w", err)
	}
	return overrides, nil
}

func applySessionTranscriptMode(w *wallet.Wallet, mode string) error {
	switch mode {
	case "oid4vp", "":
		w.SessionTranscript = oid4vp.SessionTranscriptOID4VP
	case "iso":
		w.SessionTranscript = oid4vp.SessionTranscriptISO
	default:
		return fmt.Errorf("invalid --session-transcript value %q (must be 'iso' or 'oid4vp')", mode)
	}
	return nil
}

// Some URLs come from a remote wallet. Restrict their schemes because the system
// opener can also launch files and applications.
func openBrowser(rawURL string) bool {
	if !format.IsWebURL(rawURL) {
		fmt.Fprintf(os.Stderr, "refusing to open %q: only http and https URLs\n", rawURL)
		return false
	}
	if !hasDesktopSession() {
		return false
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start() == nil
	case "linux":
		return exec.Command("xdg-open", rawURL).Start() == nil
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start() == nil
	}
	return false
}

func hasDesktopSession() bool {
	switch runtime.GOOS {
	case "darwin":
		return os.Getenv("SSH_CONNECTION") == "" && os.Getenv("SSH_TTY") == ""
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	default:
		return true
	}
}

func loadWalletECKey(path, label string) (*ecdsa.PrivateKey, error) {
	if path != "" {
		privKey, err := keys.LoadPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("loading %s key: %w", label, err)
		}
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("--%s key must be an EC private key (P-256)", label)
		}
		return ecKey, nil
	}

	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated ephemeral %s key\n", label)
	return key, nil
}

func walletRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh <credential-id>",
		Short: "Ask a credential's issuer for a fresh copy",
		Long: `Renews a credential using the refresh token its issuer handed over at issuance.

The credential keeps its id, so anything referring to it still does. A wallet
server renews on its own shortly before expiry. This asks now.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeCredentialIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			renewed, err := svc.RefreshCredential(args[0])
			if err != nil {
				return err
			}
			if jsonOutput {
				data, err := json.MarshalIndent(renewed, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}
			fmt.Printf("Renewed %s (%s)\n", docString(renewed, "id"), docCredLabel(renewed))
			if expiry := docString(renewed, "expires_at"); expiry != "" {
				fmt.Printf("Valid until %s\n", expiry)
			}
			return nil
		},
	}
}

func applyWalletOutbound(w *wallet.Wallet) error {
	var verify *bool
	if walletFlags.Changed("tls-verify") {
		verify = &walletTLSVerify
	}
	var caPEM []byte
	if walletTLSCA != "" {
		var err error
		caPEM, err = os.ReadFile(walletTLSCA)
		if err != nil {
			return fmt.Errorf("--tls-ca: %w", err)
		}
		if len(caPEM) == 0 {
			return fmt.Errorf("--tls-ca: CA bundle is empty")
		}
	}
	proxy, err := format.NewProxyFunc(format.ProxySettings{HTTPProxy: walletHTTPProxy, HTTPSProxy: walletHTTPSProxy, NoProxy: walletNoProxy})
	if err != nil {
		return fmt.Errorf("proxy settings: %w", err)
	}
	if err := w.ConfigureOutbound(wallet.OutboundConfig{TLSVerify: verify, TLSCAPEM: caPEM, Proxy: proxy}); err != nil {
		return fmt.Errorf("configuring outbound HTTP: %w", err)
	}
	return nil
}
