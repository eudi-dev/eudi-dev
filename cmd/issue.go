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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

var (
	issueClaims                string
	issueTemplate              string
	issueAlwaysDisclosed       []string
	issueSaveTemplate          string
	issueKeyPath               string
	issueCertPath              string
	issueIssuer                string
	issueVCT                   string
	issueExpires               string
	issueNBF                   string
	issueDocType               string
	issueNamespace             string
	issuePID                   bool
	issueOmit                  []string
	issueToWallet              bool
	issueBatchSize             int
	issueUnbound               bool
	issueStatusListURI         string
	issueStatusListIdx         int
	issueTrustProfile          string
	issueEntitlements          []string
	issueTrustListType         string
	issueStatusDetermination   string
	issueSchemeCommunityRule   string
	issueSchemeTerritory       string
	issueTrustEntityName       string
	issueIssuanceServiceType   string
	issueRevocationServiceType string
	issueIssuanceServiceName   string
	issueRevocationServiceName string
	issueDisplayName           string
	issueDisplayDescription    string
	issueBackgroundColor       string
	issueTextColor             string
	issueLogo                  string
	issueLogoAlt               string
	issueBackgroundImage       string
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Generate test SD-JWT, JWT, or mdoc credentials",
	Long: "Generates a signed test credential in one of two modes.\n\n" +
		"By default it prints a bare credential signed with an ephemeral key (or --key/--cert) to stdout and touches no wallet. " +
		"With --wallet it issues with the managed wallet's issuer key instead and imports the credential there: into the local store, " +
		"the remote instance selected by `wallet use`, or a running server for the same wallet directory.",
}

var issueSDJWTCmd = &cobra.Command{
	Use:   "sdjwt",
	Short: "Generate a test SD-JWT credential",
	Long: "Generate a signed SD-JWT credential with selectively disclosable claims. " +
		"By default it prints a bare credential signed with an ephemeral P-256 key. --wallet issues into the managed wallet instead.",
	RunE: runIssueSDJWT,
}

var issueJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate a test JWT VC credential",
	Long: "Generate a signed JWT VC credential with claims directly in the payload (no selective disclosure). " +
		"By default it prints a bare credential signed with an ephemeral P-256 key. --wallet issues into the managed wallet instead.",
	RunE: runIssueJWT,
}

var issueMDOCCmd = &cobra.Command{
	Use:   "mdoc",
	Short: "Generate a test mdoc credential",
	Long: "Generate a signed mdoc (IssuerSigned) credential. " +
		"By default it prints a bare credential signed with an ephemeral P-256 key. --wallet issues into the managed wallet instead.",
	RunE: runIssueMDOC,
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.PersistentFlags().StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory for --wallet, also the template location (default ~/.eudi-dev/wallet/, or an existing ~/.oid4vc-dev/wallet/)")
	issueCmd.PersistentFlags().StringVar(&templatesDir, "templates-dir", "", "Credential template directory (default <wallet-dir>/templates/)")
	issueCmd.PersistentFlags().StringVar(&storageSpec, "storage", "", storageFlagUsage)
	issueCmd.PersistentFlags().StringVar(&keySeed, "seed", "", seedFlagUsage)
	issueCmd.PersistentFlags().StringVar(&remoteFlag, "remote", "", "With --wallet: issue on a remote wallet server at this URL (\"local\" forces the local store)")
	issueCmd.AddCommand(issueSDJWTCmd)
	issueCmd.AddCommand(issueJWTCmd)
	issueCmd.AddCommand(issueMDOCCmd)

	issueSDJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueSDJWTCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file, listed by 'templates list' (--claims overrides individual claims)")
	issueSDJWTCmd.Flags().StringSliceVar(&issueAlwaysDisclosed, "always-disclosed", nil, "Claims to embed plainly instead of selectively disclosable (dotted paths for nested claims, e.g. address.country)")
	issueSDJWTCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueSDJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK). Ephemeral P-256 if omitted")
	issueSDJWTCmd.Flags().StringVar(&issueCertPath, "cert", "", "Certificate chain file (PEM, leaf first) embedded as x5c. Requires --key")
	issueSDJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueSDJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueSDJWTCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueSDJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueSDJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueSDJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Claim names to omit from the resolved claim set (e.g. place_of_birth,sex)")
	issueSDJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueSDJWTCmd.Flags().IntVar(&issueBatchSize, "batch", 0, "Issue a batch of this many distinct-key copies (--wallet only), so the wallet presents an unused one each time")
	issueSDJWTCmd.Flags().BoolVar(&issueUnbound, "unbound", false, "With --wallet: issue without a holder key (a bearer credential with no cnf). The default binds it to the wallet")
	issueSDJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueSDJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueSDJWTCmd)
	addIssueDisplayFlags(issueSDJWTCmd)

	issueJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueJWTCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file, listed by 'templates list' (--claims overrides individual claims)")
	issueJWTCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK). Ephemeral P-256 if omitted")
	issueJWTCmd.Flags().StringVar(&issueCertPath, "cert", "", "Certificate chain file (PEM, leaf first) embedded as x5c. Requires --key")
	issueJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueJWTCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Claim names to omit from the resolved claim set (e.g. place_of_birth,sex)")
	issueJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueJWTCmd)
	addIssueDisplayFlags(issueJWTCmd)

	issueMDOCCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueMDOCCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file, listed by 'templates list' (--claims overrides individual claims)")
	issueMDOCCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueMDOCCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK). Ephemeral P-256 if omitted")
	issueMDOCCmd.Flags().StringVar(&issueCertPath, "cert", "", "Certificate chain file (PEM, leaf first) embedded as x5c. Requires --key")
	issueMDOCCmd.Flags().StringVar(&issueDocType, "doc-type", "eu.europa.ec.eudi.pid.1", "Document type")
	issueMDOCCmd.Flags().StringVar(&issueNamespace, "namespace", "eu.europa.ec.eudi.pid.1", "Namespace")
	issueMDOCCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueMDOCCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueMDOCCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueMDOCCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Claim names to omit from the resolved claim set (e.g. place_of_birth,sex)")
	issueMDOCCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueMDOCCmd.Flags().IntVar(&issueBatchSize, "batch", 0, "Issue a batch of this many distinct-key copies (--wallet only), so the wallet presents an unused one each time")
	issueMDOCCmd.Flags().BoolVar(&issueUnbound, "unbound", false, "With --wallet: issue without an MSO device key (a deliberately malformed mdoc for testing verifier rejection). The default binds it to the wallet")
	issueMDOCCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueMDOCCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueMDOCCmd)
	addIssueDisplayFlags(issueMDOCCmd)

	for _, c := range []*cobra.Command{issueSDJWTCmd, issueJWTCmd, issueMDOCCmd} {
		_ = c.RegisterFlagCompletionFunc("template", completeTemplateNames)
		_ = c.RegisterFlagCompletionFunc("trust-profile", staticCompletion("auto", "pid", "local"))
	}
	_ = issueCmd.RegisterFlagCompletionFunc("remote", completeRemoteFlag)
	_ = issueCmd.MarkPersistentFlagDirname("wallet-dir")
	_ = issueCmd.MarkPersistentFlagDirname("templates-dir")
}

func runIssueSDJWT(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueSDJWTToWallet(cmd)
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	tpl, err := resolveIssueTemplate(cmd, "sdjwt")
	if err != nil {
		return err
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
	if err != nil {
		return err
	}
	alwaysDisclosed, err := resolveIssueAlwaysDisclosed("sdjwt", tpl)
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	certChain, err := loadIssueCertChain("sdjwt")
	if err != nil {
		return err
	}

	cfg := mock.SDJWTConfig{
		Issuer:          issueIssuer,
		VCT:             issueVCT,
		ExpiresIn:       expDuration,
		NotBefore:       nbf,
		Claims:          claims,
		Key:             key,
		StatusListURI:   issueStatusListURI,
		StatusListIdx:   issueStatusListIdx,
		AlwaysDisclosed: alwaysDisclosed,
		CertChain:       certChain,
		KeepTrustAnchor: issueCertPath != "",
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating SD-JWT: %w", err)
	}

	fmt.Println(result)

	if err := saveIssueTemplate("sdjwt", claims, alwaysDisclosed); err != nil {
		return err
	}
	return nil
}

func runIssueJWT(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueJWTToWallet(cmd)
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	tpl, err := resolveIssueTemplate(cmd, "jwt")
	if err != nil {
		return err
	}
	claims, err := resolveIssueClaimsForFormat("jwt", tpl)
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	certChain, err := loadIssueCertChain("jwt")
	if err != nil {
		return err
	}

	cfg := mock.JWTConfig{
		Issuer:        issueIssuer,
		VCT:           issueVCT,
		ExpiresIn:     expDuration,
		NotBefore:     nbf,
		Claims:        claims,
		Key:           key,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
		CertChain:     certChain,
	}

	result, err := mock.GenerateJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating JWT: %w", err)
	}

	fmt.Println(result)

	if err := saveIssueTemplate("jwt", claims, nil); err != nil {
		return err
	}
	return nil
}

func runIssueMDOC(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueMDOCToWallet(cmd)
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	tpl, err := resolveIssueTemplate(cmd, "mdoc")
	if err != nil {
		return err
	}
	claims, err := resolveIssueClaimsForFormat("mdoc", tpl)
	if err != nil {
		return err
	}
	if _, err := resolveIssueAlwaysDisclosed("mdoc", tpl); err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	certChain, err := loadIssueCertChain("mdoc")
	if err != nil {
		return err
	}

	cfg := mock.MDOCConfig{
		DocType:         issueDocType,
		Namespace:       issueNamespace,
		Claims:          claims,
		Key:             key,
		ExpiresIn:       expDuration,
		ValidFrom:       nbf,
		StatusListURI:   issueStatusListURI,
		StatusListIdx:   issueStatusListIdx,
		CertChain:       certChain,
		KeepTrustAnchor: issueCertPath != "",
	}

	result, err := mock.GenerateMDOC(cfg)
	if err != nil {
		return fmt.Errorf("generating mdoc: %w", err)
	}

	fmt.Println(result)

	if err := saveIssueTemplate("mdoc", claims, nil); err != nil {
		return err
	}
	return nil
}

func loadOrGenerateIssueKey() (*ecdsa.PrivateKey, error) {
	if issueKeyPath != "" {
		privKey, err := keys.LoadPrivateKey(issueKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading key: %w", err)
		}
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("--key must be an EC private key (P-256)")
		}
		return ecKey, nil
	}

	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Ephemeral signing key (public JWK):")
	fmt.Fprintln(os.Stderr, mock.PublicKeyJWK(&key.PublicKey))
	return key, nil
}

func readSigningOverrideFiles() (keyData, certData string, err error) {
	if issueCertPath == "" {
		return "", "", nil
	}
	if issueKeyPath == "" {
		return "", "", fmt.Errorf("--cert requires --key (the certificate must certify the signing key)")
	}
	key, err := os.ReadFile(issueKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("reading --key: %w", err)
	}
	cert, err := os.ReadFile(issueCertPath)
	if err != nil {
		return "", "", fmt.Errorf("reading --cert: %w", err)
	}
	return string(key), string(cert), nil
}

// loadIssueCertChain loads and validates the --cert chain. For SD-JWT, a
// chain that includes its self-signed root gets a note because HAIP 1.0
// §6.1.1 excludes the trust anchor. RFC 7515 allows it for a plain JWT VC.
func loadIssueCertChain(format string) ([]*x509.Certificate, error) {
	keyData, certData, err := readSigningOverrideFiles()
	if err != nil || certData == "" {
		return nil, err
	}
	_, chain, err := wallet.ParseSigningOverride(keyData, certData)
	if err != nil {
		return nil, err
	}
	if format != "jwt" && len(mock.WithoutSelfSignedTrustAnchor(chain)) != len(chain) {
		fmt.Fprintln(os.Stderr, "Note: the chain includes its self-signed root and is embedded as given (HAIP 1.0 §6.1.1 excludes the anchor from x5c)")
	}
	return chain, nil
}

func loadWalletForIssue(cmd *cobra.Command) (*wallet.Wallet, *wallet.WalletStore, error) {
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

	// With --cert, the request includes the supplied key and chain. With --key alone,
	// the wallet signs a new leaf certificate under its CA.
	if issueKeyPath != "" && issueCertPath == "" {
		issuerKey, err := loadWalletECKey(issueKeyPath, "issuer")
		if err != nil {
			return nil, nil, err
		}
		w.IssuerKey = issuerKey
		if len(w.CertChain) < 2 || w.CAKey == nil {
			return nil, nil, fmt.Errorf("wallet has no CA certificate chain")
		}
		if err := w.SetCertificateAuthority(w.CAKey, w.CertChain[len(w.CertChain)-1]); err != nil {
			return nil, nil, fmt.Errorf("rebuilding wallet issuer certificate chain: %w", err)
		}
	}

	if cmd.Flags().Changed("iss") {
		w.IssuerURL = strings.TrimRight(strings.TrimSpace(issueIssuer), "/")
	} else if strings.TrimSpace(w.IssuerURL) == "" || (registeredWalletListenerPort() > 0 && isLocalhostIssuerURL(w.IssuerURL)) {
		w.IssuerURL = wallet.LocalIssuerURL(defaultWalletCommandPort()+1, false)
	}

	return w, store, nil
}

func runIssueSDJWTToWallet(cmd *cobra.Command) error {
	return runIssueToWallet(cmd, "sdjwt")
}

func runIssueJWTToWallet(cmd *cobra.Command) error {
	return runIssueToWallet(cmd, "jwt")
}

func runIssueMDOCToWallet(cmd *cobra.Command) error {
	return runIssueToWallet(cmd, "mdoc")
}

func runIssueToWallet(cmd *cobra.Command, format string) error {
	req, err := issueAPIRequestFromFlags(cmd, format)
	if err != nil {
		return err
	}
	svc, err := managedWalletWithLoader(func() (*wallet.Wallet, *wallet.WalletStore, error) {
		return loadWalletForIssue(cmd)
	})
	if err != nil {
		return err
	}
	result, err := svc.Issue(req)
	if err != nil {
		return err
	}
	if _, requested := req["signing_key"]; requested {
		if applied, _ := result["signing_override"].(bool); !applied {
			return fmt.Errorf("the wallet server ignored the signing override and issued with its own issuer key (it runs a release without --key/--cert support). Update it, or remove the imported credential and retry with --remote local")
		}
	}
	fmt.Println(docString(result, "raw"))
	if path := docString(result, "template_path"); path != "" {
		printTemplateSaved("Saved", issueSaveTemplate, path)
	}
	label := docString(result, "vct")
	if label == "" {
		label = docString(result, "doctype")
	}
	fmt.Fprintf(os.Stderr, "Imported %s credential (%s) into wallet\n", docString(result, "format"), label)
	return nil
}

// Explicit flags override template defaults. With --pid and no --claims, --vct selects
// the built-in PID template.
func resolveIssueTemplate(cmd *cobra.Command, format string) (*credtemplate.Template, error) {
	var name string
	// A template named by --template must match the format. The --pid
	// template is a claim set, so `issue jwt --pid` uses the SD-JWT PID
	// template and skips the format check.
	pidTemplate := false
	switch {
	case issueTemplate != "":
		name = issueTemplate
	case issuePID && issueClaims == "":
		sdName, mdocName, _ := credtemplate.PIDTemplateNames(issueVCT)
		if format == "mdoc" {
			name = mdocName
		} else {
			name = sdName
		}
		pidTemplate = true
	default:
		return nil, nil
	}

	loc, err := resolveTemplates()
	if err != nil {
		return nil, err
	}
	tpl, err := credtemplate.Load(name, loc)
	if err != nil {
		return nil, err
	}
	if tpl.Format != "" && !pidTemplate {
		tplFormat, err := credtemplate.NormalizeFormat(tpl.Format)
		if err != nil {
			return nil, err
		}
		if tplFormat != "" && tplFormat != format {
			return nil, fmt.Errorf("template %q is for format %s, not %s", tpl.Name, tplFormat, format)
		}
	}

	flags := cmd.Flags()
	if tpl.VCT != "" && flags.Lookup("vct") != nil && !flags.Changed("vct") {
		issueVCT = tpl.VCT
	}
	if tpl.DocType != "" && flags.Lookup("doc-type") != nil && !flags.Changed("doc-type") {
		issueDocType = tpl.DocType
	}
	if tpl.Namespace != "" && flags.Lookup("namespace") != nil && !flags.Changed("namespace") {
		issueNamespace = tpl.Namespace
	}
	if tpl.Exp != "" && !flags.Changed("exp") {
		issueExpires = tpl.Exp
	}
	return tpl, nil
}

// resolveIssueAlwaysDisclosed combines the template's always-disclosed list
// with --always-disclosed. A jwt credential ignores it because all its
// claims are plain. An mdoc rejects it because every element is selectively
// disclosable.
func resolveIssueAlwaysDisclosed(format string, tpl *credtemplate.Template) ([]string, error) {
	var merged []string
	seen := make(map[string]bool)
	var lists [][]string
	if tpl != nil {
		lists = append(lists, tpl.AlwaysDisclosed)
	}
	lists = append(lists, issueAlwaysDisclosed)
	for _, list := range lists {
		for _, path := range list {
			path = strings.TrimSpace(path)
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			merged = append(merged, path)
		}
	}
	switch format {
	case "mdoc":
		if len(merged) > 0 {
			return nil, fmt.Errorf("always-disclosed claims are not supported for mdoc: every mdoc element is selectively disclosable")
		}
		return nil, nil
	case "jwt":
		return nil, nil
	default:
		return merged, nil
	}
}

func saveIssueTemplate(format string, claims map[string]any, alwaysDisclosed []string) error {
	if issueSaveTemplate == "" {
		return nil
	}
	tpl := credtemplate.Template{
		Name:            issueSaveTemplate,
		Format:          format,
		Exp:             issueExpires,
		Claims:          claims,
		AlwaysDisclosed: alwaysDisclosed,
	}
	if format == "mdoc" {
		tpl.DocType = issueDocType
		tpl.Namespace = issueNamespace
	} else {
		tpl.VCT = issueVCT
	}
	loc, err := resolveTemplates()
	if err != nil {
		return err
	}
	path, err := credtemplate.Save(loc, tpl)
	if err != nil {
		return fmt.Errorf("saving template: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Saved template %q to %s\n", issueSaveTemplate, path)
	return nil
}

// issueAPIRequestFromFlags builds the shared POST /api/issue request. Templates resolve
// on the managed wallet, so send only the name and explicit overrides.
func issueAPIRequestFromFlags(cmd *cobra.Command, format string) (map[string]any, error) {
	req := map[string]any{"format": format}
	keyData, certData, err := readSigningOverrideFiles()
	if err != nil {
		return nil, err
	}
	if certData != "" {
		if _, _, err := wallet.ParseSigningOverride(keyData, certData); err != nil {
			return nil, err
		}
		req["signing_key"] = keyData
		req["signing_cert"] = certData
	}
	if issueTemplate != "" {
		req["template"] = issueTemplate
	}
	if issuePID {
		req["pid"] = true
	}
	if issueClaims != "" {
		var data []byte
		if strings.HasPrefix(issueClaims, "@") {
			var err error
			data, err = os.ReadFile(issueClaims[1:])
			if err != nil {
				return nil, fmt.Errorf("reading claims file: %w", err)
			}
		} else {
			data = []byte(issueClaims)
		}
		var claims map[string]any
		if err := json.Unmarshal(data, &claims); err != nil {
			return nil, fmt.Errorf("parsing claims JSON: %w", err)
		}
		req["claims"] = claims
	}
	if len(issueOmit) > 0 {
		req["omit"] = issueOmit
	}
	if len(issueAlwaysDisclosed) > 0 {
		req["always_disclosed"] = issueAlwaysDisclosed
	}
	if issueSaveTemplate != "" {
		req["save_as_template"] = issueSaveTemplate
	}
	flags := cmd.Flags()
	if flags.Changed("vct") {
		req["vct"] = issueVCT
	}
	if flags.Lookup("doc-type") != nil && flags.Changed("doc-type") {
		req["doctype"] = issueDocType
	}
	if flags.Lookup("namespace") != nil && flags.Changed("namespace") {
		req["namespace"] = issueNamespace
	}
	if flags.Changed("exp") {
		req["exp"] = issueExpires
	}
	if issueNBF != "" {
		req["nbf"] = issueNBF
	}
	if flags.Changed("batch") {
		req["batch"] = issueBatchSize
	}
	if issueUnbound {
		req["unbound"] = true
	}
	if flags.Changed("status-list-uri") {
		req["status_list_uri"] = issueStatusListURI
	}
	if flags.Changed("status-list-idx") {
		req["status_list_idx"] = issueStatusListIdx
	}
	if issueTrustProfile != "" && issueTrustProfile != "auto" {
		req["trust_profile"] = issueTrustProfile
	}
	// The server fills in Format, VCT and DocType and applies the trust profile. An
	// empty trust object therefore behaves like an omitted one.
	req["trust"] = issueTrustSpecFromFlags()

	display := map[string]any{}
	if issueDisplayName != "" {
		display["name"] = issueDisplayName
	}
	if issueDisplayDescription != "" {
		display["description"] = issueDisplayDescription
	}
	if issueBackgroundColor != "" {
		display["background_color"] = issueBackgroundColor
	}
	if issueTextColor != "" {
		display["text_color"] = issueTextColor
	}
	logo, err := displayImageArg(issueLogo)
	if err != nil {
		return nil, err
	}
	if logo != "" {
		display["logo"] = logo
	}
	if issueLogoAlt != "" {
		display["logo_alt_text"] = issueLogoAlt
	}
	bg, err := displayImageArg(issueBackgroundImage)
	if err != nil {
		return nil, err
	}
	if bg != "" {
		display["background_image"] = bg
	}
	if len(display) > 0 {
		req["display"] = display
	}
	return req, nil
}

func resolveIssueClaimsForFormat(format string, tpl *credtemplate.Template) (map[string]any, error) {
	var overrides map[string]any
	if issueClaims != "" {
		var data []byte
		if strings.HasPrefix(issueClaims, "@") {
			var err error
			data, err = os.ReadFile(issueClaims[1:])
			if err != nil {
				return nil, fmt.Errorf("reading claims file: %w", err)
			}
		} else {
			data = []byte(issueClaims)
		}
		if err := json.Unmarshal(data, &overrides); err != nil {
			return nil, fmt.Errorf("parsing claims JSON: %w", err)
		}
	}

	if tpl != nil {
		return omitClaims(credtemplate.MergeClaims(tpl.Claims, overrides), issueOmit), nil
	}
	if overrides != nil {
		return omitClaims(overrides, issueOmit), nil
	}
	return omitClaims(mock.DefaultClaims, issueOmit), nil
}

// addIssueDisplayFlags registers the display flags shared by the issue
// subcommands. They set the OpenID4VCI §12.2.4 display of the imported
// credential, so they apply with --wallet.
func addIssueDisplayFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&issueDisplayName, "display-name", "", "With --wallet: the credential's display name")
	cmd.Flags().StringVar(&issueDisplayDescription, "display-description", "", "With --wallet: the credential's display description")
	cmd.Flags().StringVar(&issueBackgroundColor, "background-color", "", "With --wallet: the card background color, a CSS color (e.g. #3d59a1)")
	cmd.Flags().StringVar(&issueTextColor, "text-color", "", "With --wallet: the card text color, a CSS color")
	cmd.Flags().StringVar(&issueLogo, "logo", "", "With --wallet: the card logo, a file path, a data URI, or an http(s) URL")
	cmd.Flags().StringVar(&issueLogoAlt, "logo-alt", "", "With --wallet: the logo's alt text")
	cmd.Flags().StringVar(&issueBackgroundImage, "background-image", "", "With --wallet: the card background image, a file path, a data URI, or an http(s) URL")
}

func displayImageArg(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "data:") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return value, nil
	}
	data, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("reading display image %q: %w", value, err)
	}
	return "data:" + displayImageMIME(value, data) + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

func displayImageMIME(path string, data []byte) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	}
	return http.DetectContentType(data)
}

func addIssueTrustMetadataFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&issueTrustProfile, "trust-profile", "auto", "Trust-list profile for --wallet registration metadata: auto, pid, or local")
	cmd.Flags().StringSliceVar(&issueEntitlements, "entitlement", nil, "With --wallet: registrar entitlement URI to persist with the issued credential (repeatable)")
	cmd.Flags().StringVar(&issueTrustListType, "trust-list-type", "", "With --wallet: trust-list LoTE type to persist with the issued credential")
	cmd.Flags().StringVar(&issueStatusDetermination, "status-determination-approach", "", "With --wallet: trust-list status determination approach URI to persist with the issued credential")
	cmd.Flags().StringVar(&issueSchemeCommunityRule, "scheme-community-rule", "", "With --wallet: trust-list scheme community rule URI to persist with the issued credential")
	cmd.Flags().StringVar(&issueSchemeTerritory, "scheme-territory", "", "With --wallet: trust-list scheme territory to persist with the issued credential")
	cmd.Flags().StringVar(&issueTrustEntityName, "trust-entity-name", "", "With --wallet: trust-list entity name to persist with the issued credential")
	cmd.Flags().StringVar(&issueIssuanceServiceType, "issuance-service-type", "", "With --wallet: trust-list issuance service type identifier to persist with the issued credential")
	cmd.Flags().StringVar(&issueRevocationServiceType, "revocation-service-type", "", "With --wallet: trust-list revocation service type identifier to persist with the issued credential")
	cmd.Flags().StringVar(&issueIssuanceServiceName, "issuance-service-name", "", "With --wallet: trust-list issuance service name to persist with the issued credential")
	cmd.Flags().StringVar(&issueRevocationServiceName, "revocation-service-name", "", "With --wallet: trust-list revocation service name to persist with the issued credential")
}

func issueTrustSpecFromFlags() wallet.IssuedAttestationSpec {
	return wallet.IssuedAttestationSpec{
		Entitlements:                append([]string(nil), issueEntitlements...),
		TrustListType:               issueTrustListType,
		StatusDeterminationApproach: issueStatusDetermination,
		SchemeTypeCommunityRules:    issueSchemeCommunityRule,
		SchemeTerritory:             issueSchemeTerritory,
		EntityName:                  issueTrustEntityName,
		IssuanceServiceType:         issueIssuanceServiceType,
		RevocationServiceType:       issueRevocationServiceType,
		IssuanceServiceName:         issueIssuanceServiceName,
		RevocationServiceName:       issueRevocationServiceName,
	}
}

func parseNBF(val string) (*time.Time, error) {
	if val == "" {
		return nil, nil
	}
	if d, err := time.ParseDuration(val); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, fmt.Errorf("invalid --nbf value %q: expected RFC3339 (e.g. 2025-01-15T00:00:00Z) or duration (e.g. -1h)", val)
	}
	return &t, nil
}

func omitClaims(claims map[string]any, omit []string) map[string]any {
	if len(omit) == 0 {
		return claims
	}
	exclude := make(map[string]bool, len(omit))
	for _, name := range omit {
		exclude[strings.TrimSpace(name)] = true
	}
	result := make(map[string]any, len(claims))
	for k, v := range claims {
		if !exclude[k] {
			result[k] = v
		}
	}
	return result
}
