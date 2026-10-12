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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
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
	issueCategory              string
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
	Args: cobra.NoArgs,
	RunE: showHelp,
}

var issueSDJWTCmd = &cobra.Command{
	Use:   "sdjwt",
	Short: "Generate a test SD-JWT credential",
	Long: "Generate a signed SD-JWT credential with selectively disclosable claims. " +
		"By default it prints a bare credential signed with an ephemeral P-256 key. --wallet issues into the managed wallet instead.",
	Args: cobra.NoArgs,
	RunE: runIssueSDJWT,
}

var issueJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate a test JWT VC credential",
	Long: "Generate a signed JWT VC credential with claims directly in the payload (no selective disclosure). " +
		"By default it prints a bare credential signed with an ephemeral P-256 key. --wallet issues into the managed wallet instead.",
	Args: cobra.NoArgs,
	RunE: runIssueJWT,
}

var issueMDOCCmd = &cobra.Command{
	Use:   "mdoc",
	Short: "Generate a test mdoc credential",
	Long: "Generate a signed mdoc (IssuerSigned) credential. " +
		"By default it prints a bare credential signed with an ephemeral P-256 key. --wallet issues into the managed wallet instead.",
	Args: cobra.NoArgs,
	RunE: runIssueMDOC,
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.PersistentFlags().StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory for --wallet, also the template location (default ~/.eudi-dev/wallet/)")
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
	issueSDJWTCmd.Flags().StringVar(&issueIssuer, "iss", mock.DefaultIssuer, "Issuer URL")
	issueSDJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueSDJWTCmd.Flags().StringVar(&issueExpires, "exp", credtemplate.DefaultExp.String(), "Expiration duration (e.g. 720h, 24h)")
	issueSDJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueSDJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueSDJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Claim names to omit from the resolved claim set (e.g. place_of_birth,sex)")
	issueSDJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueSDJWTCmd.Flags().IntVar(&issueBatchSize, "batch", 0, fmt.Sprintf("Issue a batch of this many distinct-key copies, at most %d (--wallet only), so the wallet presents an unused one each time", wallet.MaxBatchSize))
	issueSDJWTCmd.Flags().BoolVar(&issueUnbound, "unbound", false, "With --wallet: issue without a holder key (a bearer credential with no cnf). The default binds it to the wallet. Only a query with require_cryptographic_holder_binding false matches it")
	issueSDJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueSDJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueSDJWTCmd)
	addIssueDisplayFlags(issueSDJWTCmd)

	issueJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueJWTCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file, listed by 'templates list' (--claims overrides individual claims)")
	issueJWTCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK). Ephemeral P-256 if omitted")
	issueJWTCmd.Flags().StringVar(&issueCertPath, "cert", "", "Certificate chain file (PEM, leaf first) embedded as x5c. Requires --key")
	issueJWTCmd.Flags().StringVar(&issueIssuer, "iss", mock.DefaultIssuer, "Issuer URL")
	issueJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueJWTCmd.Flags().StringVar(&issueExpires, "exp", credtemplate.DefaultExp.String(), "Expiration duration (e.g. 720h, 24h)")
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
	issueMDOCCmd.Flags().StringVar(&issueCertPath, "cert", "", "Certificate chain file (PEM, leaf first) embedded as x5chain. Requires --key")
	issueMDOCCmd.Flags().StringVar(&issueDocType, "doc-type", credtemplate.DefaultDocType, "Document type")
	issueMDOCCmd.Flags().StringVar(&issueNamespace, "namespace", credtemplate.DefaultDocType, "Namespace")
	issueMDOCCmd.Flags().StringVar(&issueExpires, "exp", credtemplate.DefaultExp.String(), "Expiration duration (e.g. 720h, 24h)")
	issueMDOCCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueMDOCCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueMDOCCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Claim names to omit from the resolved claim set (e.g. place_of_birth,sex)")
	issueMDOCCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueMDOCCmd.Flags().IntVar(&issueBatchSize, "batch", 0, fmt.Sprintf("Issue a batch of this many distinct-key copies, at most %d (--wallet only), so the wallet presents an unused one each time", wallet.MaxBatchSize))
	issueMDOCCmd.Flags().BoolVar(&issueUnbound, "unbound", false, "With --wallet: issue without an MSO device key (a malformed mdoc for testing verifier rejection). The default binds it to the wallet. Only a query with require_cryptographic_holder_binding false matches it, and strict mode refuses to present it")
	issueMDOCCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueMDOCCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueMDOCCmd)
	addIssueDisplayFlags(issueMDOCCmd)

	for _, c := range []*cobra.Command{issueSDJWTCmd, issueJWTCmd, issueMDOCCmd} {
		_ = c.RegisterFlagCompletionFunc("template", completeTemplateNames)
		_ = c.RegisterFlagCompletionFunc("category", staticCompletion(append(credtemplate.Categories, provider.UnlistedCategory)...))
	}
	_ = issueCmd.RegisterFlagCompletionFunc("remote", completeRemoteFlag)
	_ = issueCmd.MarkPersistentFlagDirname("wallet-dir")
	_ = issueCmd.MarkPersistentFlagDirname("templates-dir")
}

// issueWalletOnlyFlags shape what the managed wallet stores or how it
// signs. A bare credential has no use for them.
var issueWalletOnlyFlags = []string{
	"remote", "seed", "batch", "unbound", "category", "entitlement",
	"trusted-list-type", "status-determination-approach", "scheme-community-rule", "scheme-territory",
	"trusted-entity-name", "issuance-service-type", "revocation-service-type", "issuance-service-name", "revocation-service-name",
	"display-name", "display-description", "background-color", "text-color", "logo", "logo-alt", "background-image",
}

func refuseWalletOnlyFlags(cmd *cobra.Command) error {
	var set []string
	for _, name := range issueWalletOnlyFlags {
		if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
			set = append(set, "--"+name)
		}
	}
	switch len(set) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%s applies only with --wallet", set[0])
	}
	return fmt.Errorf("%s apply only with --wallet", strings.Join(set, ", "))
}

func runIssueSDJWT(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueSDJWTToWallet(cmd)
	}
	if err := refuseWalletOnlyFlags(cmd); err != nil {
		return err
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	resolved, err := resolveStandaloneIssue(cmd, "sdjwt")
	if err != nil {
		return err
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
		VCT:             resolved.VCT,
		ExpiresIn:       resolved.Exp,
		NotBefore:       nbf,
		Claims:          resolved.CredentialClaims(),
		Key:             key,
		StatusListURI:   issueStatusListURI,
		StatusListIdx:   issueStatusListIdx,
		AlwaysDisclosed: resolved.AlwaysDisclosed,
		CertChain:       certChain,
		KeepTrustAnchor: issueCertPath != "",
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating SD-JWT: %w", err)
	}

	printIssuedCredential(result, "")

	return saveIssueTemplate(resolved)
}

func runIssueJWT(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueJWTToWallet(cmd)
	}
	if err := refuseWalletOnlyFlags(cmd); err != nil {
		return err
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	resolved, err := resolveStandaloneIssue(cmd, "jwt")
	if err != nil {
		return err
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
		VCT:           resolved.VCT,
		ExpiresIn:     resolved.Exp,
		NotBefore:     nbf,
		Claims:        resolved.CredentialClaims(),
		Key:           key,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
		CertChain:     certChain,
	}

	result, err := mock.GenerateJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating JWT: %w", err)
	}

	printIssuedCredential(result, "")

	return saveIssueTemplate(resolved)
}

func runIssueMDOC(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueMDOCToWallet(cmd)
	}
	if err := refuseWalletOnlyFlags(cmd); err != nil {
		return err
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	resolved, err := resolveStandaloneIssue(cmd, "mdoc")
	if err != nil {
		return err
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
		DocType:         resolved.DocType,
		Namespace:       resolved.Namespace,
		Claims:          resolved.CredentialClaims(),
		Key:             key,
		ExpiresIn:       resolved.Exp,
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

	printIssuedCredential(result, "")

	return saveIssueTemplate(resolved)
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
	if format != "jwt" && len(certchain.WithoutSelfSignedAnchor(chain)) != len(chain) {
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
		w.OverrideURLs(w.BaseURL, strings.TrimRight(strings.TrimSpace(issueIssuer), "/"))
	} else if strings.TrimSpace(w.IssuerURL) == "" || (registeredWalletListenerPort() > 0 && isLocalhostIssuerURL(w.IssuerURL)) {
		origin, _ := walletOrigin(defaultWalletCommandPort(), "", false)
		w.OverrideURLs(w.BaseURL, origin.Issuer)
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
	if _, ok := svc.(*remoteWallet); ok {
		if err := refuseLocalIssuerFlags(cmd, svc.URL()); err != nil {
			return err
		}
	}
	result, err := svc.Issue(req)
	if err != nil {
		return err
	}
	printIssuedCredential(docString(result, "raw"), docString(result, "id"))
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

// refuseLocalIssuerFlags reports the flags a wallet server can't apply. The
// server signs with its own issuer URL and key. Only a key sent with its
// --cert chain overrides them.
func refuseLocalIssuerFlags(cmd *cobra.Command, target string) error {
	var set []string
	if cmd.Flags().Changed("iss") {
		set = append(set, "--iss")
	}
	if issueKeyPath != "" && issueCertPath == "" {
		set = append(set, "--key without --cert")
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("the wallet at %s issues with its own issuer URL and key, so it can't use %s. Pass --key with --cert to sign with your own key, or add --remote local to use the local store", target, strings.Join(set, ", "))
}

// printIssuedCredential prints the bare credential. With --json it prints
// {"credential", "id"}, and leaves out id for a credential the wallet did not store.
func printIssuedCredential(raw, id string) {
	doc := map[string]any{"credential": raw}
	if id != "" {
		doc["id"] = id
	}
	printResult(doc, func() { fmt.Println(raw) })
}

// resolveStandaloneIssue applies the flags to their template. A flag the user
// set wins over the template, and the template over the defaults. With --pid
// and no --claims, --vct selects the built-in PID template. It serves only
// as a claim set, so `issue jwt --pid` uses the SD-JWT PID claims.
func resolveStandaloneIssue(cmd *cobra.Command, format string) (credtemplate.Resolved, error) {
	overrides, err := parseClaimsArg(issueClaims)
	if err != nil {
		return credtemplate.Resolved{}, err
	}
	req := credtemplate.Request{
		Format: format, Claims: overrides, Omit: issueOmit, AlwaysDisclosed: issueAlwaysDisclosed,
	}
	flags := cmd.Flags()
	changed := func(name string) bool { return flags.Lookup(name) != nil && flags.Changed(name) }
	if changed("vct") {
		req.VCT = issueVCT
	}
	if changed("doc-type") {
		req.DocType = issueDocType
	}
	if changed("namespace") {
		req.Namespace = issueNamespace
	}
	if changed("exp") {
		if req.Exp, err = time.ParseDuration(issueExpires); err != nil {
			return credtemplate.Resolved{}, fmt.Errorf("invalid --exp duration: %w", err)
		}
	}

	var tpl *credtemplate.Template
	if issueTemplate != "" || (issuePID && issueClaims == "") {
		loc, err := resolveTemplates()
		if err != nil {
			return credtemplate.Resolved{}, err
		}
		name := issueTemplate
		if name == "" {
			req.ClaimSet = true
			sdName, mdocName, _ := credtemplate.PIDTemplateNames(issueVCT, loc)
			name = sdName
			if format == "mdoc" {
				name = mdocName
			}
		}
		if tpl, err = credtemplate.Load(name, loc); err != nil {
			return credtemplate.Resolved{}, err
		}
	}
	return credtemplate.Resolve(tpl, req)
}

// parseClaimsArg reads a --claims value, a JSON object or @file. An empty
// value means no claims.
func parseClaimsArg(arg string) (map[string]any, error) {
	if arg == "" {
		return nil, nil
	}
	data := []byte(arg)
	if strings.HasPrefix(arg, "@") {
		var err error
		if data, err = os.ReadFile(arg[1:]); err != nil {
			return nil, fmt.Errorf("reading claims file: %w", err)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims JSON: %w", err)
	}
	return claims, nil
}

func saveIssueTemplate(resolved credtemplate.Resolved) error {
	if issueSaveTemplate == "" {
		return nil
	}
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	path, err := svc.SaveTemplate(resolved.Template(issueSaveTemplate))
	if err != nil {
		return fmt.Errorf("saving template: %w", err)
	}
	if path == "" {
		path = svc.URL()
	}
	fmt.Fprintf(os.Stderr, "Saved template %q to %s\n", issueSaveTemplate, path)
	return nil
}

// issueAPIRequestFromFlags builds the shared POST /api/issue request. Templates resolve
// on the managed wallet, so send only the name and explicit overrides.
func issueAPIRequestFromFlags(cmd *cobra.Command, format string) (wallet.IssueAPIRequest, error) {
	req := wallet.IssueAPIRequest{Format: format}
	keyData, certData, err := readSigningOverrideFiles()
	if err != nil {
		return req, err
	}
	if certData != "" {
		if _, _, err := wallet.ParseSigningOverride(keyData, certData); err != nil {
			return req, err
		}
		req.SigningKey, req.SigningCert = keyData, certData
	}
	if req.Claims, err = parseClaimsArg(issueClaims); err != nil {
		return req, err
	}
	req.Template = issueTemplate
	req.PID = issuePID
	req.Omit = issueOmit
	req.AlwaysDisclosed = issueAlwaysDisclosed
	req.SaveAsTemplate = issueSaveTemplate
	flags := cmd.Flags()
	if flags.Changed("vct") {
		req.VCT = issueVCT
	}
	if flags.Lookup("doc-type") != nil && flags.Changed("doc-type") {
		req.DocType = issueDocType
	}
	if flags.Lookup("namespace") != nil && flags.Changed("namespace") {
		req.Namespace = issueNamespace
	}
	if flags.Changed("exp") {
		req.Exp = issueExpires
	}
	req.NBF = issueNBF
	if flags.Changed("batch") {
		req.Batch = issueBatchSize
	}
	req.Unbound = issueUnbound
	if flags.Changed("status-list-uri") {
		req.StatusListURI = &issueStatusListURI
	}
	if flags.Changed("status-list-idx") {
		req.StatusListIdx = &issueStatusListIdx
	}
	req.Category = issueCategory
	// The server fills in Format, VCT, DocType and the list fields of the
	// category, so an empty trust object works like an omitted one.
	req.Trust = issueTrustSpecFromFlags()

	display := wallet.IssueDisplay{
		Name:            issueDisplayName,
		Description:     issueDisplayDescription,
		BackgroundColor: issueBackgroundColor,
		TextColor:       issueTextColor,
		LogoAltText:     issueLogoAlt,
	}
	if display.Logo, err = displayImageArg(issueLogo); err != nil {
		return req, err
	}
	if display.BackgroundImage, err = displayImageArg(issueBackgroundImage); err != nil {
		return req, err
	}
	if display != (wallet.IssueDisplay{}) {
		req.Display = &display
	}
	return req, nil
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
	if mediaType, ok := format.ImageMediaType(path); ok {
		return mediaType
	}
	return http.DetectContentType(data)
}

func addIssueTrustMetadataFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&issueCategory, "category", "", "With --wallet: credential category (it selects the signer and the trusted list): pid, qeaa, pub-eaa or eaa (default the category of the template or the catalogue entry, else eaa). unlisted keeps it off every list")
	cmd.Flags().StringSliceVar(&issueEntitlements, "entitlement", nil, "With --wallet: registrar entitlement URI to persist with the issued credential (repeatable)")
	cmd.Flags().StringVar(&issueTrustListType, "trusted-list-type", "", "With --wallet: trusted list LoTE type to persist with the issued credential")
	cmd.Flags().StringVar(&issueStatusDetermination, "status-determination-approach", "", "With --wallet: trusted list status determination approach URI to persist with the issued credential")
	cmd.Flags().StringVar(&issueSchemeCommunityRule, "scheme-community-rule", "", "With --wallet: trusted list scheme community rule URI to persist with the issued credential")
	cmd.Flags().StringVar(&issueSchemeTerritory, "scheme-territory", "", "With --wallet: trusted list scheme territory to persist with the issued credential")
	cmd.Flags().StringVar(&issueTrustEntityName, "trusted-entity-name", "", "With --wallet: trusted list entity name to persist with the issued credential")
	cmd.Flags().StringVar(&issueIssuanceServiceType, "issuance-service-type", "", "With --wallet: trusted list issuance service type identifier to persist with the issued credential")
	cmd.Flags().StringVar(&issueRevocationServiceType, "revocation-service-type", "", "With --wallet: trusted list revocation service type identifier to persist with the issued credential")
	cmd.Flags().StringVar(&issueIssuanceServiceName, "issuance-service-name", "", "With --wallet: trusted list issuance service name to persist with the issued credential")
	cmd.Flags().StringVar(&issueRevocationServiceName, "revocation-service-name", "", "With --wallet: trusted list revocation service name to persist with the issued credential")
}

func issueTrustSpecFromFlags() provider.IssuedAttestationSpec {
	return provider.IssuedAttestationSpec{
		Entitlements: append([]string(nil), issueEntitlements...),
		Scheme: lote.Scheme{
			LoTEType:                    issueTrustListType,
			StatusDeterminationApproach: issueStatusDetermination,
			SchemeTypeCommunityRules:    issueSchemeCommunityRule,
			SchemeTerritory:             issueSchemeTerritory,
			EntityName:                  issueTrustEntityName,
			IssuanceServiceType:         issueIssuanceServiceType,
			RevocationServiceType:       issueRevocationServiceType,
			IssuanceServiceName:         issueIssuanceServiceName,
			RevocationServiceName:       issueRevocationServiceName,
		},
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
