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
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/output"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

var (
	keyFile        string
	trustListFile  string
	statusListFlag bool
	allowExpired   bool
	validateHAIP   bool
)

var validateCmd = &cobra.Command{
	Use:   "validate [input]",
	Short: "Validate a credential (signature, expiry, revocation)",
	Long: `Decode and validate a credential. Unlike 'decode' (which only parses and displays),
'validate' actively checks correctness:

  - Type header and disclosure digests
  - Signature verification (with --key or --trusted-list, else the embedded certificate or issuer metadata)
  - Validity period (use --allow-expired to skip)
  - Revocation status via status list when the credential contains a status reference
  - With --haip, the rules HAIP 1.0 adds on top, reported without failing

If neither --key nor --trusted-list is provided and the credential carries no
usable key, signature verification is skipped and the other checks still run.
This is useful for quick revocation checks without the issuer's key.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVar(&keyFile, "key", "", "Public key file (PEM or JWK)")
	validateCmd.Flags().StringVar(&trustListFile, "trusted-list", "", "ETSI trusted list JWT (file path or URL)")
	validateCmd.Flags().BoolVar(&statusListFlag, "status-list", true, "Check revocation via status list when the credential contains a status reference")
	validateCmd.Flags().BoolVar(&allowExpired, "allow-expired", false, "Don't fail on credentials outside their validity period")
	validateCmd.Flags().BoolVar(&validateHAIP, "haip", false, "Also check the credential against HAIP 1.0 and report what it breaks")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	raw, err := format.ReadInput(input)
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	trust, err := validateTrust()
	if err != nil {
		return err
	}
	result, err := validate.Credential(raw, trust, validate.Options{Status: statusListFlag, HAIP: validateHAIP})
	if err != nil {
		return err
	}
	var report jsonReport
	if opts.JSON {
		report = credentialReport(result)
		defer output.PrintJSON(report)
	} else {
		printCredential(result, opts)
	}
	printValidation(result, opts, report)
	return validationError(result)
}

// validateTrust reads the supplied key and trusted list, and the stored
// wallet when it exists. Its catalogue anchors credentials and its HTTP client
// fetches remote documents. validate creates no wallet.
func validateTrust() (validate.Trust, error) {
	var trust validate.Trust
	w, err := storedWallet()
	if err != nil {
		trust.CatalogueErr = err
	} else if w != nil {
		trust.Catalogue = w
		trust.HTTPClient = w.HTTPClient()
	}

	if keyFile != "" {
		key, err := keys.LoadPublicKey(keyFile)
		if err != nil {
			return trust, fmt.Errorf("loading key: %w", err)
		}
		trust.AddKey(key)
	}
	if trustListFile != "" {
		tlRaw, err := format.ReadInput(trustListFile, trust.HTTPClient)
		if err != nil {
			return trust, fmt.Errorf("reading trusted list: %w", err)
		}
		if err := trust.AddTrustedList(tlRaw, time.Now()); err != nil {
			return trust, err
		}
	}
	return trust, nil
}

// storedWallet loads the wallet of the store when it exists.
func storedWallet() (*wallet.Wallet, error) {
	store, err := openStore()
	if err != nil {
		return nil, err
	}
	if exists, err := store.Exists(); err != nil || !exists {
		return nil, err
	}
	w, _, err := loadWallet()
	return w, err
}

func credentialReport(result *validate.Result) jsonReport {
	switch result.Format {
	case validate.FormatSDJWT:
		return output.BuildSDJWTJSON(result.SDJWT)
	case validate.FormatJWT:
		return output.BuildJWTJSON(result.SDJWT)
	}
	return output.BuildMDOCJSON(result.MDOC)
}

func printCredential(result *validate.Result, opts output.Options) {
	switch result.Format {
	case validate.FormatSDJWT:
		output.PrintSDJWT(result.SDJWT, opts)
	case validate.FormatJWT:
		output.PrintJWT(result.SDJWT, opts)
	default:
		output.PrintMDOC(result.MDOC, opts)
	}
}

// printValidation prints the checks of the result in text mode, or adds them
// to the JSON report.
func printValidation(result *validate.Result, opts output.Options, report jsonReport) {
	report.add("checks", result.Checks, func() {})
	if result.HAIPFindings != nil {
		printHAIPFindings(result.HAIPFindings, report)
	}
	for _, name := range []string{validate.CheckType, validate.CheckIntegrity, validate.CheckTrustedList} {
		if c, ok := result.Find(name); ok && (c.Status == validate.Fail || c.Status == validate.Warning) {
			report.text(func() { printCheck(c) })
		}
	}

	switch {
	case result.SDJWTVerify != nil:
		report.add("verification", result.SDJWTVerify, func() { output.PrintVerifyResultSDJWT(result.SDJWTVerify, opts) })
	case result.MDOCVerify != nil:
		report.add("verification", result.MDOCVerify, func() { output.PrintVerifyResultMDOC(result.MDOCVerify, opts) })
	}
	if sig, ok := result.Find(validate.CheckSignature); ok {
		report.text(func() {
			switch {
			case sig.Status == validate.Skipped:
				fmt.Printf("\n  Signature verification skipped: %s\n", sig.Detail)
			case sig.Status == validate.Fail:
				printCheck(sig)
			case result.SignatureSource == validate.SourceX5CLeaf:
				// A green leaf result is no trust statement.
				fmt.Println("  Note: verified with the credential's embedded certificate (chain not validated). Pass --trusted-list to also validate trust.")
			}
		})
	}
	// The verification printer shows the validity period with the signature.
	if c, ok := result.Find(validate.CheckExpiry); ok && (c.Status == validate.Warning || (c.Status == validate.Fail && result.SDJWTVerify == nil && result.MDOCVerify == nil)) {
		report.text(func() { printCheck(c) })
	}

	if result.Catalogue != nil {
		reportCatalogueTrust(*result.Catalogue, report)
	} else if c, ok := result.Find(validate.CheckTrust); ok && c.Status == validate.Fail {
		report.text(func() { printCheck(c) })
	}

	if result.Status != nil {
		status := result.Status
		sig, _ := result.Find(validate.CheckStatusSignature)
		report.add("status", status, func() {
			mark := "✗"
			if status.IsValid {
				mark = "✓"
			}
			fmt.Printf("\n  %s Status: %s (index %d, status=%d, %s)\n", mark, status.StatusName, status.Index, status.Status, strings.ToUpper(status.Format))
			if sig.Status == validate.Pass {
				fmt.Printf("  ✓ Status list signature: %s\n", status.SignatureInfo)
			} else if status.IsValid {
				fmt.Printf("  ! Status list signature: %s (not anchored by a trusted list)\n", status.SignatureInfo)
			}
			for _, warning := range slices.Concat(status.Warnings, status.HAIPFindings) {
				fmt.Printf("  ! Status list: %s\n", warning)
			}
		})
	} else if c, ok := result.Find(validate.CheckStatus); ok && (c.Status == validate.Fail || c.Status == validate.Warning) {
		report.text(func() { printCheck(c) })
	}
}

func printCheck(c validate.Check) {
	mark := "✗"
	if c.Status == validate.Warning {
		mark = "!"
	}
	fmt.Printf("  %s %s: %s\n", mark, c.Name, c.Detail)
}

// validationError fails on the credential's own checks. The catalogue trust
// and HAIP checks are informational.
func validationError(result *validate.Result) error {
	failing := []string{validate.CheckType, validate.CheckIntegrity, validate.CheckSignature, validate.CheckExpiry, validate.CheckStatus}
	for _, c := range result.Checks {
		if c.Status != validate.Fail || !slices.Contains(failing, c.Name) {
			continue
		}
		if c.Name == validate.CheckExpiry && allowExpired {
			continue
		}
		return fmt.Errorf("%s: %s", c.Name, c.Detail)
	}
	return nil
}

// reportCatalogueTrust reports the catalogue result. It is informational and
// leaves the exit code alone.
func reportCatalogueTrust(anchoring wallet.CatalogueAnchoring, report jsonReport) {
	report.add("trust", anchoring, func() {
		switch {
		case anchoring.AnchoredBy != "":
			fmt.Printf("  ✓ Trust: %s (%s)\n", anchoring.Anchor(validate.ServiceIssuance), anchoring.AnchoredBy)
		case len(anchoring.Findings) > 0:
			for _, f := range anchoring.Findings {
				fmt.Printf("  ✗ %s\n", f)
			}
		default:
			fmt.Println("  – No readable trusted list in the catalogue")
			for _, w := range anchoring.Warnings {
				fmt.Printf("  ! %s\n", w)
			}
		}
	})
}

// HAIP findings are informational here. Only the credential's own checks
// affect the exit code.
func printHAIPFindings(findings []string, report jsonReport) {
	report.add("haipFindings", append([]string{}, findings...), func() {
		if len(findings) == 0 {
			fmt.Println("\n  HAIP 1.0: no findings")
			return
		}
		fmt.Println("\n  HAIP 1.0 findings:")
		for _, f := range findings {
			fmt.Printf("    - %s\n", f)
		}
	})
}

// jsonReport collects one validation as a JSON document. It is nil in text
// mode.
type jsonReport map[string]any

func (r jsonReport) add(key string, v any, printText func()) {
	if r == nil {
		printText()
		return
	}
	r[key] = v
}

// text prints only in text mode.
func (r jsonReport) text(printText func()) {
	if r == nil {
		printText()
	}
}
