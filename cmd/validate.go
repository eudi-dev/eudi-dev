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
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/output"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
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

  - Signature verification (requires --key or --trust-list)
  - Expiry check (use --allow-expired to skip)
  - Revocation status via status list when the credential contains a status reference
  - With --haip, the rules HAIP 1.0 adds on top, reported without failing

If neither --key nor --trust-list is provided, signature verification is skipped
and only expiry/status checks are performed. This is useful for quick revocation
checks without needing the issuer's key.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVar(&keyFile, "key", "", "Public key file (PEM or JWK)")
	validateCmd.Flags().StringVar(&trustListFile, "trust-list", "", "ETSI trust list JWT (file path or URL)")
	validateCmd.Flags().BoolVar(&statusListFlag, "status-list", true, "Check revocation via status list when the credential contains a status reference")
	validateCmd.Flags().BoolVar(&allowExpired, "allow-expired", false, "Don't fail on expired credentials")
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

	var pubKeys []crypto.PublicKey

	if keyFile != "" {
		key, err := keys.LoadPublicKey(keyFile)
		if err != nil {
			return fmt.Errorf("loading key: %w", err)
		}
		pubKeys = append(pubKeys, key)
	}

	var tlCerts []trustlist.CertInfo
	if trustListFile != "" {
		tlRaw, err := format.ReadInput(trustListFile)
		if err != nil {
			return fmt.Errorf("reading trust list: %w", err)
		}
		tl, err := trustlist.Parse(tlRaw)
		if err != nil {
			return fmt.Errorf("parsing trust list: %w", err)
		}
		tlCerts = trustlist.ExtractPublicKeys(tl)
		for _, ci := range tlCerts {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	detected := format.Detect(raw)

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		output.PrintSDJWT(token, opts)

		if validateHAIP {
			printHAIPFindings(haipCredentialFindings(token), opts)
		}

		if bestResult, source, err := validate.VerifyJWTSignature(token, pubKeys, tlCerts); bestResult != nil {
			output.PrintVerifyResultSDJWT(bestResult, opts)
			printLeafSourceNote(source, opts)

			if !bestResult.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if bestResult.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else if err != nil {
			return err
		} else {
			if !opts.JSON {
				printSkippedSignatureNote(token)
			}
			if exp, ok := token.ResolvedClaims["exp"]; ok {
				if expFloat, ok := exp.(float64); ok {
					if time.Unix(int64(expFloat), 0).Before(time.Now()) {
						if !opts.JSON {
							fmt.Println("  ✗ Credential expired")
						}
						if !allowExpired {
							return fmt.Errorf("credential expired")
						}
					}
				}
			}
		}

		if statusListFlag {
			if err := checkStatus(token.ResolvedClaims, tlCerts, opts); err != nil {
				return err
			}
		}

	case format.FormatJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		output.PrintJWT(token, opts)

		if validateHAIP {
			printHAIPFindings(haipCredentialFindings(token), opts)
		}

		if bestResult, source, err := validate.VerifyJWTSignature(token, pubKeys, tlCerts); bestResult != nil {
			output.PrintVerifyResultSDJWT(bestResult, opts)
			printLeafSourceNote(source, opts)

			if !bestResult.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if bestResult.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else if err != nil {
			return err
		} else {
			if !opts.JSON {
				printSkippedSignatureNote(token)
			}
			if exp, ok := token.ResolvedClaims["exp"]; ok {
				if expFloat, ok := exp.(float64); ok {
					if time.Unix(int64(expFloat), 0).Before(time.Now()) {
						if !opts.JSON {
							fmt.Println("  ✗ Credential expired")
						}
						if !allowExpired {
							return fmt.Errorf("credential expired")
						}
					}
				}
			}
		}

		if statusListFlag {
			if err := checkStatus(token.ResolvedClaims, tlCerts, opts); err != nil {
				return err
			}
		}

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mdoc: %w", err)
		}
		output.PrintMDOC(doc, opts)

		if validateHAIP {
			certs, _ := validate.ExtractMDOCX5ChainCertificates(doc)
			printHAIPFindings(validate.HAIPCredentialChain(certs), opts)
		}

		leafKey, _ := validate.ExtractMDOCX5ChainLeafKey(doc)
		if len(pubKeys) > 0 {
			x5cKey, _ := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
			bestResult := verifyWithBestKey(pubKeys, x5cKey, func(key crypto.PublicKey) (*mdoc.VerifyResult, bool) {
				r := mdoc.Verify(doc, key)
				return r, r.SignatureValid
			})
			output.PrintVerifyResultMDOC(bestResult, opts)

			if !bestResult.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if bestResult.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else if leafKey != nil {
			result := mdoc.Verify(doc, leafKey)
			output.PrintVerifyResultMDOC(result, opts)
			printLeafSourceNote(validate.SourceX5CLeaf, opts)

			if !result.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if result.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else {
			if !opts.JSON {
				fmt.Println("\n  Signature verification skipped (no --key or --trust-list provided)")
			}
			if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.ValidityInfo != nil {
				if doc.IssuerAuth.MSO.ValidityInfo.ValidUntil != nil && doc.IssuerAuth.MSO.ValidityInfo.ValidUntil.Before(time.Now()) {
					if !opts.JSON {
						fmt.Println("  ✗ Credential expired")
					}
					if !allowExpired {
						return fmt.Errorf("credential expired")
					}
				}
			}
		}

		// ExtractStatusRef expects {"status": {"status_list": ...}} and
		// MSO.Status is the inner map.
		if statusListFlag && doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.Status != nil {
			if err := checkStatus(map[string]any{"status": doc.IssuerAuth.MSO.Status}, tlCerts, opts); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	return nil
}

// printLeafSourceNote explains a leaf-only verification so a green result is
// not mistaken for a trust statement.
func printLeafSourceNote(source string, opts output.Options) {
	if source == validate.SourceX5CLeaf && !opts.JSON {
		fmt.Println("  Note: verified with the credential's embedded certificate (chain not validated). Pass --trust-list to also validate trust.")
	}
}

// verifyWithBestKey verifies with x5cKey when the credential carries one,
// because the issuer bound the token to its embedded certificate. Otherwise
// it tries pubKeys and returns the first valid result, or the last one.
func verifyWithBestKey[T any](pubKeys []crypto.PublicKey, x5cKey crypto.PublicKey, verify func(crypto.PublicKey) (T, bool)) T {
	if x5cKey != nil {
		result, _ := verify(x5cKey)
		return result
	}
	var best T
	for _, key := range pubKeys {
		result, valid := verify(key)
		best = result
		if valid {
			break
		}
	}
	return best
}

func checkStatus(claims map[string]any, tlCerts []trustlist.CertInfo, opts output.Options) error {
	ref := statuslist.ExtractStatusRef(claims)
	if ref == nil {
		return nil
	}
	if ref.Invalid != "" {
		return fmt.Errorf("status check: %s", ref.Invalid)
	}

	checkOpts := statuslist.CheckOptions{}
	for _, ci := range tlCerts {
		if len(ci.Raw) > 0 {
			checkOpts.TrustListCerts = append(checkOpts.TrustListCerts, statuslist.TrustCert{Raw: ci.Raw})
		}
	}

	// Every failed section 8.3 step returns an error, so a printed status is
	// always covered by the verified signature.
	result, err := statuslist.CheckWithOptions(ref, checkOpts)
	if err != nil {
		return fmt.Errorf("status check: %w", err)
	}
	if opts.JSON {
		output.PrintJSON(result)
	} else {
		mark := "✗"
		if result.IsValid {
			mark = "✓"
		}
		fmt.Printf("\n  %s Status: %s (index %d, status=%d, %s)\n", mark, result.StatusName, result.Index, result.Status, strings.ToUpper(result.Format))
		fmt.Printf("  ✓ Status list signature: %s\n", result.SignatureInfo)
		for _, warning := range result.Warnings {
			fmt.Printf("  ! Status list: %s\n", warning)
		}
	}
	if !result.IsValid {
		return fmt.Errorf("credential status is %s", result.StatusName)
	}
	return nil
}

// HAIP 1.0 §6.1.1 requires the issuer's signing certificate and chain in x5c, excludes
// the trust anchor and forbids a self-signed leaf.
func haipCredentialFindings(token *sdjwt.Token) []string {
	return validate.HAIPCredentialFindings(token.Header, token.Payload)
}

// Report unsupported DID key resolution separately from a missing key so the user can
// identify the cause.
func printSkippedSignatureNote(token *sdjwt.Token) {
	kid, _ := token.Header["kid"].(string)
	iss, _ := token.Payload["iss"].(string)
	if did := keys.DIDReference(kid, iss); did != "" {
		fmt.Printf("\n  Signature verification skipped (the issuer key is named by the DID %s, which this tool does not resolve)\n", did)
		return
	}
	fmt.Println("\n  Signature verification skipped (no --key/--trust-list and issuer metadata resolution unavailable)")
}

// HAIP findings are informational here. Only signature, expiry and revocation checks
// affect the exit code.
func printHAIPFindings(findings []string, opts output.Options) {
	if opts.JSON {
		output.PrintJSON(map[string][]string{"haipFindings": append([]string{}, findings...)})
		return
	}
	if len(findings) == 0 {
		fmt.Println("\n  HAIP 1.0: no findings")
		return
	}
	fmt.Println("\n  HAIP 1.0 findings:")
	for _, f := range findings {
		fmt.Printf("    - %s\n", f)
	}
}
