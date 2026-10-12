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
	"strings"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/output"
	"github.com/eudi-dev/eudi-dev/v3/internal/qr"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
	"github.com/eudi-dev/eudi-dev/v3/internal/web"
)

var (
	decodeQRSource string
	decodeQRScreen bool
	decodeFormat   string
)

var decodeCmd = &cobra.Command{
	Use:   "decode [input]",
	Short: "Auto-detect and decode credentials and OpenID4VCI/VP requests",
	Long: `Decode and inspect verifiable credentials (JWT, SD-JWT, mdoc), OpenID4VCI/VP requests, and ETSI trusted lists.

This is a read-only inspection tool. It parses and displays the content and runs
the checks of the web decoder. It verifies the signature with the embedded
certificate or the issuer metadata. Use 'validate' for explicit keys, trusted
lists, and revocation checks.

Accepts:
  - Credential strings: SD-JWT, JWT, mdoc (hex or base64url)
  - URI schemes: openid-credential-offer://, haip-vci://, eu-eaa-offer://, openid4vp://, haip-vp://, eudi-openid4vp://
  - HTTPS URLs with OID4 query parameters
  - JWT request objects (OID4VP, trusted lists)
  - Raw JSON
  - File paths
  - Stdin (pipe or use -)
  - QR code from image file (--qr) or screen capture (--screen)

Auto-detects the format. Use --format to override detection.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDecode,
}

func init() {
	decodeCmd.Flags().StringVar(&decodeQRSource, "qr", "", "Scan a QR code from an image file")
	decodeCmd.Flags().BoolVar(&decodeQRScreen, "screen", false, "Scan a QR code from a screen capture")
	decodeCmd.Flags().StringVarP(&decodeFormat, "format", "f", "", "Pin the format instead of auto-detecting: sdjwt, jwt, mdoc, vci, vp, trusted-list")
	rootCmd.AddCommand(decodeCmd)
}

var formatAliases = map[string]format.CredentialFormat{
	"sdjwt":             format.FormatSDJWT,
	"sd-jwt":            format.FormatSDJWT,
	"jwt":               format.FormatJWT,
	"mdoc":              format.FormatMDOC,
	credtype.FormatMDOC: format.FormatMDOC,
	"vci":               format.FormatOID4VCI,
	"oid4vci":           format.FormatOID4VCI,
	"vp":                format.FormatOID4VP,
	"oid4vp":            format.FormatOID4VP,
	"trusted-list":      format.FormatTrustList,
	"trust":             format.FormatTrustList,
}

func runDecode(cmd *cobra.Command, args []string) error {
	if decodeQRSource != "" && decodeQRScreen {
		return fmt.Errorf("cannot use --qr and --screen together")
	}
	if (decodeQRSource != "" || decodeQRScreen) && len(args) > 0 {
		return fmt.Errorf("cannot use --qr/--screen together with a positional argument")
	}

	var raw string
	var err error

	if decodeQRScreen {
		raw, err = qr.ScanScreen()
	} else if decodeQRSource != "" {
		raw, err = qr.ScanFile(decodeQRSource)
	} else {
		input := ""
		if len(args) > 0 {
			input = args[0]
		}
		raw, err = format.ReadInputRaw(input)
	}
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	var detected format.CredentialFormat
	if decodeFormat != "" {
		if strings.EqualFold(decodeFormat, "trustlist") {
			return fmt.Errorf("--format trustlist: renamed to --format trusted-list in 3.0.0")
		}
		f, ok := formatAliases[strings.ToLower(decodeFormat)]
		if !ok {
			return fmt.Errorf("unknown format %q (valid: sdjwt, jwt, mdoc, vci, vp, trusted-list)", decodeFormat)
		}
		detected = f
	} else {
		detected = format.Detect(raw)
	}

	if detected != format.FormatOID4VCI && detected != format.FormatOID4VP && format.IsWebURL(raw) {
		raw, err = format.FetchURL(raw)
		if err != nil {
			return err
		}
		if decodeFormat == "" {
			detected = format.Detect(raw)
		}
	}

	switch detected {
	case format.FormatSDJWT, format.FormatJWT, format.FormatMDOC:
		return decodeCredential(raw, opts)

	case format.FormatOID4VCI, format.FormatOID4VP:
		return decodeOID4(raw, opts)

	case format.FormatTrustList:
		return decodeTrustList(raw, opts)

	default:
		return fmt.Errorf("unable to auto-detect format (not a credential, OpenID4VCI/VP request, or trusted list)")
	}
}

func decodeOID4(raw string, opts output.Options) error {
	reqType, result, err := oid4vc.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing OpenID request: %w", err)
	}

	switch reqType {
	case oid4vc.TypeVCI:
		offer, ok := result.(*oid4vc.CredentialOffer)
		if !ok {
			return fmt.Errorf("unexpected result type for VCI: %T", result)
		}
		output.PrintCredentialOffer(offer, opts)
	case oid4vc.TypeVP:
		req, ok := result.(*oid4vc.AuthorizationRequest)
		if !ok {
			return fmt.Errorf("unexpected result type for VP: %T", result)
		}
		output.PrintAuthorizationRequest(req, opts)
	}

	return nil
}

func decodeTrustList(raw string, opts output.Options) error {
	tl, err := lote.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing trusted list: %w", err)
	}
	output.PrintTrustList(tl, opts)
	return nil
}

// decodeCredential runs the decoder's validation, so text and JSON report the
// same checks. Validation keeps malformed credentials visible and records
// their deviations as failed checks.
func decodeCredential(raw string, opts output.Options) error {
	if opts.JSON {
		result, err := web.Validate(raw, web.ValidateOpts{})
		if err != nil {
			return err
		}
		output.PrintJSON(result)
		return nil
	}
	result, err := validate.Credential(raw, validate.Trust{}, validate.Options{})
	if err != nil {
		return err
	}
	printCredential(result, opts)
	fmt.Println("\n  Checks:")
	for _, c := range result.Checks {
		fmt.Printf("    %s %s: %s\n", checkMark(c.Status), c.Name, c.Detail)
	}
	return nil
}

func checkMark(status string) string {
	switch status {
	case validate.Pass:
		return "✓"
	case validate.Fail:
		return "✗"
	case validate.Warning:
		return "!"
	}
	return "–"
}
