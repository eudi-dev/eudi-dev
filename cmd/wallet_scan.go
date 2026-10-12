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
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v2/internal/qr"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

// The terminal prompt fetches the offer to learn whether a transaction code is
// required. Return that copy so issuance can reuse it if the issuer serves the URI
// only once. Prompt failures leave the code empty for the flow to report.
func resolveTxCode(uri, given string, client *http.Client) (string, *oid4vc.CredentialOffer) {
	if strings.TrimSpace(given) != "" {
		return given, nil
	}
	if !isCredentialOfferURI(uri) || !stdinIsTerminal() {
		return given, nil
	}
	reqType, parsed, err := oid4vc.ParseWithOptions(uri, oid4vc.ParseOptions{HTTPClient: client})
	if err != nil || reqType != oid4vc.TypeVCI {
		return given, nil
	}
	offer, ok := parsed.(*oid4vc.CredentialOffer)
	if !ok {
		return given, nil
	}
	if len(offer.Grants.TxCode) == 0 {
		return given, offer
	}

	prompt := "Transaction code"
	if hint := describeTxCodePrompt(offer.Grants.TxCode); hint != "" {
		prompt += " (" + hint + ")"
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return given, offer
	}
	return strings.TrimSpace(line), offer
}

func describeTxCodePrompt(txCode map[string]any) string {
	if description, _ := txCode["description"].(string); strings.TrimSpace(description) != "" {
		return strings.TrimSpace(description)
	}
	mode, _ := txCode["input_mode"].(string)
	length := 0
	switch n := txCode["length"].(type) {
	case float64:
		length = int(n)
	case int:
		length = n
	}
	switch {
	case length > 0 && mode != "":
		return fmt.Sprintf("%d %s characters", length, mode)
	case length > 0:
		return fmt.Sprintf("%d characters", length)
	default:
		return mode
	}
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Choose the wallet before fetching the URI. Reading an offer here could consume it
// before the selected wallet starts issuance. Both accept and scan use this route. See
// docs/adr/0012-every-entry-point-runs-the-same-flow.md.
func acceptOID4URI(uri string, opts dispatchOID4Opts) error {
	if _, err := wallet.ParseKeyAttestationLevel(opts.keyAttestationLevel); err != nil {
		return fmt.Errorf("--key-attestation-level: %w", err)
	}
	c, err := remoteClientIfConfigured()
	if err != nil {
		return err
	}
	if c != nil {
		if err := checkRemoteOutboundFlags(); err != nil {
			return err
		}
		// The selected wallet fetches the offer and collects the transaction code.
		// Some offers can be fetched only once.
		return remoteAccept(c, uri, opts.txCode, !opts.autoAccept)
	}
	w := &wallet.Wallet{}
	if err := applyValidationMode(w, opts.mode); err != nil {
		return err
	}
	if err := applyWalletOutbound(w); err != nil {
		return err
	}
	defer w.HTTPClient().CloseIdleConnections()
	opts.txCode, opts.resolvedOffer = resolveTxCode(uri, opts.txCode, w.HTTPClient())
	return dispatchURI(uri, opts)
}

func walletAcceptCmd() *cobra.Command {
	var (
		port                int
		autoAccept          bool
		sessionTranscript   string
		txCode              string
		haip                bool
		docker              bool
		keyAttestationLevel string
	)

	cmd := &cobra.Command{
		Use:   "accept <uri>",
		Short: "Accept and process an OID4VP presentation request or OID4VCI credential offer",
		Long: `Auto-detects the URI type and dispatches to the appropriate flow:

  - openid4vp://, haip-vp://, eudi-openid4vp://     →  OID4VP presentation
  - openid-credential-offer://, haip-vci://, eu-eaa-offer:// → OID4VCI credential issuance

For OID4VP requests, the wallet evaluates the DCQL query, shows a consent UI
(unless --auto-accept), and submits a VP token to the verifier.

For OID4VCI offers, the wallet fetches the credential from the issuer and
stores it locally. A running wallet server reloads the same wallet store at
request boundaries, so later presentation requests see the new credential.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return acceptOID4URI(args[0], dispatchOID4Opts{
				port:                port,
				portExplicit:        cmd.Flags().Changed("port"),
				autoAccept:          autoAccept,
				sessionTranscript:   sessionTranscript,
				txCode:              txCode,
				haip:                haip,
				mode:                walletValidationMode,
				docker:              docker,
				keyAttestationLevel: keyAttestationLevel,
			})
		},
	}

	cmd.Flags().StringVar(&keyAttestationLevel, "key-attestation-level", "", "What the key attestation claims as key_storage and user_authentication (OpenID4VCI Appendix D.2): whatever the issuer requires (default), 'none', or one of iso_18045_high, iso_18045_moderate, iso_18045_enhanced-basic, iso_18045_basic for both. The wallet holds its keys in files and can prove none of them. A running wallet server applies its own setting")
	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Server port for OID4VP (serves trust list and consent UI)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Auto-approve OID4VP presentations")
	cmd.Flags().BoolVar(&docker, "docker", false, "Serve the trust and status lists under host.docker.internal so a verifier in a container reaches them")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mdoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().StringVar(&txCode, "tx-code", "", "Transaction code for OID4VCI pre-authorized code flow")
	cmd.Flags().BoolVar(&haip, "haip", false, "Enforce HAIP 1.0 on presentations (x509_hash, direct_post.jwt, DCQL, JAR, ES256) and on credential offers (https issuer, and authorization code offers also need PAR, PKCE S256, DPoP, client auth)")
	return cmd
}

func walletScanCmd() *cobra.Command {
	var (
		port                int
		screen              bool
		autoAccept          bool
		sessionTranscript   string
		txCode              string
		haip                bool
		docker              bool
		keyAttestationLevel string
	)

	cmd := &cobra.Command{
		Use:   "scan [image-file]",
		Short: "Scan a QR code and auto-detect the flow (accept/import)",
		Long: "Reads a QR code from an image file, or with --screen from an interactive screen capture, " +
			"and dispatches its content like `wallet accept`: a presentation request or credential offer runs " +
			"that flow, a raw credential is imported.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var content string
			var err error

			if screen {
				content, err = qr.ScanScreen()
			} else if len(args) > 0 {
				content, err = qr.ScanFile(args[0])
			} else {
				return fmt.Errorf("provide an image file or use --screen")
			}

			if err != nil {
				return fmt.Errorf("scanning QR: %w", err)
			}

			fmt.Printf("Scanned: %s\n\n", content)

			detected := format.Detect(content)

			if detected == format.FormatSDJWT || detected == format.FormatMDOC || detected == format.FormatJWT {
				svc, err := managedWallet()
				if err != nil {
					return err
				}
				imported, err := svc.ImportCredential(content)
				if err != nil {
					return err
				}
				fmt.Printf("Imported %s credential (%s)\n", docString(imported, "format"), docCredLabel(imported))
				warnAboutCredential(imported)
				return nil
			}

			return acceptOID4URI(content, dispatchOID4Opts{
				port:                port,
				portExplicit:        cmd.Flags().Changed("port"),
				autoAccept:          autoAccept,
				sessionTranscript:   sessionTranscript,
				txCode:              txCode,
				haip:                haip,
				mode:                walletValidationMode,
				docker:              docker,
				keyAttestationLevel: keyAttestationLevel,
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Server port (serves trust list and consent UI)")
	cmd.Flags().BoolVar(&screen, "screen", false, "Interactive screen capture (macOS)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Auto-approve presentations")
	cmd.Flags().BoolVar(&docker, "docker", false, "Serve the trust and status lists under host.docker.internal so a verifier in a container reaches them")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mdoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().StringVar(&txCode, "tx-code", "", "Transaction code for OID4VCI pre-authorized code flow")
	cmd.Flags().StringVar(&keyAttestationLevel, "key-attestation-level", "", "What the key attestation claims as key_storage and user_authentication (OpenID4VCI Appendix D.2): whatever the issuer requires (default), 'none', or one of iso_18045_high, iso_18045_moderate, iso_18045_enhanced-basic, iso_18045_basic for both. The wallet holds its keys in files and can prove none of them. A running wallet server applies its own setting")
	cmd.Flags().BoolVar(&haip, "haip", false, "Enforce HAIP 1.0 on presentations (x509_hash, direct_post.jwt, DCQL, JAR, ES256) and on credential offers (https issuer, and authorization code offers also need PAR, PKCE S256, DPoP, client auth)")
	return cmd
}
