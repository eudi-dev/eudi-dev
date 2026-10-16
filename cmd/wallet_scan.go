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

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/qr"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
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
	if !offer.Grants.RequiresTxCode() {
		return given, offer
	}

	prompt := "Transaction code"
	if hint := offer.Grants.TxCodeHint(); hint != "" {
		prompt += " (" + hint + ")"
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return given, offer
	}
	return strings.TrimSpace(line), offer
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Choose the wallet before fetching the URI. Reading an offer here could consume it
// before the selected wallet starts issuance. Both accept and scan use this route. See
// docs/adr/0012-every-entry-point-runs-the-same-flow.md.
func acceptOID4URI(uri string, opts dispatchOID4Opts) error {
	c, err := remoteClientIfConfigured()
	if err != nil {
		return err
	}
	if c != nil {
		if err := checkRemoteSettings(c, opts.conformanceFlags, opts.conformance); err != nil {
			return err
		}
		if err := refuseLocalListenerFlags(c.BaseURL, opts); err != nil {
			return err
		}
		// The selected wallet fetches the offer and collects the transaction code.
		// Some offers can be fetched only once.
		transcript := opts.sessionTranscript
		if transcript == string(oid4vp.SessionTranscriptOID4VP) {
			transcript = ""
		}
		return remoteAccept(c, uri, opts.txCode, transcript, !opts.autoAccept)
	}
	w := &wallet.Wallet{}
	opts.conformance.apply(w)
	if err := applyWalletOutbound(w); err != nil {
		return err
	}
	defer w.HTTPClient().CloseIdleConnections()
	opts.txCode, opts.resolvedOffer = resolveTxCode(uri, opts.txCode, w.HTTPClient())
	return dispatchURI(uri, opts)
}

// refuseLocalListenerFlags reports the flags of the local presentation
// listener. A running wallet answers on its own address.
func refuseLocalListenerFlags(target string, opts dispatchOID4Opts) error {
	var set []string
	if opts.portExplicit {
		set = append(set, "--port")
	}
	if opts.docker {
		set = append(set, "--docker")
	}
	if opts.listenExplicit {
		set = append(set, "--listen")
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("the wallet at %s answers on its own address, so it can't use %s. Add --remote local to answer from a local listener", target, strings.Join(set, ", "))
}

func walletAcceptCmd() *cobra.Command {
	var (
		port              int
		autoAccept        bool
		sessionTranscript string
		txCode            string
		conformanceFlags  *conformanceFlags
		docker            bool
		listen            string
	)

	cmd := &cobra.Command{
		Use:   "accept <uri>",
		Short: "Accept and process an OID4VP presentation request or OID4VCI credential offer",
		Long: `Auto-detects the URI type and dispatches to the appropriate flow:

  - openid4vp://, haip-vp://, eudi-openid4vp://, eu-eaap:// →  OID4VP presentation
  - openid-credential-offer://, haip-vci://, eu-eaa-offer:// → OID4VCI credential issuance

For OID4VP requests, the wallet evaluates the DCQL query, shows a consent UI
(unless --auto-accept), and submits a VP token to the verifier.

For OID4VCI offers, the wallet fetches the credential from the issuer and
stores it locally. A running wallet server reloads the same wallet store at
request boundaries, so later presentation requests see the new credential.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conformance, err := conformanceFlags.resolve()
			if err != nil {
				return err
			}
			listenHost, err := resolveListenHost(cmd, listen, docker)
			if err != nil {
				return err
			}
			return acceptOID4URI(args[0], dispatchOID4Opts{
				port:              port,
				portExplicit:      cmd.Flags().Changed("port"),
				listenHost:        listenHost,
				listenExplicit:    cmd.Flags().Changed(listenFlag),
				autoAccept:        autoAccept,
				sessionTranscript: sessionTranscript,
				txCode:            txCode,
				docker:            docker,
				conformance:       conformance,
				conformanceFlags:  conformanceFlags.changed(),
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Server port for OID4VP (serves trusted list and consent UI)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Approve presentations without asking")
	cmd.Flags().BoolVar(&docker, "docker", false, "Serve the trusted lists and the status list under host.docker.internal for verifiers in a container")
	addListenFlag(cmd, &listen, "--docker binds 0.0.0.0 unless this flag or the variable is set. ")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mdoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().StringVar(&txCode, "tx-code", "", "Transaction code for OID4VCI pre-authorized code flow")
	conformanceFlags = addConformanceFlags(cmd)
	return cmd
}

func walletScanCmd() *cobra.Command {
	var (
		port              int
		screen            bool
		autoAccept        bool
		sessionTranscript string
		txCode            string
		conformanceFlags  *conformanceFlags
		docker            bool
		listen            string
	)

	cmd := &cobra.Command{
		Use:   "scan [image-file]",
		Short: "Scan a QR code and accept or import its content",
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

			fmt.Fprintf(humanOut(), "Scanned: %s\n\n", content)

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
				printResult(imported, func() {
					fmt.Printf("Imported %s credential (%s)\n", docString(imported, "format"), docCredLabel(imported))
				})
				warnAboutCredential(imported)
				return nil
			}

			conformance, err := conformanceFlags.resolve()
			if err != nil {
				return err
			}
			listenHost, err := resolveListenHost(cmd, listen, docker)
			if err != nil {
				return err
			}
			return acceptOID4URI(content, dispatchOID4Opts{
				port:              port,
				portExplicit:      cmd.Flags().Changed("port"),
				listenHost:        listenHost,
				listenExplicit:    cmd.Flags().Changed(listenFlag),
				autoAccept:        autoAccept,
				sessionTranscript: sessionTranscript,
				txCode:            txCode,
				docker:            docker,
				conformance:       conformance,
				conformanceFlags:  conformanceFlags.changed(),
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Server port (serves trusted list and consent UI)")
	cmd.Flags().BoolVar(&screen, "screen", false, "Interactive screen capture (macOS)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Approve presentations without asking")
	cmd.Flags().BoolVar(&docker, "docker", false, "Serve the trusted lists and the status list under host.docker.internal for verifiers in a container")
	addListenFlag(cmd, &listen, "--docker binds 0.0.0.0 unless this flag or the variable is set. ")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mdoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().StringVar(&txCode, "tx-code", "", "Transaction code for OID4VCI pre-authorized code flow")
	conformanceFlags = addConformanceFlags(cmd)
	return cmd
}
