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

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func walletGeneratePIDCmd() *cobra.Command {
	var (
		claimsFlag string
		keyPath    string
		vctFlag    string
		statusList bool
		baseURL    string
		docker     bool
	)

	cmd := &cobra.Command{
		Use:   "generate-pid",
		Short: "Generate default EUDI PID credentials (SD-JWT + mdoc) (deprecated)",
		Long: "Deprecated: generate-pid will be removed in a future release. Issue from the pre-defined PID credential templates instead. " +
			"If PID credentials of the same type already exist, they are replaced. Use --claims to override specific claim values.\n\n" +
			"--vct selects the PID templates of that type and with them the claim set. " + mock.DefaultPIDVCT + " is the EUDI PID. " +
			"A type without templates gets the claim set of the EUDI PID.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printGeneratePIDDeprecation(cmd, claimsFlag, vctFlag)
			if c, err := remoteClientIfConfigured(); err != nil {
				return err
			} else if c != nil {
				overrides, err := parseClaimsOverrides(claimsFlag)
				if err != nil {
					return err
				}
				vct := ""
				if cmd.Flags().Changed("vct") {
					vct = vctFlag
				}
				return remoteGeneratePID(c, overrides, vct)
			}
			w, store, err := loadWallet()
			if err != nil {
				return err
			}

			if keyPath != "" {
				issuerKey, err := loadWalletECKey(keyPath, "issuer")
				if err != nil {
					return err
				}
				w.IssuerKey = issuerKey
			}

			// Reuse the stored serving URLs unless the user overrides them.
			// Otherwise credentials could embed URLs that the wallet server
			// does not serve. An override holds for this run only.
			explicitURLs := cmd.Flags().Changed("base-url") || cmd.Flags().Changed("docker")
			chosenBaseURL := w.BaseURL
			if explicitURLs {
				chosenBaseURL = baseURL
			}
			walletPort := defaultWalletCommandPort()
			if port := walletPortFromBaseURL(chosenBaseURL); port > 0 {
				walletPort = port
			}
			origin, err := walletOrigin(walletPort, chosenBaseURL, docker)
			if err != nil {
				return err
			}
			base, issuer := w.BaseURL, w.IssuerURL
			if statusList && (explicitURLs || base == "") {
				base = origin.Base
			}
			if explicitURLs || issuer == "" {
				issuer = origin.Issuer
			}
			w.OverrideURLs(base, issuer)

			overrides, err := parseClaimsOverrides(claimsFlag)
			if err != nil {
				return err
			}

			// Pass --vct only when the user set it. Otherwise the template's VCT
			// applies, and a user override of german-pid-sdjwt can change it.
			vct := ""
			if cmd.Flags().Changed("vct") {
				vct = vctFlag
			}
			if err := w.GenerateDefaultCredentials(overrides, vct); err != nil {
				return fmt.Errorf("generating PID credentials: %w", err)
			}

			if err := store.Save(w); err != nil {
				return fmt.Errorf("saving wallet: %w", err)
			}

			printGeneratedPID(vct)
			warnIssuedEndpointsOffline(store, w)
			return nil
		},
	}

	cmd.Flags().StringVar(&claimsFlag, "claims", "", "Claim overrides as JSON (e.g. '{\"given_name\":\"Max\"}')")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to PEM-encoded EC private key for signing (default: auto-generated)")
	cmd.Flags().StringVar(&vctFlag, "vct", mock.DefaultPIDVCT, "PID type to generate (selects the claim set)")
	_ = cmd.RegisterFlagCompletionFunc("vct", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		loc, _ := resolveTemplates()
		return credtemplate.PIDTypes(loc), cobra.ShellCompDirectiveNoFileComp
	})
	cmd.Flags().BoolVar(&statusList, "status-list", true, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL for status list endpoint (default: http://localhost:8085)")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost for --base-url")
	return cmd
}

func printGeneratePIDDeprecation(cmd *cobra.Command, claimsFlag, vctFlag string) {
	loc, _ := resolveTemplates()
	sdTemplate, mdocTemplate, known := credtemplate.PIDTemplateNames(vctFlag, loc)
	sdEquiv := binaryName() + " issue sdjwt --wallet --template " + sdTemplate
	mdocEquiv := binaryName() + " issue mdoc --wallet --template " + mdocTemplate
	if claimsFlag != "" {
		sdEquiv += " --claims '" + claimsFlag + "'"
		mdocEquiv += " --claims '" + claimsFlag + "'"
	}
	// Templates already carry their VCT. Repeating --vct would suggest that the flag
	// selects the claim set.
	if cmd.Flags().Changed("vct") && !known {
		sdEquiv += " --vct " + vctFlag
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Warning: `wallet generate-pid` is deprecated and will be removed in a future release.")
	fmt.Fprintln(cmd.ErrOrStderr(), "Issue from the pre-defined credential templates instead:")
	fmt.Fprintln(cmd.ErrOrStderr(), "  "+sdEquiv)
	fmt.Fprintln(cmd.ErrOrStderr(), "  "+mdocEquiv)
}
