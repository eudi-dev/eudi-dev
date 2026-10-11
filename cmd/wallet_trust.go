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
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func walletTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Put your providers and lists on the wallet's trusted lists",
		Long: `With --arf the wallet checks credentials, access certificates and registration
certificates against lists of trusted entities (ETSI TS 119 602). It signs a
list per credential category (pid, qeaa, pub-eaa, eaa), one for wallet
providers, one for access certificate providers (access-ca) and one for
registration certificate providers (registrar). A list of trusted lists at
/api/trustlists/lists points to all of them and to the external lists you add.

add-ca puts the CA of your own issuer or registrar on one of the wallet's lists.
add-list puts an external list on the list of trusted lists. Its signer has to
chain to the wallet CA or to a CA from wallet serve --trusted-list-ca. A list
that a list of trusted lists points to needs the certificate of its pointer
instead.

Without a subcommand, or with list, it lists what you added.`,
		Args: cobra.NoArgs,
		RunE: listTrust,
	}
	cmd.AddCommand(walletTrustAddCACmd(), walletTrustRemoveCACmd(), walletTrustAddListCmd(), walletTrustRemoveListCmd(), listSubcommand(cmd, "List the providers and lists you added"))
	return cmd
}

func listTrust(cmd *cobra.Command, args []string) error {
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	state, err := svc.TrustState()
	if err != nil {
		return err
	}
	printResult(state, func() {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tLIST\tNAME\tCERTIFICATES")
		for _, e := range state.Entities {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", e.ID, e.List, e.Name, len(e.Certificates))
		}
		_ = tw.Flush()
		fmt.Printf("\nList of trusted lists: %s\n", state.ListsURL)
		for _, l := range state.Lists {
			var notes []string
			if l.Configured {
				notes = append(notes, "--trusted-list")
			}
			if l.Via != "" {
				notes = append(notes, "from "+l.Via)
			}
			line := "  " + l.URL
			if len(notes) > 0 {
				line += " (" + strings.Join(notes, ", ") + ")"
			}
			fmt.Println(line)
			if l.Error != "" {
				fmt.Printf("    not used: %s\n", l.Error)
			}
		}
	})
	return nil
}

func walletTrustAddCACmd() *cobra.Command {
	var list, name, caFile string
	cmd := &cobra.Command{
		Use:   "add-ca",
		Short: "Put a CA on one of the wallet's lists",
		Long: `Puts the CA certificates of a PEM file on one of the wallet's lists. The wallet
signs the list with the CA on it, so with --arf the CA anchors the checks of
that list: a credential of the category, an access certificate (access-ca) or
a registration certificate and its status list (registrar).`,
		Example: `  eudi wallet trust add-ca --list pid --name "Example PID Provider" --ca pid-ca.pem
  eudi wallet trust add-ca --list registrar --ca registrar-ca.pem`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(caFile)
			if err != nil {
				return fmt.Errorf("reading --ca: %w", err)
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			entity, err := svc.AddTrustedEntity(list, name, string(data))
			if err != nil {
				return err
			}
			printResult(entity, func() { fmt.Printf("Added %s to the %s list as %s\n", entity.Name, entity.List, entity.ID) })
			return nil
		},
	}
	cmd.Flags().StringVar(&list, "list", "", "List to add the CA to: "+strings.Join(wallet.TrustedEntityLists(), ", ")+" (required)")
	cmd.Flags().StringVar(&name, "name", "", "Name of the provider on the list (default the CA's common name)")
	cmd.Flags().StringVar(&caFile, "ca", "", "PEM file with the CA certificates (required)")
	_ = cmd.RegisterFlagCompletionFunc("list", staticCompletion(wallet.TrustedEntityLists()...))
	_ = cmd.MarkFlagRequired("list")
	_ = cmd.MarkFlagRequired("ca")
	_ = cmd.MarkFlagFilename("ca", "pem")
	return cmd
}

func walletTrustRemoveCACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm-ca <id>",
		Short: "Take a CA off its list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if err := svc.RemoveTrustedEntity(args[0]); err != nil {
				return err
			}
			printResult(map[string]any{"removed": args[0]}, func() { fmt.Printf("Removed %s\n", args[0]) })
			return nil
		},
	}
}

func walletTrustAddListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-list <url>",
		Short: "Put an external list on the list of trusted lists",
		Long: `Puts an external list of trusted entities (ETSI TS 119 602) on the wallet's list
of trusted lists. With --arf its providers anchor the checks of its list type,
for example a PID provider list for received PIDs. Its signer has to chain to
the wallet CA or to a CA from wallet serve --trusted-list-ca.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			link, err := svc.AddTrustedList(args[0])
			if err != nil {
				return err
			}
			printResult(link, func() {
				fmt.Printf("Added %s\n", link.URL)
				if link.Error != "" {
					fmt.Printf("The wallet can't use it yet: %s\n", link.Error)
				}
			})
			return nil
		},
	}
}

func walletTrustRemoveListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm-list <url>",
		Short: "Take an external list off the list of trusted lists",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if err := svc.RemoveTrustedList(args[0]); err != nil {
				return err
			}
			printResult(map[string]any{"removed": args[0]}, func() { fmt.Printf("Removed %s\n", args[0]) })
			return nil
		},
	}
}
