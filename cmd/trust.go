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

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func trustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Show the wallet's trusted lists and add your own CAs and lists",
		Long: `With --arf the wallet checks credentials, access certificates and registration
certificates against lists of trusted entities (ETSI TS 119 602). The wallet
signs one list for each credential category (pid, qeaa, pub-eaa, eaa), one for
wallet providers, one for access certificate providers (access-ca) and one for
registration certificate providers (registrar). The list of trusted lists at
/api/trustlists/lists points to all of them and to the external lists you add.

show prints one of these lists. ca-cert prints the wallet CA that signs them.

add-ca adds the CA of your own issuer or registrar to one of the wallet's
lists. With --list trusted-list-ca it adds the CA of a trusted list operator.
The wallet doesn't publish that list.

add-list adds an external list to the list of trusted lists. Its signer has to
chain to the wallet CA, to a CA given with wallet serve --trusted-list-ca, or
to a CA added with add-ca --list trusted-list-ca. A list found through a list
of trusted lists must be signed with the certificate given in its pointer.

Without a subcommand, or with list, it lists the wallet's lists and what you
added.`,
		Args: cobra.NoArgs,
		RunE: listTrust,
	}
	cmd.AddCommand(
		listSubcommand(cmd, "List the wallet's trusted lists and the providers and lists you added"),
		trustShowCmd(),
		trustCACertCmd(),
		trustAddCACmd(), trustRemoveCACmd(), trustAddListCmd(), trustRemoveListCmd(),
	)
	return cmd
}

// trustOverview is the --json document of trust list.
type trustOverview struct {
	trustedlists.Summary
	TrustLists []map[string]any `json:"trust_lists"`
}

func listTrust(cmd *cobra.Command, args []string) error {
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	index, err := svc.TrustListIndex()
	if err != nil {
		return err
	}
	state, err := svc.TrustState()
	if err != nil {
		return err
	}
	printResult(trustOverview{Summary: state, TrustLists: index}, func() {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "LIST\tDEFAULT\tCATEGORY\tPATH")
		for _, entry := range index {
			def := ""
			if isDefault, _ := entry["default"].(bool); isDefault {
				def = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", docString(entry, "id"), def, docString(entry, "category"), docString(entry, "path"))
		}
		_ = tw.Flush()
		if len(state.Entities) > 0 {
			fmt.Println()
			tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tLIST\tNAME\tCERTIFICATES")
			for _, e := range state.Entities {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", e.ID, e.List, e.Name, len(e.Certificates))
			}
			_ = tw.Flush()
		}
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

func trustShowCmd() *cobra.Command {
	var (
		port    int
		docker  bool
		urlOnly bool
		vct     string
		docType string
	)

	cmd := &cobra.Command{
		Use:   "show [list]",
		Short: "Print one of the wallet's trusted lists, or its URL",
		Long: `Prints one of the wallet's lists of trusted entities (ETSI TS 119 602) as a
signed JWT. You can save it to a file or pass it to validate --trusted-list.

The list is pid, qeaa, pub-eaa, eaa, wallet-provider, access-ca, registrar or
the tl- id of a custom list. "lists" prints the list of trusted lists, and
'trust list' shows all of them. Without an argument it prints the PID provider
list, as /api/trustlist does.

--vct or --doctype selects the list for that credential type. --url prints
only the URL of the list on a running wallet server.`,
		Example: `  eudi trust show > trustlist.jwt
  eudi trust show eaa --url
  eudi trust show --doctype org.iso.23220.photoid.1 --url
  eudi trust show --url --docker`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeTrustListIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			if id != "" && (vct != "" || docType != "") {
				return fmt.Errorf("a list ID cannot be combined with --vct or --doctype")
			}
			// A remote wallet has its own CA. Reading the local store would return the
			// wrong trust anchor.
			client, err := remoteClientIfConfigured()
			if err != nil {
				return err
			}

			if urlOnly {
				path := remote.TrustListPath(id, vct, docType)
				var trustListURL string
				if client != nil {
					trustListURL = client.BaseURL + path
				} else {
					origin, _ := walletOrigin(port, "", docker)
					trustListURL = origin.Base + path
				}
				printResult(map[string]string{"url": trustListURL}, func() { fmt.Println(trustListURL) })
				return nil
			}

			if client != nil {
				jwt, err := client.TrustList(id, vct, docType)
				if err != nil {
					return err
				}
				printTrustList(jwt)
				return nil
			}

			w, _, err := loadWallet()
			if err != nil {
				return err
			}

			if w.CAKey == nil || len(w.CertChain) < 2 {
				return fmt.Errorf("wallet has no CA certificate chain")
			}
			if id == trustedlists.ListOfListsID {
				jwt, err := w.TrustedLists().ListOfLists(w.IssuerURL)
				if err != nil {
					return fmt.Errorf("generating the list of trusted lists: %w", err)
				}
				printTrustList(jwt)
				return nil
			}
			group, ok := w.TrustedLists().FindGroup(id, vct, docType)
			if !ok {
				return fmt.Errorf("wallet has no matching trusted list")
			}
			jwt, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, provider.TrustedListPath(group.ID))
			if err != nil {
				return fmt.Errorf("generating trusted list: %w", err)
			}

			printTrustList(jwt)
			return nil
		},
	}

	cmd.Flags().BoolVar(&urlOnly, "url", false, "Print only the trusted list URL (for a running wallet server)")
	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Wallet server port (used with --url)")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost (used with --url)")
	cmd.Flags().StringVar(&vct, "vct", "", "Select the trusted list covering this SD-JWT VCT")
	cmd.Flags().StringVar(&docType, "doctype", "", "Select the trusted list covering this mdoc docType")
	return cmd
}

func printTrustList(jwt string) {
	printResult(map[string]string{"trust_list": jwt}, func() { fmt.Println(jwt) })
}

func completeTrustListIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var svc walletService = &localWallet{load: loadWallet}
	if c := completionClient(); c != nil {
		svc = &remoteWallet{c: c}
	} else if !localWalletExists() {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	index, err := svc.TrustListIndex()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := []string{trustedlists.ListOfListsID + "\tlist of trusted lists"}
	for _, entry := range index {
		completions = append(completions, docString(entry, "id")+"\t"+docString(entry, "category"))
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func trustCACertCmd() *cobra.Command {
	var (
		outPath string
		asPEM   bool
		asJWKS  bool
	)

	cmd := &cobra.Command{
		Use:   "ca-cert",
		Short: "Print or export the shared wallet CA certificate",
		Long: `Loads or creates the shared wallet CA certificate and prints it as PEM.
Wallets under the same parent directory share this root for signing, trusted
lists and HTTPS certificate chains. New provider chains include an
intermediate CA.

Use --jwks to export the certificate as a JWKS document (public key with x5c
chain).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			certFormat, err := certificateExportFormat(asPEM, asJWKS)
			if err != nil {
				return err
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			certData, err := svc.Certificate("ca", certFormat, walletCertOptions{})
			if err != nil {
				return err
			}
			return writeCertificateExport(cmd, "CA", certFormat, certData, outPath)
		},
	}

	cmd.Flags().StringVar(&outPath, "out", "", "Write the shared wallet CA certificate to a file instead of stdout")
	cmd.Flags().BoolVar(&asPEM, "pem", false, "Output as PEM (the default)")
	cmd.Flags().BoolVar(&asJWKS, "jwks", false, "Output as JWKS (public key with x5c chain)")
	return cmd
}

func trustAddCACmd() *cobra.Command {
	var list, name, caFile string
	cmd := &cobra.Command{
		Use:   "add-ca",
		Short: "Put a CA on one of the wallet's lists",
		Long: `Adds the CA certificates of a PEM file to one of the wallet's lists, and the
wallet signs the list again. With --arf the CA is then a trust anchor for that
list: for credentials of its category, for access certificates (access-ca), or
for registration certificates and their status list (registrar).

The trusted-list-ca list holds the CAs of trusted list operators. The wallet
doesn't publish it. It accepts external lists signed under these CAs.`,
		Example: `  eudi trust add-ca --list pid --name "Example PID Provider" --ca pid-ca.pem
  eudi trust add-ca --list registrar --ca registrar-ca.pem
  eudi trust add-ca --list trusted-list-ca --ca lists-ca.pem`,
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
	cmd.Flags().StringVar(&list, "list", "", "List to add the CA to: "+strings.Join(trustedlists.EntityLists(), ", ")+" (required)")
	cmd.Flags().StringVar(&name, "name", "", "Name of the provider on the list (default the CA's common name)")
	cmd.Flags().StringVar(&caFile, "ca", "", "PEM file with the CA certificates (required)")
	_ = cmd.RegisterFlagCompletionFunc("list", staticCompletion(trustedlists.EntityLists()...))
	_ = cmd.MarkFlagRequired("list")
	_ = cmd.MarkFlagRequired("ca")
	_ = cmd.MarkFlagFilename("ca", "pem")
	return cmd
}

func trustRemoveCACmd() *cobra.Command {
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

func trustAddListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-list <url>",
		Short: "Put an external list on the list of trusted lists",
		Long: `Adds an external list of trusted entities (ETSI TS 119 602) to the wallet's list
of trusted lists. With --arf the wallet trusts the providers on it for the
list's type, for example a PID provider list for received PIDs. The list's
signer has to chain to the wallet CA, to a CA given with wallet serve
--trusted-list-ca, or to a CA added with trust add-ca --list trusted-list-ca.`,
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

func trustRemoveListCmd() *cobra.Command {
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
