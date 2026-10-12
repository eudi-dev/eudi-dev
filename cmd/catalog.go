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

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func catalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "List, add and remove attestation types in the catalogue of attestations",
		Long: `The wallet keeps a catalogue of attestations (EC TS11 v1.0). Each entry describes
an attestation type: its formats and the schema of each, its rulebook, its level
of security and the trusted list of its issuers.

Every predefined credential template is in the catalogue. To add a user
template, tick "Add the template to the attestation catalogue" when you save
it. You can also add other attestation types. When you register a
verifier or an issuer in the web UI, the type fields suggest these types.

Without a subcommand, or with list, it lists the catalogue.`,
		Args: cobra.NoArgs,
		RunE: listCatalog,
	}
	cmd.AddCommand(catalogAddCmd(), catalogRemoveCmd(), listSubcommand(cmd, "List the attestation types in the catalogue"))
	return cmd
}

func listCatalog(cmd *cobra.Command, args []string) error {
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	entries, err := svc.CatalogAttestations()
	if err != nil {
		return err
	}
	printResult(entries, func() {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCATEGORY\tTYPES\tLEVEL OF SECURITY")
		for _, e := range entries {
			types := make([]string, 0, len(e.Credentials))
			for _, c := range e.Credentials {
				types = append(types, c.Format+":"+c.Type)
			}
			name := e.Name
			if e.Template {
				name += " (template)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Schema.ID, name, e.Category, strings.Join(types, " "), e.Schema.AttestationLoS)
		}
		_ = tw.Flush()
	})
	return nil
}

func catalogAddCmd() *cobra.Command {
	var (
		name, category           string
		types, claims            []string
		los, trustedList         string
		bindingType, rulebookURI string
		issuerCA                 string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an attestation type to the catalogue",
		Long: `Adds an attestation type. The catalogue assigns its id and serves a schema for
each format: SD-JWT VC Type Metadata for dc+sd-jwt, and the doctype with its
namespaces for mso_mdoc.

--type takes format:type, once per format. --claim takes format:claim. For
SD-JWT, separate path segments with dots. An mdoc claim is an element of
the doctype's namespace, or namespace:element.

--category is pid, qeaa, pub-eaa or eaa. The wallet signs credentials of the
type under the provider CA of that category, and the entry links the
category's trusted list unless --trusted-list names another. --issuer-ca puts
the CA of your own issuer on the category's list, so with --arf its
credentials of the type pass the trusted list check. It can't go with
--trusted-list, because the entry then links another list.`,
		Example: `  eudi catalog add --name "University diploma" --type dc+sd-jwt:urn:example:diploma:1 --claim dc+sd-jwt:degree
  eudi catalog add --name "University diploma" --type mso_mdoc:org.example.diploma.1 --claim mso_mdoc:degree --category qeaa
  eudi catalog add --name "University diploma" --type mso_mdoc:org.example.diploma.1 --los moderate --trusted-list https://example.com/lote`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entry := registrar.CatalogAttestation{Name: name, Category: category}
			for _, value := range types {
				format, typ, ok := strings.Cut(value, ":")
				if !ok || strings.TrimSpace(typ) == "" {
					return fmt.Errorf("--type %q is not format:type, such as dc+sd-jwt:urn:example:diploma:1", value)
				}
				entry.Credentials = append(entry.Credentials, registrar.CatalogCredential{Format: format, Type: strings.TrimSpace(typ)})
			}
			for _, value := range claims {
				format, claim, ok := strings.Cut(value, ":")
				i := -1
				for j, c := range entry.Credentials {
					if c.Format == format {
						i = j
					}
				}
				if !ok || claim == "" || i < 0 {
					return fmt.Errorf("--claim %q is not format:claim for a format of --type", value)
				}
				entry.Credentials[i].Claims = append(entry.Credentials[i].Claims, catalogClaimPath(format, entry.Credentials[i].Type, claim))
			}
			if los != "" {
				entry.Schema.AttestationLoS = attestationLoSPrefix + los
			}
			entry.Schema.BindingType = bindingType
			entry.Schema.RulebookURI = rulebookURI
			if trustedList != "" {
				isLOTE := true
				entry.Schema.TrustedAuthorities = []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: trustedList, IsLOTE: &isLOTE}}
			}
			var caPEM []byte
			if issuerCA != "" {
				if trustedList != "" {
					return fmt.Errorf("--issuer-ca puts the CA on the wallet's list of the category, and --trusted-list links another list. Use one of them")
				}
				var err error
				if caPEM, err = os.ReadFile(issuerCA); err != nil {
					return fmt.Errorf("reading --issuer-ca: %w", err)
				}
				// The entry is added only with a usable CA.
				if _, err := trustedlists.NewEntity(credtemplate.CategoryEAA, "", string(caPEM)); err != nil {
					return fmt.Errorf("--issuer-ca: %w", err)
				}
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			added, err := svc.AddCatalogAttestation(entry)
			if err != nil {
				return err
			}
			if caPEM != nil {
				if _, err := svc.AddTrustedEntity(added.Category, added.Name+" issuer", string(caPEM)); err != nil {
					// The entry stays only together with its CA.
					if rmErr := svc.DeleteCatalogAttestation(added.Schema.ID); rmErr != nil {
						return fmt.Errorf("putting --issuer-ca on the %s list: %w (removing the added entry %s: %w)", added.Category, err, added.Schema.ID, rmErr)
					}
					return fmt.Errorf("putting --issuer-ca on the %s list: %w", added.Category, err)
				}
			}
			printResult(added, func() {
				fmt.Printf("Added %s as %s\n", added.Name, added.Schema.ID)
				for _, uri := range added.Schema.SchemaURIs {
					fmt.Printf("Schema %s: %s\n", uri.FormatIdentifier, uri.URI)
				}
			})
			return nil
		},
	}
	var levels []string
	for _, value := range registrar.OptionValues(registrar.AttestationLevels) {
		levels = append(levels, strings.TrimPrefix(value, attestationLoSPrefix))
	}
	bindings := registrar.OptionValues(registrar.BindingTypes)
	cmd.Flags().StringVar(&name, "name", "", "Name of the attestation type (required)")
	cmd.Flags().StringArrayVar(&types, "type", nil, "Format and type, such as dc+sd-jwt:urn:example:diploma:1 or mso_mdoc:org.example.diploma.1 (repeatable, required)")
	cmd.Flags().StringArrayVar(&claims, "claim", nil, "Format and claim, such as dc+sd-jwt:address.locality or mso_mdoc:degree (repeatable)")
	cmd.Flags().StringVar(&category, "category", "eaa", "Credential category: pid, qeaa, pub-eaa or eaa")
	cmd.Flags().StringVar(&los, "los", "", "Level of security: "+strings.Join(levels, ", ")+" (default high, and basic for eaa)")
	cmd.Flags().StringVar(&bindingType, "binding", "", "How the attestation is bound to its holder: "+strings.Join(bindings, ", ")+" (default key)")
	cmd.Flags().StringVar(&rulebookURI, "rulebook", "", "URL of the rulebook (default a placeholder page on the wallet)")
	cmd.Flags().StringVar(&trustedList, "trusted-list", "", "URL of the trusted list of its issuers (ETSI TS 119 602, default the category's list on the wallet)")
	cmd.Flags().StringVar(&issuerCA, "issuer-ca", "", "PEM file with the CA of your issuer. The wallet puts it on the trusted list of the category")
	_ = cmd.MarkFlagFilename("issuer-ca", "pem")
	_ = cmd.RegisterFlagCompletionFunc("category", staticCompletion(credtemplate.Categories...))
	_ = cmd.RegisterFlagCompletionFunc("los", staticCompletion(levels...))
	_ = cmd.RegisterFlagCompletionFunc("binding", staticCompletion(bindings...))
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

// attestationLoSPrefix starts every TS11 attestationLoS value. --los takes
// the rest.
const attestationLoSPrefix = "iso_18045_"

// catalogClaimPath turns a claim flag into a claim path. An mdoc claim
// without a namespace is in the doctype's namespace.
func catalogClaimPath(format, typ, claim string) []any {
	if format == credtype.FormatMDOC {
		if at := strings.LastIndex(claim, ":"); at > 0 {
			return []any{claim[:at], claim[at+1:]}
		}
		return []any{typ, claim}
	}
	path := []any{}
	for _, segment := range strings.Split(claim, ".") {
		path = append(path, segment)
	}
	return path
}

func catalogRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <id>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove an added attestation type",
		Long:    "Removes an added attestation type, also one added with a template. The entries of the predefined templates can't be removed.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if err := svc.DeleteCatalogAttestation(args[0]); err != nil {
				return err
			}
			printResult(map[string]string{"removed": args[0]}, func() {
				fmt.Printf("Removed %s\n", args[0])
			})
			return nil
		},
	}
}
