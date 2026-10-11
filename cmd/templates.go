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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
)

var (
	templateFormat          string
	templateVCT             string
	templateDocType         string
	templateNamespace       string
	templateExp             string
	templateClaims          string
	templateAlwaysDisclosed []string
	templateDescription     string
	templateFrom            string
	templateImportName      string
)

var templatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "Manage credential templates",
	Long: "Manage credential templates: named, reusable claim sets with per-format defaults. " +
		"The predefined PID templates and the demo ticket are built in (see `templates list`). User templates are JSON files " +
		"in the wallet directory's templates/ subdirectory. Use them with `issue <format> --template <name>`.",
}

var templatesListCmd = &cobra.Command{
	Use:   "list",
	Args:  cobra.NoArgs,
	Short: "List available credential templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}
		templates, err := svc.Templates()
		if err != nil {
			return err
		}
		if jsonOutput {
			if templates == nil {
				templates = []credtemplate.Template{}
			}
			output.PrintJSON(templates)
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tFORMAT\tTYPE\tCLAIMS\tSOURCE")
		for _, t := range templates {
			credType := t.VCT
			if credType == "" {
				credType = t.DocType
			}
			source := "user"
			if t.Predefined {
				source = "predefined"
			}
			format := t.Format
			if format == "" {
				format = "any"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", t.Name, format, credType, len(t.Claims), source)
		}
		return tw.Flush()
	},
}

var templatesShowCmd = &cobra.Command{
	Use:               "show <name>",
	Short:             "Print a credential template as JSON",
	Long:              "Prints a credential template as JSON. `templates import` reads this output.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeTemplateNames,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}
		tpl, err := svc.Template(args[0])
		if err != nil {
			return err
		}
		return output.WriteJSON(os.Stdout, tpl)
	},
}

var templatesSaveCmd = &cobra.Command{
	Use:               "save <name>",
	Short:             "Create or update a user credential template",
	ValidArgsFunction: completeTemplateNames,
	Long: "Create or update a user credential template from flags. Use --from to copy an existing template " +
		"as the starting point (e.g. to customize a predefined one). Other flags override the copied values.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}

		var tpl credtemplate.Template
		if templateFrom != "" {
			from, err := svc.Template(templateFrom)
			if err != nil {
				return err
			}
			tpl = *from
		}
		tpl.Name = args[0]

		flags := cmd.Flags()
		if flags.Changed("format") {
			tpl.Format = templateFormat
		}
		if flags.Changed("vct") {
			tpl.VCT = templateVCT
		}
		if flags.Changed("doc-type") {
			tpl.DocType = templateDocType
		}
		if flags.Changed("namespace") {
			tpl.Namespace = templateNamespace
		}
		if flags.Changed("exp") {
			tpl.Exp = templateExp
		}
		if flags.Changed("description") {
			tpl.Description = templateDescription
		}
		if flags.Changed("always-disclosed") {
			tpl.AlwaysDisclosed = templateAlwaysDisclosed
		}
		if flags.Changed("claims") {
			claims, err := parseClaimsArg(templateClaims)
			if err != nil {
				return err
			}
			tpl.Claims = claims
		}
		if tpl.Claims == nil {
			return fmt.Errorf("template has no claims: pass --claims or --from")
		}

		tpl.Predefined = false
		path, err := svc.SaveTemplate(tpl)
		if err != nil {
			return err
		}
		printTemplateSaved("Saved", tpl.Name, path)
		printTemplateResult(tpl.Name, path)
		return nil
	},
}

var templatesImportCmd = &cobra.Command{
	Use:   "import <file|json|->",
	Short: "Import a credential template from a JSON file, a JSON string, or stdin (-)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		arg := args[0]
		switch {
		case arg == "-":
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		case strings.HasPrefix(strings.TrimSpace(arg), "{"):
			data = []byte(arg)
		default:
			data, err = os.ReadFile(arg)
			if err != nil {
				return fmt.Errorf("reading template file: %w", err)
			}
		}

		var tpl credtemplate.Template
		if err := json.Unmarshal(data, &tpl); err != nil {
			return fmt.Errorf("parsing template JSON: %w", err)
		}
		if templateImportName != "" {
			tpl.Name = templateImportName
		}
		if strings.TrimSpace(tpl.Name) == "" && !strings.HasPrefix(strings.TrimSpace(arg), "{") && arg != "-" {
			base := filepath.Base(arg)
			tpl.Name = strings.TrimSuffix(strings.TrimSuffix(base, ".json"), ".template")
		}

		svc, err := managedWallet()
		if err != nil {
			return err
		}
		if svc.URL() != "" && strings.TrimSpace(tpl.Name) == "" {
			return fmt.Errorf("template name is required: pass --name")
		}
		path, err := svc.SaveTemplate(tpl)
		if err != nil {
			return err
		}
		printTemplateSaved("Imported", tpl.Name, path)
		printTemplateResult(tpl.Name, path)
		return nil
	},
}

var templatesDeleteCmd = &cobra.Command{
	Use:               "delete <name>",
	Short:             "Delete a user credential template",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeTemplateNames,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}
		if err := svc.DeleteTemplate(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Deleted template %q\n", args[0])
		printResult(map[string]string{"deleted": args[0]}, func() {})
		return nil
	},
}

func init() {
	rootCmd.AddCommand(templatesCmd)
	templatesCmd.PersistentFlags().StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory holding the templates/ subdirectory (default ~/.eudi-dev/wallet/)")
	templatesCmd.PersistentFlags().StringVar(&templatesDir, "templates-dir", "", "Credential template directory (default <wallet-dir>/templates/)")
	templatesCmd.PersistentFlags().StringVar(&storageSpec, "storage", "", storageFlagUsage)
	templatesCmd.PersistentFlags().StringVar(&remoteFlag, "remote", "", "Manage templates on a remote wallet server at this URL (\"local\" forces the local store)")
	templatesCmd.AddCommand(templatesListCmd)
	templatesCmd.AddCommand(templatesShowCmd)
	templatesCmd.AddCommand(templatesSaveCmd)
	templatesCmd.AddCommand(templatesImportCmd)
	templatesCmd.AddCommand(templatesDeleteCmd)

	templatesSaveCmd.Flags().StringVar(&templateFrom, "from", "", "Copy this template (name or file) as the starting point")
	templatesSaveCmd.Flags().StringVar(&templateFormat, "format", "", "Credential format: sdjwt, jwt, or mdoc (empty: any)")
	templatesSaveCmd.Flags().StringVar(&templateVCT, "vct", "", "Verifiable Credential Type (sdjwt/jwt)")
	templatesSaveCmd.Flags().StringVar(&templateDocType, "doc-type", "", "Document type (mdoc)")
	templatesSaveCmd.Flags().StringVar(&templateNamespace, "namespace", "", "Default namespace (mdoc)")
	templatesSaveCmd.Flags().StringVar(&templateExp, "exp", "", "Default expiration duration (e.g. 720h)")
	templatesSaveCmd.Flags().StringVar(&templateClaims, "claims", "", "Claims as JSON string or @filepath")
	templatesSaveCmd.Flags().StringSliceVar(&templateAlwaysDisclosed, "always-disclosed", nil, "Claims to embed plainly instead of selectively disclosable (dotted paths for nested claims)")
	templatesSaveCmd.Flags().StringVar(&templateDescription, "description", "", "Template description")

	templatesImportCmd.Flags().StringVar(&templateImportName, "name", "", "Save the imported template under this name")

	_ = templatesSaveCmd.RegisterFlagCompletionFunc("from", completeTemplateNames)
	_ = templatesSaveCmd.RegisterFlagCompletionFunc("format", staticCompletion("sdjwt", "jwt", "mdoc"))
	_ = templatesCmd.RegisterFlagCompletionFunc("remote", completeRemoteFlag)
	_ = templatesCmd.MarkPersistentFlagDirname("wallet-dir")
	_ = templatesCmd.MarkPersistentFlagDirname("templates-dir")
}

// printTemplateResult prints the saved template's name and path with --json.
// A remote wallet reports no path.
func printTemplateResult(name, path string) {
	doc := map[string]string{"name": name}
	if path != "" {
		doc["path"] = path
	}
	printResult(doc, func() {})
}

func printTemplateSaved(verb, name, path string) {
	if path != "" {
		fmt.Fprintf(os.Stderr, "%s template %q to %s\n", verb, name, path)
		return
	}
	fmt.Fprintf(os.Stderr, "%s template %q\n", verb, name)
}

func resolveTemplates() (credtemplate.Location, error) {
	if templatesDir != "" {
		return credtemplate.FileLocation(templatesDir), nil
	}
	store, err := openStore()
	if err != nil {
		return credtemplate.Location{}, err
	}
	return store.Templates(), nil
}
