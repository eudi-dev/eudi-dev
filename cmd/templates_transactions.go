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
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/output"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
)

var transactionTemplateImportName string

var transactionTemplatesCmd = &cobra.Command{
	Use:   "transactions",
	Short: "Manage transaction templates",
	Long: "Manage transaction templates: named transaction data entries (OpenID4VP 1.0 §5.1) for presentation requests. " +
		"The wallet comes with one example for each SCA transaction type of EUDI TS12 v1.0.1.",
	Args: cobra.NoArgs,
	RunE: showHelp,
}

var transactionTemplatesListCmd = &cobra.Command{
	Use:   "list",
	Args:  cobra.NoArgs,
	Short: "List the transaction templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}
		templates, err := svc.TransactionTemplates()
		if err != nil {
			return err
		}
		if jsonOutput {
			if templates == nil {
				templates = []txtemplate.Template{}
			}
			output.PrintJSON(templates)
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tTYPE\tSOURCE\tDESCRIPTION")
		for _, t := range templates {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.Type(), transactionTemplateSource(t), t.Description)
		}
		return tw.Flush()
	},
}

func transactionTemplateSource(t txtemplate.Template) string {
	switch {
	case t.Configured:
		return "config"
	case t.Predefined:
		return "predefined"
	}
	return "user"
}

var transactionTemplatesShowCmd = &cobra.Command{
	Use:               "show <name>",
	Short:             "Print a transaction template as JSON",
	Long:              "Prints a transaction template as JSON. `templates transactions import` reads this output.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeTransactionTemplateNames,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}
		tpl, err := svc.TransactionTemplate(args[0])
		if err != nil {
			return err
		}
		return output.WriteJSON(os.Stdout, tpl)
	},
}

var transactionTemplatesImportCmd = &cobra.Command{
	Use:   "import <file|json|->",
	Short: "Import transaction templates from a JSON or YAML file, a JSON string, or stdin (-)",
	Long: "Imports transaction templates. A template has a name, an optional description and the transaction_data object. " +
		"The input holds one template, a list of templates, or YAML documents separated by ---. " +
		"With more than one template, each needs a name. A TS12 template that breaks the TS12 schema is still saved, and its findings print as warnings.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, file, err := readImportArg(args[0])
		if err != nil {
			return err
		}
		templates, err := txtemplate.DecodeAll(data)
		if err != nil {
			return fmt.Errorf("parsing transaction template: %w", err)
		}
		switch {
		case len(templates) == 0:
			return fmt.Errorf("the input holds no transaction template")
		case len(templates) > 1 && transactionTemplateImportName != "":
			return fmt.Errorf("--name sets the name of one template, but the input holds %d. Give each template a name in the file", len(templates))
		}
		if transactionTemplateImportName != "" {
			templates[0].Name = transactionTemplateImportName
		}
		if len(templates) == 1 && strings.TrimSpace(templates[0].Name) == "" && file != "" {
			base := filepath.Base(file)
			templates[0].Name = strings.TrimSuffix(base, filepath.Ext(base))
		}
		for i, tpl := range templates {
			if strings.TrimSpace(tpl.Name) == "" {
				if len(templates) == 1 {
					return fmt.Errorf("transaction template name is required: pass --name")
				}
				return fmt.Errorf("transaction template %d needs a name, because the input holds more than one template", i+1)
			}
		}

		svc, err := managedWallet()
		if err != nil {
			return err
		}
		var results []map[string]string
		for _, tpl := range templates {
			if err := svc.SaveTransactionTemplate(tpl); err != nil {
				if len(results) > 0 {
					return fmt.Errorf("transaction template %q: %w. The %d templates before it are imported", tpl.Name, err, len(results))
				}
				return fmt.Errorf("transaction template %q: %w", tpl.Name, err)
			}
			fmt.Fprintf(os.Stderr, "Imported transaction template %q\n", tpl.Name)
			for _, warning := range oid4vp.TS12Findings(tpl.TransactionData).Texts() {
				fmt.Fprintf(os.Stderr, "  warning: %s\n", warning)
			}
			results = append(results, map[string]string{"name": tpl.Name})
		}
		if len(results) == 1 {
			printResult(results[0], func() {})
			return nil
		}
		printResult(results, func() {})
		return nil
	},
}

var transactionTemplatesDeleteCmd = &cobra.Command{
	Use:               "delete <name>",
	Short:             "Delete a user transaction template",
	Long:              "Deletes a user transaction template. Deleting one that replaces a predefined template brings the predefined one back.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeTransactionTemplateNames,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := managedWallet()
		if err != nil {
			return err
		}
		if err := svc.DeleteTransactionTemplate(args[0]); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Deleted transaction template %q\n", args[0])
		printResult(map[string]string{"deleted": args[0]}, func() {})
		return nil
	},
}

// readImportArg reads the argument of an import command. The argument is "-"
// for stdin, a JSON object or list, or a file path. For a file path it also
// returns the path.
func readImportArg(arg string) (data []byte, file string, err error) {
	trimmed := strings.TrimSpace(arg)
	switch {
	case arg == "-":
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, "", fmt.Errorf("reading stdin: %w", err)
		}
		return data, "", nil
	case strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		return []byte(arg), "", nil
	}
	data, err = os.ReadFile(arg)
	if err != nil {
		return nil, "", fmt.Errorf("reading template file: %w", err)
	}
	return data, arg, nil
}

func completeTransactionTemplateNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	svc, err := managedWallet()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	templates, err := svc.TransactionTemplates()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := make([]string, 0, len(templates))
	for _, tpl := range templates {
		completions = append(completions, tpl.Name+"\t"+tpl.Type())
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	templatesCmd.AddCommand(transactionTemplatesCmd)
	transactionTemplatesCmd.AddCommand(transactionTemplatesListCmd)
	transactionTemplatesCmd.AddCommand(transactionTemplatesShowCmd)
	transactionTemplatesCmd.AddCommand(transactionTemplatesImportCmd)
	transactionTemplatesCmd.AddCommand(transactionTemplatesDeleteCmd)
	transactionTemplatesImportCmd.Flags().StringVar(&transactionTemplateImportName, "name", "", "Save the imported template under this name")
}
