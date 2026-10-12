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

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

var (
	jsonOutput bool
	noColor    bool
	verbose    bool
)

func binaryName() string {
	return "eudi"
}

var rootCmd = &cobra.Command{
	Use:   binaryName(),
	Short: "Decode, validate, and test verifiable credentials (SD-JWT, mdoc)",
	Long:  "A local-first CLI tool for decoding, validating, and testing verifiable credentials. Supports SD-JWT, mdoc (mso_mdoc), OID4VP/OID4VCI flows, ETSI trusted lists, and includes a testing wallet.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		applyNoColor()
		for _, warning := range config.LegacyHomeWarnings() {
			fmt.Fprintln(os.Stderr, warning)
		}
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Print one JSON document on stdout (messages go to stderr)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
}

// showHelp runs a command that only groups subcommands. With cobra.NoArgs as
// its Args, an unknown subcommand fails instead of printing the help.
func showHelp(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

func applyNoColor() {
	if noColor {
		color.NoColor = true
	}
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
