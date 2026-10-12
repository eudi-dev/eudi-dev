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
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	noColor    bool
	verbose    bool
)

// binaryName keeps help and completion consistent with the invoked name, including the
// oid4vc-dev alias.
func binaryName() string {
	base := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	if strings.HasPrefix(base, "oid4vc-dev") {
		return "oid4vc-dev"
	}
	return "eudi"
}

var rootCmd = &cobra.Command{
	Use:   binaryName(),
	Short: "Decode, validate, and test verifiable credentials (SD-JWT, mdoc)",
	Long:  "A local-first CLI tool for decoding, validating, and testing verifiable credentials. Supports SD-JWT, mdoc (mso_mdoc), OID4VP/OID4VCI flows, ETSI trust lists, and includes a testing wallet.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		applyNoColor()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
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
