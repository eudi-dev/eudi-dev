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

	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/output"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

var dcqlCmd = &cobra.Command{
	Use:   "dcql [input]",
	Short: "Generate a DCQL query from a credential's claims",
	Long:  "Generates a DCQL (Digital Credentials Query Language) query based on the claims found in an SD-JWT or mdoc credential.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDCQL,
}

func init() {
	rootCmd.AddCommand(dcqlCmd)
}

func runDCQL(cmd *cobra.Command, args []string) error {
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	raw, err := format.ReadInput(input)
	if err != nil {
		return err
	}

	detected := format.Detect(raw)

	var query *dcql.Query

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		query = dcql.FromSDJWT(token)

	case format.FormatJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		query = dcql.FromJWT(token)

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mdoc: %w", err)
		}
		query = dcql.FromMDOC(doc)

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	// DCQL is a JSON format, so the output is JSON regardless of --json.
	output.PrintJSON(query)

	return nil
}
