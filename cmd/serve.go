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

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/imprint"
	"github.com/eudi-dev/eudi-dev/v2/internal/web"
)

var (
	port             int
	serveImprintFile string
)

var serveCmd = &cobra.Command{
	Use:   "serve [credential]",
	Short: "Start a local web UI for decoding and validating credentials",
	Long:  "Starts a local HTTP server with a web UI for decoding, validating, and inspecting verifiable credentials (SD-JWT, JWT, mdoc). Optionally pass a credential to pre-fill the input.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().IntVar(&port, "port", config.DefaultServePort, "Port to listen on")
	serveCmd.Flags().StringVar(&serveImprintFile, "imprint-file", "", "HTML snippet with the site operator's legal notice, served at /imprint (required for public EU hosting)")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	var credential string
	if len(args) > 0 {
		raw, err := format.ReadInput(args[0])
		if err != nil {
			return err
		}
		credential = raw
	}

	opts := web.MuxOptions{Credential: credential, Version: Version}
	if serveImprintFile != "" {
		page, err := imprint.Load(serveImprintFile)
		if err != nil {
			return err
		}
		opts.ImprintHTML = page
	}

	fmt.Printf("Starting EUDI Dev Web UI at http://localhost:%d\n", port)
	return web.ListenAndServe(port, opts)
}
