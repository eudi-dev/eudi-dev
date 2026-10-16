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
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
	"github.com/eudi-dev/eudi-dev/v3/internal/urlhandler"
)

// walletOpenURLCmd is what the registered URL scheme handler runs for a
// clicked link. It is hidden because people use 'wallet accept'.
func walletOpenURLCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "open-url <uri>",
		Short:  "Hand a clicked link to the wallet (run by the URL scheme handler)",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, registered, err := urlhandler.LoadOptions()
			if err != nil {
				return err
			}
			if !registered {
				opts.ListenerPort = config.DefaultWalletPort
			}
			binary, err := os.Executable()
			if err != nil {
				return fmt.Errorf("finding executable path: %w", err)
			}
			// Cobra reports the returned error on stderr, so only the file gets it here.
			var log io.Writer = os.Stderr
			var file io.Writer = io.Discard
			if err := os.MkdirAll(config.BaseDir(), 0o755); err == nil {
				if f, err := os.OpenFile(urlhandler.DispatchLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
					defer f.Close()
					file = f
					log = io.MultiWriter(os.Stderr, f)
				}
			}
			fmt.Fprintf(log, "%s open-url %s\n", time.Now().Format(time.RFC3339), args[0])
			err = urlhandler.NewDispatcher(opts, binary, Version, remote.Active(), openBrowser, log).Dispatch(args[0])
			if err != nil {
				fmt.Fprintf(file, "%v\n", err)
			}
			return err
		},
	}
}
