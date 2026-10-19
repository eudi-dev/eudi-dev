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

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/browserlaunch"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcextension"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
)

func walletExtensionCmd() *cobra.Command {
	var walletURL string

	cmd := &cobra.Command{
		Use:   "extension <dir>",
		Args:  cobra.ExactArgs(1),
		Short: "Write the browser extension for the Digital Credentials API",
		Long: `Writes the eudi-dev browser extension into a folder. The extension answers
navigator.credentials.get() with an eudi-dev wallet, so you can test a
verifier that uses the Digital Credentials API without a phone.

Chrome installs it from the folder: open chrome://extensions, turn on
Developer mode, choose Load unpacked and select the folder. Every wallet
server also offers the extension as a zip file at /` + dcextension.ZipName + `.
'eudi wallet browser' opens Chrome with the extension without these steps.

--wallet-url sets the wallet the extension uses, by default the public demo
at ` + config.PublicDemoURL + `. You can change it later in the extension's popup.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if err := dcextension.WriteDir(dir, dcextension.Options{WalletURL: walletURL, Version: Version}); err != nil {
				return fmt.Errorf("writing the extension: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote the extension for the wallet at %s to %s\n\n", walletURL, dir)
			fmt.Fprintln(cmd.OutOrStdout(), "Install it in Chrome:")
			fmt.Fprintln(cmd.OutOrStdout(), "  1. Open chrome://extensions")
			fmt.Fprintln(cmd.OutOrStdout(), "  2. Turn on Developer mode")
			fmt.Fprintf(cmd.OutOrStdout(), "  3. Choose Load unpacked and select %s\n", dir)
			return nil
		},
	}

	cmd.Flags().StringVar(&walletURL, "wallet-url", config.PublicDemoURL, "Wallet that answers the requests")
	return cmd
}

func walletBrowserCmd() *cobra.Command {
	var walletURL, browserPath string

	cmd := &cobra.Command{
		Use:   "browser [url]",
		Args:  cobra.MaximumNArgs(1),
		Short: "Open Chrome with the browser extension for the Digital Credentials API",
		Long: `Opens Chrome, Chromium, Edge or Brave with the eudi-dev browser extension
loaded. Pages in that window that call navigator.credentials.get() get the
presentation from the wallet. The window opens the given URL, or the demo
verifier of the wallet.

The browser uses its own profile in the eudi-dev folder, next to your everyday
profile. Chrome loads the extension this way only into a separate profile. The
command ends when you close the browser. To use the extension in your
everyday profile, install it with 'eudi wallet extension <dir>'.

The wallet is the one other wallet commands use: --remote, the target set with
'wallet use', or a running wallet server for the wallet directory. Without
any of them it is the public demo at ` + config.PublicDemoURL + `. --wallet-url
sets another one. Works on macOS and Linux.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := browserWalletURL(walletURL)
			if err != nil {
				return err
			}
			page := target + "/verifier/"
			if len(args) == 1 {
				page = args[0]
			}
			base := filepath.Join(config.BaseDir(), "browser")
			extensionDir := filepath.Join(base, "extension")
			// The folder belongs to this command, so it is written fresh for
			// the current version and wallet.
			if err := os.RemoveAll(extensionDir); err != nil {
				return err
			}
			if err := dcextension.WriteDir(extensionDir, dcextension.Options{WalletURL: target, Version: Version}); err != nil {
				return fmt.Errorf("writing the extension: %w", err)
			}
			browser, err := browserlaunch.Launch(browserlaunch.Options{
				Executable:   browserPath,
				ProfileDir:   filepath.Join(base, "profile"),
				ExtensionDir: extensionDir,
				URL:          page,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Opened %s with the extension for the wallet at %s.\nClose the browser to end this command.\n", page, target)
			return browser.Wait()
		},
	}

	cmd.Flags().StringVar(&walletURL, "wallet-url", "", "Wallet that answers the requests, instead of the wallet the other commands use")
	cmd.Flags().StringVar(&browserPath, "browser-path", "", "Browser binary. By default the first installed Chrome, Chromium, Edge or Brave")
	return cmd
}

// browserWalletURL returns the wallet the browser extension uses.
func browserWalletURL(flag string) (string, error) {
	if url := strings.TrimSpace(flag); url != "" {
		return strings.TrimRight(url, "/"), nil
	}
	url, err := activeRemoteURL()
	if err != nil {
		return "", err
	}
	if url == "" && !forcedLocal() {
		if inst := remote.InstanceForWalletDir(resolvedWalletDir(), instanceProbeTimeout); inst != nil {
			url = inst.URL
		}
	}
	if url == "" {
		fmt.Fprintf(os.Stderr, "No wallet server runs for this wallet directory, so the extension uses the public demo at %s.\n", config.PublicDemoURL)
		return config.PublicDemoURL, nil
	}
	return strings.TrimRight(url, "/"), nil
}
