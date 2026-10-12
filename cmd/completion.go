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

// This replaces Cobra's generated completion command to add `completion install`.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func completionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate or install shell completion",
		Long: "Generates the completion script for a shell. Use `completion install` to add it to your shell " +
			"init automatically. Completion covers subcommands, flags, and known values (template names, " +
			"credential IDs, running wallet instances).",
		Args: cobra.NoArgs,
		RunE: showHelp,
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "bash",
		Short: "Generate the bash completion script",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return rootCmd.GenBashCompletionV2(os.Stdout, true)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "zsh",
		Short: "Generate the zsh completion script",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return rootCmd.GenZshCompletion(os.Stdout)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "fish",
		Short: "Generate the fish completion script",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return rootCmd.GenFishCompletion(os.Stdout, true)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "powershell",
		Short: "Generate the powershell completion script",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		},
	})
	cmd.AddCommand(completionInstallCmd())
	for _, sub := range cmd.Commands() {
		sub.PreRunE = func(*cobra.Command, []string) error {
			return rejectJSON("completion prints a shell script")
		}
	}
	return cmd
}

func completionInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install [bash|zsh|fish]",
		Short: "Install shell completion into your shell init",
		Long: "Adds the completion setup to your shell init: a source line in ~/.bashrc or ~/.zshrc, or a " +
			"completion file in ~/.config/fish/completions. Without an argument the shell is detected from $SHELL. " +
			"Running it again is safe (already installed setups are left untouched).",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: staticCompletion("bash", "zsh", "fish"),
		RunE: func(c *cobra.Command, args []string) error {
			shell := ""
			if len(args) > 0 {
				shell = args[0]
			} else {
				shell = filepath.Base(os.Getenv("SHELL"))
			}
			switch shell {
			case "bash":
				return installRCLine(".bashrc", "bash")
			case "zsh":
				return installRCLine(".zshrc", "zsh")
			case "fish":
				return installFishCompletion()
			default:
				return fmt.Errorf("unsupported or undetected shell %q: pass bash, zsh, or fish (powershell users add `eudi completion powershell | Out-String | Invoke-Expression` to their profile)", shell)
			}
		},
	}
}

func installRCLine(rcName, shell string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	rcPath := filepath.Join(home, rcName)
	line := fmt.Sprintf("source <(%s completion %s)", rootCmd.Name(), shell)

	existing, err := os.ReadFile(rcPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(existing), line) {
		fmt.Printf("Completion already installed in %s\n", rcPath)
		return nil
	}

	// 0600 only applies when the rc file does not exist yet. Existing rc
	// files keep their permissions.
	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "\n# eudi-dev shell completion\n%s\n", line); err != nil {
		return err
	}
	fmt.Printf("Installed completion in %s\n", rcPath)
	if shell == "zsh" {
		fmt.Println("Make sure compinit runs in your .zshrc (autoload -U compinit && compinit).")
	}
	fmt.Println("Restart your shell or source the file to activate it.")
	return nil
}

func installFishCompletion() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".config", "fish", "completions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, rootCmd.Name()+".fish")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := rootCmd.GenFishCompletion(f, true); err != nil {
		return err
	}
	fmt.Printf("Installed completion in %s\n", path)
	fmt.Println("Restart your shell to activate it.")
	return nil
}

func init() {
	rootCmd.AddCommand(completionCmd())
}
