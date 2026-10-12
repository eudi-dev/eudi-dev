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
	"errors"
	"strings"

	"github.com/spf13/cobra"
)

// movedCommands map a command path of eudi-dev 2 to the commands that replace it.
var movedCommands = []struct {
	old string
	new []string
}{
	{"serve", []string{"decoder"}},
	{"wallet registrar", []string{"registrar"}},
	{"wallet catalog", []string{"catalog"}},
	{"wallet trust", []string{"trust"}},
	{"wallet trust-list", []string{"trust show"}},
	{"wallet trusted-list", []string{"trust show"}},
	{"wallet ca-cert", []string{"trust ca-cert"}},
	{"wallet present", []string{"wallet accept"}},
	{"wallet listen", []string{"wallet serve --register"}},
	{"wallet generate-pid", []string{"issue sdjwt --wallet --pid", "issue mdoc --wallet --pid"}},
	{"wallet instances", []string{"wallet ps"}},
}

// addMovedCommands registers a hidden stub for every moved command. A stub
// parses nothing and runs nothing. It only names the new command.
func addMovedCommands() {
	for _, moved := range movedCommands {
		path := strings.Fields(moved.old)
		parent := rootCmd
		if len(path) == 2 {
			parent = walletCmd
		}
		replacements := make([]string, len(moved.new))
		for i, cmd := range moved.new {
			replacements[i] = binaryName() + " " + cmd
		}
		err := errors.New(binaryName() + " " + moved.old + " is now " + strings.Join(replacements, " and "))
		parent.AddCommand(&cobra.Command{
			Use:                path[len(path)-1],
			Hidden:             true,
			DisableFlagParsing: true,
			RunE: func(*cobra.Command, []string) error {
				return err
			},
		})
	}
}
