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

// movedCommands map a command path of eudi-dev 2 to the command that replaces it.
var movedCommands = []struct{ old, new string }{
	{"serve", "decoder"},
	{"wallet registrar", "registrar"},
	{"wallet catalog", "catalog"},
	{"wallet trust", "trust"},
	{"wallet trust-list", "trust show"},
	{"wallet trusted-list", "trust show"},
	{"wallet ca-cert", "trust ca-cert"},
	{"wallet present", "wallet accept"},
	{"wallet listen", "wallet serve --register"},
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
		err := errors.New(binaryName() + " " + moved.old + " is now " + binaryName() + " " + moved.new)
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
