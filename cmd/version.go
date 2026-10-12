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
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

// Version is set at build time via -ldflags:
//
//	go build -ldflags="-X github.com/eudi-dev/eudi-dev/v2/cmd.Version=1.0.0"
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s (eudi-dev)\n", binaryName(), Version)
	},
}

func init() {
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
	}
	remote.SetVersion(Version)
	wallet.SetHandlerScriptVersion(Version)
	rootCmd.AddCommand(versionCmd)
}
