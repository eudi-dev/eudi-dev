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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/eudi-dev/eudi-dev/v3/internal/output"
)

// decode prints the lines of the chain in its JSON output (ADR-0012).
func TestDecodePrintsTheChainLines(t *testing.T) {
	for _, fixture := range []string{"delegate-sd-jwt-kb.txt", "delegate-sd-jwt-3-links.txt"} {
		t.Run(fixture, func(t *testing.T) {
			resetRemoteTestState(t)
			data, err := os.ReadFile(filepath.Join("..", "e2e", "fixtures", fixture))
			if err != nil {
				t.Fatal(err)
			}
			raw := strings.TrimSpace(string(data))

			var chain output.ChainJSON
			encoded, _ := json.Marshal(runJSON(t, "decode", raw)["chain"])
			if err := json.Unmarshal(encoded, &chain); err != nil || len(chain.Parts) == 0 {
				t.Fatalf("decode --json has no chain: %s (%v)", encoded, err)
			}
			text := runText(t, "decode", raw)
			rest := text
			for _, line := range output.ChainLines(chain) {
				i := strings.Index(rest, line+"\n")
				if i < 0 {
					t.Fatalf("decode does not print %q after the lines before it:\n%s", line, text)
				}
				rest = rest[i+len(line):]
			}
		})
	}
}

func runText(t *testing.T, args ...string) string {
	t.Helper()
	t.Cleanup(func() { resetFlags(rootCmd) })
	resetFlags(rootCmd)
	var runErr error
	out := captureStdout(t, func() {
		// The colored headings go to color.Output, which holds the os.Stdout
		// of program start.
		previous := color.Output
		color.Output = os.Stdout
		defer func() { color.Output = previous }()
		rootCmd.SetOut(nil)
		rootCmd.SetArgs(args)
		runErr = rootCmd.Execute()
	})
	if runErr != nil {
		t.Fatalf("%v: %v", args, runErr)
	}
	return out
}
