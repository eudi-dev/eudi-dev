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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// runCommand runs the root command with args and returns what it printed.
func runCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Cleanup(func() {
		jsonOutput = false
		resetFlags(rootCmd)
		format.SetFetchPolicy(nil)
	})
	resetFlags(rootCmd)
	var err error
	out := captureStdout(t, func() {
		rootCmd.SetOut(nil)
		rootCmd.SetArgs(args)
		err = rootCmd.Execute()
	})
	return out, err
}

// busyPort holds a port, so the decoder fails to listen after its setup.
func busyPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

func TestTheDecoderStartsOnTheGivenPort(t *testing.T) {
	resetRemoteTestState(t)
	t.Setenv(allowPrivateNetworksEnv, "")
	port := busyPort(t)
	imprintFile := filepath.Join(t.TempDir(), "imprint.html")
	if err := os.WriteFile(imprintFile, []byte("<p>Operator</p>"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCommand(t, "decoder", "--port", fmt.Sprint(port), "--imprint-file", imprintFile, "eyJhbGciOiJub25lIn0.e30.")
	if !strings.Contains(out, fmt.Sprintf("Starting %s at http://localhost:%d", config.DecoderName, port)) {
		t.Errorf("printed %q, want the decoder URL", out)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("error %v, want the port in use", err)
	}
	if err := privateFetchError(t); err == nil || !strings.Contains(err.Error(), "--allow-private-networks") {
		t.Errorf("a private address was not refused: %v", err)
	}
}

func TestTheDecoderRefusesBadSetup(t *testing.T) {
	notHTML := filepath.Join(t.TempDir(), "imprint.txt")
	if err := os.WriteFile(notHTML, []byte("Operator"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"json output", "", []string{"decoder", "--json"}, "--json does not work with this command"},
		{"invalid variable", "maybe", []string{"decoder"}, allowPrivateNetworksEnv + `="maybe" is not a boolean`},
		{"imprint that is not html", "", []string{"decoder", "--imprint-file", notHTML}, "must be an .html snippet"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetRemoteTestState(t)
			t.Setenv(allowPrivateNetworksEnv, c.env)
			if _, err := runCommand(t, append(c.args, "--port", fmt.Sprint(busyPort(t)))...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want %q", err, c.want)
			}
		})
	}
}
