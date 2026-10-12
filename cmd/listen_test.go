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
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func resolveListen(t *testing.T, env string, docker bool, args ...string) (string, error) {
	t.Helper()
	t.Setenv(listenEnv, env)
	cmd := &cobra.Command{}
	var listen string
	addListenFlag(cmd, &listen, "")
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return resolveListenHost(cmd, listen, docker)
}

// A server binds the flag, else the variable, else every interface for
// --docker, else loopback.
func TestListenHostResolution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    string
		docker bool
		args   []string
		want   string
	}{
		{name: "default", want: "127.0.0.1"},
		{name: "docker", docker: true, want: "0.0.0.0"},
		{name: "variable", env: "0.0.0.0", want: "0.0.0.0"},
		{name: "variable over docker", env: "127.0.0.1", docker: true, want: "127.0.0.1"},
		{name: "flag over variable", env: "0.0.0.0", args: []string{"--listen", "::1"}, want: "::1"},
		{name: "flag over docker", docker: true, args: []string{"--listen", "localhost"}, want: "127.0.0.1"},
	} {
		got, err := resolveListen(t, tc.env, tc.docker, tc.args...)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v, want %q", tc.name, got, err, tc.want)
		}
	}
}

func TestListenHostErrorNamesItsSource(t *testing.T) {
	if _, err := resolveListen(t, "", false, "--listen", "example.com"); err == nil || !strings.HasPrefix(err.Error(), "--listen:") {
		t.Errorf("flag error = %v, want one naming --listen", err)
	}
	if _, err := resolveListen(t, "wallet.local", false); err == nil || !strings.HasPrefix(err.Error(), listenEnv+":") {
		t.Errorf("variable error = %v, want one naming %s", err, listenEnv)
	}
}
