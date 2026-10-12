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
	"strings"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
)

const (
	listenFlag = "listen"
	listenEnv  = "EUDI_DEV_LISTEN"
	// listenAll is what --docker binds. On Linux, host.docker.internal
	// reaches the host at the Docker bridge address, not at loopback.
	listenAll = "0.0.0.0"
)

// addListenFlag registers --listen. note adds what the command does
// differently.
func addListenFlag(cmd *cobra.Command, target *string, note string) {
	cmd.Flags().StringVar(target, listenFlag, netaddr.DefaultListenHost,
		"IP address to bind. 127.0.0.1 keeps the server on this machine, 0.0.0.0 opens it to the network. "+note+"Also set by $"+listenEnv)
}

// resolveListenHost returns the bind address of a server: --listen, else
// $EUDI_DEV_LISTEN, else 0.0.0.0 for --docker, else 127.0.0.1.
func resolveListenHost(cmd *cobra.Command, value string, docker bool) (string, error) {
	source := "--" + listenFlag
	if !cmd.Flags().Changed(listenFlag) {
		if raw := strings.TrimSpace(os.Getenv(listenEnv)); raw != "" {
			value, source = raw, listenEnv
		} else if docker {
			value = listenAll
		}
	}
	host, err := netaddr.ParseListenHost(value)
	if err != nil {
		return "", fmt.Errorf("%s: %w", source, err)
	}
	return host, nil
}
