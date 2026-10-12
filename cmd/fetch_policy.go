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
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

const (
	allowPrivateNetworksFlag = "allow-private-networks"
	allowPrivateNetworksEnv  = "EUDI_DEV_ALLOW_PRIVATE_NETWORKS"
)

// addAllowPrivateNetworksFlag registers the flag. note adds what the
// command does differently.
func addAllowPrivateNetworksFlag(cmd *cobra.Command, target *bool, note string) {
	cmd.Flags().BoolVar(target, allowPrivateNetworksFlag, false,
		"Let outbound requests reach private networks (RFC 1918, link local, CGNAT, unique local), for issuers and verifiers on a LAN, in Docker or in a cluster. Loopback is always reachable. "+note+"(default $"+allowPrivateNetworksEnv+")")
}

// installFetchPolicy limits where a server connects. Visitors hand a server
// URLs: credential offers and request URIs to the wallet, trusted lists,
// issuers and status lists to the decoder. So a server reaches public
// addresses and loopback, where developers run issuer and verifier next to the
// wallet. --allow-private-networks lifts the limit. A public demo reaches
// public addresses only. Every server reaches the operator's destinations at
// their exact address and port: its own origins, the configured trusted lists
// and the forward proxy, which sees every proxied destination in place of the
// server.
func installFetchPolicy(cmd *cobra.Command, allowPrivate, demo bool, operatorURLs ...string) error {
	if !cmd.Flags().Changed(allowPrivateNetworksFlag) {
		if raw := strings.TrimSpace(os.Getenv(allowPrivateNetworksEnv)); raw != "" {
			value, err := strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("%s=%q is not a boolean", allowPrivateNetworksEnv, raw)
			}
			allowPrivate = value
		}
	}
	if demo && allowPrivate && cmd.Flags().Changed(allowPrivateNetworksFlag) {
		return fmt.Errorf("--%s does not apply to --demo, which reaches public addresses only", allowPrivateNetworksFlag)
	}
	if allowPrivate && !demo {
		format.SetFetchPolicy(nil)
		return nil
	}
	policy := format.BlockPrivateAddresses
	if !demo {
		policy = format.AllowLoopback(policy)
	}
	format.SetFetchPolicy(format.AllowOwnOrigins(withFlagHint(policy, demo), operatorURLs...))
	return nil
}

func withFlagHint(policy format.FetchPolicy, demo bool) format.FetchPolicy {
	if demo {
		return policy
	}
	return func(network, address string) error {
		if err := policy(network, address); err != nil {
			return fmt.Errorf("%w (start the server with --%s to reach private networks)", err, allowPrivateNetworksFlag)
		}
		return nil
	}
}
