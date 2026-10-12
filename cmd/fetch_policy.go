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

// installFetchPolicy limits where a server connects. Visitors give a server
// URLs to fetch: credential offers and request URIs for the wallet, trusted
// lists, issuers and status lists for the decoder. A server reaches public
// addresses and loopback, because developers run issuers and verifiers next
// to the wallet. A public demo reaches public addresses only.
// --allow-private-networks lifts the limit in both cases. Every server can
// reach the operator's destinations at their exact address and port. These
// are its own origins, the configured trusted lists and the forward proxy.
// The proxy sees every proxied destination in place of the server. It
// reports whether the limit is lifted.
func installFetchPolicy(cmd *cobra.Command, allowPrivate, demo bool, operatorURLs ...string) (bool, error) {
	if !cmd.Flags().Changed(allowPrivateNetworksFlag) {
		if raw := strings.TrimSpace(os.Getenv(allowPrivateNetworksEnv)); raw != "" {
			value, err := strconv.ParseBool(raw)
			if err != nil {
				return false, fmt.Errorf("%s=%q is not a boolean", allowPrivateNetworksEnv, raw)
			}
			allowPrivate = value
		}
	}
	if allowPrivate {
		format.SetFetchPolicy(nil)
		return true, nil
	}
	policy := format.BlockPrivateAddresses
	if !demo {
		policy = format.AllowLoopback(policy)
	}
	format.SetFetchPolicy(format.AllowOwnOrigins(withFlagHint(policy, demo), operatorURLs...))
	return false, nil
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
