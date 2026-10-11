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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

// privateFetchError fetches an address on a private network. The policy
// refuses it before the connection starts. Without a policy the connection
// attempt runs into the deadline.
func privateFetchError(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.255.255.1:9/", nil)
	resp, err := format.HTTPClient().Do(req)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func loopbackFetchError(t *testing.T) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := format.FetchURL(srv.URL)
	return err
}

func policyCommand(t *testing.T, args ...string) (*cobra.Command, *bool) {
	t.Helper()
	t.Cleanup(func() { format.SetFetchPolicy(nil) })
	cmd := &cobra.Command{}
	var allow bool
	addAllowPrivateNetworksFlag(cmd, &allow, "")
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return cmd, &allow
}

func TestServersBlockPrivateNetworksAndReachLoopbackByDefault(t *testing.T) {
	t.Setenv(allowPrivateNetworksEnv, "")
	cmd, allow := policyCommand(t)
	if err := installFetchPolicy(cmd, *allow, false); err != nil {
		t.Fatal(err)
	}
	if err := privateFetchError(t); err == nil || !strings.Contains(err.Error(), "--allow-private-networks") {
		t.Errorf("a private address was not refused with a hint to the flag: %v", err)
	}
	if err := loopbackFetchError(t); err != nil {
		t.Errorf("loopback is not reachable: %v", err)
	}
}

func TestAllowPrivateNetworksLiftsTheLimit(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) []string{
		"flag": func(t *testing.T) []string {
			t.Setenv(allowPrivateNetworksEnv, "")
			return []string{"--allow-private-networks"}
		},
		"variable": func(t *testing.T) []string { t.Setenv(allowPrivateNetworksEnv, "true"); return nil },
	} {
		t.Run(name, func(t *testing.T) {
			cmd, allow := policyCommand(t, setup(t)...)
			if err := installFetchPolicy(cmd, *allow, false); err != nil {
				t.Fatal(err)
			}
			if err := privateFetchError(t); err != nil && strings.Contains(err.Error(), "not allowed") {
				t.Errorf("a private address is still refused: %v", err)
			}
		})
	}
}

func TestDemoReachesPublicAddressesAndItsOwnOrigins(t *testing.T) {
	t.Setenv(allowPrivateNetworksEnv, "true")
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer own.Close()
	cmd, allow := policyCommand(t)
	if err := installFetchPolicy(cmd, *allow, true, own.URL); err != nil {
		t.Fatal(err)
	}
	if err := loopbackFetchError(t); err == nil {
		t.Error("the demo reached another loopback service")
	}
	if err := privateFetchError(t); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("the demo did not refuse a private address: %v", err)
	}
	if _, err := format.FetchURL(own.URL); err != nil {
		t.Errorf("the demo cannot reach its own origin: %v", err)
	}
}

func TestDemoRefusesTheExplicitFlag(t *testing.T) {
	cmd, allow := policyCommand(t, "--allow-private-networks")
	if err := installFetchPolicy(cmd, *allow, true); err == nil {
		t.Fatal("--demo accepted --allow-private-networks")
	}
}

func TestAllowPrivateNetworksVariableMustBeABoolean(t *testing.T) {
	t.Setenv(allowPrivateNetworksEnv, "sometimes")
	cmd, allow := policyCommand(t)
	if err := installFetchPolicy(cmd, *allow, false); err == nil {
		t.Fatal("an invalid variable was accepted")
	}
}
