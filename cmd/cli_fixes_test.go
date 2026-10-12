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
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// wallet serve -d passes every flag to the child. A string array keeps a
// value with a comma whole.
func TestSerializeWalletServeArgsKeepsStringArrays(t *testing.T) {
	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().StringArray("trusted-list", nil, "")
	cmd.SetArgs([]string{"--trusted-list", "https://lists.example/a,b", "--trusted-list", "https://lists.example/c"})
	var got []string
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		var err error
		got, err = serializeWalletServeArgs(cmd)
		return err
	}
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want := []string{"--trusted-list", "https://lists.example/a,b", "--trusted-list", "https://lists.example/c"}
	if !slices.Equal(got, want) {
		t.Fatalf("serialized %#v, want %#v", got, want)
	}
}

type fakeServer struct {
	stopped chan struct{}
}

func (f *fakeServer) ListenAndServe() error {
	<-f.stopped
	return http.ErrServerClosed
}

func (f *fakeServer) Shutdown() { close(f.stopped) }

// Ctrl-C stops the server and returns, so wallet serve removes its instance
// file on the way out.
func TestServeUntilSignalStopsOnASignal(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	done := make(chan error, 1)
	go func() { done <- serveUntilSignal(&fakeServer{stopped: make(chan struct{})}, signals) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilSignal: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server kept running after the signal")
	}
}

// Cobra accepts stray arguments for a command without an Args rule, so every
// runnable command states which arguments it takes.
func TestEveryCommandDeclaresItsArguments(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Runnable() && c.Args == nil && !c.DisableFlagParsing && c.Name() != "help" {
			t.Errorf("%s has no Args rule", c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// POST /api/shutdown stops the server like a signal, so wallet serve returns
// and its deferred cleanup runs.
func TestServeWalletReturnsAfterAPIShutdown(t *testing.T) {
	port, err := findFreePresentationPortPair(23000)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, _ := mock.GenerateKey()
	issuerKey, _ := mock.GenerateKey()
	srv := wallet.NewServer(wallet.New(holderKey, issuerKey, false), port, nil)
	done := make(chan error, 1)
	go func() { done <- serveWallet(srv, make(chan os.Signal)) }()
	c := remote.NewClient(fmt.Sprintf("http://localhost:%d", port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := c.Shutdown(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("shutdown request: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveWallet: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server kept running after POST /api/shutdown")
	}
}

// The wallet drops its oldest log entries. A follower prints what came after
// the last entry it printed, even when the log keeps its length.
func TestLogEntriesAfterFollowsATrimmedLog(t *testing.T) {
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	entry := func(i int) wallet.LogEntry {
		return wallet.LogEntry{Time: at.Add(time.Duration(i) * time.Second), Action: "issuance", Detail: string(rune('a' + i))}
	}
	printed := []wallet.LogEntry{entry(0), entry(1), entry(2)}
	trimmed := []wallet.LogEntry{entry(1), entry(2), entry(3)}
	if got := logEntriesAfter(trimmed, &printed[2]); len(got) != 1 || got[0].Detail != "d" {
		t.Fatalf("new entries %v, want the one after c", got)
	}
	cleared := []wallet.LogEntry{entry(5)}
	if got := logEntriesAfter(cleared, &printed[2]); len(got) != 1 || got[0].Detail != "f" {
		t.Fatalf("after a clear: %v", got)
	}
}

// A registry entry can outlive its server. Its pid may then belong to another
// program, which must not get the signal.
func TestKillLeavesAReusedPidAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep and signal 0")
	}
	resetRemoteTestState(t)
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })

	inst := remote.DiscoveredInstance{Instance: remote.Instance{PID: other.Process.Pid, URL: "http://127.0.0.1:1"}, Source: "registry"}
	if err := stopInstance(inst); err == nil {
		t.Fatal("stopping a wallet that does not answer reported success")
	}
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the other program was signalled: %v", err)
	}
}

// Tab completion only reads. It must not create a wallet in an empty
// directory.
func TestDeferredCompletionCreatesNoWallet(t *testing.T) {
	resetRemoteTestState(t)
	useLocalTestWallet(t)
	completeDeferredIDs(walletCmd, nil, "")
	if entries, _ := os.ReadDir(walletDir); len(entries) > 0 {
		t.Fatalf("completion wrote %d entries to the wallet directory, such as %s", len(entries), entries[0].Name())
	}
}

// draft-ietf-oauth-status-list §7.1 defines 0x02 as SUSPENDED.
func TestCredStatusLabelNamesSuspended(t *testing.T) {
	for status, want := range map[float64]string{0: "active", 1: "revoked", 2: "suspended", 5: "status 5"} {
		if got := credStatusLabel(map[string]any{"status": map[string]any{"status": status}}); !strings.Contains(got, want) {
			t.Errorf("status %v labelled %q, want %q", status, got, want)
		}
	}
}

// eudi decoder has no --demo, so its help says nothing about it.
func TestAllowPrivateNetworksHelpFitsTheCommand(t *testing.T) {
	decoderHelp := decoderCmd.Flags().Lookup(allowPrivateNetworksFlag).Usage
	if strings.Contains(decoderHelp, "--demo") {
		t.Errorf("eudi decoder help mentions --demo: %s", decoderHelp)
	}
	walletHelp := walletServeCmd().Flags().Lookup(allowPrivateNetworksFlag).Usage
	if !strings.Contains(walletHelp, "--demo refuses the flag") {
		t.Errorf("wallet serve help: %s", walletHelp)
	}
}
