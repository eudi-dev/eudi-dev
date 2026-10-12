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

package remote

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := configBaseDir
	configBaseDir = func() string { return dir }
	t.Cleanup(func() { configBaseDir = prev })
	return dir
}

func TestActiveRemoteRoundTrip(t *testing.T) {
	withTempConfigDir(t)

	if Active() != "" {
		t.Fatalf("expected no active remote, got %q", Active())
	}

	normalized, err := SetActive("localhost:9099/")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "http://localhost:9099" {
		t.Errorf("unexpected normalization: %q", normalized)
	}
	if Active() != "http://localhost:9099" {
		t.Errorf("active mismatch: %q", Active())
	}

	if err := ClearActive(); err != nil {
		t.Fatal(err)
	}
	if Active() != "" {
		t.Errorf("expected cleared remote, got %q", Active())
	}
	if err := ClearActive(); err != nil {
		t.Errorf("clearing twice must not fail: %v", err)
	}
}

func TestDiscoverIncludesActiveRemote(t *testing.T) {
	withTempConfigDir(t)

	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.Write([]byte(`{"build_id": "remote-build", "version": "1.19.0", "pid": 1}`))
		case "/api/config":
			w.Write([]byte(`{"wallet_dir": "/home/app/.eudi-dev/wallet"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer live.Close()

	if _, err := SetActive(live.URL); err != nil {
		t.Fatal(err)
	}

	found := Discover(500 * time.Millisecond)
	var actives []DiscoveredInstance
	for _, di := range found {
		if di.Source == "active" {
			actives = append(actives, di)
		}
	}
	if len(actives) != 1 {
		t.Fatalf("expected the active remote to be discovered, got %v", found)
	}
	liveURL, _ := url.Parse(live.URL)
	livePort, _ := strconv.Atoi(liveURL.Port())
	got := actives[0]
	if got.Port != livePort || got.PID != 1 || got.BuildID != "remote-build" || got.Version != "1.19.0" || got.WalletDir != "/home/app/.eudi-dev/wallet" {
		t.Errorf("unexpected active instance: %+v", got)
	}

	if err := RegisterInstance(Instance{PID: 1, Port: livePort, URL: live.URL, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	found = Discover(500 * time.Millisecond)
	for _, di := range found {
		if di.Source == "active" {
			t.Fatalf("expected no active row next to the registry entry, got %v", found)
		}
	}

	live.Close()
	if err := os.RemoveAll(instancesDir()); err != nil {
		t.Fatal(err)
	}
	for _, di := range Discover(500 * time.Millisecond) {
		if di.Source == "active" || di.URL == live.URL {
			t.Fatalf("expected no row for a dead remote, got %+v", di)
		}
	}
}

func TestNormalizeURLRejectsInvalid(t *testing.T) {
	for _, raw := range []string{"", "ftp://host", "http://"} {
		if _, err := NormalizeURL(raw); err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
}

func TestClientErrorsCarryServerMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "nope"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Credentials()
	if err == nil || !contains(err.Error(), "nope") {
		t.Errorf("expected server error message, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// exitedPID returns the process ID of a child that has exited.
func exitedPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

func versionServer(t *testing.T, pid int) (*httptest.Server, int) {
	t.Helper()
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"build_id": "test-build", "pid": %d}`, pid)
	}))
	t.Cleanup(live.Close)
	liveURL, _ := url.Parse(live.URL)
	port, _ := strconv.Atoi(liveURL.Port())
	return live, port
}

func TestDiscoverRegistryAndPrune(t *testing.T) {
	withTempConfigDir(t)
	self, dead := os.Getpid(), exitedPID(t)
	live, livePort := versionServer(t, self)

	if err := RegisterInstance(Instance{PID: self, Port: livePort, URL: live.URL, WalletDir: "/tmp/w", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterInstance(Instance{PID: dead, Port: 1, URL: "http://localhost:1", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	found := Discover(500 * time.Millisecond)
	var registryHits []DiscoveredInstance
	for _, di := range found {
		if di.Source == "registry" {
			registryHits = append(registryHits, di)
		}
	}
	if len(registryHits) != 1 {
		t.Fatalf("expected exactly the live registry instance, got %v", found)
	}
	if registryHits[0].PID != self || registryHits[0].BuildID != "test-build" || registryHits[0].WalletDir != "/tmp/w" {
		t.Errorf("unexpected instance: %+v", registryHits[0])
	}

	if _, err := os.Stat(instanceFile(dead)); !os.IsNotExist(err) {
		t.Error("the entry of an exited process was not pruned")
	}
	if _, err := os.Stat(instanceFile(self)); err != nil {
		t.Error("live instance file must remain")
	}

	UnregisterInstance(self)
	if _, err := os.Stat(instanceFile(self)); !os.IsNotExist(err) {
		t.Error("unregister did not remove the instance file")
	}
}

// A server that is too busy to answer the health check still owns its wallet
// directory. Only an exited process loses its entry.
func TestDiscoverKeepsALiveInstanceThatDoesNotAnswer(t *testing.T) {
	withTempConfigDir(t)
	walletDir := t.TempDir()
	if err := RegisterInstance(Instance{PID: os.Getpid(), Port: 1, URL: "http://localhost:1", WalletDir: walletDir, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	inst := InstanceForWalletDir(walletDir, 200*time.Millisecond)
	if inst == nil || inst.PID != os.Getpid() {
		t.Fatalf("InstanceForWalletDir = %+v, want the registered live process", inst)
	}
	if _, err := os.Stat(instanceFile(os.Getpid())); err != nil {
		t.Fatalf("the entry of a live process was removed: %v", err)
	}
}

func TestInstanceForWalletDir(t *testing.T) {
	withTempConfigDir(t)
	walletDir := t.TempDir()
	self := os.Getpid()
	live, port := versionServer(t, self)

	if err := RegisterInstance(Instance{PID: self, Port: port, URL: live.URL, WalletDir: walletDir, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	inst := InstanceForWalletDir(walletDir, 500*time.Millisecond)
	if inst == nil {
		t.Fatal("expected to find the instance for its wallet dir")
	}
	if inst.PID != self || inst.URL != live.URL {
		t.Errorf("unexpected instance: %+v", inst)
	}

	if got := InstanceForWalletDir(t.TempDir(), 500*time.Millisecond); got != nil {
		t.Errorf("expected no instance for an unrelated dir, got %+v", got)
	}
	if got := InstanceForWalletDir("", 500*time.Millisecond); got != nil {
		t.Errorf("expected no instance for an empty dir, got %+v", got)
	}
}

func TestDiscoverDedupesStaleRegistryFilesOnSamePort(t *testing.T) {
	withTempConfigDir(t)
	self, dead := os.Getpid(), exitedPID(t)
	live, port := versionServer(t, self)

	// The current server reused the port of an exited one, so both registry
	// files list it. Discovery removes the entry of the exited process.
	if err := RegisterInstance(Instance{PID: dead, Port: port, URL: live.URL, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterInstance(Instance{PID: self, Port: port, URL: live.URL, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	found := Discover(500 * time.Millisecond)
	count := 0
	for _, di := range found {
		if di.Port == port {
			count++
			if di.PID != self {
				t.Errorf("expected live pid %d, got %d", self, di.PID)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one instance for the port, got %d (%v)", count, found)
	}
	if _, err := os.Stat(instanceFile(dead)); !os.IsNotExist(err) {
		t.Error("stale registry file for the dead pid not pruned")
	}
	if _, err := os.Stat(instanceFile(self)); err != nil {
		t.Error("live instance file must remain")
	}
}
