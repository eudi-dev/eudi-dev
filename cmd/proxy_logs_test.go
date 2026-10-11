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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/dominikschlosser/eudi-dev/v3/internal/proxy"
)

// The renderer writes to both stdout and the color package writer. Capture both to
// check the terminal output.
func runProxyLogs(t *testing.T, args ...string) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldColor := os.Stdout, color.Output
	os.Stdout, color.Output = w, w
	defer func() { os.Stdout, color.Output = oldStdout, oldColor }()

	cmd := proxyLogsCmd()
	cmd.SetOut(w)
	cmd.SetErr(w)
	cmd.SetArgs(args)
	runErr := cmd.Execute()

	w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("proxy logs %v: %v (output %q)", args, runErr, buf.String())
	}
	return buf.String()
}

func proxyDashboardWith(t *testing.T, entries ...*proxy.TrafficEntry) *httptest.Server {
	t.Helper()
	store := proxy.NewStore(50)
	for _, entry := range entries {
		store.Add(entry)
	}
	srv := httptest.NewServer(proxy.NewDashboard(store).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestProxyLogsPrintsWhatTheProxyRecorded(t *testing.T) {
	srv := proxyDashboardWith(t,
		&proxy.TrafficEntry{Method: "POST", URL: "http://issuer.example/token", StatusCode: 200, ClassLabel: "VCI Token"},
		&proxy.TrafficEntry{Method: "GET", URL: "http://verifier.example/request", StatusCode: 404, ClassLabel: "VP Request Object"},
	)

	output := runProxyLogs(t, srv.URL)

	for _, want := range []string{
		"http://issuer.example/token",
		"http://verifier.example/request",
		"VCI Token",
		"404",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not mention %q:\n%s", want, output)
		}
	}
}

// Decode links must use the proxy's dashboard URL. A container's localhost address is
// not reachable from the host.
func TestProxyLogsLinksDecodeAtTheProxyItRead(t *testing.T) {
	srv := proxyDashboardWith(t, &proxy.TrafficEntry{
		Method: "POST", URL: "http://verifier.example/response", StatusCode: 200,
		ClassLabel:       "VP Authorization Response",
		Credentials:      []string{"credential-value"},
		CredentialLabels: []string{"vp_token"},
	})

	output := runProxyLogs(t, srv.URL)

	if !strings.Contains(output, srv.URL+"/decode/#credential=credential-value") {
		t.Errorf("decode link does not point at the proxy that was read:\n%s", output)
	}
	if strings.Contains(output, "localhost:9091") {
		t.Errorf("decode link fell back to a local dashboard:\n%s", output)
	}
}

func TestProxyLogsJSON(t *testing.T) {
	srv := proxyDashboardWith(t, &proxy.TrafficEntry{Method: "GET", URL: "http://target/one", StatusCode: 200})

	jsonOutput = true
	defer func() { jsonOutput = false }()

	output := runProxyLogs(t, srv.URL)
	var entries []map[string]any
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, output)
	}
	if len(entries) != 1 || entries[0]["url"] != "http://target/one" {
		t.Errorf("unexpected JSON: %s", output)
	}
}

// An unreachable proxy must produce an error.
func TestProxyLogsReportsAnUnreachableProxy(t *testing.T) {
	cmd := proxyLogsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"http://127.0.0.1:1"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("reading an unreachable proxy succeeded")
	}

	cmd = proxyLogsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"ftp://proxy.example"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a non-http dashboard URL was accepted")
	}
}

func TestProxyLogsRefusesJSONWithFollow(t *testing.T) {
	jsonOutput = true
	defer func() { jsonOutput = false }()

	cmd := proxyLogsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--follow"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("--json --follow was accepted")
	}
}

// followRun runs "proxy logs --follow" and collects what it prints while it
// runs. It stops in a test cleanup. Close the dashboard server in a cleanup
// registered before, so the stream ends first.
type followRun struct {
	mu     sync.Mutex
	output bytes.Buffer
	copied chan struct{}
	done   chan error
	cancel context.CancelFunc
	stop   func() string
}

func startFollow(t *testing.T, dashboardURL string, reconnectDelay time.Duration) *followRun {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldColor := os.Stdout, color.Output
	os.Stdout, color.Output = w, w

	ctx, cancel := context.WithCancel(context.Background())
	run := &followRun{copied: make(chan struct{}), done: make(chan error, 1), cancel: cancel}
	go func() {
		defer close(run.copied)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			run.mu.Lock()
			run.output.Write(buf[:n])
			run.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	cmd := proxyLogsCmdReconnectingAfter(reconnectDelay)
	cmd.SetOut(w)
	cmd.SetErr(w)
	cmd.SetArgs([]string{dashboardURL, "--follow"})
	cmd.SetContext(ctx)
	go func() { run.done <- cmd.Execute() }()

	stopped := false
	run.stop = func() string {
		t.Helper()
		if !stopped {
			stopped = true
			cancel()
			select {
			case err := <-run.done:
				if err != nil {
					t.Errorf("follow ended with %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("follow did not stop when the context ended")
			}
			os.Stdout, color.Output = oldStdout, oldColor
			w.Close()
			<-run.copied
		}
		run.mu.Lock()
		defer run.mu.Unlock()
		return run.output.String()
	}
	t.Cleanup(func() { run.stop() })
	return run
}

func (run *followRun) waitForOutput(t *testing.T, want string) {
	t.Helper()
	waitUntil(t, "the output to contain "+want, func() bool {
		run.mu.Lock()
		defer run.mu.Unlock()
		return strings.Contains(run.output.String(), want)
	})
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Subscribing before reading history can deliver the same entry twice. Follow must
// print it only once.
func TestProxyLogsFollowsWithoutRepeatingWhatItAlreadyPrinted(t *testing.T) {
	store := proxy.NewStore(50)
	store.Add(&proxy.TrafficEntry{Method: "GET", URL: "http://target/recorded", StatusCode: 200})
	srv := httptest.NewServer(proxy.NewDashboard(store).Handler())
	t.Cleanup(srv.Close)

	run := startFollow(t, srv.URL, time.Second)
	waitUntil(t, "the stream subscription", func() bool { return store.SubscriberCount() == 1 })
	store.Add(&proxy.TrafficEntry{Method: "POST", URL: "http://target/live", StatusCode: 201})
	// Output keeps its order, so once the last entry shows, any repeat would too.
	store.Add(&proxy.TrafficEntry{Method: "GET", URL: "http://target/last", StatusCode: 200})
	run.waitForOutput(t, "http://target/last")
	output := run.stop()

	if got := strings.Count(output, "http://target/recorded"); got != 1 {
		t.Errorf("the recorded entry was printed %d times, want once:\n%s", got, output)
	}
	if got := strings.Count(output, "http://target/live"); got != 1 {
		t.Errorf("the live entry was printed %d times, want once:\n%s", got, output)
	}
}

// Swapping the store simulates a proxy restart. The old stream closes and entry IDs
// start over, so the first entry after the restart reuses the ID of the last one
// printed before it.
func TestProxyLogsFollowSurvivesARestartedProxy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		beforeReattach bool
	}{
		{name: "traffic after the reattach"},
		{name: "traffic before the reattach", beforeReattach: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			store := proxy.NewStore(50)
			store.Add(&proxy.TrafficEntry{Method: "GET", URL: "http://target/before-restart", StatusCode: 200})

			current := func() *proxy.Store {
				mu.Lock()
				defer mu.Unlock()
				return store
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxy.NewDashboard(current()).Handler().ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			run := startFollow(t, srv.URL, 10*time.Millisecond)
			run.waitForOutput(t, "http://target/before-restart")
			waitUntil(t, "the stream subscription", func() bool { return current().SubscriberCount() == 1 })

			restarted := proxy.NewStore(50)
			after := &proxy.TrafficEntry{Method: "POST", URL: "http://target/after-restart", StatusCode: 201}
			if tc.beforeReattach {
				restarted.Add(after)
			}
			mu.Lock()
			store = restarted
			mu.Unlock()
			srv.CloseClientConnections()
			waitUntil(t, "the reattached stream", func() bool { return restarted.SubscriberCount() == 1 })
			if !tc.beforeReattach {
				restarted.Add(after)
			}
			run.waitForOutput(t, "http://target/after-restart")
		})
	}
}
