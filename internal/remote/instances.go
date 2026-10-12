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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// Instance describes a running wallet server. Every `wallet serve` writes an
// instance file on startup and removes it on graceful shutdown. Discovery
// removes files whose process is gone.
type Instance struct {
	PID       int       `json:"pid"`
	Port      int       `json:"port"`
	URL       string    `json:"url"`
	WalletDir string    `json:"wallet_dir,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

type DiscoveredInstance struct {
	Instance
	BuildID string `json:"build_id,omitempty"`
	// Version is the release reported on /api/version. Older
	// instances report none.
	Version string `json:"version,omitempty"`
	// Source is "registry" for an instance file, "process" for a process scan
	// match without an instance file, or "active" for the remote target set by
	// "wallet use". Local discovery cannot see that target.
	Source string `json:"source"`
}

func instancesDir() string {
	return filepath.Join(configBaseDir(), "instances")
}

func instanceFile(pid int) string {
	return filepath.Join(instancesDir(), fmt.Sprintf("%d.json", pid))
}

// RegisterInstance writes the file beside its final name and renames it, so
// discovery never reads a partial entry.
func RegisterInstance(inst Instance) error {
	if err := os.MkdirAll(instancesDir(), 0o755); err != nil {
		return fmt.Errorf("creating instances directory: %w", err)
	}
	data, err := json.MarshalIndent(inst, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(instancesDir(), ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating instance file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("writing instance file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing instance file: %w", err)
	}
	return os.Rename(tmp.Name(), instanceFile(inst.PID))
}

func UnregisterInstance(pid int) {
	_ = os.Remove(instanceFile(pid))
}

func (d *DiscoveredInstance) applyHealth(version map[string]any) {
	if build, ok := version["build_id"].(string); ok {
		d.BuildID = build
	}
	if release, ok := version["version"].(string); ok {
		d.Version = strings.TrimSpace(release)
	}
}

// getInstanceJSON reads a JSON document from a wallet instance. ok is false when
// the instance does not answer in time or answers with something else.
func getInstanceJSON(baseURL, path string, timeout time.Duration) (doc map[string]any, ok bool) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	if _, err := format.DecodeRemoteJSON(resp.Body, "wallet instance "+path, &doc); err != nil {
		return nil, false
	}
	return doc, true
}

func instanceWalletDir(baseURL string, timeout time.Duration) string {
	cfg, _ := getInstanceJSON(baseURL, "/api/config", timeout)
	dir, _ := cfg["wallet_dir"].(string)
	return dir
}

// Discover finds running wallet instances on the local system. It reads the
// instance registry, removes entries whose process has exited and scans the
// process list for wallet serve processes. It also includes the active remote
// target set by "wallet use" when that target responds.
//
// A registered instance that is alive but does not answer in time stays listed.
// A busy server still owns its wallet directory.
func Discover(timeout time.Duration) []DiscoveredInstance {
	if timeout <= 0 {
		timeout = time.Second
	}
	var found []DiscoveredInstance
	seenPorts := map[int]bool{}

	entries, _ := os.ReadDir(instancesDir())
	for _, entry := range entries {
		name := entry.Name()
		pid, err := strconv.Atoi(strings.TrimSuffix(name, ".json"))
		if entry.IsDir() || !strings.HasSuffix(name, ".json") || err != nil {
			continue
		}
		path := filepath.Join(instancesDir(), name)
		if !processAlive(pid) {
			_ = os.Remove(path)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var inst Instance
		if json.Unmarshal(data, &inst) != nil || inst.URL == "" {
			continue
		}
		di := DiscoveredInstance{Instance: inst, Source: "registry"}
		if version, ok := getInstanceJSON(inst.URL, "/api/version", timeout); ok {
			// Another server listens on the registered port. It is discovered
			// through its own entry.
			if livePID, ok := version["pid"].(float64); ok && int(livePID) != inst.PID {
				continue
			}
			di.applyHealth(version)
		}
		if seenPorts[inst.Port] {
			continue
		}
		found = append(found, di)
		seenPorts[inst.Port] = true
	}

	for _, proc := range scanProcesses() {
		if seenPorts[proc.Port] {
			continue
		}
		url := fmt.Sprintf("http://localhost:%d", proc.Port)
		version, alive := getInstanceJSON(url, "/api/version", timeout)
		if !alive {
			continue
		}
		di := DiscoveredInstance{
			Instance: Instance{PID: proc.PID, Port: proc.Port, URL: url, WalletDir: instanceWalletDir(url, timeout)},
			Source:   "process",
		}
		di.applyHealth(version)
		found = append(found, di)
		seenPorts[proc.Port] = true
	}

	// An active remote may run in a container or on another host, outside local
	// process discovery.
	if active := Active(); active != "" {
		known := false
		for _, inst := range found {
			if strings.TrimRight(inst.URL, "/") == active {
				known = true
				break
			}
		}
		if !known {
			if version, alive := getInstanceJSON(active, "/api/version", timeout); alive {
				di := DiscoveredInstance{Instance: Instance{URL: active, WalletDir: instanceWalletDir(active, timeout)}, Source: "active"}
				if u, err := url.Parse(active); err == nil {
					if p, err := strconv.Atoi(u.Port()); err == nil {
						di.Port = p
					}
				}
				if pid, ok := version["pid"].(float64); ok {
					di.PID = int(pid)
				}
				di.applyHealth(version)
				found = append(found, di)
			}
		}
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
	return found
}

// processAlive reports whether pid belongs to a running process. On Unix, signal 0
// tests for the process without delivering anything. EPERM means it runs under
// another user. On Windows, FindProcess opens the process and fails once it
// has exited.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer func() { _ = proc.Release() }()
	if runtime.GOOS == "windows" {
		return true
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// InstanceForWalletDir returns the running wallet instance that serves the
// given wallet directory, or nil when no live instance owns it. While a server
// owns a wallet directory, CLI commands route through its API so the server
// stays the only writer.
func InstanceForWalletDir(dir string, timeout time.Duration) *DiscoveredInstance {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	want := normalizePath(dir)
	for _, inst := range Discover(timeout) {
		if inst.WalletDir != "" && normalizePath(inst.WalletDir) == want {
			found := inst
			return &found
		}
	}
	return nil
}

func SamePath(a, b string) bool {
	return normalizePath(a) == normalizePath(b)
}

func normalizePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return filepath.Clean(p)
}

type scannedProcess struct {
	PID  int
	Port int
}

var portFlagPattern = regexp.MustCompile(`--port(?:[= ])(\d+)`)

// scanProcesses finds `wallet serve` processes in the local process list.
// Windows has no ps. There the instance registry is the only source.
func scanProcesses() []scannedProcess {
	if runtime.GOOS == "windows" {
		return nil
	}
	out, err := exec.Command("ps", "-axo", "pid=,command=").Output()
	if err != nil {
		return nil
	}
	var procs []scannedProcess
	self := os.Getpid()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "wallet serve") {
			continue
		}
		if !strings.Contains(line, "oid4vc") && !strings.Contains(line, "eudi") {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == self {
			continue
		}
		port := config.DefaultWalletPort
		if m := portFlagPattern.FindStringSubmatch(fields[1]); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				port = p
			}
		}
		procs = append(procs, scannedProcess{PID: pid, Port: port})
	}
	return procs
}
