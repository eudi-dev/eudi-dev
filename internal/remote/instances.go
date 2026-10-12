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
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
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
	// Version is the release the instance reports on /api/version. Older
	// instances report none.
	Version string `json:"version,omitempty"`
	// Source is "registry" for an instance file, "process" for a process scan
	// match without an instance file, or "active" for the remote target set by
	// "wallet use" that local discovery cannot see.
	Source string `json:"source"`
}

func instancesDir() string {
	return filepath.Join(configBaseDir(), "instances")
}

func instanceFile(pid int) string {
	return filepath.Join(instancesDir(), fmt.Sprintf("%d.json", pid))
}

func RegisterInstance(inst Instance) error {
	if err := os.MkdirAll(instancesDir(), 0o755); err != nil {
		return fmt.Errorf("creating instances directory: %w", err)
	}
	data, err := json.MarshalIndent(inst, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(instanceFile(inst.PID), append(data, '\n'), 0o644)
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

func healthCheck(url string, timeout time.Duration) (map[string]any, bool) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/api/version")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var version map[string]any
	if json.NewDecoder(resp.Body).Decode(&version) != nil {
		return nil, false
	}
	return version, true
}

func fetchInstanceConfig(url string, timeout time.Duration) map[string]any {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/api/config")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var cfg map[string]any
	if json.NewDecoder(resp.Body).Decode(&cfg) != nil {
		return nil
	}
	return cfg
}

// Discover finds running wallet instances on the local system. It reads the
// instance registry, removes entries whose server is gone and scans the process
// list for wallet serve processes. It also includes the active remote target
// set by "wallet use" when that target responds.
func Discover(timeout time.Duration) []DiscoveredInstance {
	if timeout <= 0 {
		timeout = time.Second
	}
	var found []DiscoveredInstance
	seenPorts := map[int]bool{}

	entries, _ := os.ReadDir(instancesDir())
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(instancesDir(), entry.Name()))
		if err != nil {
			continue
		}
		var inst Instance
		if json.Unmarshal(data, &inst) != nil || inst.URL == "" {
			_ = os.Remove(filepath.Join(instancesDir(), entry.Name()))
			continue
		}
		version, alive := healthCheck(inst.URL, timeout)
		if !alive {
			_ = os.Remove(filepath.Join(instancesDir(), entry.Name()))
			continue
		}
		livePID := inst.PID
		if pid, ok := version["pid"].(float64); ok {
			livePID = int(pid)
		}
		if livePID != inst.PID {
			// A new process can reuse a dead server's port, so the process ID must match.
			_ = os.Remove(filepath.Join(instancesDir(), entry.Name()))
		}
		if seenPorts[inst.Port] {
			continue
		}
		di := DiscoveredInstance{Instance: inst, Source: "registry"}
		di.PID = livePID
		di.applyHealth(version)
		found = append(found, di)
		seenPorts[inst.Port] = true
	}

	for _, proc := range scanProcesses() {
		if seenPorts[proc.Port] {
			continue
		}
		url := fmt.Sprintf("http://localhost:%d", proc.Port)
		version, alive := healthCheck(url, timeout)
		if !alive {
			continue
		}
		di := DiscoveredInstance{
			Instance: Instance{PID: proc.PID, Port: proc.Port, URL: url},
			Source:   "process",
		}
		di.applyHealth(version)
		if cfg := fetchInstanceConfig(url, timeout); cfg != nil {
			if dir, ok := cfg["wallet_dir"].(string); ok {
				di.WalletDir = dir
			}
		}
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
			if version, alive := healthCheck(active, timeout); alive {
				di := DiscoveredInstance{Instance: Instance{URL: active}, Source: "active"}
				if u, err := url.Parse(active); err == nil {
					if p, err := strconv.Atoi(u.Port()); err == nil {
						di.Port = p
					}
				}
				if pid, ok := version["pid"].(float64); ok {
					di.PID = int(pid)
				}
				di.applyHealth(version)
				if cfg := fetchInstanceConfig(active, timeout); cfg != nil {
					if dir, ok := cfg["wallet_dir"].(string); ok {
						di.WalletDir = dir
					}
				}
				found = append(found, di)
			}
		}
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
	return found
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
