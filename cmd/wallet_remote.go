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
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/output"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// remoteFlag is the one-off remote override (--remote <url>, or --remote
// local to force the local store despite a persisted remote).
var remoteFlag string

// activeRemoteURL resolves the remote wallet target: the --remote flag wins,
// then the target persisted by `wallet use`. Empty means local management.
func activeRemoteURL() (string, error) {
	if strings.TrimSpace(remoteFlag) != "" {
		if forcedLocal() {
			return "", nil
		}
		return remote.NormalizeURL(remoteFlag)
	}
	return remote.Active(), nil
}

// Route through a running server to keep one writer per wallet directory. Selection
// order is --remote, the saved remote target, then a server for the same directory.
// --remote local forces direct storage access.
func remoteClientIfConfigured() (*remote.Client, error) {
	url, err := activeRemoteURL()
	if err != nil {
		return nil, err
	}
	if url != "" {
		if err := refuseLocalStateFlags(url, ""); err != nil {
			return nil, err
		}
		return remote.NewClient(url), nil
	}
	if forcedLocal() {
		return nil, nil
	}
	if inst := remote.InstanceForWalletDir(resolvedWalletDir(), instanceProbeTimeout); inst != nil {
		if err := refuseLocalStateFlags(inst.URL, "wallet-dir"); err != nil {
			return nil, err
		}
		version := inst.Version
		if version == "" {
			version = "unknown version"
		}
		fmt.Fprintf(os.Stderr, "Routing through the running wallet instance %s (%s, pid %d, same wallet directory). Use --remote local for direct file access.\n", inst.URL, version, inst.PID)
		// The instance may run an older binary than this CLI, even one a major
		// release behind.
		if notice := incompatibilityNotice(inst.URL, inst.Version); notice != "" {
			fmt.Fprintln(os.Stderr, notice)
		}
		return remote.NewClient(inst.URL), nil
	}
	return nil, nil
}

// instanceProbeTimeout bounds each health check of a registered instance while
// the CLI picks its target.
const instanceProbeTimeout = 2 * time.Second

func forcedLocal() bool {
	return strings.EqualFold(strings.TrimSpace(remoteFlag), "local")
}

// localStateFlags shape the local wallet store. A remote wallet keeps its own
// store, so every remote path refuses them.
var localStateFlags = []struct {
	name string
	set  func() bool
}{
	{"wallet-dir", func() bool { return walletDir != "" }},
	{"storage", func() bool { return storageSpec != "" }},
	{"templates-dir", func() bool { return templatesDir != "" }},
	{"seed", func() bool { return keySeed != "" }},
}

// refuseLocalStateFlags reports the local state flags set for a command that
// manages the wallet at target. selector is the flag that chose target.
func refuseLocalStateFlags(target, selector string) error {
	var set []string
	for _, flag := range localStateFlags {
		if flag.name != selector && flag.set() {
			set = append(set, "--"+flag.name)
		}
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("the wallet at %s keeps its own store, so it can't use %s. Add --remote local to use the local store", target, strings.Join(set, ", "))
}

func walletUseCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:               "use [url|local]",
		ValidArgsFunction: completeUseTargets,
		Short:             "Manage a remote wallet server, or the local store again",
		Long: `Selects the wallet that the management commands work on. With a URL the CLI
manages that wallet server over its HTTP API. "local" switches back to the
local store. Without an argument it prints the current choice.

The CLI first checks that the server answers and compares its version. A
different major version is refused unless you pass --force.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				active := remote.Active()
				if active == "" {
					printResult(map[string]any{"target": "local"}, func() { fmt.Println("local") })
					return nil
				}
				identity, ok := instanceIdentityOf(active)
				doc := map[string]any{"target": active, "reachable": ok}
				if identity.Version != "" {
					doc["version"] = identity.Version
				}
				printResult(doc, func() { fmt.Println(active) })
				if !ok {
					fmt.Fprintln(os.Stderr, "Warning: the remote wallet is not reachable")
					return nil
				}
				fmt.Fprintf(os.Stderr, "The instance runs %s\n", identity)
				if notice := incompatibilityNotice(active, identity.Version); notice != "" {
					fmt.Fprintln(os.Stderr, notice)
				}
				return nil
			}

			target := args[0]
			if strings.EqualFold(target, "local") {
				if err := remote.ClearActive(); err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "Managing the local wallet store again")
				printResult(map[string]any{"target": "local"}, func() {})
				return nil
			}

			normalized, err := remote.NormalizeURL(target)
			if err != nil {
				return err
			}
			identity, ok := instanceIdentityOf(normalized)
			if !ok {
				return fmt.Errorf("no eudi-dev wallet reachable at %s (is it running?)", normalized)
			}
			notice := incompatibilityNotice(normalized, identity.Version)
			if notice != "" && !force {
				return fmt.Errorf("%s\nRun with --force to manage it anyway", notice)
			}
			if _, err := remote.SetActive(normalized); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Managing remote wallet %s %s\n", normalized, identity)
			if notice != "" {
				fmt.Fprintln(os.Stderr, notice)
			}
			doc := map[string]any{"target": normalized, "reachable": true}
			if identity.Version != "" {
				doc["version"] = identity.Version
			}
			printResult(doc, func() {})
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Select the instance even when its release is incompatible with this CLI")
	return cmd
}

type instanceIdentity struct {
	Version string
	PID     int
}

// String renders the identity for a status line: "1.19.0 (pid 4711)", with
// each part left out when the instance does not report it (a demo instance
// hides its pid).
func (i instanceIdentity) String() string {
	parts := []string{}
	if i.Version != "" {
		parts = append(parts, i.Version)
	}
	if i.PID > 0 {
		parts = append(parts, fmt.Sprintf("(pid %d)", i.PID))
	}
	if len(parts) == 0 {
		return "(version unknown)"
	}
	return strings.Join(parts, " ")
}

func instanceIdentityOf(url string) (instanceIdentity, bool) {
	client := remote.NewClient(url)
	doc, err := client.Version()
	if err != nil {
		return instanceIdentity{}, false
	}
	identity := instanceIdentity{}
	if version, ok := doc["version"].(string); ok {
		identity.Version = strings.TrimSpace(version)
	}
	if pid, ok := doc["pid"].(float64); ok {
		identity.PID = int(pid)
	}
	return identity, true
}

// Only a major version difference indicates an incompatible API. Development builds
// have no comparable release version.
func incompatibilityNotice(url, instanceVersion string) string {
	if remote.CheckCompatibility(Version, instanceVersion) != remote.Incompatible {
		return ""
	}
	return fmt.Sprintf("Incompatible: %s runs %s, this CLI is %s. Different major releases do not share a management API.",
		url, instanceVersion, Version)
}

func walletPsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List running wallet instances",
		Long: "Lists running wallet servers. The CLI reads its instance registry and the\n" +
			"local process list, and asks each server for its version. A registered server\n" +
			"whose process still runs stays in the list when it doesn't answer.\n" +
			"\n" +
			"The remote wallet set with `wallet use <url>` is listed when it answers, also\n" +
			"when it runs elsewhere, such as in a Docker container.\n" +
			"\n" +
			"Use `wallet use <url>` to manage a server and `wallet kill <target>` to stop\n" +
			"one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstancesList()
		},
	}
}

func runInstancesList() error {
	instances := remote.Discover(time.Second)
	active := remote.Active()

	// Discover includes a responding active remote, so a missing one is down.
	if active != "" {
		listed := false
		for _, inst := range instances {
			if strings.TrimRight(inst.URL, "/") == active {
				listed = true
				break
			}
		}
		if !listed {
			fmt.Fprintf(os.Stderr, "Active remote wallet %s is not responding.\n", active)
		}
	}

	managed := managedInstanceURL(instances)

	if jsonOutput {
		type listedInstance struct {
			remote.DiscoveredInstance
			Active bool `json:"active"`
		}
		listed := make([]listedInstance, len(instances))
		for i, inst := range instances {
			listed[i] = listedInstance{
				DiscoveredInstance: inst,
				Active:             managed != "" && managed == strings.TrimRight(inst.URL, "/"),
			}
		}
		return output.WriteJSON(os.Stdout, listed)
	}

	if len(instances) == 0 {
		fmt.Println("No running wallet instances found.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "URL\tVERSION\tPID\tWALLET DIR\tSOURCE\tACTIVE")
	var skewed []remote.DiscoveredInstance
	for _, inst := range instances {
		activeMark := ""
		if managed != "" && managed == strings.TrimRight(inst.URL, "/") {
			activeMark = "*"
		}
		dir := inst.WalletDir
		if dir == "" {
			dir = "-"
		}
		version := inst.Version
		if version == "" {
			version = "-"
		}
		if remote.CheckCompatibility(Version, inst.Version) == remote.Incompatible {
			version += " (!)"
			skewed = append(skewed, inst)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", inst.URL, version, inst.PID, dir, inst.Source, activeMark)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	// Explain the version warning so users know why the CLI may be incompatible.
	for _, inst := range skewed {
		fmt.Fprintf(os.Stderr, "(!) %s runs %s, incompatible with this CLI (%s)\n", inst.URL, inst.Version, Version)
	}
	return nil
}

// managedInstanceURL returns the discovered instance that management commands
// target. It follows the routing rules of remoteClientIfConfigured. The
// --remote flag or the saved remote target comes first, then the instance
// that serves the local wallet directory. Empty means the CLI manages the
// local store directly.
func managedInstanceURL(instances []remote.DiscoveredInstance) string {
	if url, err := activeRemoteURL(); err == nil && url != "" {
		return url
	}
	if forcedLocal() {
		return ""
	}
	localDir := resolvedWalletDir()
	for _, inst := range instances {
		if inst.WalletDir != "" && remote.SamePath(inst.WalletDir, localDir) {
			return strings.TrimRight(inst.URL, "/")
		}
	}
	return ""
}

func walletKillCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               "kill [pid|port|url]",
		ValidArgsFunction: completeInstanceTargets,
		Short:             "Stop a running eudi-dev wallet instance",
		Long: "Stops a wallet server listed by `wallet ps`. Name it by process id, port or\n" +
			"URL. The CLI first asks the server to shut down. If it doesn't answer, a local\n" +
			"process gets SIGTERM.",
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return fmt.Errorf("--all does not take a target")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			instances := remote.Discover(time.Second)

			var targets []remote.DiscoveredInstance
			if all {
				// --all stops the local instances only. An active remote's pid
				// belongs to another host, so it has to be named explicitly.
				for _, inst := range instances {
					if inst.Source == "active" {
						fmt.Fprintf(os.Stderr, "Skipping active remote %s (stop it by name if you mean to).\n", inst.URL)
						continue
					}
					targets = append(targets, inst)
				}
			} else {
				target, err := matchInstance(instances, args[0])
				if err != nil {
					return err
				}
				targets = []remote.DiscoveredInstance{target}
			}
			stopped := []map[string]any{}
			if len(targets) == 0 {
				printResult(map[string]any{"stopped": stopped}, func() { fmt.Println("No running wallet instances found.") })
				return nil
			}

			active := remote.Active()
			failed := 0
			for _, inst := range targets {
				if err := stopInstance(inst); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to stop %s (pid %d): %v\n", inst.URL, inst.PID, err)
					failed++
					continue
				}
				stopped = append(stopped, map[string]any{"url": inst.URL, "pid": inst.PID})
				fmt.Fprintf(humanOut(), "Stopped %s (pid %d)\n", inst.URL, inst.PID)
				if active != "" && active == strings.TrimRight(inst.URL, "/") {
					fmt.Fprintln(os.Stderr, "Note: this was the active remote wallet. Run `wallet use local` or pick another instance.")
				}
			}
			printResult(map[string]any{"stopped": stopped}, func() {})
			if failed > 0 {
				return fmt.Errorf("%d of %d wallet instances did not stop", failed, len(targets))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Stop all running wallet instances")
	return cmd
}

func matchInstance(instances []remote.DiscoveredInstance, target string) (remote.DiscoveredInstance, error) {
	target = strings.TrimSpace(target)
	noMatch := fmt.Errorf("no running wallet instance matches %q (run `wallet ps`)", target)

	if number, err := strconv.Atoi(target); err == nil {
		// A port match wins because users read ports off a URL or `wallet ps`.
		// `kill 8085` stops the server on port 8085 even when some process has
		// pid 8085.
		var byPort, byPID []remote.DiscoveredInstance
		for _, inst := range instances {
			switch {
			case inst.Port == number:
				byPort = append(byPort, inst)
			case inst.PID == number:
				byPID = append(byPID, inst)
			}
		}
		switch {
		case len(byPort) == 1:
			return byPort[0], nil
		case len(byPort) > 1:
			return remote.DiscoveredInstance{}, fmt.Errorf("%d instances match port %d (disambiguate by URL)", len(byPort), number)
		case len(byPID) == 1:
			return byPID[0], nil
		case len(byPID) > 1:
			return remote.DiscoveredInstance{}, fmt.Errorf("%d instances match pid %d (disambiguate by URL)", len(byPID), number)
		}
		return remote.DiscoveredInstance{}, noMatch
	}

	normalizedURL, err := remote.NormalizeURL(target)
	if err != nil {
		return remote.DiscoveredInstance{}, noMatch
	}
	for _, inst := range instances {
		if strings.TrimRight(inst.URL, "/") == normalizedURL {
			return inst, nil
		}
	}
	return remote.DiscoveredInstance{}, noMatch
}

func stopInstance(inst remote.DiscoveredInstance) error {
	client := remote.NewClient(inst.URL)
	if err := client.Shutdown(); err == nil {
		remote.UnregisterInstance(inst.PID)
		return nil
	}
	if inst.Source == "active" {
		// The pid of an active remote belongs to another system (for example
		// a container), so a signal from here would hit the wrong process.
		return fmt.Errorf("shutdown request failed and the instance is not a local process")
	}
	if inst.PID <= 0 {
		return fmt.Errorf("shutdown request failed and no pid is known")
	}
	// The process may have exited and its pid gone to another program. Only
	// a wallet that still answers under its pid gets the signal.
	version, err := client.Version()
	if pid, ok := version["pid"].(float64); err != nil || (ok && int(pid) != inst.PID) {
		remote.UnregisterInstance(inst.PID)
		return fmt.Errorf("the wallet does not answer at %s, so pid %d may belong to another program. Its stale entry is removed", inst.URL, inst.PID)
	}
	proc, err := os.FindProcess(inst.PID)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM: %w", err)
	}
	remote.UnregisterInstance(inst.PID)
	return nil
}

// warnServingConfigDivergence compares a running instance's introspection
// document with the local wallet file when both describe the same wallet
// directory. A running server keeps the serving config it read at startup,
// so after the file changed the two disagree until the server restarts.
func warnServingConfigDivergence(cfg map[string]any) {
	instanceDir, _ := cfg["wallet_dir"].(string)
	if instanceDir == "" {
		return
	}
	if backend, _ := cfg["storage"].(string); backend != "" && backend != storage.KindFile {
		return
	}
	store, err := openStore()
	if err != nil || !remote.SamePath(instanceDir, store.Dir) || store.Backend().Kind() != storage.KindFile {
		return
	}
	if exists, err := store.Exists(); err != nil || !exists {
		return
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		return
	}
	instanceIssuer, _ := cfg["issuer_url"].(string)
	instanceBase, _ := cfg["base_url"].(string)
	var diffs []string
	if strings.TrimSpace(w.IssuerURL) != strings.TrimSpace(instanceIssuer) {
		diffs = append(diffs, fmt.Sprintf("issuer_url (instance %q, file %q)", instanceIssuer, w.IssuerURL))
	}
	if strings.TrimSpace(w.BaseURL) != strings.TrimSpace(instanceBase) {
		diffs = append(diffs, fmt.Sprintf("base_url (instance %q, file %q)", instanceBase, w.BaseURL))
	}
	if len(diffs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "Warning: the running instance and wallet.json disagree on %s. Restart `%s wallet serve` to apply the file.\n",
		strings.Join(diffs, " and "), binaryName())
}

func walletInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info",
		Aliases: []string{"config"},
		Short:   "Show the configuration of the managed wallet (local or remote)",
		Long: `Prints the configuration of the managed wallet. For a remote wallet this is
its GET /api/config document, with the process id, port, directories, URLs and
settings. For the local store it prints the same fields.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			cfg, err := svc.Config()
			if err != nil {
				return err
			}
			if err := output.WriteJSON(os.Stdout, cfg); err != nil {
				return err
			}
			if svc.URL() != "" {
				warnServingConfigDivergence(cfg)
			}
			return nil
		},
	}
}
