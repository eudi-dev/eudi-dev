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

// Package browserlaunch opens Chrome, Chromium, Edge or Brave with an unpacked
// extension. Chrome 137 ignores --load-extension, so the extension is loaded
// with the Chrome DevTools Protocol command Extensions.loadUnpacked. That
// command works only over --remote-debugging-pipe with
// --enable-unsafe-extension-debugging.
package browserlaunch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Launch starts the browser, loads the extension and opens the URL.
func Launch(opts Options) (*Browser, error) {
	exe := opts.Executable
	if exe == "" {
		var err error
		if exe, err = FindExecutable(); err != nil {
			return nil, err
		}
	}
	cmd, commands, answers, err := startBrowser(exe, browserArgs(opts))
	if err != nil {
		return nil, err
	}
	b := &Browser{Executable: exe, cmd: cmd, client: newCDPClient(commands, answers)}
	if err := b.setup(opts); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	return b, nil
}

// Options describe one browser launch.
type Options struct {
	// Executable is the browser binary. Empty finds an installed browser.
	Executable string
	// ProfileDir holds the browser profile. Chrome allows remote debugging
	// only for a profile other than the default one.
	ProfileDir string
	// ExtensionDir is the unpacked extension.
	ExtensionDir string
	// URL is the page the browser opens.
	URL string
}

// Browser is a running browser with the extension loaded.
type Browser struct {
	// Executable is the binary that runs.
	Executable string
	// ExtensionID is the ID Chrome gave the extension.
	ExtensionID string

	cmd    *exec.Cmd
	client *cdpClient
}

// Wait waits until the user closes the browser.
func (b *Browser) Wait() error {
	return b.cmd.Wait()
}

func browserArgs(opts Options) []string {
	return []string{
		"--user-data-dir=" + opts.ProfileDir,
		"--remote-debugging-pipe",
		"--enable-unsafe-extension-debugging",
		"--no-first-run",
		"--no-default-browser-check",
		"about:blank",
	}
}

// setup loads the extension and replaces the start page with opts.URL. A page
// opened before the extension loads would miss its content scripts.
func (b *Browser) setup(opts Options) error {
	var loaded struct {
		ID string `json:"id"`
	}
	if err := b.client.call("Extensions.loadUnpacked", map[string]any{"path": opts.ExtensionDir}, &loaded); err != nil {
		return fmt.Errorf("loading the extension: %w", err)
	}
	b.ExtensionID = loaded.ID

	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := b.client.call("Target.createTarget", map[string]any{"url": opts.URL}, &created); err != nil {
		return fmt.Errorf("opening %s: %w", opts.URL, err)
	}
	var targets struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			URL      string `json:"url"`
		} `json:"targetInfos"`
	}
	if err := b.client.call("Target.getTargets", nil, &targets); err != nil {
		return nil
	}
	for _, t := range targets.TargetInfos {
		if t.Type == "page" && t.TargetID != created.TargetID && t.URL == "about:blank" {
			_ = b.client.call("Target.closeTarget", map[string]any{"targetId": t.TargetID}, nil)
		}
	}
	return nil
}

// FindExecutable returns the first installed browser: Chrome, Chromium, Edge
// or Brave.
func FindExecutable() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		for _, app := range []string{"Google Chrome", "Chromium", "Microsoft Edge", "Brave Browser"} {
			for _, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
				path := filepath.Join(root, app+".app", "Contents", "MacOS", app)
				if _, err := os.Stat(path); err == nil {
					return path, nil
				}
			}
		}
	default:
		for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable", "brave-browser"} {
			if path, err := exec.LookPath(name); err == nil {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("found no Chrome, Chromium, Edge or Brave. Pass the browser binary with --browser-path")
}
