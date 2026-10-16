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

//go:build linux

package urlhandler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Register installs a hidden desktop entry for the URL schemes and makes it
// their default handler. It runs 'wallet open-url' with the clicked link.
func Register(opts Options) (Registration, error) {
	executable, err := os.Executable()
	if err != nil {
		return Registration{}, fmt.Errorf("finding executable path: %w", err)
	}
	binary := stableBinaryPath(executable)
	dirs, err := currentXDGDirs()
	if err != nil {
		return Registration{}, err
	}
	entry, err := desktopEntry(binary)
	if err != nil {
		return Registration{}, err
	}
	desktopFile := dirs.desktopFile()
	if err := os.MkdirAll(filepath.Dir(desktopFile), 0o755); err != nil {
		return Registration{}, fmt.Errorf("creating the applications directory: %w", err)
	}
	if err := os.WriteFile(desktopFile, []byte(entry), 0o644); err != nil {
		return Registration{}, fmt.Errorf("writing the desktop entry: %w", err)
	}
	if err := saveOptions(opts); err != nil {
		return Registration{}, err
	}
	warnings, err := dirs.applyDefaults()
	if err != nil {
		return Registration{}, err
	}
	refreshDesktopCaches(filepath.Dir(desktopFile))
	return Registration{
		Registered:  true,
		DesktopFile: desktopFile,
		Handler:     binary + " wallet open-url",
		Binary:      binary,
		AutoAccept:  opts.AutoAccept,
		ServeArgs:   slices.Clone(opts.ServeArgs),
		Schemes:     slices.Clone(URLSchemes),
		Warnings:    append(warnings, desktopWarnings(binary, exec.LookPath, os.Getenv)...),
	}, nil
}

func Unregister() (Unregistration, error) {
	dirs, err := currentXDGDirs()
	if err != nil {
		return Unregistration{}, err
	}
	if err := dirs.removeAllDefaults(); err != nil {
		return Unregistration{}, err
	}
	desktopFile := dirs.desktopFile()
	err = os.Remove(desktopFile)
	installed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Unregistration{}, fmt.Errorf("removing the desktop entry: %w", err)
	}
	_ = os.Remove(optionsPath())
	refreshDesktopCaches(filepath.Dir(desktopFile))
	if !installed {
		return Unregistration{}, nil
	}
	return Unregistration{Unregistered: true, DesktopFile: desktopFile}, nil
}

// refreshDesktopCaches rebuilds the caches of desktop entries where a tool
// for it is installed. GIO and xdg-mime read mimeapps.list directly, and KDE
// reads its sycoca cache.
func refreshDesktopCaches(applicationsDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if path, err := exec.LookPath("update-desktop-database"); err == nil {
		_ = exec.CommandContext(ctx, path, applicationsDir).Run()
	}
	for _, tool := range []string{"kbuildsycoca6", "kbuildsycoca5"} {
		if path, err := exec.LookPath(tool); err == nil {
			_ = exec.CommandContext(ctx, path).Run()
			return
		}
	}
}

// currentXDGDirs applies the defaults of the XDG Base Directory Specification
// 0.8 to unset or relative values.
func currentXDGDirs() (xdgDirs, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return xdgDirs{}, fmt.Errorf("finding the home directory: %w", err)
	}
	dir := func(env, fallback string) string {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			return v
		}
		return filepath.Join(home, fallback)
	}
	var desktops []string
	for _, name := range strings.Split(os.Getenv("XDG_CURRENT_DESKTOP"), ":") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			desktops = append(desktops, name)
		}
	}
	return xdgDirs{dataHome: dir("XDG_DATA_HOME", ".local/share"), configHome: dir("XDG_CONFIG_HOME", ".config"), desktops: desktops}, nil
}

func (x xdgDirs) desktopFile() string {
	return filepath.Join(x.dataHome, "applications", desktopID)
}

// removeAllDefaults takes the desktop entry out of the user's mimeapps.list
// files. A file managed elsewhere stays as it is.
func (x xdgDirs) removeAllDefaults() error {
	types := schemeMIMETypes()
	main, overrides := x.mimeappsFiles()
	for _, path := range append([]string{main}, overrides...) {
		if err := removeDefaults(path, types, desktopID); err != nil && !errors.Is(err, errManagedElsewhere) {
			return fmt.Errorf("updating %s: %w", path, err)
		}
	}
	return nil
}
