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

package qr

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// portalTimeout bounds the wait for the user's selection.
const portalTimeout = 5 * time.Minute

// captureScreen asks the Screenshot portal for an interactive screenshot. X11
// window managers such as i3 have no portal backend that takes screenshots,
// so there a region selection tool takes it.
func captureScreen() (string, func(), error) {
	path, cleanup, err := capturePortal()
	var unusable portalUnusableError
	if err != nil && errors.As(err, &unusable) && x11Session() {
		return captureX11Region()
	}
	return path, cleanup, err
}

func capturePortal() (string, func(), error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "", nil, portalUnusableError{fmt.Errorf("--screen needs a desktop session with xdg-desktop-portal (%w). Take a screenshot and scan the image file instead", err)}
	}
	defer func() { _ = conn.Close() }()

	tokenBytes := make([]byte, 8)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, err
	}
	token := "eudi_dev_" + hex.EncodeToString(tokenBytes)
	expected := portalRequestPath(conn.Names()[0], token)
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(portalRequest), dbus.WithMatchMember("Response")); err != nil {
		return "", nil, fmt.Errorf("subscribing to the screenshot portal: %w", err)
	}
	signals := make(chan *dbus.Signal, 4)
	conn.Signal(signals)

	options := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(token),
		"interactive":  dbus.MakeVariant(true),
	}
	var handle dbus.ObjectPath
	if err := conn.Object(portalService, portalPath).Call(portalScreenshot, 0, "", options).Store(&handle); err != nil {
		return "", nil, portalUnusableError{fmt.Errorf("the desktop offers no screenshot portal (%w). Install xdg-desktop-portal with the backend of your desktop, or take a screenshot and scan the image file instead", err)}
	}

	timeout := time.After(portalTimeout)
	for {
		select {
		case signal := <-signals:
			if signal == nil || signal.Name != portalResponse || (signal.Path != expected && signal.Path != handle) {
				continue
			}
			path, err := portalScreenshotFile(signal.Body)
			if err != nil {
				return "", nil, err
			}
			// The portal saved the screenshot for this request only.
			return path, func() { _ = os.Remove(path) }, nil
		case <-timeout:
			return "", nil, fmt.Errorf("no screen region was selected within %s", portalTimeout)
		}
	}
}

// x11Session reports an X11 desktop. XWayland also sets DISPLAY, so a
// Wayland session is excluded by WAYLAND_DISPLAY.
func x11Session() bool {
	return os.Getenv("DISPLAY") != "" && os.Getenv("WAYLAND_DISPLAY") == ""
}

// x11RegionTools select a screen region and save it to the file given as the
// last argument, in order of preference.
var x11RegionTools = []struct {
	name string
	args []string
}{
	{"maim", []string{"-s"}},
	{"scrot", []string{"-s"}},
}

// errNoX11RegionTool explains the install on X11 desktops without a portal.
var errNoX11RegionTool = errors.New(`this X11 desktop has no screenshot portal, so --screen needs maim or scrot to select a screen region.
Install one of them, for example:

  sudo apt install maim

Or take a screenshot and scan the image file instead`)

func captureX11Region() (string, func(), error) {
	for _, tool := range x11RegionTools {
		bin, err := exec.LookPath(tool.name)
		if err != nil {
			continue
		}
		tmpDir, err := os.MkdirTemp("", "eudi-dev-qr-*")
		if err != nil {
			return "", nil, fmt.Errorf("creating temp dir: %w", err)
		}
		cleanup := func() { _ = os.RemoveAll(tmpDir) }
		file := filepath.Join(tmpDir, "capture.png")

		var stderr bytes.Buffer
		cmd := exec.Command(bin, append(tool.args, file)...)
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			cleanup()
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return "", nil, fmt.Errorf("%s: %s", tool.name, msg)
		}
		if _, err := os.Stat(file); err != nil {
			cleanup()
			return "", nil, errCaptureCancelled
		}
		return file, cleanup, nil
	}
	return "", nil, errNoX11RegionTool
}
