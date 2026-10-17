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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

// portalTimeout bounds the wait for the user's selection.
const portalTimeout = 5 * time.Minute

// captureScreen asks the Screenshot portal for an interactive screenshot.
func captureScreen() (string, func(), error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "", nil, fmt.Errorf("--screen needs a desktop session with xdg-desktop-portal (%w). Take a screenshot and pass it with --qr instead", err)
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
		return "", nil, fmt.Errorf("the desktop offers no screenshot portal (%w). Take a screenshot and pass it with --qr instead", err)
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
