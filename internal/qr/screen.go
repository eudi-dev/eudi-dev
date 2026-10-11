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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func ScanScreen() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("--screen is only supported on macOS (use --qr with an image file instead)")
	}

	tmpDir, err := os.MkdirTemp("", "eudi-dev-qr-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "capture.png")

	var stderr bytes.Buffer
	cmd := exec.Command("screencapture", "-i", tmpFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if strings.Contains(errMsg, "cannot capture") || strings.Contains(errMsg, "image from rect") {
			_ = exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture").Run()
			return "", fmt.Errorf("screen recording permission denied\n\nSystem Settings has been opened to the Screen Recording pane.\nGrant access to your terminal app, then re-run the command.")
		}
		return "", fmt.Errorf("screencapture failed: %s", errMsg)
	}

	// Escape cancels the selection and leaves no file.
	if _, err := os.Stat(tmpFile); err != nil {
		return "", fmt.Errorf("screen capture cancelled")
	}

	return ScanFile(tmpFile)
}
