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

//go:build darwin || linux

package qr

import "fmt"

// ScanScreen lets the user select a screen region and decodes the QR code in
// it. captureScreen is platform specific.
func ScanScreen() (string, error) {
	path, cleanup, err := captureScreen()
	if err != nil {
		return "", err
	}
	defer cleanup()
	content, err := ScanFile(path)
	if err != nil {
		return "", fmt.Errorf("decoding the screen capture: %w", err)
	}
	return content, nil
}
