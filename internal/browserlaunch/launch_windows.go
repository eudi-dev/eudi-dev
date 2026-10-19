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

package browserlaunch

import (
	"errors"
	"io"
	"os/exec"
)

// Chrome on Windows expects the debugging pipe as inherited handles.
var errPipeUnsupported = errors.New("opening the browser works on macOS and Linux. On Windows, install the extension with 'eudi wallet extension <dir>' and Load unpacked")

func startBrowser(string, []string) (*exec.Cmd, io.Writer, io.Reader, error) {
	return nil, nil, nil, errPipeUnsupported
}
