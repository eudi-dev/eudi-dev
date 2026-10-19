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

//go:build !windows

package browserlaunch

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

// startBrowser starts the browser with the debugging pipe. The browser reads
// commands from fd 3 and writes answers to fd 4.
func startBrowser(exe string, args []string) (*exec.Cmd, io.Writer, io.Reader, error) {
	commandsR, commandsW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	answersR, answersW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd := exec.Command(exe, args...)
	cmd.ExtraFiles = []*os.File{commandsR, answersW}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("starting %s: %w", exe, err)
	}
	_ = commandsR.Close()
	_ = answersW.Close()
	return cmd, commandsW, answersR, nil
}
