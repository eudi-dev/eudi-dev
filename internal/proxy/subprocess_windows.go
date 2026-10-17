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

//go:build windows

package proxy

import (
	"os"
	"os/exec"
)

// setProcAttr does nothing on Windows, where SysProcAttr has no process groups.
func setProcAttr(cmd *exec.Cmd) {}

func (s *Subprocess) Stop() {
	if s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(os.Kill)
}
