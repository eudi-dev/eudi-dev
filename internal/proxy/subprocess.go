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

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/fatih/color"
)

// Subprocess manages a child process. Its stdout and stderr are scanned for
// encryption keys and credentials.
type Subprocess struct {
	cmd     *exec.Cmd
	scanner *OutputScanner
	out     io.Writer
	// The exit error is written before done closes, so every waiter can read it.
	done chan struct{}
	err  error
	// outputMu serializes the two stream-scanning goroutines. They share the
	// OutputScanner and the terminal, and a line's prefix and body stay together.
	outputMu sync.Mutex
}

// StartSubprocess launches args[0] with args[1:] as a child process. It scans
// stdout and stderr line by line and forwards them to out with a [service]
// prefix.
func StartSubprocess(args []string, scanner *OutputScanner, out io.Writer) (*Subprocess, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	setProcAttr(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", args[0], err)
	}

	sub := &Subprocess{
		cmd:     cmd,
		scanner: scanner,
		out:     out,
		done:    make(chan struct{}),
	}

	// Both streams are read at once. A service that logs heavily to stderr
	// while stdout stays open must never block on a full stderr pipe.
	var reading sync.WaitGroup
	reading.Add(2)
	go func() { defer reading.Done(); sub.scanStream(stdout) }()
	go func() { defer reading.Done(); sub.scanStream(stderr) }()

	go func() {
		// exec.Cmd.Wait closes the pipes, so it runs after both are read to
		// the end.
		reading.Wait()
		sub.err = cmd.Wait()
		close(sub.done)
	}()

	return sub, nil
}

// maxLineLength bounds the memory for one output line. A longer line is
// forwarded in pieces of this length.
const maxLineLength = 1024 * 1024

func (s *Subprocess) scanStream(r io.Reader) {
	dim := color.New(color.Faint)
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 0, 64*1024), maxLineLength)
	scan.Split(scanLinesUpTo(maxLineLength))
	for scan.Scan() {
		line := scan.Text()
		s.outputMu.Lock()
		s.scanner.Scan(line)
		_, _ = dim.Fprint(s.out, "[service] ")
		fmt.Fprintln(s.out, line)
		s.outputMu.Unlock()
	}
}

// scanLinesUpTo splits like bufio.ScanLines and cuts a line that reaches max
// bytes, so the scanner never stops with bufio.ErrTooLong.
func scanLinesUpTo(max int) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, atEOF)
		if advance > 0 || token != nil || err != nil {
			return advance, token, err
		}
		if len(data) >= max {
			return max, data[:max], nil
		}
		return 0, nil, nil
	}
}

// Wait blocks until the subprocess exits and returns its error. It is safe for
// concurrent use.
func (s *Subprocess) Wait() error {
	<-s.done
	return s.err
}

// Done returns a channel that is closed when the process exits. Read the exit
// error with Wait afterwards.
func (s *Subprocess) Done() <-chan struct{} {
	return s.done
}
