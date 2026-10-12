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

// Package serverlog writes a server's console output as JSON log records.
package serverlog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/fatih/color"
)

const (
	FormatText = "text"
	FormatJSON = "json"
)

func ParseFormat(value string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(value)); v {
	case "", FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unknown log format %q: use 'text' or 'json'", value)
	}
}

// Writer turns each Write into one record. The log package writes each entry in a
// single call, so a multi-line entry such as a pretty-printed token response stays
// one record.
type Writer struct {
	logger *slog.Logger
}

func NewWriter(out io.Writer) *Writer {
	return &Writer{logger: slog.New(slog.NewJSONHandler(out, nil))}
}

// Components tag their lines with a capitalized name such as [VCI]. Lowercase
// brackets are content, such as the credential format in [mso_mdoc].
var componentTag = regexp.MustCompile(`^\[([A-Z][A-Za-z0-9 ]*)\]\s*`)

func (w *Writer) Write(p []byte) (int, error) {
	w.record(string(p))
	return len(p), nil
}

func (w *Writer) record(text string) {
	msg := strings.TrimSpace(text)
	var attrs []slog.Attr
	if m := componentTag.FindStringSubmatch(msg); m != nil {
		attrs = append(attrs, slog.String("component", m[1]))
		msg = msg[len(m[0]):]
	}
	// Separator lines and blank lines carry no information.
	if !strings.ContainsFunc(msg, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) {
		return
	}
	level := slog.LevelInfo
	if label, rest, found := strings.Cut(msg, ":"); found && !strings.ContainsAny(label, " \n") {
		switch strings.ToLower(label) {
		case "warning":
			level, msg = slog.LevelWarn, strings.TrimSpace(rest)
		case "error":
			level, msg = slog.LevelError, strings.TrimSpace(rest)
		}
	}
	// Console lines align their values with runs of spaces.
	if !strings.Contains(msg, "\n") {
		msg = strings.Join(strings.Fields(msg), " ")
	}
	w.logger.LogAttrs(context.Background(), level, msg, attrs...)
}

// RedirectProcessOutput sends the log package, color output, os.Stdout and
// os.Stderr through one JSON writer on out. Each line printed with fmt is one
// record. The returned function restores the original output. It waits for
// every pending line first, so an error printed afterwards reaches the console.
func RedirectProcessOutput(out io.Writer) (restore func(), err error) {
	origStdout, origStderr := os.Stdout, os.Stderr
	origColorOutput, origNoColor := color.Output, color.NoColor
	origLogWriter, origLogFlags := log.Writer(), log.Flags()

	jw := NewWriter(out)
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// ReadString has no line length limit. A reader that stops on a long line
		// blocks every later print once the pipe buffer is full.
		lines := bufio.NewReader(reader)
		for {
			line, err := lines.ReadString('\n')
			jw.record(line)
			if err != nil {
				return
			}
		}
	}()

	os.Stdout, os.Stderr = writer, writer
	color.Output, color.NoColor = writer, true
	log.SetOutput(jw)
	log.SetFlags(0)

	return func() {
		os.Stdout, os.Stderr = origStdout, origStderr
		color.Output, color.NoColor = origColorOutput, origNoColor
		log.SetOutput(origLogWriter)
		log.SetFlags(origLogFlags)
		_ = writer.Close()
		<-done
		_ = reader.Close()
	}, nil
}
