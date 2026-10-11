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
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONWriterWritesNDJSON(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, false)

	entry := &TrafficEntry{
		ID:         1,
		Timestamp:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token",
		StatusCode: 200,
		Class:      ClassVPAuthRequest,
		ClassLabel: "VP auth request",
		DurationMS: 42,
	}

	w.WriteEntry(entry)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["method"] != "GET" {
		t.Errorf("expected method GET, got %v", parsed["method"])
	}
	if parsed["classLabel"] != "VP auth request" {
		t.Errorf("expected classLabel VP auth request, got %v", parsed["classLabel"])
	}
}

func TestJSONWriterFiltersUnknown(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, false)

	entry := &TrafficEntry{
		ID:         1,
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
	}

	w.WriteEntry(entry)

	if buf.Len() != 0 {
		t.Errorf("expected no output for ClassUnknown without allTraffic, got %q", buf.String())
	}
}

func TestJSONWriterAllTrafficIncludesUnknown(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, true)

	entry := &TrafficEntry{
		ID:         1,
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
	}

	w.WriteEntry(entry)

	if buf.Len() == 0 {
		t.Error("expected output for ClassUnknown with allTraffic=true")
	}
}

func TestJSONWriterMultipleEntries(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, false)

	for i := 0; i < 3; i++ {
		w.WriteEntry(&TrafficEntry{
			ID:         int64(i + 1),
			Method:     "POST",
			URL:        "http://example.com/response",
			StatusCode: 200,
			Class:      ClassVPAuthResponse,
			ClassLabel: "VP auth response",
		})
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 NDJSON lines, got %d", len(lines))
	}

	for i, line := range lines {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Errorf("line %d: invalid JSON: %v", i, err)
		}
	}
}
