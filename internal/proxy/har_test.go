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
	"net/http"
	"testing"
	"time"
)

func TestGenerateHAREmpty(t *testing.T) {
	har := GenerateHAR(nil)
	log, ok := har["log"].(map[string]any)
	if !ok {
		t.Fatal("expected log object")
	}
	if log["version"] != "1.2" {
		t.Errorf("expected version 1.2, got %v", log["version"])
	}
	entries, ok := log["entries"].([]map[string]any)
	if !ok {
		t.Fatal("expected entries array")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestGenerateHARWithEntries(t *testing.T) {
	entries := []*TrafficEntry{
		{
			ID:              1,
			Timestamp:       time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
			Method:          "GET",
			URL:             "http://example.com/authorize?client_id=test",
			RequestHeaders:  http.Header{"Accept": {"application/json"}},
			StatusCode:      200,
			ResponseHeaders: http.Header{"Content-Type": {"application/json"}},
			ResponseBody:    `{"ok":true}`,
			DurationMS:      42,
		},
		{
			ID:              2,
			Timestamp:       time.Date(2025, 6, 15, 10, 30, 1, 0, time.UTC),
			Method:          "POST",
			URL:             "http://example.com/response",
			RequestHeaders:  http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
			RequestBody:     "state=abc&vp_token=eyJ...",
			StatusCode:      302,
			ResponseHeaders: http.Header{"Location": {"http://example.com/callback"}},
			DurationMS:      89,
		},
	}

	har := GenerateHAR(entries)
	log := har["log"].(map[string]any)
	harEntries := log["entries"].([]map[string]any)

	if len(harEntries) != 2 {
		t.Fatalf("expected 2 HAR entries, got %d", len(harEntries))
	}

	e1 := harEntries[0]
	if e1["startedDateTime"] != "2025-06-15T10:30:00.000Z" {
		t.Errorf("unexpected startedDateTime: %v", e1["startedDateTime"])
	}

	req := e1["request"].(map[string]any)
	if req["method"] != "GET" {
		t.Errorf("expected method GET, got %v", req["method"])
	}
	if req["url"] != "http://example.com/authorize?client_id=test" {
		t.Errorf("unexpected URL: %v", req["url"])
	}

	resp := e1["response"].(map[string]any)
	if resp["status"] != 200 {
		t.Errorf("expected status 200, got %v", resp["status"])
	}
	content := resp["content"].(map[string]any)
	if content["text"] != `{"ok":true}` {
		t.Errorf("unexpected response body: %v", content["text"])
	}

	e2 := harEntries[1]
	req2 := e2["request"].(map[string]any)
	postData, ok := req2["postData"].(map[string]any)
	if !ok {
		t.Fatal("expected postData on POST request")
	}
	if postData["text"] != "state=abc&vp_token=eyJ..." {
		t.Errorf("unexpected postData text: %v", postData["text"])
	}
}

func TestHarHeadersSorted(t *testing.T) {
	h := http.Header{
		"Zebra":   {"z"},
		"Alpha":   {"a"},
		"Content": {"c"},
	}

	result := harHeaders(h)
	if len(result) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(result))
	}
	if result[0]["name"] != "Alpha" {
		t.Errorf("expected first header Alpha, got %s", result[0]["name"])
	}
	if result[2]["name"] != "Zebra" {
		t.Errorf("expected last header Zebra, got %s", result[2]["name"])
	}
}

func TestHarHeadersNil(t *testing.T) {
	result := harHeaders(nil)
	if len(result) != 0 {
		t.Errorf("expected empty slice for nil headers, got %d", len(result))
	}
}

func TestHarHeadersMultiValue(t *testing.T) {
	h := http.Header{
		"Accept": {"text/html", "application/json"},
	}

	result := harHeaders(h)
	if len(result) != 2 {
		t.Fatalf("expected 2 header entries, got %d", len(result))
	}
}

func TestGenerateHARCreator(t *testing.T) {
	har := GenerateHAR(nil)
	log := har["log"].(map[string]any)
	creator := log["creator"].(map[string]any)
	if creator["name"] != "eudi-dev" {
		t.Errorf("expected creator name eudi-dev, got %v", creator["name"])
	}
}

// HAR 1.2 has -1 for a size that is not known, and a truncated body has no
// known size.
func TestGenerateHARMarksTruncatedBodies(t *testing.T) {
	har := GenerateHAR([]*TrafficEntry{{
		Method:            "POST",
		URL:               "http://example.com/upload",
		RequestBody:       "start",
		RequestTruncated:  true,
		StatusCode:        200,
		ResponseBody:      "start",
		ResponseTruncated: true,
	}})
	entry := har["log"].(map[string]any)["entries"].([]map[string]any)[0]
	req := entry["request"].(map[string]any)
	resp := entry["response"].(map[string]any)
	content := resp["content"].(map[string]any)
	if req["bodySize"] != -1 || resp["bodySize"] != -1 || content["size"] != -1 {
		t.Errorf("sizes %v, %v, %v, want -1", req["bodySize"], resp["bodySize"], content["size"])
	}
	if req["postData"].(map[string]any)["comment"] != harTruncatedComment || content["comment"] != harTruncatedComment {
		t.Errorf("the truncated bodies carry no comment: %v, %v", req["postData"], content)
	}
}
