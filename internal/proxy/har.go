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
	"sort"
)

// GenerateHAR builds a HAR 1.2 archive from the given traffic entries.
func GenerateHAR(entries []*TrafficEntry) map[string]any {
	harEntries := make([]map[string]any, 0, len(entries))

	for _, e := range entries {
		harEntries = append(harEntries, harEntry(e))
	}

	return map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"creator": map[string]any{
				"name":    "eudi-dev",
				"version": "1.0.0",
			},
			"entries": harEntries,
		},
	}
}

func harEntry(e *TrafficEntry) map[string]any {
	entry := map[string]any{
		"startedDateTime": e.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		"time":            e.DurationMS,
		"request":         harRequest(e),
		"response":        harResponse(e),
		"cache":           map[string]any{},
		"timings": map[string]any{
			"send":    -1,
			"wait":    e.DurationMS,
			"receive": -1,
		},
	}
	return entry
}

func harRequest(e *TrafficEntry) map[string]any {
	req := map[string]any{
		"method":      e.Method,
		"url":         e.URL,
		"httpVersion": "HTTP/1.1",
		"cookies":     []any{},
		"headers":     harHeaders(e.RequestHeaders),
		"queryString": []any{},
		"headersSize": -1,
		"bodySize":    harBodySize(e.RequestBody, e.RequestTruncated),
	}

	if e.RequestBody != "" {
		contentType := ""
		if e.RequestHeaders != nil {
			contentType = e.RequestHeaders.Get("Content-Type")
		}
		postData := map[string]any{
			"mimeType": contentType,
			"text":     e.RequestBody,
		}
		if e.RequestTruncated {
			postData["comment"] = harTruncatedComment
		}
		req["postData"] = postData
	}

	return req
}

func harResponse(e *TrafficEntry) map[string]any {
	contentType := ""
	if e.ResponseHeaders != nil {
		contentType = e.ResponseHeaders.Get("Content-Type")
	}

	content := map[string]any{
		"size":     harBodySize(e.ResponseBody, e.ResponseTruncated),
		"mimeType": contentType,
		"text":     e.ResponseBody,
	}
	if e.ResponseTruncated {
		content["comment"] = harTruncatedComment
	}
	return map[string]any{
		"status":      e.StatusCode,
		"statusText":  http.StatusText(e.StatusCode),
		"httpVersion": "HTTP/1.1",
		"cookies":     []any{},
		"headers":     harHeaders(e.ResponseHeaders),
		"content":     content,
		"redirectURL": "",
		"headersSize": -1,
		"bodySize":    harBodySize(e.ResponseBody, e.ResponseTruncated),
	}
}

const harTruncatedComment = "The proxy kept only the start of this body."

// HAR 1.2 sets bodySize to -1 when the size is not available.
func harBodySize(body string, truncated bool) int {
	if truncated {
		return -1
	}
	return len(body)
}

func harHeaders(h http.Header) []map[string]string {
	if h == nil {
		return []map[string]string{}
	}

	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []map[string]string
	for _, name := range names {
		for _, val := range h[name] {
			out = append(out, map[string]string{"name": name, "value": val})
		}
	}
	return out
}
