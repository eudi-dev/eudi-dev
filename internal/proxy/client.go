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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Streaming has no deadline, so history reads need their own timeout. A
// dashboard that does not send the response head in this time fails too.
var entriesTimeout = 30 * time.Second

// DashboardClient reads the dashboard's traffic history and event stream.
type DashboardClient struct {
	// BaseURL is the dashboard origin, without a trailing slash.
	BaseURL string
	// HTTPClient sends the requests. A nil client uses newDashboardHTTPClient.
	HTTPClient *http.Client
}

// NewDashboardClient returns a client for the dashboard at rawURL. A bare
// host or host:port gets the http scheme, as in `eudi proxy logs localhost:9091`.
func NewDashboardClient(rawURL string) (*DashboardClient, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("no dashboard URL")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid dashboard URL %q: %w", rawURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("dashboard URL %q has no host", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("dashboard URL %q must be http or https", rawURL)
	}
	base := parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.Path, "/")
	return &DashboardClient{BaseURL: base, HTTPClient: newDashboardHTTPClient()}, nil
}

// newDashboardHTTPClient sets no overall timeout because an event stream
// stays open. It limits the wait for the response head instead.
func newDashboardHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = entriesTimeout
	return &http.Client{Transport: transport}
}

func (c *DashboardClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return newDashboardHTTPClient()
}

func (c *DashboardClient) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching the proxy dashboard at %s: %w", c.BaseURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("proxy dashboard at %s answered %s for %s", c.BaseURL, resp.Status, path)
	}
	return resp, nil
}

func (c *DashboardClient) Entries(ctx context.Context) ([]*TrafficEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, entriesTimeout)
	defer cancel()

	resp, err := c.get(ctx, "/api/entries")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []*TrafficEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("reading the recorded traffic: %w", err)
	}
	return entries, nil
}

type EntryStream struct {
	body   io.ReadCloser
	reader *bufio.Reader
}

// Stream subscribes to the dashboard's event stream. The subscription is
// active on return, so the caller gets every later entry while it reads the
// earlier ones.
func (c *DashboardClient) Stream(ctx context.Context) (*EntryStream, error) {
	resp, err := c.get(ctx, "/api/stream")
	if err != nil {
		return nil, err
	}
	return &EntryStream{body: resp.Body, reader: bufio.NewReader(resp.Body)}, nil
}

// Next returns the next entry, blocking until one arrives. It returns
// io.EOF when the proxy closed the stream.
func (s *EntryStream) Next() (*TrafficEntry, error) {
	var data []string
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			// A blank line ends an event. An event without data is a keepalive.
			if len(data) == 0 {
				continue
			}
			// The event stream format joins the data fields of one event with newlines.
			payload := strings.Join(data, "\n")
			data = nil
			var entry *TrafficEntry
			if err := json.Unmarshal([]byte(payload), &entry); err != nil || entry == nil {
				// One malformed event must not end the stream.
				continue
			}
			return entry, nil
		case strings.HasPrefix(line, ":"):
			// The keepalive is a comment line.
			continue
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
}

func (s *EntryStream) Close() error {
	return s.body.Close()
}
