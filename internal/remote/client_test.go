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

package remote

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recorder struct {
	method      string
	path        string
	rawQuery    string
	body        string
	contentType string

	status int
	reply  string
}

func (r *recorder) server(t *testing.T) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.method = req.Method
		r.path = req.URL.Path
		r.rawQuery = req.URL.RawQuery
		r.contentType = req.Header.Get("Content-Type")
		data, _ := io.ReadAll(req.Body)
		r.body = string(data)

		if r.status != 0 {
			w.WriteHeader(r.status)
		}
		reply := r.reply
		if reply == "" {
			reply = "{}"
		}
		_, _ = w.Write([]byte(reply))
	}))
	return NewClient(srv.URL), srv.Close
}

func TestClientEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		reply      string
		call       func(*Client) error
		wantMethod string
		wantPath   string
		wantQuery  string
		wantBody   string
	}{
		{
			name:  "Version",
			reply: `{"version":"1.2.3"}`,
			call: func(c *Client) error {
				out, err := c.Version()
				if err == nil && out["version"] != "1.2.3" {
					t.Errorf("version = %v", out["version"])
				}
				return err
			},
			wantMethod: http.MethodGet, wantPath: "/api/version",
		},
		{
			name:       "ServerConfig",
			call:       func(c *Client) error { _, err := c.ServerConfig(); return err },
			wantMethod: http.MethodGet, wantPath: "/api/config",
		},
		{
			name:  "Credentials",
			reply: `[{"id":"one"}]`,
			call: func(c *Client) error {
				out, err := c.Credentials()
				if err == nil && (len(out) != 1 || out[0]["id"] != "one") {
					t.Errorf("credentials = %v", out)
				}
				return err
			},
			wantMethod: http.MethodGet, wantPath: "/api/credentials",
		},
		{
			name:       "Credential",
			call:       func(c *Client) error { _, err := c.Credential("abc"); return err },
			wantMethod: http.MethodGet, wantPath: "/api/credentials/abc",
		},
		{
			name:       "ImportCredential",
			call:       func(c *Client) error { _, err := c.ImportCredential("eyJ.raw~"); return err },
			wantMethod: http.MethodPost, wantPath: "/api/credentials", wantBody: "eyJ.raw~",
		},
		{
			name:       "RefreshCredential",
			call:       func(c *Client) error { _, err := c.RefreshCredential("abc"); return err },
			wantMethod: http.MethodPost, wantPath: "/api/credentials/abc/refresh",
		},
		{
			name:       "RemoveCredential",
			call:       func(c *Client) error { return c.RemoveCredential("abc") },
			wantMethod: http.MethodDelete, wantPath: "/api/credentials/abc",
		},
		{
			name:  "RemoveAllCredentials",
			reply: `{"deleted":4,"kept_protected":2}`,
			call: func(c *Client) error {
				var out struct {
					Deleted       int `json:"deleted"`
					KeptProtected int `json:"kept_protected"`
				}
				err := c.RemoveAllCredentials(&out)
				if err == nil && (out.Deleted != 4 || out.KeptProtected != 2) {
					t.Errorf("removed = %+v, want 4 deleted and 2 kept", out)
				}
				return err
			},
			wantMethod: http.MethodDelete, wantPath: "/api/credentials",
		},
		{
			name:       "Issue",
			call:       func(c *Client) error { _, err := c.Issue(map[string]any{"vct": "urn:test"}); return err },
			wantMethod: http.MethodPost, wantPath: "/api/issue", wantBody: `{"vct":"urn:test"}`,
		},
		{
			name:  "Log",
			reply: `[{"event":"issuance"}]`,
			call: func(c *Client) error {
				out, err := c.Log()
				if err == nil && !strings.Contains(string(out), "issuance") {
					t.Errorf("log = %s", out)
				}
				return err
			},
			wantMethod: http.MethodGet, wantPath: "/api/log",
		},
		{
			name:       "Templates",
			reply:      `[{"name":"pid"}]`,
			call:       func(c *Client) error { _, err := c.Templates(); return err },
			wantMethod: http.MethodGet, wantPath: "/api/templates",
		},
		{
			name:       "Template",
			call:       func(c *Client) error { _, err := c.Template("pid"); return err },
			wantMethod: http.MethodGet, wantPath: "/api/templates/pid",
		},
		{
			name:       "PutTemplate",
			call:       func(c *Client) error { _, err := c.PutTemplate("pid", map[string]any{"vct": "urn:x"}); return err },
			wantMethod: http.MethodPut, wantPath: "/api/templates/pid", wantBody: `{"vct":"urn:x"}`,
		},
		{
			name:       "DeleteTemplate",
			call:       func(c *Client) error { return c.DeleteTemplate("pid") },
			wantMethod: http.MethodDelete, wantPath: "/api/templates/pid",
		},
		{
			name:  "Certificate as PEM",
			reply: "-----BEGIN CERTIFICATE-----",
			call: func(c *Client) error {
				out, err := c.Certificate("ca", "pem")
				if err == nil && !strings.HasPrefix(string(out), "-----BEGIN") {
					t.Errorf("certificate = %s", out)
				}
				return err
			},
			wantMethod: http.MethodGet, wantPath: "/api/certificates/ca",
		},
		{
			name:       "Certificate as JWKS asks for the format",
			call:       func(c *Client) error { _, err := c.Certificate("tls", "jwks"); return err },
			wantMethod: http.MethodGet, wantPath: "/api/certificates/tls", wantQuery: "format=jwks",
		},
		{
			name:       "Present",
			call:       func(c *Client) error { _, err := c.Present("openid4vp://request", false, ""); return err },
			wantMethod: http.MethodPost, wantPath: "/api/presentations",
			wantBody: `{"uri":"openid4vp://request"}`,
		},
		{
			name:       "AcceptOffer",
			call:       func(c *Client) error { _, err := c.AcceptOffer("openid-credential-offer://x", "", false); return err },
			wantMethod: http.MethodPost, wantPath: "/api/offers",
			wantBody: `{"uri":"openid-credential-offer://x"}`,
		},
		{
			name:       "AcceptOffer with a transaction code",
			call:       func(c *Client) error { _, err := c.AcceptOffer("offer://x", "123456", false); return err },
			wantMethod: http.MethodPost, wantPath: "/api/offers",
			wantBody: `{"tx_code":"123456","uri":"offer://x"}`,
		},
		{
			name:  "TrustList",
			reply: "  header.payload.signature  ",
			call: func(c *Client) error {
				out, err := c.TrustList("", "", "")
				if err == nil && out != "header.payload.signature" {
					t.Errorf("trust list = %q, want it trimmed", out)
				}
				return err
			},
			wantMethod: http.MethodGet, wantPath: "/api/trustlist",
		},
		{
			name:  "TrustLists",
			reply: `{"trust_lists":[{"id":"pid"}]}`,
			call: func(c *Client) error {
				out, err := c.TrustLists()
				if err == nil && (len(out) != 1 || out[0]["id"] != "pid") {
					t.Errorf("trust lists = %v", out)
				}
				return err
			},
			wantMethod: http.MethodGet, wantPath: "/api/trustlists",
		},
		{
			name:       "OfferStatus",
			call:       func(c *Client) error { _, err := c.OfferStatus("offer-1"); return err },
			wantMethod: http.MethodGet, wantPath: "/api/offers/offer-1",
		},
		{
			name:       "DeferredIssuances",
			reply:      `[{"id":"deferred-1"}]`,
			call:       func(c *Client) error { _, err := c.DeferredIssuances(); return err },
			wantMethod: http.MethodGet, wantPath: "/api/deferred",
		},
		{
			name:       "CollectDeferred",
			call:       func(c *Client) error { _, err := c.CollectDeferred("deferred-1"); return err },
			wantMethod: http.MethodPost, wantPath: "/api/deferred/deferred-1/collect",
		},
		{
			name:       "AbandonDeferred",
			call:       func(c *Client) error { _, err := c.AbandonDeferred("deferred-1"); return err },
			wantMethod: http.MethodDelete, wantPath: "/api/deferred/deferred-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{reply: tt.reply}
			client, closeFn := rec.server(t)
			defer closeFn()

			if err := tt.call(client); err != nil {
				t.Fatalf("call: %v", err)
			}
			if rec.method != tt.wantMethod {
				t.Errorf("method = %s, want %s", rec.method, tt.wantMethod)
			}
			if rec.path != tt.wantPath {
				t.Errorf("path = %s, want %s", rec.path, tt.wantPath)
			}
			if tt.wantQuery != "" && rec.rawQuery != tt.wantQuery {
				t.Errorf("query = %s, want %s", rec.rawQuery, tt.wantQuery)
			}
			if tt.wantBody != "" && strings.TrimSpace(rec.body) != tt.wantBody {
				t.Errorf("body = %s, want %s", rec.body, tt.wantBody)
			}
		})
	}
}

// A raw string body must arrive unchanged, so an imported credential is not
// JSON-quoted.
func TestClientSendsARawStringBodyUnchanged(t *testing.T) {
	rec := &recorder{}
	client, closeFn := rec.server(t)
	defer closeFn()

	if _, err := client.ImportCredential(`eyJhbGciOiJFUzI1NiJ9.payload.sig~disclosure~`); err != nil {
		t.Fatalf("ImportCredential: %v", err)
	}
	if strings.HasPrefix(rec.body, `"`) {
		t.Errorf("body = %s, want the raw credential rather than a JSON string", rec.body)
	}
	if rec.contentType == "application/json" {
		t.Error("a raw credential was sent as application/json")
	}
}

func TestClientReportsTheServerError(t *testing.T) {
	rec := &recorder{status: http.StatusBadRequest, reply: `{"error":"credential is protected"}`}
	client, closeFn := rec.server(t)
	defer closeFn()

	err := client.RemoveCredential("pid")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "credential is protected") {
		t.Errorf("error = %q, want the server's message", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %q, want the status code too", err)
	}
}

func TestClientErrorsOnNonJSONFailures(t *testing.T) {
	t.Run("a plain text body", func(t *testing.T) {
		rec := &recorder{status: http.StatusInternalServerError, reply: "everything is on fire"}
		client, closeFn := rec.server(t)
		defer closeFn()

		err := client.RemoveCredential("x")
		if err == nil || !strings.Contains(err.Error(), "everything is on fire") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("an empty body falls back to the status text", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		err := NewClient(srv.URL).RemoveCredential("x")
		if err == nil || !strings.Contains(err.Error(), http.StatusText(http.StatusNotFound)) {
			t.Errorf("error = %v, want the status text", err)
		}
	})

	t.Run("a body that is not the JSON expected", func(t *testing.T) {
		rec := &recorder{reply: "not json"}
		client, closeFn := rec.server(t)
		defer closeFn()

		_, err := client.Version()
		if err == nil || !strings.Contains(err.Error(), "decoding response") {
			t.Errorf("error = %v, want a decode failure", err)
		}
	})

	t.Run("a wallet that is not listening", func(t *testing.T) {
		// Port 1 on loopback refuses connections at once.
		_, err := NewClient("http://127.0.0.1:1").Version()
		if err == nil || !strings.Contains(err.Error(), "calling") {
			t.Errorf("error = %v, want it to name the call", err)
		}
	})

	t.Run("a body that cannot be encoded", func(t *testing.T) {
		rec := &recorder{}
		client, closeFn := rec.server(t)
		defer closeFn()

		_, err := client.Issue(map[string]any{"bad": make(chan int)})
		if err == nil || !strings.Contains(err.Error(), "encoding request") {
			t.Errorf("error = %v, want an encoding failure", err)
		}
	})
}

func TestNewClientTrimsTheBaseURL(t *testing.T) {
	if got := NewClient("  https://wallet.example/  ").BaseURL; got != "https://wallet.example" {
		t.Errorf("BaseURL = %q, want it trimmed of space and trailing slash", got)
	}
}

// A 204 with no body is a success.
func TestClientAcceptsAnEmptySuccessBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := NewClient(srv.URL).RemoveCredential("abc"); err != nil {
		t.Errorf("RemoveCredential: %v", err)
	}
}

func TestTrustListPath(t *testing.T) {
	tests := []struct {
		name             string
		id, vct, docType string
		want             string
	}{
		{name: "no selector", want: "/api/trustlist"},
		{name: "by id", id: "pid-list", want: "/api/trustlists/pid-list"},
		{name: "an id needing escaping", id: "a/b", want: "/api/trustlists/a%2Fb"},
		{name: "by vct", vct: "urn:eudi:pid:1", want: "/api/trustlist?vct=urn%3Aeudi%3Apid%3A1"},
		{name: "by doctype", docType: "eu.europa.ec.eudi.pid.1", want: "/api/trustlist?doctype=eu.europa.ec.eudi.pid.1"},
		// An id selects exactly one list, so it takes precedence over the filters.
		{name: "id beats the filters", id: "pid-list", vct: "urn:x", want: "/api/trustlists/pid-list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrustListPath(tt.id, tt.vct, tt.docType); got != tt.want {
				t.Errorf("TrustListPath = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientTrustListSelectors(t *testing.T) {
	rec := &recorder{reply: "a.b.c"}
	client, closeFn := rec.server(t)
	defer closeFn()

	if _, err := client.TrustList("pid-list", "", ""); err != nil {
		t.Fatalf("TrustList: %v", err)
	}
	if rec.path != "/api/trustlists/pid-list" {
		t.Errorf("path = %s", rec.path)
	}
}

// The PEM and JWT endpoints need the raw bytes when decoding into a []byte.
func TestClientReturnsRawBytesUnparsed(t *testing.T) {
	rec := &recorder{reply: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}
	client, closeFn := rec.server(t)
	defer closeFn()

	out, err := client.Certificate("ca", "")
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	if !strings.Contains(string(out), "BEGIN CERTIFICATE") {
		t.Errorf("certificate = %s", out)
	}
	var asJSON any
	if json.Unmarshal(out, &asJSON) == nil {
		t.Error("the PEM was parsed as JSON")
	}
}

func TestPresentAndAcceptOfferSendInteractive(t *testing.T) {
	r := &recorder{reply: "{}"}
	c, closeFn := r.server(t)
	defer closeFn()

	if _, err := c.Present("openid4vp://x", true, ""); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !strings.Contains(r.body, `"interactive":true`) {
		t.Errorf("interactive Present body = %q, want interactive:true", r.body)
	}

	if _, err := c.AcceptOffer("openid-credential-offer://x", "", true); err != nil {
		t.Fatalf("AcceptOffer: %v", err)
	}
	if !strings.Contains(r.body, `"interactive":true`) {
		t.Errorf("interactive AcceptOffer body = %q, want interactive:true", r.body)
	}
}

func TestPresentSendsTheSessionTranscript(t *testing.T) {
	r := &recorder{reply: "{}"}
	c, closeFn := r.server(t)
	defer closeFn()

	if _, err := c.Present("openid4vp://x", false, "iso"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !strings.Contains(r.body, `"session_transcript":"iso"`) {
		t.Errorf("Present body = %q, want the session transcript", r.body)
	}
}

// An identifier stays one path segment, whatever characters it holds.
func TestClientEscapesEveryIdentifierSegment(t *testing.T) {
	const id = "a/b?c#d e"
	got := make(chan string, 16)
	mux := http.NewServeMux()
	for _, pattern := range []string{
		"GET /api/credentials/{id}",
		"POST /api/credentials/{id}/refresh",
		"DELETE /api/credentials/{id}",
		"GET /api/templates/{id}",
		"PUT /api/templates/{id}",
		"DELETE /api/templates/{id}",
		"GET /api/offers/{id}",
		"POST /api/deferred/{id}/collect",
		"DELETE /api/deferred/{id}",
		"GET /api/certificates/{id}",
	} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			got <- r.PathValue("id")
			w.Write([]byte(`{}`))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(srv.URL)

	calls := map[string]func() error{
		"Credential":        func() error { _, err := c.Credential(id); return err },
		"RefreshCredential": func() error { _, err := c.RefreshCredential(id); return err },
		"RemoveCredential":  func() error { return c.RemoveCredential(id) },
		"Template":          func() error { _, err := c.Template(id); return err },
		"PutTemplate":       func() error { _, err := c.PutTemplate(id, map[string]any{}); return err },
		"DeleteTemplate":    func() error { return c.DeleteTemplate(id) },
		"OfferStatus":       func() error { _, err := c.OfferStatus(id); return err },
		"CollectDeferred":   func() error { _, err := c.CollectDeferred(id); return err },
		"AbandonDeferred":   func() error { _, err := c.AbandonDeferred(id); return err },
		"Certificate":       func() error { _, err := c.Certificate(id, "pem"); return err },
	}
	for name, call := range calls {
		if err := call(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if segment := <-got; segment != id {
			t.Errorf("%s sent the segment %q, want %q", name, segment, id)
		}
	}
}

// The registrar caps its page size, so the client reads every page.
func TestRegistrarRecordsFollowsTheCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{"data": [{"tradeName": "a"}, {"tradeName": "b"}], "pagination": {"has_next_page": true, "next_cursor": "2"}}`))
		case "2":
			_, _ = w.Write([]byte(`{"data": [{"tradeName": "c"}], "pagination": {"has_next_page": false}}`))
		default:
			http.Error(w, "unknown cursor", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	var records []struct {
		TradeName string `json:"tradeName"`
	}
	if err := NewClient(srv.URL).RegistrarRecords(&records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || records[2].TradeName != "c" {
		t.Errorf("records %v, want a, b and c", records)
	}
}
