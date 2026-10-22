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

package typemetadata

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// typeServer serves Type Metadata documents by path. Each document is a
// template where {base} stands for the server URL.
type typeServer struct {
	*httptest.Server
	docs        map[string]string
	contentType string
	header      http.Header
}

func newTypeServer(t *testing.T, docs map[string]string) *typeServer {
	t.Helper()
	ts := &typeServer{docs: docs, contentType: "application/json", header: http.Header{}}
	ts.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := ts.docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		for name, values := range ts.header {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Type", ts.contentType)
		_, _ = w.Write([]byte(ts.body(doc)))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *typeServer) body(doc string) string { return strings.ReplaceAll(doc, "{base}", ts.URL) }

func (ts *typeServer) resolver() Resolver { return Resolver{Client: ts.Client()} }

func sri(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// The example of §5.6.5.2 (Figures 20 to 22), with display metadata on the
// base type only.
func TestResolveAppliesTheExtendedType(t *testing.T) {
	ts := newTypeServer(t, map[string]string{
		"/base": `{"vct":"{base}/base","display":[{"locale":"en","name":"Base"}],"claims":[
			{"path":["name"],"display":[{"label":"Full Name","locale":"en"}]},
			{"path":["address","city"],"display":[{"label":"City","locale":"en"}]}]}`,
	})
	ts.docs["/custom"] = `{"vct":"{base}/custom","extends":"{base}/base","extends#integrity":"` + sri(ts.body(ts.docs["/base"])) + `","claims":[
		{"path":["address","city"],"display":[{"label":"Town","locale":"en"}]},
		{"path":["nationalities"],"display":[{"label":"Nationalities","locale":"en"}]}]}`

	metadata, err := ts.resolver().Resolve(ts.URL+"/custom", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{ts.URL + "/custom", ts.URL + "/base"}; !reflect.DeepEqual(metadata.Types, want) {
		t.Errorf("types = %v, want %v", metadata.Types, want)
	}
	if len(metadata.Display) != 1 || metadata.Display[0].Name != "Base" {
		t.Errorf("display = %+v, want the display of the base type (§5.5.2)", metadata.Display)
	}
	labels := map[string]string{}
	for _, claim := range metadata.Claims {
		labels[PathString(claim.Path)] = claim.Display[0].Label
	}
	if want := map[string]string{"name": "Full Name", "address.city": "Town", "nationalities": "Nationalities"}; !reflect.DeepEqual(labels, want) {
		t.Errorf("claim labels = %v, want %v", labels, want)
	}
}

func TestResolveRefusesAnExtensionThatLoosensTheExtendedType(t *testing.T) {
	for name, child := range map[string]string{
		"sd":        `{"path":["name"],"sd":"never"}`,
		"mandatory": `{"path":["name"],"mandatory":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			ts := newTypeServer(t, map[string]string{
				"/base":  `{"vct":"{base}/base","claims":[{"path":["name"],"sd":"always","mandatory":true}]}`,
				"/child": `{"vct":"{base}/child","extends":"{base}/base","claims":[` + child + `]}`,
			})
			_, err := ts.resolver().Resolve(ts.URL+"/child", "")
			if processing := (*ProcessingError)(nil); !errors.As(err, &processing) || !strings.Contains(err.Error(), "§5.6.5.1") {
				t.Errorf("err = %v, want a §5.6.5.1 processing error", err)
			}
		})
	}
}

// §7.4: "Consumers MUST detect such circular dependencies and reject the
// credential."
func TestResolveRejectsACircularChain(t *testing.T) {
	ts := newTypeServer(t, map[string]string{
		"/a": `{"vct":"{base}/a","extends":"{base}/b"}`,
		"/b": `{"vct":"{base}/b","extends":"{base}/a"}`,
	})
	_, err := ts.resolver().Resolve(ts.URL+"/a", "")
	if processing := (*ProcessingError)(nil); !errors.As(err, &processing) || !strings.Contains(err.Error(), "§7.4") {
		t.Errorf("err = %v, want a §7.4 processing error", err)
	}
}

func TestResolveReportsUnavailableMetadata(t *testing.T) {
	for _, tt := range []struct {
		name, path, integrity, contentType, want string
	}{
		{"urn type", "/urn", "", "", "only from an HTTPS URL"},
		{"missing document", "/missing", "", "", "HTTP 404"},
		{"other vct", "/other", "", "", "describes the type"},
		{"wrong media type", "/plain", "", "text/plain", "application/json"},
		{"integrity mismatch", "/plain", "sha256-AAAA", "", "does not match"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTypeServer(t, map[string]string{
				"/urn":   `{"vct":"{base}/urn","extends":"urn:eudi:pid:1"}`,
				"/other": `{"vct":"https://elsewhere.example/type"}`,
				"/plain": `{"vct":"{base}/plain"}`,
			})
			if tt.contentType != "" {
				ts.contentType = tt.contentType
			}
			_, err := ts.resolver().Resolve(ts.URL+tt.path, tt.integrity)
			if retrieval := (*RetrievalError)(nil); !errors.As(err, &retrieval) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a retrieval error with %q", err, tt.want)
			}
		})
	}
}

// §3: the Consumer limits the redirects of a retrieval. eudi-dev follows 5.
func TestResolveFollowsUpTo5Redirects(t *testing.T) {
	ts := newTypeServer(t, map[string]string{"/type": `{"vct":"{base}/hop/5"}`})
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/type" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(ts.body(ts.docs["/type"])))
			return
		}
		var n int
		_, _ = fmt.Sscanf(r.URL.Path, "/hop/%d", &n)
		next := "/type"
		if n > 1 {
			next = fmt.Sprintf("/hop/%d", n-1)
		}
		http.Redirect(w, r, next, http.StatusFound)
	})
	if _, err := ts.resolver().Resolve(ts.URL+"/hop/5", ""); err != nil {
		t.Errorf("5 redirects: %v", err)
	}
	if _, err := ts.resolver().Resolve(ts.URL+"/hop/6", ""); err == nil || !strings.Contains(err.Error(), "more than 5 redirects") {
		t.Errorf("6 redirects: err = %v, want the redirect limit", err)
	}
}

func TestResolveRejectsMalformedClaimMetadata(t *testing.T) {
	ts := newTypeServer(t, map[string]string{
		"/path": `{"vct":"{base}/path","claims":[{"path":[]}]}`,
		"/sd":   `{"vct":"{base}/sd","claims":[{"path":["name"],"sd":"sometimes"}]}`,
		"/type": `{"vct":"{base}/type","claims":[{"path":["name"],"mandatory":"yes"}]}`,
	})
	for _, path := range []string{"/path", "/sd", "/type"} {
		_, err := ts.resolver().Resolve(ts.URL+path, "")
		if processing := (*ProcessingError)(nil); !errors.As(err, &processing) {
			t.Errorf("%s: err = %v, want a processing error (§5.6)", path, err)
		}
	}
}

// §5.3.4: metadata covered by integrity metadata can be cached indefinitely.
// Otherwise the HTTP caching model decides.
func TestResolveSetsTheFreshnessLifetime(t *testing.T) {
	ts := newTypeServer(t, map[string]string{"/type": `{"vct":"{base}/type"}`})
	ts.header.Set("Cache-Control", "public, max-age=3600")
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	resolver := ts.resolver()
	resolver.Now = func() time.Time { return now }

	metadata, err := resolver.Resolve(ts.URL+"/type", "")
	if err != nil || !metadata.Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("expires = %v err %v, want an hour from now", metadata, err)
	}
	metadata, err = resolver.Resolve(ts.URL+"/type", sri(ts.body(ts.docs["/type"])))
	if err != nil || !metadata.Expires.IsZero() || metadata.Stale(now.Add(24*365*time.Hour)) {
		t.Errorf("expires = %v err %v, want no expiry", metadata, err)
	}
}

// §6: the strongest supported algorithm decides, and any of its hash
// expressions may match.
func TestVerifyIntegrityUsesTheStrongestAlgorithm(t *testing.T) {
	doc := []byte(`{"vct":"https://example.com/type"}`)
	sha512Sum := sha512.Sum512(doc)
	good512 := "sha512-" + base64.StdEncoding.EncodeToString(sha512Sum[:])
	good256 := sri(string(doc))
	bad512 := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	for _, tt := range []struct {
		metadata string
		ok       bool
	}{
		{good256, true},
		{bad512 + " " + good512, true},
		{good256 + " " + bad512, false},
		{"md5-AAAA", false},
	} {
		if err := VerifyIntegrity(doc, tt.metadata); (err == nil) != tt.ok {
			t.Errorf("VerifyIntegrity(%q) = %v, want ok %v", tt.metadata, err, tt.ok)
		}
	}
}
