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

package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func fileListJSON(next time.Time) string {
	return fmt.Sprintf(`{"ListAndSchemeInformation": {"LoTEVersionIdentifier": 1, "LoTESequenceNumber": 1,
		"LoTEType": "https://example.com/LoTEType/Demo", "ListIssueDateTime": %q, "NextUpdate": %q,
		"SchemeOperatorName": [{"lang": "en", "value": "Example Operator"}]}, "TrustedEntitiesList": []}`,
		next.Add(-48*time.Hour).UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339))
}

func tomorrow() time.Time { return time.Now().Add(24 * time.Hour) }

func walletWithFileList(t *testing.T, name, content string) *Wallet {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	lists, err := LoadTrustedListFiles(path)
	if err != nil {
		t.Fatalf("LoadTrustedListFiles: %v", err)
	}
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	w.TrustSettings.FileLists = lists
	return w
}

func TestTrustedListFilesArePublishedSignedAndListed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "operator.json"), []byte(fileListJSON(tomorrow())), 0o600); err != nil {
		t.Fatal(err)
	}
	lists, err := LoadTrustedListFiles(dir)
	if err != nil {
		t.Fatalf("LoadTrustedListFiles: %v", err)
	}
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	w.TrustSettings.FileLists = lists
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/api/trustlists/operator", "")
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/jwt" {
		t.Fatalf("GET = %d %s", resp.Code, resp.Header().Get("Content-Type"))
	}
	signed := resp.Body.String()
	list, err := lote.Parse(signed)
	if err != nil {
		t.Fatalf("parsing the published list: %v", err)
	}
	if list.SchemeInfo.SchemeOperatorName != "Example Operator" {
		t.Errorf("operator = %q", list.SchemeInfo.SchemeOperatorName)
	}
	operators, err := w.TrustedLists().ListCAs()
	if err != nil {
		t.Fatal(err)
	}
	if err := trustedlists.VerifyListSigner(signed, operators); err != nil {
		t.Errorf("the wallet's signature: %v", err)
	}

	var index struct {
		TrustLists []struct {
			ID         string `json:"id"`
			EntityName string `json:"entityName"`
		} `json:"trust_lists"`
	}
	if err := json.Unmarshal(serverRequest(t, srv, "GET", "/api/trustlists", "").Body.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range index.TrustLists {
		found = found || (entry.ID == "operator" && entry.EntityName == "Example Operator")
	}
	if !found {
		t.Errorf("index misses the list: %+v", index.TrustLists)
	}

	listed := false
	for _, tl := range w.TrustedLists().Lists() {
		listed = listed || (tl.Err == nil && tl.List.SchemeInfo.SchemeOperatorName == "Example Operator")
	}
	if !listed {
		t.Error("the wallet does not read the list as one of its own")
	}
	lol, err := lote.Parse(serverRequest(t, srv, "GET", "/api/trustlists/lists", "").Body.String())
	if err != nil {
		t.Fatal(err)
	}
	pointed := false
	for _, pointer := range lol.SchemeInfo.Pointers {
		pointed = pointed || strings.HasSuffix(pointer.Location, "/api/trustlists/operator")
	}
	if !pointed {
		t.Error("the list of trusted lists does not point to the list")
	}

	byID := serverRequest(t, srv, "GET", "/api/trustlists/operator", "")
	jwtPath := filepath.Join(t.TempDir(), "signed.jwt")
	if err := os.WriteFile(jwtPath, byID.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	signedFile, err := LoadTrustedListFiles(jwtPath)
	if err != nil || len(signedFile) != 1 || signedFile[0].ID != "signed" {
		t.Fatalf("a signed file: %+v, %v", signedFile, err)
	}
	w.TrustSettings.FileLists = signedFile
	srv = NewServer(w, 0, nil)
	if got := serverRequest(t, srv, "GET", "/api/trustlists/signed", "").Body.String(); got != byID.Body.String() {
		t.Error("a signed file must be served as it is")
	}
}

func TestExternalListDocumentServesOnlyTrustedListDocuments(t *testing.T) {
	signed := serverRequest(t, newTestServer(t, false), "GET", "/api/trustlists/eaa", "").Body.String()
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/list" {
			_, _ = rw.Write([]byte(signed))
			return
		}
		if r.URL.Path == "/forbidden" {
			http.Error(rw, "secret", http.StatusForbidden)
			return
		}
		_, _ = rw.Write([]byte(`{"secret": "internal"}`))
	}))
	defer upstream.Close()
	w := generateTestWallet(t)
	w.TrustSettings.ConfiguredLists = []string{upstream.URL + "/list", upstream.URL + "/secret", upstream.URL + "/forbidden"}
	srv := NewServer(w, 0, nil)
	document := func(url string) *httptest.ResponseRecorder {
		return serverRequest(t, srv, "GET", "/api/trust/lists/document?url="+url, "")
	}

	if resp := document(upstream.URL + "/list"); resp.Code != http.StatusOK || resp.Body.String() != signed {
		t.Errorf("a list = %d", resp.Code)
	}
	resp := document(upstream.URL + "/secret")
	if resp.Code != http.StatusBadGateway || strings.Contains(resp.Body.String(), "secret") {
		t.Errorf("another document = %d %s", resp.Code, resp.Body.String())
	}
	refused := document(upstream.URL + "/forbidden")
	if refused.Code != http.StatusBadGateway || strings.Contains(refused.Body.String(), "secret") {
		t.Errorf("a refused fetch = %d %s", refused.Code, refused.Body.String())
	}
	if resp := document("https://attacker.example/list"); resp.Code != http.StatusNotFound {
		t.Errorf("an unlisted URL = %d", resp.Code)
	}
}

func TestFileListCannotReplaceAnOwnList(t *testing.T) {
	w := walletWithFileList(t, "pid.json", fileListJSON(tomorrow()))
	if err := w.TrustedLists().FileListProblem(); err == nil || !strings.Contains(err.Error(), "rename") {
		t.Errorf("FileListProblem = %v", err)
	}
	body := serverRequest(t, NewServer(w, 0, nil), "GET", "/api/trustlists/pid", "").Body.String()
	if list, err := lote.Parse(body); err != nil || list.SchemeInfo.SchemeOperatorName == "Example Operator" {
		t.Errorf("the own list was replaced: %v", err)
	}
}

func TestExpiredFileListIsRefusedAndReported(t *testing.T) {
	w := walletWithFileList(t, "operator.json", fileListJSON(time.Now().Add(-time.Hour)))
	if err := w.TrustedLists().FileListProblem(); err == nil {
		t.Error("FileListProblem = nil, want the expiry")
	}
	summary := w.TrustedLists().Summary()
	found := false
	for _, link := range summary.Lists {
		found = found || (strings.HasSuffix(link.URL, "/api/trustlists/operator") && link.Error != "" && link.Configured)
	}
	if !found {
		t.Errorf("Summary misses the problem: %+v", summary.Lists)
	}
}

func TestFileListStaysAfterADemoReset(t *testing.T) {
	w := walletWithFileList(t, "operator.json", fileListJSON(tomorrow()))
	srv := NewServer(w, 0, nil)
	w.ResetToBaseline()
	if resp := serverRequest(t, srv, "GET", "/api/trustlists/operator", ""); resp.Code != http.StatusOK {
		t.Errorf("after a reset = %d", resp.Code)
	}
}

func TestCachedAnchorsDoesNotFetch(t *testing.T) {
	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer upstream.Close()
	w := generateTestWallet(t)
	if anchors := w.TrustedLists().CachedAnchors(upstream.URL + "/list"); anchors != nil || hits != 0 {
		t.Errorf("anchors %v after %d fetches", anchors, hits)
	}
}

func TestLoadTrustedListFilesRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"Bad_Name.json": fileListJSON(tomorrow()), "lists.json": fileListJSON(tomorrow()), "operator.yaml": fileListJSON(tomorrow()), "empty.json": "{}", "broken.jwt": "not a jwt"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrustedListFiles(path); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := LoadTrustedListFiles(t.TempDir()); err == nil {
		t.Error("an empty directory: want an error")
	}
}
