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
	"net/http"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/news"
)

func TestNewsIsServedWithItsIDInTheConfig(t *testing.T) {
	srv := newTestServer(t, false)
	srv.SetNews(&news.News{ID: "abc", HTML: "<h2>New</h2>"})

	resp := serverRequest(t, srv, http.MethodGet, "/api/news", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /api/news = %d", resp.Code)
	}
	if got := decodeJSON(t, resp); got["id"] != "abc" || got["html"] != "<h2>New</h2>" {
		t.Errorf("news = %v", got)
	}
	if got := decodeJSON(t, serverRequest(t, srv, http.MethodGet, "/api/config", "")); got["news_id"] != "abc" {
		t.Errorf("news_id = %v", got["news_id"])
	}
}
