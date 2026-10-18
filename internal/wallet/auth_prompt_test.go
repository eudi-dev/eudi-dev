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
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
)

func received(ch <-chan consent.AuthorizationPrompt) (consent.AuthorizationPrompt, bool) {
	select {
	case p := <-ch:
		return p, true
	default:
		return consent.AuthorizationPrompt{}, false
	}
}

// Visitors of a shared wallet start offers at the same time. Each offer
// returns the sign-in URL of its own flow, and only the owner's browser
// navigates to it (ADR-0011).
func TestSignInPromptReachesOnlyItsFlowAndOwner(t *testing.T) {
	w := generateTestWallet(t)
	flowA, unsubA := w.Consents().SubscribeAuthorization(func(p consent.AuthorizationPrompt) bool { return p.Flow == "a" })
	defer unsubA()
	flowB, unsubB := w.Consents().SubscribeAuthorization(func(p consent.AuthorizationPrompt) bool { return p.Flow == "b" })
	defer unsubB()
	otherBrowser, unsubOther := w.Consents().SubscribeAuthorization(func(p consent.AuthorizationPrompt) bool { return consent.OwnedBy([]string{"visitor-2"}, p.Owner) })
	defer unsubOther()

	if !w.Consents().NotifyAuthorization(consent.AuthorizationPrompt{URL: "https://issuer.example/authorize?a", Owner: "visitor-1", Flow: "a"}) {
		t.Fatal("the flow's own caller did not count as receiving the prompt")
	}
	if p, ok := received(flowA); !ok || p.URL != "https://issuer.example/authorize?a" {
		t.Fatalf("flow a got %+v, %v", p, ok)
	}
	if p, ok := received(flowB); ok {
		t.Fatalf("flow b picked up the prompt of flow a: %+v", p)
	}
	if p, ok := received(otherBrowser); ok {
		t.Fatalf("another visitor's browser got the prompt: %+v", p)
	}

	if w.Consents().NotifyAuthorization(consent.AuthorizationPrompt{URL: "https://issuer.example/authorize?c", Owner: "visitor-3", Flow: "c"}) {
		t.Fatal("a prompt nobody of its flow received counted as delivered")
	}
}

// RFC 9126 §4 allows one use of a request_uri. Only one open page of a
// browser opens the sign-in: the page that started the flow, else the newest
// page.
func TestSignInPromptReachesOnePageOfTheBrowser(t *testing.T) {
	w := generateTestWallet(t)
	rt := w.Consents()
	owners := []string{"visitor-1"}
	older, unsubOlder := rt.SubscribePageAuthorization(owners, "tab-older")
	defer unsubOlder()
	newer, unsubNewer := rt.SubscribePageAuthorization(owners, "tab-newer")
	defer unsubNewer()
	otherBrowser, unsubOther := rt.SubscribePageAuthorization([]string{"visitor-2"}, "tab-older")
	defer unsubOther()

	for _, tc := range []struct {
		name string
		tab  string
		want <-chan consent.AuthorizationPrompt
	}{
		{"the approving page", "tab-older", older},
		{"a flow without a page goes to the newest page", "", newer},
		{"a closed page goes to the newest page", "tab-closed", newer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !rt.NotifyAuthorization(consent.AuthorizationPrompt{URL: "https://issuer.example/authorize", Owner: "visitor-1", Tab: tc.tab}) {
				t.Fatal("no page received the prompt")
			}
			for name, ch := range map[string]<-chan consent.AuthorizationPrompt{"older": older, "newer": newer, "other browser": otherBrowser} {
				_, got := received(ch)
				if got != (ch == tc.want) {
					t.Errorf("%s page received the prompt: %v", name, got)
				}
			}
		})
	}
}

// A browser redirected to the sign-in opens it itself, so no page of that
// browser navigates. The caller of the flow still receives the prompt.
func TestNoPageNavigatesWhenTheCallerOpensTheSignIn(t *testing.T) {
	w := generateTestWallet(t)
	rt := w.Consents()
	page, unsubPage := rt.SubscribePageAuthorization([]string{"visitor-1"}, "tab")
	defer unsubPage()
	prompt := consent.AuthorizationPrompt{URL: "https://issuer.example/authorize", Owner: "visitor-1", Flow: "f", CallerNavigates: true}
	if rt.NotifyAuthorization(prompt) {
		t.Fatal("a prompt without a caller counted as delivered")
	}
	caller, unsubCaller := rt.SubscribeAuthorization(func(p consent.AuthorizationPrompt) bool { return p.Flow == "f" })
	defer unsubCaller()
	if !rt.NotifyAuthorization(prompt) {
		t.Fatal("the caller did not receive the prompt")
	}
	if _, ok := received(caller); !ok {
		t.Error("the caller has no prompt")
	}
	if p, ok := received(page); ok {
		t.Errorf("the page received %+v", p)
	}
}
