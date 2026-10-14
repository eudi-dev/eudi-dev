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

package cmd

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// pendingConsent creates a pending request like a flow does. The returned
// channel receives the answer.
func pendingConsent(t *testing.T, w *wallet.Wallet, typ string, created time.Time) (*consent.Request, <-chan consent.Result) {
	t.Helper()
	req := consent.NewRequest(typ, "")
	req.CreatedAt = created
	if err := w.Consents().Create(req); err != nil {
		t.Fatal(err)
	}
	answers := make(chan consent.Result, 1)
	go func() {
		answer := <-req.ResultCh
		req.SubmissionCh <- consent.SubmissionResult{StatusCode: 200}
		answers <- answer
	}()
	return req, answers
}

func TestWalletRequestsAnswerTheNewestRequestOfAType(t *testing.T) {
	resetRemoteTestState(t)
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	presentation, presented := pendingConsent(t, w, consent.TypePresentation, time.Now().Add(-time.Minute))
	offer, offered := pendingConsent(t, w, consent.TypeIssuance, time.Now())
	srv := wallet.NewServer(w, 0, nil)
	srv.ShutdownFunc = func() {}
	url, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatal(err)
	}

	listed := captureStdout(t, func() {
		resetFlags(rootCmd)
		rootCmd.SetArgs([]string{"wallet", "requests", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(listed, presentation.ID) || !strings.Contains(listed, offer.ID) {
		t.Fatalf("list %q, want both requests", listed)
	}

	// The newer offer is no presentation, so --type picks the older request.
	approved := captureStdout(t, func() {
		resetFlags(rootCmd)
		rootCmd.SetArgs([]string{"wallet", "requests", "approve", "--type", "presentation",
			"--body", `{"selected_claims":{"cred":["given_name"]}}`, "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(approved, presentation.ID+" approved") {
		t.Errorf("approve printed %q", approved)
	}
	answer := <-presented
	if !answer.Approved || !slices.Equal(answer.SelectedClaims["cred"], []string{"given_name"}) {
		t.Errorf("answer %+v, want the approval with the chosen claims", answer)
	}

	captureStdout(t, func() {
		resetFlags(rootCmd)
		rootCmd.SetArgs([]string{"wallet", "requests", "deny", offer.ID, "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	if answer := <-offered; answer.Approved {
		t.Errorf("answer %+v, want the denial", answer)
	}
}
