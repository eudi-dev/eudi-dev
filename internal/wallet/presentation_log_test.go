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
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// The console shows the presentation's transcript mode. A request can choose
// its own.
func TestMDocPresentationLogsItsOwnTranscript(t *testing.T) {
	w := pidBaselineWallet(t)
	w.SessionTranscript = oid4vp.SessionTranscriptOID4VP
	matches := mdocMatches(t, w)

	var out bytes.Buffer
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)
	if _, err := w.createVPTokenMap(matches[:1], &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "c", ResponseURI: "https://v.example/r"}, SessionTranscript: oid4vp.SessionTranscriptISO}); err != nil {
		t.Fatalf("presenting: %v", err)
	}
	if !strings.Contains(out.String(), "transcript="+string(oid4vp.SessionTranscriptISO)) {
		t.Errorf("log %q does not name the iso transcript", out.String())
	}
}

func TestSpecCitedSummaryNamesEveryCitedSpecification(t *testing.T) {
	list := findings.List{
		findings.OID4VP.Protocol("§5.2").New("nonce is required"),
		findings.ARF.Registration("RPRC_19").New("the request has no registration certificate"),
		findings.ETSI119475.Registration("GEN-5.2.4-08").New("x"),
		findings.OID4VP.Protocol("Appendix A.2").New("expected_origins must include the caller origin"),
		findings.Uncited("Request Object x5c chain is not internally consistent"),
	}
	want := "The request does not follow OID4VP 1.0 and ARF and ETSI TS 119 475"
	if got := specCitedSummary("The request", list); got != want {
		t.Errorf("summary = %q\nwant      %q", got, want)
	}
}
