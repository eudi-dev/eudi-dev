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
	findings := []string{
		"OID4VP 1.0 §5.2: nonce is required",
		"ARF RPRC_19: the request has no registration certificate",
		"RFC 9101 §4: the request_uri response Content-Type must be application/oauth-authz-req+jwt",
		"ETSI TS 119 475 V1.2.1 GEN-5.2.4-08: x",
		"ETSI TS 119 475 V1.2.1 Table 7: the certificate has no status",
		"HAIP 1.0: y",
		"OID4VP 1.0 Appendix A.2: expected_origins must include the caller origin",
		"Request Object x5c chain is not internally consistent: x509: bad",
	}
	want := "The request does not follow OID4VP 1.0 and ARF and RFC 9101 and ETSI TS 119 475 V1.2.1 and HAIP 1.0"
	if got := specCitedSummary("The request", findings); got != want {
		t.Errorf("summary = %q\nwant      %q", got, want)
	}
}
