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
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
)

// The parser can skip invalid items and duplicate element identifiers. Selecting by
// position in the raw array could therefore disclose the wrong element. Reversing the
// raw array here checks that selection uses each parsed item's RawCBOR.
func TestCreateMDocPresentationSelectsElementByIdentifier(t *testing.T) {
	w := generateTestWallet(t)

	xBytes, _ := cbor.Marshal("element-x")
	yBytes, _ := cbor.Marshal("element-y")

	rawIssuerSigned, err := cbor.Marshal(map[string]any{
		"nameSpaces": map[string]any{"ns": []any{cbor.RawMessage(yBytes), cbor.RawMessage(xBytes)}},
		"issuerAuth": []any{},
	})
	if err != nil {
		t.Fatalf("marshaling IssuerSigned: %v", err)
	}
	cred := StoredCredential{
		ID:      "mdoc-order",
		Format:  "mso_mdoc",
		DocType: "ns",
		Raw:     hex.EncodeToString(rawIssuerSigned),
		NameSpaces: map[string][]mdoc.IssuerSignedItem{"ns": {
			{ElementIdentifier: "x", RawCBOR: xBytes},
			{ElementIdentifier: "y", RawCBOR: yBytes},
		}},
	}

	result, err := w.createMDocPresentation(cred, []string{"ns:y"},
		PresentationParams{Nonce: "n", ClientID: "c", ResponseURI: "r"}, "", w.HolderKey)
	if err != nil {
		t.Fatalf("createMDocPresentation: %v", err)
	}

	respBytes, err := format.DecodeBase64URL(result.Token)
	if err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var resp struct {
		Documents []struct {
			IssuerSigned struct {
				NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
			} `cbor:"issuerSigned"`
		} `cbor:"documents"`
	}
	if err := cbor.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("decoding DeviceResponse: %v", err)
	}
	got := resp.Documents[0].IssuerSigned.NameSpaces["ns"]
	if len(got) != 1 || !bytes.Equal(got[0], yBytes) {
		t.Errorf("selected ns:y but the presentation carried the wrong element bytes: %x", got)
	}
}

func mdocMatches(t *testing.T, w *Wallet) []CredentialMatch {
	t.Helper()
	var matches []CredentialMatch
	for _, c := range w.GetCredentials() {
		if c.Format != "mso_mdoc" {
			continue
		}
		keys := make([]string, 0, len(c.Claims))
		for k := range c.Claims {
			keys = append(keys, k)
		}
		matches = append(matches, CredentialMatch{
			QueryID:      fmt.Sprintf("q%d", len(matches)),
			CredentialID: c.ID,
			Format:       c.Format,
			DocType:      c.DocType,
			SelectedKeys: keys,
		})
	}
	return matches
}

// ISO 18013-7 Annex B carries one generated nonce per response in apu. The verifier
// uses that nonce to rebuild every document's transcript. All documents must therefore
// use the same nonce.
func TestISOResponseSignsEveryMDocOverTheReportedNonce(t *testing.T) {
	w := pidBaselineWallet(t)
	w.SessionTranscript = SessionTranscriptISO

	matches := mdocMatches(t, w)
	if len(matches) < 2 {
		t.Fatalf("the baseline holds %d mdoc credentials, want at least 2", len(matches))
	}

	params := PresentationParams{
		Nonce:       "verifier-nonce",
		ClientID:    "x509_hash:example",
		ResponseURI: "https://verifier.example/response",
	}
	result, err := w.CreateVPTokenMap(matches, params)
	if err != nil {
		t.Fatalf("creating the vp_token map: %v", err)
	}
	if result.MDocNonce == "" {
		t.Fatal("ISO mode reported no mdoc generated nonce")
	}

	transcript, err := buildSessionTranscriptISO(params.ClientID, params.ResponseURI, params.Nonce, result.MDocNonce)
	if err != nil {
		t.Fatalf("rebuilding the session transcript: %v", err)
	}

	for _, m := range matches {
		tokens := result.TokenMap[m.QueryID]
		if len(tokens) != 1 {
			t.Fatalf("query %s has %d presentations, want 1", m.QueryID, len(tokens))
		}
		doc, err := mdoc.Parse(tokens[0])
		if err != nil {
			t.Fatalf("query %s: parsing the DeviceResponse: %v", m.QueryID, err)
		}
		if err := mdoc.VerifyDeviceAuth(doc, transcript); err != nil {
			t.Errorf("query %s: device auth does not verify against the reported mdoc nonce: %v", m.QueryID, err)
		}
	}
}
