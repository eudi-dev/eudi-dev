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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

// The expected bytes come from the worked example in OpenID4VCI 1.1 Appendix A.2.5.
const (
	iaeExampleEndpoint = "https://example.com/iae"
	iaeExampleNonce    = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
	iaeExampleThumb    = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
	// SessionTranscript = [null, null, ["OpenID4VCIIAEHandover", <hash>]]
	iaeExampleTranscript = "83f6f682754f70656e49443456434949414548616e646f7665725820" +
		"df679426cc1bf8996e8eb549ee078815a87a97c5e95c1c5a8ec39eedca28a838"
)

func TestBuildSessionTranscriptOID4VCIIAEMatchesTheDraftExample(t *testing.T) {
	thumbprint, err := hex.DecodeString(iaeExampleThumb)
	if err != nil {
		t.Fatalf("decoding the example thumbprint: %v", err)
	}

	transcript, err := mdoc.OID4VCIIAESessionTranscript(iaeExampleEndpoint, iaeExampleNonce, thumbprint)
	if err != nil {
		t.Fatalf("mdoc.OID4VCIIAESessionTranscript() error = %v", err)
	}
	if got := hex.EncodeToString(transcript); got != iaeExampleTranscript {
		t.Errorf("SessionTranscript =\n  %s\nwant\n  %s", got, iaeExampleTranscript)
	}
}

// OpenID4VCI 1.1 Appendix A.2.5: "If the Response Mode is ia_post, the third
// element MUST be null". This holds even when the request carried an encryption key.
func TestBuildSessionTranscriptOID4VCIIAEOmitsTheThumbprintForIAPost(t *testing.T) {
	w := generateTestWallet(t)
	key := ecEncJWK(t, "enc")
	meta := map[string]any{"jwks": map[string]any{"keys": []any{key}}}

	if got := w.handoverJWKThumbprint(PresentationParams{ResponseMode: "ia_post", ClientMetadata: meta}); got != nil {
		t.Errorf("ia_post handover thumbprint = %x, want null", got)
	}
	want := computeJWKThumbprint(key)
	if got := w.handoverJWKThumbprint(PresentationParams{ResponseMode: "ia_post.jwt", ClientMetadata: meta}); hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("ia_post.jwt handover thumbprint = %x, want %x", got, want)
	}
}

// Interactive Authorization defines its own handover. The wallet's ISO transcript
// setting only applies to OpenID4VP presentations.
func TestInteractiveAuthorizationTranscriptIgnoresTheSessionTranscriptMode(t *testing.T) {
	params := PresentationParams{
		ResponseMode:                     "ia_post",
		Nonce:                            iaeExampleNonce,
		InteractiveAuthorizationEndpoint: iaeExampleEndpoint,
	}

	oid4vpWallet := generateTestWallet(t)
	oid4vpWallet.SessionTranscript = oid4vp.SessionTranscriptOID4VP
	fromOID4VP, err := oid4vpWallet.buildSessionTranscript(params, "", nil)
	if err != nil {
		t.Fatalf("oid4vp mode: %v", err)
	}

	isoWallet := generateTestWallet(t)
	isoWallet.SessionTranscript = oid4vp.SessionTranscriptISO
	fromISO, err := isoWallet.buildSessionTranscript(params, "mdoc-nonce", nil)
	if err != nil {
		t.Fatalf("iso mode: %v", err)
	}

	if hex.EncodeToString(fromOID4VP) != hex.EncodeToString(fromISO) {
		t.Error("the session transcript mode changed an interactive authorization transcript")
	}
}

// The challenge endpoint is required to bind the presentation to the authorization
// request.
func TestBuildSessionTranscriptOID4VCIIAERefusesAnEmptyEndpoint(t *testing.T) {
	if _, err := mdoc.OID4VCIIAESessionTranscript("  ", iaeExampleNonce, nil); err == nil {
		t.Fatal("built a transcript without an authorization challenge endpoint")
	}
}

// Appendix A.3.5 binds an SD-JWT presentation through the Key Binding JWT
// audience. The ia: prefix separates it from a client_id.
func TestSDJWTAudienceForInteractiveAuthorization(t *testing.T) {
	audience := sdJWTAudience(PresentationParams{
		ResponseMode:                     "ia_post",
		ClientID:                         "x509_hash:something-else",
		InteractiveAuthorizationEndpoint: "https://issuer.example/authorize-challenge",
	})
	if audience != "ia:https://issuer.example/authorize-challenge" {
		t.Errorf("aud = %q, want the challenge endpoint with the ia: prefix", audience)
	}
	if !strings.HasPrefix(audience, "ia:") {
		t.Errorf("aud = %q, want an ia: prefix", audience)
	}

	plain := sdJWTAudience(PresentationParams{
		ResponseMode: "direct_post",
		ClientID:     "x509_hash:verifier",
	})
	if plain != "x509_hash:verifier" {
		t.Errorf("direct_post aud = %q, want the client_id", plain)
	}
}
