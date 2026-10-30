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
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/typemetadata"
)

// typeMetadataRefresh is how often the wallet looks for stale Type Metadata.
const typeMetadataRefresh = time.Hour

// typeMetadataResult is the Type Metadata of a credential and the processing
// and validation failures it found. §5.7 and §7.4 reject the credential for
// them.
type typeMetadataResult struct {
	metadata *typemetadata.Metadata
	problems findings.List
}

// typeMetadata processes the Type Metadata of an SD-JWT VC whose vct is an
// HTTPS URL (SD-JWT VC §5.3.1). The wallet retrieves it when it stores the
// credential, so a presentation sends no request that reveals the use
// (§8.4). Metadata that is not available leaves the credential without it.
// The retrieval makes HTTP requests, so callers run it before they take the
// store lock.
func (w *Wallet) typeMetadata(raw, action string) typeMetadataResult {
	token, err := sdjwt.ParseLenient(strings.TrimSpace(raw))
	if err != nil {
		return typeMetadataResult{}
	}
	vct := jsonutil.Text(token.Payload["vct"])
	if !typemetadata.IsRetrievable(vct) {
		return typeMetadataResult{}
	}
	metadata, err := w.resolveTypeMetadata(vct, jsonutil.Text(token.Payload["vct#integrity"]), action)
	if processing := (*typemetadata.ProcessingError)(nil); errors.As(err, &processing) {
		return typeMetadataResult{problems: findings.List{findings.FromError(err)}}
	}
	if err != nil {
		log.Printf("[Wallet] No Type Metadata for %s: %v", vct, err)
		return typeMetadataResult{}
	}
	return typeMetadataResult{metadata, metadata.Validate(token.Payload, token.Disclosures)}
}

func (w *Wallet) resolveTypeMetadata(vct, integrity, action string) (*typemetadata.Metadata, error) {
	resolver := typemetadata.Resolver{
		Client: w.HTTPClient(),
		OnRetrieval: func(r typemetadata.Retrieval) {
			details := map[string]any{"direction": "inbound", "url": r.URL}
			if r.Status != 0 {
				details["status"] = r.Status
			}
			if r.Err != nil {
				details["error"] = r.Err.Error()
			}
			var body any = r.Body
			var document map[string]any
			if json.Unmarshal([]byte(r.Body), &document) == nil {
				body = document
			}
			w.addProtocolLog(action, "type_metadata_response", "Type Metadata from "+r.URL, r.Err == nil, details, &LogPayload{Label: "Response", Body: body})
		},
	}
	return resolver.Resolve(vct, integrity)
}

// withTypeMetadata stores the metadata with the credential. A credential
// without a display of its own takes the type's display (§5.5).
func withTypeMetadata(cred StoredCredential, metadata *typemetadata.Metadata) StoredCredential {
	cred.TypeMetadata = metadata
	if cred.Display == nil {
		cred.Display = typeDisplay(metadata)
	}
	return cred
}

// typeDisplay picks the English display of a type, or its first one.
func typeDisplay(metadata *typemetadata.Metadata) *oid4vc.CredentialDisplay {
	if metadata == nil || len(metadata.Display) == 0 {
		return nil
	}
	chosen := metadata.Display[0]
	for _, display := range metadata.Display {
		if display.Locale == "en" || strings.HasPrefix(display.Locale, "en-") {
			chosen = display
			break
		}
	}
	return &oid4vc.CredentialDisplay{Name: chosen.Name, Description: chosen.Description, Locale: chosen.Locale}
}

// extendedTypes lists the types a credential extends according to its Type
// Metadata (§5.4).
func (c StoredCredential) extendedTypes() []string {
	if c.TypeMetadata == nil || len(c.TypeMetadata.Types) < 2 {
		return nil
	}
	return c.TypeMetadata.Types[1:]
}

// typeMetadataKey identifies the Type Metadata of a credential: its vct and
// vct#integrity.
type typeMetadataKey struct{ vct, integrity string }

func (c StoredCredential) typeMetadataKey() typeMetadataKey {
	token, err := sdjwt.ParseLenient(c.Raw)
	if err != nil {
		return typeMetadataKey{vct: c.VCT}
	}
	return typeMetadataKey{c.VCT, jsonutil.Text(token.Payload["vct#integrity"])}
}

// refreshTypeMetadata retrieves stale Type Metadata again (§5.3.4, RFC 9111)
// and saves it. Metadata that cannot be retrieved stays until the next
// attempt.
func (s *Server) refreshTypeMetadata(now time.Time) error {
	fresh := map[typeMetadataKey]*typemetadata.Metadata{}
	for _, cred := range s.wallet.GetCredentials() {
		if cred.TypeMetadata == nil || !cred.TypeMetadata.Stale(now) {
			continue
		}
		key := cred.typeMetadataKey()
		if _, done := fresh[key]; done {
			continue
		}
		metadata, err := s.wallet.resolveTypeMetadata(key.vct, key.integrity, "wallet")
		if err != nil {
			log.Printf("[Wallet] Keeping stale Type Metadata for %s: %v", key.vct, err)
			continue
		}
		fresh[key] = metadata
	}
	if len(fresh) == 0 {
		return nil
	}
	// §5.7: changed metadata is validated before the wallet uses it. The
	// credential is already stored, so a failure is a warning.
	for _, cred := range s.wallet.GetCredentials() {
		metadata, ok := fresh[cred.typeMetadataKey()]
		token, err := sdjwt.ParseLenient(cred.Raw)
		if !ok || cred.TypeMetadata == nil || err != nil || sameTypeMetadata(cred.TypeMetadata, metadata) {
			continue
		}
		if problems := metadata.Validate(token.Payload, token.Disclosures); len(problems) > 0 {
			s.wallet.warnFindings("wallet", "type_metadata", subjectCredential, typeMetadataSummary(cred.VCT), problems, map[string]any{"credential_id": cred.ID})
		}
	}
	s.saveMutation(func() bool {
		s.wallet.mu.Lock()
		defer s.wallet.mu.Unlock()
		changed := false
		for i, cred := range s.wallet.Credentials {
			if metadata, ok := fresh[cred.typeMetadataKey()]; ok && cred.TypeMetadata != nil && !reflect.DeepEqual(cred.TypeMetadata, metadata) {
				s.wallet.Credentials[i].TypeMetadata = metadata
				changed = true
			}
		}
		return changed
	})
	return nil
}

// sameTypeMetadata reports whether 2 retrievals returned the same metadata,
// whatever their freshness lifetime.
func sameTypeMetadata(a, b *typemetadata.Metadata) bool {
	x, y := *a, *b
	x.Expires, y.Expires = time.Time{}, time.Time{}
	return reflect.DeepEqual(x, y)
}

func typeMetadataSummary(vct string) string {
	return fmt.Sprintf("The Type Metadata of %s", vct)
}
