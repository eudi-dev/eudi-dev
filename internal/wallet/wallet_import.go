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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// Commands accept unambiguous prefixes of these IDs. Generation panics only if system
// entropy is unavailable.
func newCredentialID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("wallet: no entropy for a credential id: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ImportCredential returns a copy that survives changes to the wallet's credential slice.
func (w *Wallet) ImportCredential(raw string) (*StoredCredential, error) {
	return w.importCredential(raw, "", "", w.typeMetadata(raw, "wallet"))
}

// Set batch fields before checking holder binding so a copy with its own key is
// recognized as presentable.
func (w *Wallet) importBatchCopy(raw, group, bindingKeyPEM string, typed typeMetadataResult) (*StoredCredential, error) {
	return w.importCredential(raw, group, bindingKeyPEM, typed)
}

func (w *Wallet) importCredential(raw, group, bindingKeyPEM string, typed typeMetadataResult) (*StoredCredential, error) {
	parsed, err := w.parseDetectedFormat(strings.TrimSpace(raw), group, bindingKeyPEM)
	if err != nil {
		return nil, err
	}
	// Manual import keeps the credential and only warns.
	if len(typed.problems) > 0 {
		w.warnFindings("wallet", "type_metadata", subjectCredential, typeMetadataSummary(parsed.VCT), typed.problems, nil)
	}
	cred := w.appendCredential(withTypeMetadata(parsed, typed.metadata))
	w.adoptOwnStatusEntry(cred)
	w.noteUnheldKeyBinding(cred)
	w.noteDIDIssuerKey(cred)
	return cred, nil
}

// mdoc identifies the signer through its COSE certificate chain. Only JWT formats can
// have a DID issuer here.
func credentialIssuerDID(raw string) string {
	jwtPart := strings.TrimSpace(raw)
	if idx := strings.Index(jwtPart, "~"); idx >= 0 {
		jwtPart = jwtPart[:idx]
	}
	header, payload, _, err := format.ParseJWTParts(jwtPart)
	if err != nil {
		return ""
	}
	kid, _ := header["kid"].(string)
	iss, _ := payload["iss"].(string)
	return keys.DIDReference(kid, iss)
}

// The wallet can't resolve DID issuer keys. It finds issuer keys through x5c, as
// HAIP 1.0 §6.1.1 requires, or through SD-JWT VC issuer metadata. Keep the
// credential and report its unchecked signature and unverifiable status list.
func (w *Wallet) noteDIDIssuerKey(cred *StoredCredential) {
	if w == nil || cred == nil {
		return
	}
	did := credentialIssuerDID(cred.Raw)
	if did == "" {
		return
	}
	details := map[string]any{
		"credential_id":  cred.ID,
		"format":         cred.Format,
		"issuer_key_did": did,
	}
	addStringDetail(details, "vct", cred.VCT)
	finding := findings.HAIP.Protocol("§6.1.1").Newf(
		"credential %s names its issuer key by the DID %s, and the issuer's signing certificate belongs in the x5c header. This wallet does not resolve DIDs, so it keeps the credential with an unverified issuer signature. A status list token signed this way can't be checked either",
		credentialLabel(*cred), did)
	w.warnFinding("wallet", "credential_issuer_key_is_a_did", subjectCredential, finding, details)
	log.Printf("[Wallet] WARNING: %s", finding)
}

// parseDetectedFormat parses a credential into a new wallet entry without
// storing it. It sets the batch group and binding key before the caller
// appends the entry, because clones forward credentials at that point.
func (w *Wallet) parseDetectedFormat(raw, group, bindingKeyPEM string) (StoredCredential, error) {
	w.mu.RLock()
	limit := w.capacity.CredentialBytes
	w.mu.RUnlock()
	if limit > 0 && len(raw) > limit {
		return StoredCredential{}, visitorLimit("the public demo stores credentials of up to %d KB. This one has %d KB", limit>>10, (len(raw)+1023)>>10)
	}
	if strings.Contains(raw, "~") {
		cred, err := w.parseSDJWTEntry(raw, group, bindingKeyPEM)
		if err != nil {
			return StoredCredential{}, err
		}
		log.Printf("[Wallet] Imported SD-JWT credential: vct=%s claims=%d disclosures=%d", cred.VCT, len(cred.Claims), len(cred.Disclosures))
		return cred, nil
	}

	detected := format.Detect(raw)
	if detected == format.FormatMDOC {
		cred, err := w.parseMDocEntry(raw, group, bindingKeyPEM)
		if err != nil {
			return StoredCredential{}, err
		}
		log.Printf("[Wallet] Imported mdoc credential: docType=%s claims=%d", cred.DocType, len(cred.Claims))
		return cred, nil
	}

	if strings.Count(raw, ".") == 2 {
		cred, err := w.parsePlainJWTEntry(raw, group, bindingKeyPEM)
		if err != nil {
			return StoredCredential{}, err
		}
		log.Printf("[Wallet] Imported plain JWT credential: vct=%s claims=%d", cred.VCT, len(cred.Claims))
		return cred, nil
	}

	return StoredCredential{}, fmt.Errorf("unable to detect credential format (expected SD-JWT or mdoc)")
}

// Adopt imported status entries that reference this wallet's own list. The demo issuer
// uses this list, and the wallet needs local entries to revoke those credentials.
// An import cannot take over the index of another credential.
func (w *Wallet) adoptOwnStatusEntry(cred *StoredCredential) {
	if w == nil || cred == nil {
		return
	}
	ref := w.ownStatusRef(*cred)
	if ref == nil {
		return
	}
	if _, exists := w.StatusEntryFor(cred.ID); exists {
		return
	}
	if w.statusIndexFree(ref.Idx, cred.ID) != nil {
		return
	}
	w.registerStatusEntry(cred.ID, ref.Idx)
}

// ownStatusRef is the credential's status reference if it points at the
// wallet's own status list.
func (w *Wallet) ownStatusRef(cred StoredCredential) *statuslist.StatusRef {
	own := strings.TrimSpace(w.StatusListURL())
	ref := CredentialStatusRef(cred)
	if own == "" || ref == nil || ref.URI != own {
		return nil
	}
	return ref
}

func (w *Wallet) appendCredential(cred StoredCredential) *StoredCredential {
	w.mu.Lock()
	w.makeCredentialRoomLocked()
	w.Credentials = append(w.Credentials, cred)
	w.mu.Unlock()
	return &cred
}

// Strict mode rejects RFC 9901 violations. Debug mode keeps the credential and warns.
func (w *Wallet) parseCredentialSDJWT(raw string) (*sdjwt.Token, error) {
	token, err := sdjwt.ParseLenient(raw)
	if err != nil {
		return nil, err
	}
	// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires the typ dc+sd-jwt. The
	// earlier vc+sd-jwt value still decodes but is a deviation.
	var vcType []string
	if check := validate.CheckSDJWTType(token); check.Status == validate.Fail {
		vcType = append(vcType, check.Detail)
	}
	// §2.2.2.3 makes vct REQUIRED.
	if vct, _ := token.Payload["vct"].(string); vct == "" {
		vcType = append(vcType, "the credential has no vct claim, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 makes REQUIRED")
	}
	vcType = append(vcType, validate.DisclosedRegisteredClaims(token)...)
	deviations := token.Deviations
	// RFC 9901 §7.2: "The Issuer provides the Holder with an SD-JWT, not an
	// SD-JWT+KB. If the Holder receives an SD-JWT+KB, it MUST be rejected."
	if token.KeyBindingJWT != nil {
		deviations = append(slices.Clone(deviations), "the credential carries a Key Binding JWT, and RFC 9901 §7.2 has the Holder reject an SD-JWT+KB from an Issuer")
	}
	if err := w.reportCredentialDeviations("RFC 9901", deviations); err != nil {
		return nil, err
	}
	if err := w.reportCredentialDeviations("draft-ietf-oauth-sd-jwt-vc-19", vcType); err != nil {
		return nil, err
	}
	return token, nil
}

// reportCredentialDeviations groups deviations into one log entry with the
// full list in its details.
func (w *Wallet) reportCredentialDeviations(spec string, deviations []string) error {
	if len(deviations) == 0 {
		return nil
	}
	return w.reportDeviation(deviation{
		action: "wallet", event: "credential_structure_deviation", subject: subjectCredential,
		summary: "The credential deviates from " + spec, findings: findings.UncitedAll(deviations),
	})
}

func (w *Wallet) parseSDJWTEntry(raw, group, bindingKeyPEM string) (StoredCredential, error) {
	token, err := w.parseCredentialSDJWT(raw)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("parsing SD-JWT: %w", err)
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        credtype.FormatSDJWT,
		Raw:           raw,
		Claims:        token.ResolvedClaims,
		Disclosures:   token.Disclosures,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}
	cred.issuedAt = jwtIssuedAt(token.ResolvedClaims)

	if vct, ok := token.Payload["vct"].(string); ok {
		cred.VCT = vct
	}

	return cred, nil
}

func (w *Wallet) parsePlainJWTEntry(raw, group, bindingKeyPEM string) (StoredCredential, error) {
	_, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("parsing JWT: %w", err)
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        credtype.FormatJWTVC,
		Raw:           raw,
		Claims:        payload,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}
	cred.issuedAt = jwtIssuedAt(payload)

	if vct, ok := payload["vct"].(string); ok && vct != "" {
		cred.VCT = vct
	} else {
		cred.VCT = jwtVCType(payload)
	}

	return cred, nil
}

// VC Data Model 1.1 puts the type array inside vc. Some issuers put it at the payload
// root. Use the last type other than VerifiableCredential as the display type.
func jwtVCType(payload map[string]any) string {
	types := payload["type"]
	if vc, ok := payload["vc"].(map[string]any); ok && vc["type"] != nil {
		types = vc["type"]
	}
	switch v := types.(type) {
	case string:
		if v != "VerifiableCredential" {
			return v
		}
	case []any:
		specific := ""
		for _, t := range v {
			if s, ok := t.(string); ok && s != "" && s != "VerifiableCredential" {
				specific = s
			}
		}
		return specific
	}
	return ""
}

func (w *Wallet) parseMDocEntry(raw, group, bindingKeyPEM string) (StoredCredential, error) {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("parsing mdoc: %w", err)
	}
	// Strict mode rejects credentials that required dropping invalid content. Debug
	// mode keeps them.
	if err := w.reportCredentialDeviations("ISO/IEC 18013-5", doc.Deviations); err != nil {
		return StoredCredential{}, err
	}

	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		for _, item := range items {
			claims[ns+":"+item.ElementIdentifier] = item.ElementValue
		}
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        credtype.FormatMDOC,
		Raw:           raw,
		Claims:        claims,
		DocType:       doc.DocType,
		NameSpaces:    doc.NameSpaces,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}
	cred.issuedAt = mdocSignedAt(doc)

	return cred, nil
}

func (w *Wallet) ImportCredentialFromFile(path string) error {
	raw, err := format.ReadInput(path)
	if err != nil {
		return fmt.Errorf("reading credential file: %w", err)
	}
	_, err = w.ImportCredential(raw)
	return err
}

// Rehydrate rebuilds parsed fields from Raw because they are not serialized.
func (c *StoredCredential) Rehydrate() error {
	if r := c.Renewal; r != nil && r.ClientAuth != nil && r.ClientAuth.LegacyClientID != "" {
		r.ClientID = jsonutil.FirstNonEmpty(r.ClientID, r.ClientAuth.LegacyClientID)
		r.ClientAuth.LegacyClientID = ""
	}
	if c.Raw == "" {
		return nil
	}

	switch c.Format {
	case credtype.FormatSDJWT:
		token, err := sdjwt.ParseLenient(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		c.Disclosures = token.Disclosures
		if c.Claims == nil {
			c.Claims = token.ResolvedClaims
		}
		c.issuedAt = jwtIssuedAt(token.ResolvedClaims)

	case credtype.FormatJWTVC:
		_, payload, _, err := format.ParseJWTParts(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		if c.Claims == nil {
			c.Claims = payload
		}
		c.issuedAt = jwtIssuedAt(payload)

	case credtype.FormatMDOC:
		doc, err := mdoc.Parse(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing mdoc: %w", err)
		}
		c.NameSpaces = doc.NameSpaces
		c.issuedAt = mdocSignedAt(doc)
		if c.Claims == nil {
			claims := make(map[string]any)
			for ns, items := range doc.NameSpaces {
				for _, item := range items {
					claims[ns+":"+item.ElementIdentifier] = item.ElementValue
				}
			}
			c.Claims = claims
		}
	}

	return nil
}

// Store renewal context only when the issuer supplies a refresh token.
func (w *Wallet) rememberRenewal(credentialID string, renewal CredentialRenewal) {
	if w == nil || !renewal.renewable() {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == credentialID {
			w.Credentials[i].Renewal = &renewal
			return
		}
	}
}

// jwtIssuedAt reads iat from the claims. An SD-JWT passes its resolved
// claims, because a PID carries iat as a disclosure (CIR (EU) 2024/2977 Annex
// section 4.2, as replaced by CIR (EU) 2026/1731).
func jwtIssuedAt(claims map[string]any) time.Time {
	if iat, ok := claims["iat"].(float64); ok && iat > 0 {
		return time.Unix(int64(iat), 0)
	}
	return time.Time{}
}

func mdocSignedAt(doc *mdoc.Document) time.Time {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.ValidityInfo == nil || doc.IssuerAuth.MSO.ValidityInfo.Signed == nil {
		return time.Time{}
	}
	return *doc.IssuerAuth.MSO.ValidityInfo.Signed
}
