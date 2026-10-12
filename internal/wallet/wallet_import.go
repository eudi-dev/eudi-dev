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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
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
	return w.importCredential(raw, "", "")
}

// Record the binding key during import so the credential can be presented. Clones
// forward both the credential and key to the original wallet.
func (w *Wallet) importPrimaryCredential(raw string, keys []*ecdsa.PrivateKey) (*StoredCredential, error) {
	return w.importCredential(raw, "", primaryBindingKeyPEM(raw, keys))
}

// Set batch fields before checking holder binding so a copy with its own key is
// recognized as presentable.
func (w *Wallet) importBatchCopy(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	return w.importCredential(raw, group, bindingKeyPEM)
}

func (w *Wallet) importCredential(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	cred, err := w.importDetectedFormat(strings.TrimSpace(raw), group, bindingKeyPEM)
	if err != nil {
		return nil, err
	}
	w.adoptOwnStatusEntry(cred)
	w.noteUnheldKeyBinding(cred)
	w.noteDIDIssuerKey(cred)
	return cred, nil
}

// mdoc identifies the signer through its COSE certificate chain. Only JWT formats can
// name a DID issuer here.
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

// DID issuer keys cannot be resolved here. The toolkit uses x5c as required by HAIP
// 1.0 §6.1.1 or SD-JWT VC issuer metadata. Keep the credential and report its
// unchecked signature and unverifiable status list.
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
	detail := fmt.Sprintf(
		"Credential %s names its issuer key by the DID %s. Nothing here resolves a DID (HAIP 1.0 §6.1.1 has the issuer's signing certificate travel in the x5c header), so this credential is kept with its issuer signature unverified, and a status list token signed the same way cannot be checked either.",
		credentialLabel(*cred), did)
	w.addProtocolWarning("wallet", "credential_issuer_key_is_a_did", detail, details)
	log.Printf("[Wallet] WARNING: %s", detail)
}

// Set the batch group and binding key before appending because clones forward
// credentials at that point.
func (w *Wallet) importDetectedFormat(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	if strings.Contains(raw, "~") {
		cred, err := w.importSDJWT(raw, group, bindingKeyPEM)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported SD-JWT credential: vct=%s claims=%d disclosures=%d", cred.VCT, len(cred.Claims), len(cred.Disclosures))
		return cred, nil
	}

	detected := format.Detect(raw)
	if detected == format.FormatMDOC {
		cred, err := w.importMDoc(raw, group, bindingKeyPEM)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported mdoc credential: docType=%s claims=%d", cred.DocType, len(cred.Claims))
		return cred, nil
	}

	if strings.Count(raw, ".") == 2 {
		cred, err := w.importPlainJWT(raw, group, bindingKeyPEM)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported plain JWT credential: vct=%s claims=%d", cred.VCT, len(cred.Claims))
		return cred, nil
	}

	return nil, fmt.Errorf("unable to detect credential format (expected SD-JWT or mdoc)")
}

// Adopt imported status entries that reference this wallet's own list. The demo issuer
// uses this list, and the wallet needs local entries to revoke those credentials.
func (w *Wallet) adoptOwnStatusEntry(cred *StoredCredential) {
	if w == nil || cred == nil {
		return
	}
	own := strings.TrimSpace(w.StatusListURL())
	if own == "" {
		return
	}
	ref := CredentialStatusRef(*cred)
	if ref == nil || ref.URI != own {
		return
	}
	if _, exists := w.StatusEntryFor(cred.ID); exists {
		return
	}
	w.registerStatusEntry(cred.ID, ref.Idx)
}

func (w *Wallet) appendCredential(cred StoredCredential) *StoredCredential {
	w.mu.Lock()
	w.Credentials = append(w.Credentials, cred)
	sink := w.credentialSink
	w.mu.Unlock()
	// Forward imports from clones to the original wallet so issued credentials survive
	// the end of the request.
	if sink != nil {
		sink(cred)
	}
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
	if typ, _ := token.Header["typ"].(string); typ == sdjwt.TypeSDJWTVCLegacy {
		vcType = append(vcType, fmt.Sprintf("the typ header is %s, draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires %s", sdjwt.TypeSDJWTVCLegacy, sdjwt.TypeSDJWTVC))
	}
	if w.Mode() == ValidationModeStrict {
		if all := append(append([]string{}, token.Deviations...), vcType...); len(all) > 0 {
			return nil, fmt.Errorf("%s", strings.Join(all, ". "))
		}
		return token, nil
	}
	w.recordCredentialDeviations("RFC 9901", token.Deviations)
	w.recordCredentialDeviations("draft-ietf-oauth-sd-jwt-vc-19", vcType)
	return token, nil
}

// Group deviations into one log entry with the full list in its details.
func (w *Wallet) recordCredentialDeviations(spec string, deviations []string) {
	if len(deviations) == 0 {
		return
	}
	finding := "findings"
	if len(deviations) == 1 {
		finding = "finding"
	}
	detail := fmt.Sprintf("The credential deviates from %s (%d %s, see details)", spec, len(deviations), finding)
	w.addProtocolWarning("wallet", "credential_structure_deviation", detail,
		map[string]any{"deviations": deviations})
}

func (w *Wallet) importSDJWT(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	token, err := w.parseCredentialSDJWT(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing SD-JWT: %w", err)
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        "dc+sd-jwt",
		Raw:           raw,
		Claims:        token.ResolvedClaims,
		Disclosures:   token.Disclosures,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}
	cred.issuedAt = jwtIssuedAt(token.Payload)

	if vct, ok := token.Payload["vct"].(string); ok {
		cred.VCT = vct
	}

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
}

func (w *Wallet) importPlainJWT(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	_, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        "jwt_vc_json",
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

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
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

func (w *Wallet) importMDoc(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing mdoc: %w", err)
	}
	// Strict mode rejects credentials that required dropping invalid content. Debug
	// mode keeps them.
	if len(doc.Deviations) > 0 {
		if w.Mode() == ValidationModeStrict {
			return nil, fmt.Errorf("%s", strings.Join(doc.Deviations, ". "))
		}
		w.recordCredentialDeviations("ISO/IEC 18013-5", doc.Deviations)
	}

	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		for _, item := range items {
			claims[ns+":"+item.ElementIdentifier] = item.ElementValue
		}
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        "mso_mdoc",
		Raw:           raw,
		Claims:        claims,
		DocType:       doc.DocType,
		NameSpaces:    doc.NameSpaces,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}
	cred.issuedAt = mdocSignedAt(doc)

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
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
	if c.Raw == "" {
		return nil
	}

	switch c.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.ParseLenient(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		c.Disclosures = token.Disclosures
		if c.Claims == nil {
			c.Claims = token.ResolvedClaims
		}
		c.issuedAt = jwtIssuedAt(token.Payload)

	case "jwt_vc_json":
		_, payload, _, err := format.ParseJWTParts(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		if c.Claims == nil {
			c.Claims = payload
		}
		c.issuedAt = jwtIssuedAt(payload)

	case "mso_mdoc":
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
func (w *Wallet) rememberRenewal(credentialID, refreshToken string, renewal CredentialRenewal) {
	if w == nil || refreshToken == "" || renewal.CredentialEndpoint == "" || renewal.TokenEndpoint == "" {
		return
	}
	renewal.RefreshToken = refreshToken

	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == credentialID {
			w.Credentials[i].Renewal = &renewal
			return
		}
	}
}

func (w *Wallet) logCredentialImport(imported *StoredCredential, issuer string, details map[string]any, credentials []*StoredCredential) {
	details["issuer"] = issuer
	w.addProtocolLog("issuance", "credential_imported", fmt.Sprintf("Imported credential %s", imported.ID), true, details, credentialImportLogPayload(credentials))
}

func jwtIssuedAt(payload map[string]any) time.Time {
	if iat, ok := payload["iat"].(float64); ok && iat > 0 {
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
