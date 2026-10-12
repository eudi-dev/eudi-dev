# Only what the EUDI stack references is supported

This toolkit implements the specifications that underlie the EUDI Architecture and Reference Framework: OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0, SD-JWT and SD-JWT VC, ISO 18013-5, ETSI TS 119 602, and the Token Status List draft. `docs/spec-compliance.md` lists them and says what is implemented from each.

The toolkit reports mechanisms outside that set as unsupported.

## Reporting unsupported mechanisms

If the toolkit ignored an unsupported mechanism, a request could look verified. When a request, credential or token uses an unsupported mechanism, the toolkit reports it in a finding. The finding identifies the skipped mechanism and what remains unchecked. The affected key or signature stays unresolved.

## In the code

`openid_federation:` as a Client Identifier Prefix is refused with "not supported by this wallet". OID4VP 1.0 §5.9.3 defers its processing rules to OpenID Federation, and the wallet resolves no trust chain (`internal/oid4vp/clientid_prefixes.go`).

A key identified by a DID is reported as unresolved: in the credential import warning, in the HAIP findings, in the skipped-signature note of `validate`, and in the failure of a status list check (`keys.DIDReference`). An issuer key is resolved through the `x5c` chain (required by HAIP 1.0 §6.1.1) or through the issuer metadata defined by SD-JWT VC. `did:key` carries its key in the identifier and would be easy to decode. It is left out on purpose.

The Status List Token check accepts ES256 and ES384 for a JWT, and ES256, ESP256 and ES384 for a CWT (`internal/statuslist`).

## Deviations are still processed

Debug mode continues when the toolkit can process a request despite a profile violation. It collects findings ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)), so developers can inspect the exchange. For example, it can send `direct_post` where HAIP requires `direct_post.jwt`, or use a supported credential format outside the profile. A mechanism with no implementation cannot complete the flow, so the wallet reports it as unsupported.

A supported mechanism is checked. For request objects and signed issuer metadata, signature verification uses the supplied certificate chain. Trust in the signer requires a configured anchor ([ADR-0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md)).

## Consequences

Add support when the EUDI ARF or a referenced specification defines the mechanism. Until then, report its use clearly. Revisit this decision when the supported specification set changes.

Findings must distinguish unsupported key resolution from a missing key or failed fetch. `SECURITY.md` and `docs/spec-compliance.md` describe the supported mechanisms.

The wallet does not resolve the key of a Request Object under a `decentralized_identifier:` client identifier. Under `verifier_attestation:` it reads the key from the attestation, but it cannot anchor the attestation issuer. `VerifyRequestObjectSignature` reports which key it needs and where that key would come from. It does the same for a bare `client_id`. Its key would have to be pre-registered. This wallet has no pre-registered clients.
