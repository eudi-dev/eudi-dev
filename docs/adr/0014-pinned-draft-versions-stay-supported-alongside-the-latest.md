# Pinned draft versions stay supported alongside the latest

The EUDI Architecture and Reference Framework determines which specifications the toolkit supports ([ADR-0013](0013-only-the-eudi-stack-is-supported.md)). Some of those specifications reference particular drafts of their dependencies. The toolkit keeps supporting these pinned drafts when it adds newer versions.

OAuth 2.0 Attestation-Based Client Authentication (ABCA) is an example. OpenID4VCI 1.0 pins draft-07 and requires implementations to prefer pinned references (§14.7). The OpenID4VCI 1.1 editor draft pins draft-08. Draft-08 removed `iss` from the client attestation and its proof of possession. Draft-10 adds combined DPoP authentication and metadata for negotiating proof methods.

## Compatibility rules

Outgoing messages include claims needed by every compatible draft. ABCA drafts permit additional JWT claims (§5.1 and §5.2 rule 1), so including the older claims also works with newer verifiers. The wallet therefore includes `iss` and `nbf` in both the attestation and its proof, regardless of `--vci-version`. If draft requirements become incompatible, the configured OpenID4VCI version selects the message format.

Incoming messages are accepted when valid under any supported draft. A warning identifies differences from the configured draft. Messages invalid under every supported draft are rejected.

New authentication methods are negotiated through server metadata. A server offering only `attest_jwt_client_auth_dpop` or `dpop_combined` receives the combined proof. The wallet warns when the configured draft predates that method. Metadata can also advertise newer capabilities because older clients ignore unknown parameters.

## Consequences

When a dependency publishes a new draft, review how it relates to the ARF references and check conformance before adopting changed behavior ([ADR-0010](0010-spec-conformance-is-checked-before-and-after-every-change.md)). The shared protocol flow handles version selection and compatibility warnings.

Issuers following draft-07 reject an attestation without `iss` or a proof without `nbf` and `exp`. Sending only the draft-08 claims would break those issuers.
