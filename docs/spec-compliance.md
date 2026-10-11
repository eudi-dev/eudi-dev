# Spec compliance

This page lists which specifications of the EUDI Architecture and Reference Framework the wallet supports. The wallet reports unsupported mechanisms when it encounters them ([ADR-0013](adr/0013-only-the-eudi-stack-is-supported.md)).

The [EUDI version table and test certificate profiles](test-certificates.md) list the versions, checked on 1 October 2026.

Three settings control validation:

- `--mode strict` rejects validation violations. `--mode debug` reports them and continues where the flow can proceed. Advisory findings are warnings in both modes. Each finding cites the specification and rule.
- `--haip` enables the HAIP 1.0 profile checks listed below.
- `--arf` enables the ARF checks of access certificates, registration certificates and received credentials (see [ARF checks](wallet/presenting.md#arf-checks)).

`--vci-version 1.0` (default) uses the published OpenID4VCI version. `1.1` adds draft features when the issuer advertises them. See [OpenID4VCI feature level](wallet/issuing.md#openid4vci-feature-level).

## OID4VP 1.0 (OpenID for Verifiable Presentations)

| Feature | Status | Notes |
|---------|--------|-------|
| Authorization request parsing | Implemented | `openid4vp://`, `haip-vp://`, `eudi-openid4vp://` schemes |
| Request Object parameter extraction | Enforced | The wallet uses only the Request Object parameters (§5.10.1: "The Wallet MUST only use the parameters in this Request Object, even if the same parameter was provided in an Authorization Request query parameter"). A parameter missing from the Request Object counts as absent. A Request Object `client_id` that differs from the outer one aborts the flow |
| Undefined parameters | Warned | The wallet warns in every mode about request parameters that OID4VP 1.0 does not define and about response fields other than `redirect_uri` (§8.2). RFC 6749 §3.1 requires ignoring unrecognized parameters |
| Required request parameters | Enforced | `nonce` (§5.2), exactly one of `dcql_query` and `scope` on a `vp_token` request (§5.1), and no `redirect_uri` alongside `response_uri` (§8.2) |
| `request_uri` (GET) | Implemented | Fetches and parses signed request objects |
| `request_uri_method=post` | Implemented | Sends `wallet_metadata` and `wallet_nonce`. If the request object echoes `wallet_nonce`, it must match the one sent. A request object without it is accepted because the parameter is optional there |
| Encrypted request objects (JWE) | Implemented | The wallet always sends an encryption key in `wallet_metadata` and decrypts an encrypted request object. `--require-encrypted-request` rejects an unencrypted one |
| DCQL query evaluation | Implemented | Includes `credential_sets` constraints. If an otherwise matching credential lacks some required claim paths, debug mode warns and continues. Strict mode treats that credential as non-matching |
| `require_cryptographic_holder_binding` | Implemented | The parameter defaults to `true` (§6.1). An SD-JWT VC without `cnf` or an mdoc without a device key only matches a query that sets it to `false`. It does not apply to `jwt_vc_json` credentials. In strict mode an mdoc without a device key matches no query, because strict mode never presents one. A value other than `true` or `false` is a warning in debug mode and refused in strict mode. In debug mode an unbound credential appears among the non-matching credentials, and you can still pick it |
| `vct_values` matching across extending types | Implemented | A credential matches a `vct_values` entry for its own type, for a type in its `aka_vcts` claim, or for a parent type. So any domestic PID (`urn:eudi:pid:de:1`, `urn:eudi:pid:fr:1`, …) matches a request for `urn:eudi:pid:1`. ARF Annex 2 v3.0.0 PID_14 defines these domestic PID types. Matching goes in that direction only. A match does not establish trust (see [credential type inheritance](wallet.md#credential-type-inheritance)) |
| `multiple` | Implemented | Without `multiple`, the wallet sends the newest matching credential. With `multiple: true` it sends all matching credentials. A batch counts as one credential. A `multiple` value other than `true` or `false` produces a warning. Strict mode refuses the query (§6.1) |
| `direct_post` response mode | Implemented | |
| `direct_post.jwt` response mode | Implemented | JARM-encrypted responses |
| `dc_api` response mode | Implemented | Browser API responses via `/api/dc-api` |
| `dc_api.jwt` response mode | Implemented | Encrypted Browser API responses via `/api/dc-api` |
| Response encryption key | Implemented | The response JWE is encrypted to the Verifier's `client_metadata.jwks` key. ECDH-ES for an EC P-256 key (the OID4VP baseline, preferred when the Verifier offers both) or RSA-OAEP for an RSA key. If the Verifier publishes only a key marked for signing, debug mode warns and encrypts to it anyway. Strict mode refuses the request. Under `--haip`, only ECDH-ES on P-256 is conformant (§5). Any other key is a violation |
| JAR (signed request objects) | Implemented | The JWS signature is verified with the leaf `x5c` key in every mode. Strict mode rejects an invalid signature. Debug mode reports it and continues. The chain is checked for internal consistency. It is not anchored to a pre-registered verifier CA (see [SECURITY.md](../SECURITY.md)). With `--arf` the wallet checks the chain against the CAs on its `access-ca` lists |
| `x509_san_dns:` client_id | Implemented | Verified against the leaf certificate SAN |
| `x509_hash:` client_id | Implemented | SHA-256 of the leaf certificate matched against the prefix value |
| `redirect_uri:` client_id | Implemented | Requires unsigned request objects and checks that the prefix value matches `response_uri` |
| `verifier_attestation:` client_id | Validated | Checks the JWT structure in the header and that its `sub` claim matches the client_id. The Request Object signing key is in the attestation's `cnf` claim. The wallet does not read that claim, so it reports the signature as not verified |
| `decentralized_identifier:` client_id | Validated | Validates the DID format and cross-checks `kid`. DID resolution is not implemented, so the wallet reports the Request Object signature as not verified ([ADR-0013](adr/0013-only-the-eudi-stack-is-supported.md)) |
| Pre-registered client (no prefix) | Validated | A Client Identifier without a `:` refers to a pre-registered client (§5.9.2). The wallet does not report it as an unknown prefix. No client keys are pre-registered with this wallet, so it reports the Request Object signature as not verified |
| `origin:` client_id | Refused | §5.9.3 reserves the prefix: "The Wallet MUST NOT accept this Client Identifier Prefix in requests". The prefix identifies the audience of a Digital Credentials API presentation. The wallet derives that audience from the caller origin reported by the platform |
| `openid_federation:` client_id | Refused | §5.9.3 defers the prefix to OpenID Federation. Trust chain resolution is not implemented, so the request is refused |
| Unsigned Digital Credentials API requests | Implemented | Per Appendix A.2, such a request carries no `client_id`. The wallet discards both `client_id` and `expected_origins` before processing it. The platform reports the caller origin. The presentation audience is that origin prefixed with `origin:` |
| `expected_origins` on signed Digital Credentials API requests | Enforced | Appendix A.2 requires the parameter on a signed request. The wallet returns an error when the caller origin is not among its entries |
| VP Token as JSON array | Implemented | Multiple credentials in a single response |
| `fragment` response mode | Implemented | Builds the redirect URL with `vp_token` and `state` as fragment parameters. Not the default |
| SIOPv2 self-issued `id_token` | Implemented | `response_type=vp_token id_token` or `id_token` alone |
| Request object `typ` header | Enforced in strict mode | Debug mode logs a warning and continues |
| `trusted_authorities` (`etsi_tl`, `aki`) | Implemented | Filters credentials by checking the issuer certificate chain against ETSI trusted lists or by matching Authority Key Identifier values |
| `transaction_data` | Enforced in strict mode | §5 requires a wallet that does not support the parameter to reject a request carrying it. Strict mode rejects it. Debug mode logs a warning and continues |
| `verifier_info` | Implemented | The wallet shows the purpose from a wallet-relying-party registration certificate (typ `rc-wrp+jwt` per ETSI TS 119 475, format `registration_cert` per ETSI TS 119 472-2) (§5.1). The certificate's signature is checked against its own x5c leaf. Only certificates that belong to the access certificate that signed the request object count. A request without a request object shows no purpose. The consent dialog also links the registered privacy policy (ARF RPA_10). Other attestation formats are ignored. `--arf` checks the certificate against the ARF (see [ARF checks](wallet/presenting.md#arf-checks)) |
| ARF relying party checks (`--arf`) | Enforced in strict mode | Checks the access certificate (RPA_03, RPA_04) and the registration certificate (RPRC_02a, RPRC_17, RPRC_17a). The request must carry exactly one registration certificate (RPRC_19). The wallet checks the registrar's status list for a revocation. The list must chain to a trusted registrar (RPACANot_03b). The wallet also checks whether the request asks for more than was registered (RPRC_21). Strict mode refuses a request with a finding. If only ARF findings remain and a trusted access certificate signed the request, the wallet sends the verifier `access_denied` (§8.5), also over the Digital Credentials API and from `wallet accept`. Debug mode warns and returns the findings in the API response. Without `--arf` the wallet does not check them. See [ARF checks](wallet/presenting.md#arf-checks) |
| ARF issuer checks (`--arf`) | Enforced in strict mode | Before it requests a credential, the wallet checks the issuer. The metadata must be signed with an access certificate (ISSU_22, ISSU_32) from a trusted access certificate authority (ISSU_24, ISSU_34). `issuer_info` (ETSI TS 119 472-3 V1.1.1 §4.2.3) must carry a registration certificate from a trusted registrar (ISSU_23c, ISSU_33a). That certificate must be valid and not revoked (RPRC_22a). It must name the access certificate's provider (RPRC_22b), have the provider entitlement for the offered type (ISSU_24a, ISSU_34a) and list that type (RPRC_23, ISSU_24b, ISSU_34b). Strict mode refuses the offer before the consent dialog. Debug mode warns and returns the findings in the issuance result. A received credential must chain to the trusted list of its catalogue entry, or for a PID or a PuB-EAA to a list of its type on the list of trusted lists (ISSU_07 to ISSU_10). A PID, QEAA or PuB-EAA entry must link a readable trusted list. ISSU_10 applies only when the wallet has anchors. A fetched trusted list must be signed by the wallet CA or a `--trusted-list-ca` CA (PPNot_05, TLPub_05, TLPub_07). If this check fails, strict mode doesn't store the credential (ISSU_11b). An offered type outside the catalogue only gets a warning. See [issuing](wallet/issuing.md#arf-checks) |
| Relying party registrar | Implemented | The wallet registers verifiers and issuers in the TS05 v1.5 data model and serves the TS05 registry API. It issues access certificates (ETSI TS 119 411-8) for CSRs and registration certificates (ETSI TS 119 475) per intended use (RPRC_09) or per issuer service (RPRC_13). The registrar returns a verifier's certificate in a `verifier_info` value with the registrar dataset (ETSI TS 119 472-2 V1.2.1 §6.3.2.2), and an issuer's certificate in an `issuer_info` value (ETSI TS 119 472-3 V1.1.1 §4.2.3). See [registrar](wallet/registrar.md) |
| Catalogue of attestations | Implemented | The registrar keeps a catalogue in the EC TS11 v1.0 data model (§4.3) and serves its API (§5.3): signed `GET /schemas` with filters and paging, `GET`, `PUT` and `DELETE /schemas/{schemaId}`. The schema behind a `dc+sd-jwt` schema URI is SD-JWT VC Type Metadata. The one behind an `mso_mdoc` schema URI lists the doctype's namespaces and elements, and has not been checked against ISO 23220-2. See [attestation catalogue](wallet/registrar.md#attestation-catalogue) |


## OID4VCI 1.0 (OpenID for Verifiable Credential Issuance)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential offer parsing | Implemented | `openid-credential-offer://`, `haip-vci://` and EUDI `eu-eaa-offer://` schemes |
| Pre-authorized code grant | Implemented | With optional `tx_code` |
| Authorization code grant | Implemented | The server defaults `client_id` to its origin and `redirect_uri` to that origin plus `/callback`. Uses PAR, DPoP and client attestation when advertised. Without PAR, it calls the authorization endpoint directly. Attestation JWTs carry the draft-07 claims, which drafts 08 and 10 accept. Newer proof methods are negotiated through metadata ([ADR-0014](adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md), [wallet attestation](wallet/issuing.md#wallet-attestation)) |
| Pushed Authorization Request (PAR) | Implemented | Used by the authorization code flow |
| Token endpoint | Implemented | Exchanges pre-authorized code or authorization code for access token |
| Credential endpoint | Implemented | Sends OID4VCI 1.0 final `proofs.jwt` or `proofs.attestation` (Appendix F.1 and F.3), chosen from the configuration's `proof_types_supported`. Sends `credential_identifier` or `credential_configuration_id` as required. §8.2 forbids both together and forbids either one where the token response did not require it |
| Key proof `iss` | Implemented | The JWT key proof sets `iss` to the client (Appendix F.1) when the wallet got the access token as an identified client (the authorization code flow, or a pre-authorized flow that authenticated the client). An anonymous pre-authorized flow omits `iss` |
| Nonce endpoint | Implemented | The wallet takes the key-proof challenge only from this endpoint (§8.2). The request is unauthenticated (§7.1). Strict mode ignores a `c_nonce` in the token response. Debug uses it when no Nonce Endpoint is advertised and logs the issuer as pre-1.0 |
| `invalid_nonce` retry | Implemented | After a rejected nonce, the wallet fetches a new one from the Nonce Endpoint and resends the request once with new proofs (§8.3.1.2) |
| Credential response shape | Enforced | The wallet reads only the `credentials` array of objects (§8.3). It refuses the draft formats (a top-level `credential` string or an array of bare strings) |
| Batch credential issuance | Implemented | Requests one key per copy (one `jwt` proof each, or a single key attestation listing every key, Appendix F.1 and F.3). Imports every returned credential (one per key, §8.3), even if that is fewer than requested. A copy bound to no proof key, bound to a key another copy uses, or unreadable is a deviation. Strict mode refuses the response. Debug mode warns and leaves the copy out. Each copy has its own key, separate from the main holder key. The wallet signs the copy's key binding with that key |
| Proof signing algorithm | Implemented | The wallet signs the proof and its key attestation with ES256. If the chosen proof type's `proof_signing_alg_values_supported` lacks ES256, strict mode refuses the configuration and debug mode reports it. Appendix F.1 and F.3 require `alg` to match that list. HAIP §7 requires issuers to support ES256 |
| Key attestation proof types | Implemented | The key attestation (Appendix D) goes in the `key_attestation` header of a `jwt` proof (F.1). Under the `attestation` proof type it is the proof itself, with the issuer's `c_nonce` inside the attestation (F.3). The wallet picks `attestation` when it is the only type in `proof_types_supported` or when the `jwt` type requires a key attestation. Otherwise it picks `jwt` |
| Deferred credential issuance | Implemented | Both grant flows poll `deferred_credential_endpoint` with the `transaction_id`. Each poll uses the request encryption the issuer requires and carries its own `credential_response_encryption` (§9.1). A pending credential is HTTP 202 with `transaction_id` and `interval` (§9.2) |
| Notification Endpoint | Implemented | The wallet sends a `credential_accepted` notification when the issuer publishes `notification_endpoint` and the response carries a `notification_id`. This applies to both grant flows and to a deferred credential once collected. §11 makes the endpoint OPTIONAL, so a refused notification is a warning and the wallet keeps the credential. Any 2xx is a success (§11.2). The wallet reports error responses that match neither of the two defined in §11.3 |
| Transaction code | Implemented | The wallet sends a `tx_code` when the offer's pre-authorized grant requires one (§4.1.1). `wallet accept` prompts for it at the terminal when it runs the flow itself. Without a code, the wallet refuses the issuance before it uses the pre-authorized code. The error states the length and input mode required by the offer |
| Credential response encryption | Implemented | Requests `credential_response_encryption` when advertised, and only when the request itself can be encrypted (§8.2 requires request encryption whenever the parameter is sent) |
| Credential Issuer Metadata retrieval | Implemented | `Accept: application/json, application/jwt` (§12.2.2). With `--arf` the wallet prefers the signed form (`application/jwt, application/json;q=0.5`). The ARF requires issuers to provide it (ISSU_22, ISSU_32). The response is refused unless `credential_issuer` is identical to the requested identifier (§12.2.4) |
| Signed Credential Issuer Metadata verification | Implemented | The wallet checks `typ`, an asymmetric `alg`, a `sub` matching the issuer identifier and the signature against the `x5c` leaf. Without `iat`, or with an `exp` that has passed, strict mode refuses the metadata and debug mode reads it with a warning in the activity log. It tries to anchor the signer in the system root store. A signer that matches no root is logged as unanchored and accepted (§12.2.3). With `--arf` the signer must chain to a trusted access certificate authority |
| Credential configuration display and claims | Implemented | Reads `credential_metadata` (§12.2.4) for consent. Stores the first display entry's name, description, logo, colors and background image. By default, the wallet fetches each image once through the restricted HTTP client. Input is capped at 4 MB and 32 megapixels. Images are downscaled and cached at 256 KB. See [display images](wallet/serve.md#display-images) for on-demand fetching. Invalid CSS Color Level 3 values are dropped with a warning. Contrast below 3:1 produces a warning. Display findings do not fail issuance |
| Authorization server selection | Implemented | The offer's `authorization_server` grant parameter selects the server. A value that matches no entry of `authorization_servers` aborts the flow (§12.2.4). Before using the code, the wallet checks the selected server's `grant_types_supported` against the grant. Strict mode refuses a mismatch stated in the metadata. Debug mode warns and switches to the first advertised server whose metadata lists the grant. If no server lists it, the wallet keeps the selected server |
| Credential Issuer metadata publication | Implemented | The wallet serves `/.well-known/openid-credential-issuer` as `application/json` by default and as `application/jwt` when the `Accept` header ranks it above `application/json` (§12.2.2). The JWT is signed with the access certificate key. Both forms include `issuer_info` with the registrar dataset and a registration certificate signed by the registrar. The dataset and the certificate name the provider by the access certificate's `organizationIdentifier` (ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-10) |
| Registrar-style issuer authorization data | Implemented | The wallet serves the TS05 v1.5 registry API at `/api/registrar/wrp`. The demo issuer is registered there like any relying party, with the `entitlements` of its credential categories and `providesAttestations` entries of `format` and `type` |
| Provider registration status and revocation | Implemented | Registration certificates carry a status list entry, and the registrar revokes them through its status list. See [registrar](wallet/registrar.md#revocation) |
| Wallet HTTPS certificate verification | Implemented | Strict mode checks the chain, hostname and validity dates for all destinations and redirects (OpenID4VP 1.0 Final §14.6). Debug skips verification by default. `--tls-verify` overrides either mode. `--tls-ca` adds CA certificates to system trust |
| HTTPS JWT VC issuer metadata publication | Implemented | The wallet serves `/.well-known/jwt-vc-issuer` with JWKS for wallet-issued SD-JWTs |

## OID4VCI 1.1 draft (selected with `--vci-version 1.1`)

These features are active only with `--vci-version 1.1` and only when the issuer's metadata advertises them.

1.1 is an editor's draft. The wallet implements the revision of 4 August 2026 and `draft-ietf-oauth-first-party-apps-04`, which §6 profiles.

| Feature | Status | Notes |
|---------|--------|-------|
| Interactive Authorization (§6) | Implemented | Used when the authorization server publishes `authorization_challenge_endpoint` (§13.3). It replaces the redirect flow of §5 and needs no `--vci-redirect-uri`. At feature level 1.0, the activity log shows the flag that enables it |
| Authorization Challenge Request (§6.1) | Implemented | The initial request carries `interaction_types_supported`, PKCE S256, the credential scope and the offer's `issuer_state`. Later requests carry `auth_session`, read again from every response (§5.3.1 of the first-party-apps specification: clients "MUST NOT assume that auth_session values are static"). The code arrives in `authorization_code`. The token request for it omits `redirect_uri` (first-party-apps §6). For a code from the auth_via_web browser redirect, the token request repeats the redirect URI, as RFC 6749 §4.1.3 requires |
| Presentation interaction (§6.2.1.1) | Implemented | The wallet advertises only interactions that it can complete (§6.2.1). The wallet accepts a signed or unsigned `openid4vp_request`. `response_mode` must be `ia_post` or `ia_post.jwt`. The wallet sends the response as `openid4vp_response` in the next challenge request. If no credential matches, it answers with an OpenID4VP error |
| Presentation binding, SD-JWT VC (Appendix A.3.5) | Implemented, with a caveat | The Key Binding JWT `aud` is the Authorization Challenge Endpoint prefixed with `ia:`. Only A.3.5 says "the derived **Origin** ... of the Authorization Challenge Endpoint". A.1.1.5 (JWT VC), A.1.2.5 (Data Integrity) and A.2.5 (mdoc) bind the endpoint itself. §6.2.1.5 describes "binding the Authorization Challenge Endpoint to the Verifiable Presentation". A.3.5's own example also uses the endpoint. So the wallet sends the endpoint. A verifier that reads A.3.5 literally computes `ia:https://host` and refuses the presentation |
| Presentation binding, mdoc (Appendix A.2.5) | Implemented | `OpenID4VCIIAEHandover` over the challenge endpoint, the nonce and (for `ia_post.jwt` only) the encryption key thumbprint. Checked against the worked example in the appendix |
| `expected_origins` check (§6.2.1.1, §6.2.1.5) | Enforced | When present, it must contain only the derived origin of the challenge endpoint, compared exactly. This detects a request forwarded from another authorization server. Unsigned requests are checked too, because no platform reports the caller origin here. Strict mode refuses any other value. Debug mode warns and continues |
| `auth_session` beyond one issuance | Deliberate deviation | Section 5.3.1 of the first-party-apps specification says a client "MUST store the auth_session beyond the issuance of the authorization code to be able to use it in future requests". The wallet keeps it for one exchange only. A stored session would let an authorization server correlate later issuances. Dropping it costs at most one more interaction |
| The `presentation_during_issuance_session` extension | Not implemented | A community extension outside the OpenID4VCI drafts. The challenge endpoint responds with HTTP 400 and a `presentation` member that carries an `openid4vp://` request URI, without `interaction_type_required`. The extension expects the presentation at the verifier's own `response_uri`. These response fields distinguish it from the §6 flow. The wallet aborts and reports the missing member (§6.2.1) |
| Authorization via web (§6.2.1.2) | Implemented | The wallet advertises `urn:openid:dcp:ia:auth_via_web` when a redirect URI is configured and the server publishes an `authorization_endpoint`. It turns the response's `request_uri` into an authorization request (RFC 9126 §4) and passes the sign-in URL to the user's browser. The redirect back carries either a `code` or an `auth_session` that continues the challenge exchange. The token request repeats the redirect URI for a code obtained this way (RFC 6749 §4.1.3) and omits it for one from the challenge endpoint (first-party-apps §6). The wallet refuses a server that requests an interaction that the wallet did not advertise |
| Custom interaction types (§6.2.1.3) | Not implemented | An unsupported `interaction_type_required` aborts the issuance (§6.2.1) |

## HAIP 1.0 (High Assurance Interoperability Profile)

`--haip` enables the checks below. Strict mode rejects violations. Debug mode logs them and continues. If a verifier offers only one supported AES content encryption algorithm, the wallet issues an advisory in either mode.

| Feature | Status | Notes |
|---------|--------|-------|
| VP `response_type` | Enforced | §5: "The Response type MUST be vp_token" |
| VP response modes | Enforced | Only `direct_post.jwt` (§5.1) and `dc_api.jwt` (§5.2) |
| VP Client Identifier Prefix | Enforced | §5 allows only `x509_hash` for signed requests, so `x509_san_dns:` is refused |
| VP request signature | Enforced | The Request Object signature is verified, and the `x509_hash` value must be the SHA-256 of the certificate that signed it |
| VP signing certificate rules | Enforced | §5: the certificate signing the request must not be self-signed, and the trust anchor must not be in the `x5c` header |
| VP signed request object (JAR) | Enforced | §5.1 requires JAR with the `request_uri` parameter, so an inline request object over redirects is refused. Unsigned requests are accepted only over the Digital Credentials API, where §5.2 requires them and they carry no `client_id` |
| VP DCQL query | Enforced | §5: "The DCQL query and response MUST be used as defined in Section 6 of [OIDF.OID4VP]" |
| VP credential formats | Enforced | `mso_mdoc` (§5.3.1) or `dc+sd-jwt` (§5.3.2). Any other format identifier in the query is refused |
| VP Verifier response encryption metadata | Advisory | §5 requires both `A128GCM` and `A256GCM`. If the Verifier offers only one and the wallet can use it, the wallet warns in either mode |
| VP `expected_origins` | Enforced | A signed Digital Credentials API request must list the caller origin (OpenID4VP Appendix A.2, which §5.2 incorporates) |
| VP Request Object `alg` | Enforced | `ES256`. §7 sets it as the minimum, and the wallet advertises it in `request_object_signing_alg_values_supported` |
| DPoP proof shape | Implemented | `htm` and `htu` per RFC 9449 §4.2. `htu` is the target URI "without query and fragment parts". A proof sent with an access token carries `ath` (the SHA-256 of the token). Each proof has a fresh `jti`. When the server asks for a `DPoP-Nonce`, the wallet echoes it and retries once |
| VCI authorization code profile requirements | Enforced | The client uses PAR, PKCE S256 and DPoP. An offer that uses the authorization endpoint is rejected unless the authorization server supports the authorization code flow and offers a pushed authorization request endpoint (or an `authorization_challenge_endpoint`, since interactive authorization sends no pushed request). It is also rejected when the server advertises PKCE without `S256` or DPoP without `ES256`. Metadata that omits PKCE, DPoP and client authentication passes, because §4 defers those to FAPI 2.0. FAPI 2.0 constrains behaviour only. For a pre-authorized code offer, only the https transport rule applies (§4) |
| VCI encrypted credential responses | Implemented | Requests `credential_response_encryption` and decrypts returned compact JWEs |
| VCI received credential | Enforced | §6.1.1: an SD-JWT VC carries the issuer's signing certificate and its chain in `x5c`, without the trust anchor, and the signing certificate is not self-signed. The wallet checks every received credential, on every issuance flow and for every copy of a batch |

The OIDF HAIP wallet conformance plans test these rules.

## SD-JWT (Selective Disclosure JWT)

Selective disclosure is RFC 9901. The credential profile on top of it is `draft-ietf-oauth-sd-jwt-vc-19`.

| Feature | Status | Notes |
|---------|--------|-------|
| Parsing (header, payload, disclosures) | Implemented | |
| RFC 9901 §7.1 verification and processing | Enforced | Parsing applies all of §7.1 and refuses a credential that violates any of its MUST-reject conditions (a disclosure named `_sd` or `...`, a disclosure whose claim name already exists at the level of its `_sd` key, a disclosure whose element count does not match the position of its digest, a digest that appears twice, a disclosure not referenced by any digest) |
| `_sd` claim resolution | Implemented | Recursive. `_sd` must hold an array of strings (§4.2.4.1) |
| Array disclosures | Implemented | A `{"...": digest}` element must carry that one key and nothing else (§4.2.4.2). An element whose digest has no disclosure is removed (§7.1 step 3.d) |
| `_sd_alg` handling | Implemented | Compared case-sensitively, defaults to `sha-256`, and refused in any object nested within the payload (§4.1.1) |
| Key Binding JWT | Implemented | Generated during presentation |
| Signature verification (ES256/384/512) | Implemented | |
| Signature verification (RS256/384/512, PS256) | Implemented | |
| SHA-256/384/512 disclosure digests | Implemented | |
| Disclosure digest integrity check | Implemented | Checks that each disclosure hash appears in an `_sd` array |
| `kid` header on generated SD-JWTs | Implemented | Deterministic RFC 7638 thumbprint of the signing key |
| X.509 trust-chain based issuer key publication | Implemented | Generated SD-JWTs carry the leaf and intermediate certificates in `x5c` and omit the root. Wallet trusted lists publish the service certificates and provider CAs |
| SD-JWT VC `typ` header | Implemented | Generated credentials carry `dc+sd-jwt`. The parser also accepts `vc+sd-jwt` and reports it as a deviation. Strict mode refuses it |
| Credentials with no selectively disclosable claims | Implemented | `_sd` is omitted from the payload and the serialization ends in a single tilde (SD-JWT VC §2.2.2.5 and RFC 9901 §4) |
| Registered claims that cannot be selectively disclosed | Enforced | `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` and `status` are embedded plainly in generated credentials (SD-JWT VC §2.2.2.3). `iat` is plain too because the generator sets it |
| `aka_vcts` claim | Implemented | Read when matching a credential against a requested type (§2.2.2.2). Written into issued credentials whose type extends another. Never treated as evidence of issuer authorization (§6.6) |
| Type Metadata `extends` | Not implemented | The relationship is resolved from PID_14 for PID types and from `aka_vcts` for any type. EUDI PID `vct` values are URNs, and §4.4 does not cover URNs. The ARF only asks a Scheme Provider to "consider defining" a Type Metadata Document (Annex 2 v3.0.0, ARB_31) |
| JWT VC Issuer Metadata key resolution | Implemented | `/.well-known/jwt-vc-issuer` is inserted between the host and the path of `iss` (SD-JWT VC §3), so a tenant-scoped issuer resolves. The document must contain `issuer` identical to `iss` and either `jwks` or `jwks_uri`, never both (§3.2 and §3.3) |

## mdoc / ISO 18013-5

| Feature | Status | Notes |
|---------|--------|-------|
| IssuerSigned CBOR parsing | Implemented | |
| DeviceResponse generation | Implemented | |
| COSE_Sign1 verification | Implemented | ES256/384/512, PS256 |
| MSO (Mobile Security Object) parsing | Implemented | |
| Validity info (validFrom, validUntil) | Implemented | |
| IssuerSignedItem digest verification | Implemented | |
| Session transcript (OID4VP mode) | Implemented | Default |
| Session transcript (ISO 18013-7 mode) | Implemented | `--session-transcript iso` |
| DeviceSigned generation | Implemented | Wallet generates DeviceAuth in DeviceResponse |

## ETSI TS 119 602 lists of trusted entities

| Feature | Status | Notes |
|---------|--------|-------|
| Trusted entity list JWT generation | Implemented | V1.1.1 JSON binding. The lists of the wallet are scheme explicit and carry every element of Table 1. The list of trusted lists is scheme implicit. One list per credential category: the PID list (Annex D), the PuB-EAA list (Annex H) and lists for QEAA and EAA providers with types of this project (`https://eudi-test.dev/LoTEType/QEAAProvidersList` and `EAAProvidersList`, Annex C.1 and §6.3.3). Also the wallet provider list (Annex E), the access certificate provider list (Annex F) and the registration certificate provider list (Annex G). Provider signing certificates, English text, postal addresses and retained list instances. The PuB-EAA list has no pointers (Table H.1). The other lists point to themselves. Updates advance the sequence number |
| List of trusted lists | Implemented | `/api/trustlists/lists` points to every list of the wallet and to added external lists, with the signer certificate and the qualifiers of §6.3.13 c). The wallet follows the pointers of an external list of trusted lists one level deep and authenticates each list with the certificate of its pointer |
| Trusted entity list JWT parsing | Implemented | Requires the ETSI JSON-binding `LoTE` wrapper. Accepts EUDI-style fields such as `ListIssueDateTime`. `validate` does not verify the signature (a debugging choice) |
| Trusted entity list signature verification | Implemented with `--arf` | The wallet verifies the JAdES signature of a fetched list (Annexes D.4 to H.4) and requires the signer to chain to the wallet CA or a `--trusted-list-ca` CA (ARF PPNot_05, TLPub_05, TLPub_07). A list past its next update anchors nothing (§6.3.15) |
| Certificate chain validation against trusted entity list | Implemented | In `validate` command |

The ETSI TS 119 612 XML trusted-list format is not implemented.

## Token Status List (`draft-ietf-oauth-status-list`)

The tracked revision is **draft-ietf-oauth-status-list-21** (editor's copy at <https://drafts.oauth.net/draft-ietf-oauth-status-list/draft-ietf-oauth-status-list.html>). Section numbers below refer to it.

| Feature | Status | Notes |
|---------|--------|-------|
| Status List Token generation (JWT) | Implemented | Available for generated wallet credentials (`--pid` or `--status-list`) |
| Status List Token generation (CWT) | Implemented | Served under `application/statuslist+cwt` when the client asks for it |
| Status List Token parsing (JWT and CWT) | Implemented | The wallet reads both media types. It asks for the format of the credential first: JWT for an SD-JWT VC or a registration certificate, CWT for an mdoc. The other one follows with `q=0.5` (Section 8.1 uses RFC 9110 content negotiation) |
| Content negotiation on the status list endpoint | Implemented | Section 8.1. JWT is the default |
| CORS on the status list endpoint | Implemented | Section 8.1 (browser-based clients) |
| Historical resolution (the `time` query parameter) | Not implemented | The endpoint answers 501 (section 8.4) |
| Status List Token validation rules (section 8.3) | Implemented | Signature, `typ`, `sub` against the credential's `uri`, `iat`, `exp`, `bits`, index bounds. A token that fails any of them yields no status |
| Status List Token signature verification | Implemented | Always performed. The key comes from the trusted list chain, a caller-supplied key, `x5c`/`x5chain`, or the token's own `jwk`. A key without a trust anchor is reported as unanchored |
| Status Types (section 7.1) | Implemented | Reported by name (VALID, INVALID, SUSPENDED, application specific, unknown) |
| Revocation status check | Implemented | In `validate` and the validate UI when a status reference is present |
| Runtime status changes via API | Implemented | `POST /api/credentials/<id>/status`. Accepts any Status Type value from 0 to 255. The published list widens to 1, 2, 4 or 8 bits to hold the value |
| Status List Aggregation (section 9) | Not implemented | |
| Appendix C test vectors | Verified | A table test in `internal/statuslist` covers the 1, 2, 4 and 8-bit vectors |
