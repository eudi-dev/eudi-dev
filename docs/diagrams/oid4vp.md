# OID4VP flows

This page shows the OID4VP presentation flows implemented by the `eudi-dev` wallet.

## Flow map

```mermaid
sequenceDiagram
    actor Browser
    participant RP as Verifier
    participant Wallet as eudi-dev

    RP-->>Browser: Presentation request
    Browser->>Wallet: Open URI request or trigger Browser API request
    opt request object is by reference
        Wallet->>RP: Fetch request_uri
    end
    Wallet->>Wallet: Parse request and validate client_id / request object
    Wallet->>Wallet: Evaluate dcql_query
    Wallet->>Wallet: Build vp_token and optional id_token
    alt response_mode = direct_post
        Wallet->>RP: direct_post
    else response_mode = direct_post.jwt
        Wallet->>RP: encrypted direct_post.jwt
    else response_mode = fragment
        Wallet-->>Browser: redirect_uri with fragment payload
    else response_mode = dc_api
        Wallet-->>Browser: Browser API plain response
    else response_mode = dc_api.jwt
        Wallet-->>Browser: Browser API encrypted response
    end
```

## Common request fields

| Field / setting | Why it matters in `eudi-dev` |
|-----------------|--------------------------------|
| `client_id` | Required except in an unsigned Digital Credentials API request. That request carries no `client_id` (OpenID4VP Appendix A.2). The wallet validates the Client Identifier Prefix (see the prefix table below). |
| `response_type` | Supports `vp_token`, `vp_token id_token`, and `id_token`. |
| `response_mode` | Selects the response branch: `direct_post`, `direct_post.jwt`, `fragment`, `dc_api`, or `dc_api.jwt`. |
| `nonce` | Bound into SD-JWT key binding JWTs and self-issued `id_token`s. |
| `state` | Reflected in the authorization response when present. |
| `response_uri` | Required for `direct_post` and `direct_post.jwt`. |
| `redirect_uri` | Used for `fragment`. When absent, the wallet uses `response_uri`. |
| `dcql_query` | The query matched against the stored credentials. |
| `request` or `request_uri` | A request object sent directly or by reference. |
| `client_metadata` | Controls format negotiation. Mandatory for encrypted response modes, because `client_metadata.jwks` carries the verifier encryption key. |

## URI-based presentation flow

```mermaid
sequenceDiagram
    actor Browser
    participant RP as Verifier
    participant Wallet as eudi-dev

    RP-->>Browser: Authorization request URI or link
    Browser->>Wallet: Open openid4vp://, haip-vp://, eudi-openid4vp:// or eu-eaap:// request
    Wallet->>RP: Fetch request_uri if present
    Wallet->>Wallet: Validate client_id and request object
    Wallet->>Wallet: Evaluate dcql_query against stored credentials
    opt response_type contains id_token
        Wallet->>Wallet: Create self-issued id_token
    end
    opt response_type contains vp_token
        Wallet->>Wallet: Create vp_token from selected credentials
    end
    alt response_mode = direct_post
        Wallet->>RP: POST optional vp_token, optional id_token, state
    else response_mode = direct_post.jwt
        Wallet->>RP: POST encrypted response JWT
    else response_mode = fragment
        Wallet-->>Browser: redirect_uri#vp_token=...&state=...
    end
```

### Relevant parameters

| Field / setting | Used how |
|-----------------|----------|
| `response_type=vp_token` | Standard VP-only flow. |
| `response_type=vp_token id_token` | The wallet returns both. |
| `response_type=id_token` | SIOPv2-only branch without a VP token. |
| `response_mode=direct_post` | Wallet posts a form with plain `vp_token`, optional `id_token`, and `state`. |
| `response_mode=direct_post.jwt` | Wallet requires a verifier encryption key in `client_metadata.jwks` and posts an encrypted response JWT. |
| `response_mode=fragment` | Wallet builds a redirect URL using `redirect_uri`. |
| `--auto-accept` | Skips the consent UI and submits one credential per credential query (the most recently issued match), or all matching ones when the query sets `multiple: true`. |
| `--preferred-format ...` | `dc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json`. Prefers that format when more than one stored credential satisfies the same query. |
| `--session-transcript ...` | `oid4vp` or `iso`. Selects how the mdoc session transcript is built. |

## `request_uri_method=post` and encrypted request objects

```mermaid
sequenceDiagram
    participant Verifier
    participant Wallet as eudi-dev

    Verifier-->>Wallet: Authorization request with request_uri and request_uri_method=post
    Wallet->>Verifier: POST request_uri<br/>wallet_metadata (always sends an encryption JWK) + wallet_nonce
    alt Verifier encrypts the request object
        Verifier-->>Wallet: Encrypted request object JWE
        Wallet->>Wallet: Decrypt JWE and continue with normal request validation
    else Verifier sends it unencrypted
        Verifier-->>Wallet: Signed or unsecured request object JWT
        Note over Wallet: Accepted (rejected only under --require-encrypted-request)
    end
    Wallet->>Wallet: Check wallet_nonce if the verifier echoed it back
```

### Relevant parameters

| Field / setting | Used how |
|-----------------|----------|
| `request_uri` | The wallet fetches the request object from this URI. |
| `request_uri_method=post` | Switches the request-object fetch from GET to POST. |
| `wallet_metadata` | Sent by the wallet. Includes supported formats, the Request Object signing algorithms (only when the client identifier prefix permits a signed Request Object), the Authorization Response encryption algorithms, and an encryption JWK. |
| `wallet_nonce` | Sent by the wallet for replay protection and checked if returned inside the request object. |
| `--require-encrypted-request` | Rejects a POSTed `request_uri` response that is not a compact JWE. The encryption JWK is sent either way. |
| Request object `Content-Type` | The wallet expects `application/oauth-authz-req+jwt` on the POST response. |

## Browser API flow

```mermaid
sequenceDiagram
    actor Browser
    participant RP as Verifier page in the browser
    participant Wallet as eudi-dev

    Browser->>RP: Trigger digital credentials request
    RP->>Wallet: Browser API request envelope
    Wallet->>Wallet: Parse signed or unsigned browser request
    Wallet->>Wallet: Validate caller origin, client identifier and request object
    Wallet->>Wallet: Evaluate dcql_query and build response
    alt response_mode = dc_api
        Wallet-->>RP: Plain Browser API response object
    else response_mode = dc_api.jwt
        Wallet-->>RP: Encrypted Browser API response JWT
    end
```

### Relevant parameters

| Field / setting | Used how |
|-----------------|----------|
| Browser API protocol `openid4vp-v1-unsigned` | Unsigned Browser API request branch. |
| Browser API protocol `openid4vp-v1-signed` | Signed Browser API request branch. Request data can be a compact JWT or an object containing `request` or `request_uri`. |
| Browser API protocol `openid4vp-v1-multisigned` | Multi-signed Browser API request branch. The wallet takes the first verifiable signature, or else the first one that parses. |
| `response_mode=dc_api` | Wallet returns plain JSON through the Browser API response envelope. |
| `response_mode=dc_api.jwt` | Wallet encrypts the response and returns a `response` JWT in the Browser API envelope. |
| Unsigned Browser API request | Carries no `client_id` (OpenID4VP Appendix A.2). The verifier is identified by the origin reported by the platform. Any `client_id` or `expected_origins` in the request data is discarded. |

## Client identifier prefixes and policy switches

| Item | Behavior in `eudi-dev` |
|------|---------------------------|
| `x509_hash:` | Implemented and verified. |
| `x509_san_dns:` | Implemented and verified against the verifier certificate SAN. |
| `redirect_uri:` | Implemented. Requires unsigned request objects and must match `response_uri`. |
| `verifier_attestation:` | Attestation claims and both signatures are checked. The attestation issuer is reported as not anchored. |
| `decentralized_identifier:` | DID syntax and the `kid` cross-check are validated. The signing key is reported as unresolved (ADR-0013). |
| No prefix (no `:` in the value) | Treated as a pre-registered client (OpenID4VP §5.9.2). The wallet registers no clients, so a signed request object under it is reported as not verified. |
| `origin:` | Refused. §5.9.3 reserves it and forbids a wallet to accept it in a request. |
| `openid_federation:` | Refused. Trust chain resolution is outside the supported EUDI stack (ADR-0013). |
| `--haip` | Requires HAIP 1.0 from the verifier: `response_type=vp_token`, encrypted response modes, the `x509_hash` prefix with a verified request signature and certificate rules, a signed request object through `request_uri`, DCQL and a P-256 response encryption key. A verifier that lists only one of `A128GCM` and `A256GCM` gets a warning. The wallet mode decides what happens on a violation. `strict` refuses the request. `debug` reports it and continues. |
| Wallet mode `debug` vs `strict` | Both collect request findings. `debug` reports them, keeps partially matching DCQL credentials and continues. `strict` refuses the request on the same findings. |
