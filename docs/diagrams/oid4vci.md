# OID4VCI flows

This page shows the OID4VCI flows implemented by the `eudi-dev` wallet for a received credential offer.

## Flow map

```mermaid
sequenceDiagram
    actor Browser
    participant Wallet as eudi-dev
    participant Issuer
    participant AS as Authorization Server

    Browser->>Wallet: Open credential offer
    Wallet->>Issuer: Fetch issuer metadata
    alt Offer uses pre-authorized code
        Wallet->>AS: Token request with pre-authorized_code and optional tx_code
    else Offer uses authorization code
        Wallet->>AS: PAR request
        Wallet->>AS: Authorization request via request_uri
        Wallet->>AS: Token request with code + PKCE
    end
    Wallet->>Issuer: Credential request with proofs (jwt or attestation)
    opt transaction_id returned
        Wallet->>Issuer: Deferred credential request
    end
    Issuer-->>Wallet: Credential
    Wallet->>Wallet: Import credential
```

## Common inputs

| Field / setting | Role in `eudi-dev` |
|-----------------|--------------------------------|
| `credential_offer` or `credential_offer_uri` | One of these starts the issuance flow. |
| `credential_issuer` | Used to fetch `/.well-known/openid-credential-issuer` and resolve the token and credential endpoints. |
| `credential_configuration_ids` | The wallet requests one configuration: the one picked in the consent dialog or sent as `credential_configuration_id`, otherwise the first. It resolves the format and, in the authorization code flow, the scope. |
| Issuer metadata `nonce_endpoint` | Provides the challenge signed by the key proof (OpenID4VCI 1.0 §8.2). The wallet calls it whenever the metadata advertises it. |
| `authorization_details[].credential_identifiers` | When present in the token response, the wallet sends `credential_identifier` at the credential endpoint instead of `credential_configuration_id`. |
| Issuer metadata `credential_response_encryption` support | When advertised, the wallet requests encrypted credential responses and decrypts compact JWE responses. |

## Pre-authorized code flow

```mermaid
sequenceDiagram
    actor Browser
    participant Wallet as eudi-dev
    participant AS as Authorization Server
    participant Issuer

    Browser->>Wallet: Open credential offer URI
    Wallet->>Issuer: Fetch issuer metadata
    Wallet->>AS: POST token request<br/>grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
    Note over Wallet,AS: Optional tx_code is included when the wallet was given one.
    AS-->>Wallet: access_token,<br/>optional authorization_details
    Wallet->>Issuer: POST nonce request
    Issuer-->>Wallet: c_nonce
    Wallet->>Issuer: POST credential request with proofs (jwt or attestation)
    alt Deferred issuance
        Issuer-->>Wallet: transaction_id
        Wallet->>Issuer: POST deferred credential request
        Issuer-->>Wallet: credential
    else Encrypted credential response
        Issuer-->>Wallet: compact JWE credential response
        Wallet->>Wallet: decrypt response
    else Plain credential response
        Issuer-->>Wallet: credential
    end
    Wallet->>Wallet: import credential
    opt Notification callback
        Wallet->>Issuer: POST notification_endpoint with notification_id
    end
```

### Relevant parameters

| Field / setting | Usage |
|-----------------|----------|
| `grants.urn:ietf:params:oauth:grant-type:pre-authorized_code.pre-authorized_code` | Selects the pre-authorized code branch. |
| `grants...tx_code` | Optional. When present, the issuer expects an out-of-band transaction code. Pass it with `wallet accept --tx-code ...`. |
| `access_token` | Authorizes the credential endpoint call. |
| `c_nonce` | Taken from the Nonce Endpoint. A `c_nonce` in the token response is a pre-1.0 parameter. Strict mode ignores it. Debug mode uses it when the issuer advertises no Nonce Endpoint, and reports the issuer as pre-1.0. When the issuer rejects the challenge with `invalid_nonce`, the wallet fetches a new one and retries once with rebuilt proofs (§8.3.1.2). |
| `proofs` | One proof type, chosen from the configuration's `proof_types_supported`. Either `jwt` proofs (one per batch key, or a single holder-key proof carrying the key attestation when one is required) or the key attestation itself as the `attestation` proof (Appendix F.1 and F.3). |
| `credential_identifier` vs `credential_configuration_id` | The wallet uses `credential_identifier` when the token response includes it. Otherwise the wallet uses the chosen `credential_configuration_id`. |

## Authorization code flow

```mermaid
sequenceDiagram
    actor Browser
    participant Wallet as eudi-dev
    participant Issuer
    participant AS as Authorization Server

    Browser->>Wallet: Open credential offer URI
    Wallet->>Issuer: Fetch issuer metadata
    Wallet->>AS: Fetch OAuth metadata
    Wallet->>AS: POST PAR request<br/>response_type=code, client_id, redirect_uri,<br/>scope, PKCE, optional issuer_state
    AS-->>Wallet: request_uri
    Wallet->>AS: Open authorization request<br/>client_id + request_uri + state
    AS-->>Wallet: redirect_uri?code=...&state=...
    Wallet->>AS: POST token request<br/>grant_type=authorization_code + code + PKCE
    AS-->>Wallet: access_token,<br/>optional authorization_details
    Wallet->>Issuer: POST nonce request
    Issuer-->>Wallet: c_nonce
    Wallet->>Issuer: POST credential request with proofs (jwt or attestation)
    alt Deferred issuance
        Issuer-->>Wallet: transaction_id
        Wallet->>Issuer: POST deferred credential request
        Issuer-->>Wallet: credential
    else Immediate issuance
        Issuer-->>Wallet: credential
    end
    Wallet->>Wallet: import credential
    opt Notification callback
        Wallet->>Issuer: POST notification_endpoint with notification_id
    end
```

### Relevant parameters

| Field / setting | Usage |
|-----------------|----------|
| `eudi wallet serve --vci-client-id ...` | Sets a fixed client ID. Without it, a flow with client attestation uses a random client ID and other flows use the wallet origin. |
| `eudi wallet serve --vci-redirect-uri ...` | Overrides the callback URL, which defaults to the wallet origin plus `/callback`. Interactive authorization (below) can run without a redirect. |
| OAuth metadata `pushed_authorization_request_endpoint` | Used when published (publishing it is a SHOULD in RFC 9126). Otherwise the request goes straight to the authorization endpoint. `--haip` requires PAR unless the server publishes an `authorization_challenge_endpoint`. |
| OAuth metadata `authorization_endpoint` | Required for the browser redirect. |
| OAuth metadata DPoP support | Optional. The wallet binds its tokens with DPoP when the metadata advertises it and uses bearer tokens otherwise. Under `--haip`, advertising DPoP without `ES256` is a violation. |
| `credential_configuration_ids` -> scope | The scope comes from the chosen credential configuration and goes into PAR. |
| `grants.authorization_code.issuer_state` | Forwarded into the PAR request when present. |
| `token_endpoint_auth_methods_supported` | The wallet supports `none`, `private_key_jwt`, `attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`. `client_secret_*` methods are rejected, since the wallet holds no client secret. |
| `transaction_id` + `deferred_credential_endpoint` | The wallet takes this branch after a deferred credential response. |
| `notification_id` + `notification_endpoint` | When both are present, the wallet sends a notification after a successful import. |

## Interactive Authorization (OpenID4VCI 1.1)

At feature level 1.1 (`--vci-version 1.1`), an authorization server that publishes `authorization_challenge_endpoint` triggers this flow instead of the browser redirect above. The wallet answers the challenge with an OpenID4VP presentation or sends the user to a browser sign-in (`auth_via_web`). After the authorization code, the ordinary token and credential exchange runs. See [interactive authorization](../wallet/issuing.md#interactive-authorization).

```mermaid
sequenceDiagram
    actor Browser
    participant Wallet as eudi-dev
    participant AS as Authorization Server

    Browser->>Wallet: Open credential offer URI
    Wallet->>AS: POST challenge request<br/>response_type=code, interaction_types_supported
    AS-->>Wallet: 403 insufficient_authorization<br/>interaction_type_required, auth_session
    alt Presentation interaction (openid4vp_presentation)
        Note over Wallet: The user consents and the wallet builds the vp_token
        Wallet->>AS: POST challenge request<br/>auth_session, openid4vp_response
        AS-->>Wallet: 200 authorization_code
    else Browser interaction (auth_via_web)
        Wallet->>Browser: Open the sign-in URL built from the returned request_uri
        Browser->>Wallet: Redirect back with the code, or auth_session for further challenges
    end
    Wallet->>AS: POST token request<br/>grant_type=authorization_code + code + PKCE
```

### Relevant parameters

| Field / setting | Usage |
|-----------------|----------|
| `eudi wallet serve --vci-version 1.1` | Selects the feature level. At `1.0` the redirect flow runs. |
| OAuth metadata `authorization_challenge_endpoint` | Publishing it switches an offer to this flow. |
| `interaction_types_supported` | The wallet always advertises `urn:openid:dcp:ia:openid4vp_presentation`, and `urn:openid:dcp:ia:auth_via_web` only when an https redirect URI is configured and the metadata includes an `authorization_endpoint`. |
| `openid4vp_request` | The OpenID4VP request of the presentation interaction, with response mode `ia_post` or `ia_post.jwt`. |
| `auth_session` | Carries the authorization state across challenge requests and the browser redirect. |
