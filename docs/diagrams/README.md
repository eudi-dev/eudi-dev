# Flow diagrams

These Mermaid diagrams show how `eudi-dev` interacts with issuers and verifiers. Each page also lists the request parameters and wallet flags that affect the flow.

## Pages

| Page | Scope |
|------|-------|
| [OID4VP flows](./oid4vp.md) | Presentation request variants, response modes, Browser API, and request-object handling |
| [OID4VCI flows](./oid4vci.md) | Credential offer variants, grant flows, and the credential request branches |

## Whole interaction

```mermaid
sequenceDiagram
    actor Browser as Browser / calling app
    participant Issuer
    participant AS as Authorization Server
    participant Wallet as eudi-dev
    participant RP as Verifier

    Issuer-->>Browser: credential_offer or credential_offer_uri
    Browser->>Wallet: eu-eaa-offer://, openid-credential-offer:// or haip-vci://
    Wallet->>AS: token request
    Wallet->>Issuer: credential request
    Issuer-->>Wallet: credential

    RP-->>Browser: authorization request or Browser API request
    Browser->>Wallet: openid4vp:// / haip-vp:// / eudi-openid4vp:// / eu-eaap:// or dc_api*
    Wallet-->>RP: presentation response
```

## Supported flow map

```mermaid
sequenceDiagram
    actor Browser
    participant Wallet as eudi-dev
    participant Issuer
    participant AS as Authorization Server
    participant RP as Verifier

    Note over Browser,AS: OID4VCI branch
    Browser->>Wallet: receive and open credential offer
    alt pre-authorized code
        Wallet->>AS: token request with pre-authorized_code
    else authorization code
        Wallet->>AS: PAR, authorization, token request
    else authorization challenge endpoint published (1.1)
        Wallet->>AS: challenge request, answered by a presentation or a browser sign-in, then token request
    end
    Wallet->>Issuer: credential request with proofs (jwt or attestation)
    opt transaction_id returned
        Wallet->>Issuer: deferred credential request
    end
    Issuer-->>Wallet: credential

    Note over Browser,RP: OID4VP branch
    Browser->>Wallet: open URI request or trigger Browser API request
    opt request_uri present
        Wallet->>RP: fetch request_uri
    end
    Wallet->>Wallet: evaluate dcql_query against stored credentials
    alt direct_post
        Wallet->>RP: direct_post response
    else direct_post.jwt
        Wallet->>RP: encrypted direct_post.jwt response
    else fragment
        Wallet-->>Browser: redirect URI with fragment response
    else dc_api / dc_api.jwt
        Wallet-->>Browser: Browser API response
    end
```

## Reading guide

- [OID4VCI flows](./oid4vci.md) shows how credentials get into the wallet.
- [OID4VP flows](./oid4vp.md) shows how the wallet selects and returns stored credentials.
- The parameter tables on each page list the request fields and wallet flags that change behavior.
