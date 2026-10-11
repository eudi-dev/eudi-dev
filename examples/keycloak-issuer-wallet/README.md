# Keycloak issuer + eudi-dev wallet

This example runs a local OpenID4VCI issuance flow from Keycloak into `eudi-dev`.

## Flow

1. `docker compose up -d --force-recreate` starts Keycloak `26.7.2`, enables OID4VCI, and imports `realm/oid4vc-demo-realm.json`.
2. `./scripts/bootstrap.sh` waits for the imported realm, assigns the `membership-credential` to `alice` through the admin API (Keycloak 26.7.2 creates an offer only for a credential already assigned to the user), and prints the issuer endpoints.
3. `./scripts/create-offer.sh` logs in as `alice`, calls Keycloak's `create-credential-offer` endpoint, resolves the generated offer once, and emits an inline `openid-credential-offer://?credential_offer=...` URI.
4. `eudi wallet accept` resolves the offer URI, fetches issuer metadata and authorization details from Keycloak, creates proof-of-possession material, and stores the returned SD-JWT VC in the local wallet directory.

## Flow diagram

```mermaid
sequenceDiagram
    participant U as User
    participant KC as Keycloak 26.7.2
    participant W as eudi wallet

    U->>KC: import static realm, user, client, credential scope
    U->>KC: assign membership-credential to alice (admin API)
    U->>KC: password grant as alice
    KC-->>U: access token
    U->>KC: GET /protocol/oid4vc/create-credential-offer
    KC-->>U: issuer + nonce
    U->>W: wallet accept openid-credential-offer://...
    W->>KC: fetch issuer metadata
    W->>KC: redeem pre-authorized offer and submit proof
    KC-->>W: dc+sd-jwt credential
    W-->>U: credential stored in ~/.eudi-dev/wallet
```

## Files

- `start.sh`: starts Keycloak, bootstraps the issuer, and by default redeems a credential into `eudi-dev`
- `docker-compose.yml`: starts Keycloak with OID4VCI enabled and imports the realm from `realm/`
- `realm/oid4vc-demo-realm.json`: the Keycloak realm config for the example
- `scripts/bootstrap.sh`: waits for the imported realm, assigns the credential to `alice`, and prints the issuer endpoints
- `scripts/create-offer.sh`: creates a fresh pre-authorized offer URI
- `scripts/redeem-offer.sh`: creates an offer and passes it into `eudi-dev`

## Quick start

```bash
cd examples/keycloak-issuer-wallet
./start.sh
eudi wallet list
```

If `eudi-dev` is not already installed, `start.sh` installs the latest release with `go install github.com/dominikschlosser/eudi-dev/v3@latest`.

Setup only:

```bash
./start.sh --setup-only
```

Manual flow:

```bash
OFFER_URI=$(./scripts/create-offer.sh)
eudi wallet accept "$OFFER_URI"
```

Public Keycloak through ngrok:

```bash
./start.sh --public                      # ngrok picks the hostname
./start.sh --public --domain kc.example.ngrok.app
```

`--public` publishes Keycloak through an ngrok tunnel and uses its https URL as the Keycloak base URL. It needs the [ngrok CLI](https://ngrok.com/download). `--domain` sets a reserved ngrok hostname (`KEYCLOAK_NGROK_DOMAIN` or `NGROK_DOMAIN` work too). A sandbox certificate (`EXAMPLES_SANDBOX_PEM`, `SANDBOX_PEM` or `SANDBOX_DIR`) overrides the hostname with its subject alternative name.

## Parameters

### Keycloak

| Parameter | Value |
|---|---|
| Image | `quay.io/keycloak/keycloak:26.7.2` |
| Startup flags | `start-dev`, `--features=oid4vc-vci:v1,oid4vc-vci-preauth-code:v1,oid4vc-vci-rest-credential-offer`, `--http-port=8080`, `--proxy-headers=xforwarded` |
| Realm | `oid4vc-demo` |
| Admin user | `admin` / `admin` |
| Demo user | `alice` / `alice` |
| OIDC client | `oid4vc-demo-client` |
| Client type | public client |
| Client attributes | `oid4vci.enabled=true`, `pkce.code.challenge.method=S256` |
| Redirect URIs | `*` |
| Credential configuration ID | `membership-credential` |
| Credential format | `dc+sd-jwt` |
| `vct` | `https://credentials.example.com/membership` |
| Signing algorithm | `ES256` |
| Binding requirement | `vc.binding_required=true` |
| Proof types | `vc.binding_required_proof_types=jwt` |
| Binding methods | `vc.cryptographic_binding_methods_supported=jwk` |
| Claims | `given_name`, `family_name`, `email`, `jti`, `iat` |
| Offer endpoint | `/realms/oid4vc-demo/protocol/oid4vc/create-credential-offer` |
| Issuer metadata | `/realms/oid4vc-demo/.well-known/openid-credential-issuer` |

### eudi-dev

| Parameter | Value |
|---|---|
| Wallet directory | `~/.eudi-dev/wallet` |
| Input | `openid-credential-offer://?credential_offer=...` |

### Inline `credential_offer`

This example uses the OpenID4VCI by-value `credential_offer` form.

- Some wallets dereference `credential_offer_uri` more than once across preview and issuance steps.
- Keycloak serves an offer URI once for this flow, so the second fetch fails.
- The example resolves the offer once and passes the inline JSON to the wallet.
- The demo realm also omits `vc.credential_identifier`, so wallets that request credentials by `credential_configuration_id` work. With that attribute set, Keycloak 26.7.2 requires a `credential_identifier` field on the credential request.

## Useful overrides

```bash
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=oid4vc-demo
OID4VCI_CLIENT_ID=oid4vc-demo-client
OID4VCI_CREDENTIAL_SCOPE=membership-credential
OID4VCI_USER=alice
OID4VCI_USER_PASSWORD=alice
```

## Cleanup

```bash
docker compose down -v
eudi wallet remove --all
```
