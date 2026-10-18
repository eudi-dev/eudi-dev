# Keycloak verifier + `keycloak-extension-oid4vp`

This example runs a local same-device OpenID4VP login against Keycloak using `eudi-dev` as the wallet.

## Flow

1. `./scripts/download-extension.sh` downloads `keycloak-extension-oid4vp` `0.11.1` into `providers/`.
2. `./scripts/generate-wallet.sh` prepares the standard `eudi-dev` wallet with PID credentials and a trusted list endpoint reachable from Docker as `http://host.docker.internal:8085`.
3. `docker compose up --force-recreate` starts Keycloak `26.7.2`, mounts `realm/wallet-demo-realm.json`, imports the realm on startup, and loads the OID4VP provider jar.
4. `./scripts/bootstrap.sh` waits for the imported realm and prints the endpoints.
5. `./scripts/login.py` starts the OIDC browser login, extracts the `openid4vp://` request, passes it to `eudi wallet accept --auto-accept --docker --port 8085`, follows the broker flow, and exchanges the returned code for tokens.

## Flow diagram

```mermaid
sequenceDiagram
    participant U as User
    participant KC as Keycloak 26.7.2
    participant EXT as keycloak-extension-oid4vp 0.11.1
    participant W as eudi wallet

    U->>W: issue sdjwt --wallet --pid --iss https://host.docker.internal:8086
    U->>KC: import static realm, client, OID4VP IdP
    U->>KC: start OIDC authorize request
    KC->>EXT: invoke oid4vp identity provider
    EXT-->>U: same-device login page with openid4vp:// request
    U->>W: wallet accept --auto-accept --docker --port 8085 openid4vp://... (headless script)
    W->>EXT: direct_post VP token
    EXT->>W: trusted list and issuer metadata verification
    EXT-->>KC: brokered identity
    KC-->>U: authorization code
    U->>KC: token request
    KC-->>U: ID token / access token
```

## Files

- `start.sh`: runs the full setup and by default executes the headless same-device verifier flow
- `docker-compose.yml`: starts Keycloak, mounts provider jars from `providers/`, and imports the realm from `realm/`
- `realm/wallet-demo-realm.json`: the Keycloak realm config for the example
- `scripts/download-extension.sh`: downloads `keycloak-extension-oid4vp` `0.11.1`
- `scripts/bootstrap.sh`: waits for the imported realm and prints the endpoints
- `scripts/generate-wallet.sh`: generates the wallet's PID credentials and exports the wallet CA
- `scripts/login.py`: runs the same-device flow end to end and exchanges the returned code
- `scripts/test-oidc-flow.sh`: starts a browser-driven flow for a system-registered `eudi-dev` wallet

## Quick start

```bash
cd examples/keycloak-verifier-oid4vp
./start.sh
```

If `eudi-dev` is not already installed, `start.sh` installs the latest release with `go install github.com/eudi-dev/eudi-dev/v3@latest`.

Browser-driven flow:

```bash
./start.sh --browser
```

`./start.sh --browser` runs `eudi wallet register` automatically. On macOS that installs the custom scheme handlers. On Linux and Windows it does nothing. When Keycloak shows the wallet page, copy the `openid4vp://...` link target and run:

```bash
eudi wallet accept '<openid4vp://...>'
```

Setup only:

```bash
./start.sh --setup-only
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
| Startup flags | `start-dev`, `--import-realm`, `--http-port=8080`, `--proxy-headers=xforwarded`, `--truststore-paths=/opt/keycloak/conf/oid4vc-wallet-ca.pem`, `--tls-hostname-verifier=ANY` |
| Mounted provider jar | `providers/keycloak-extension-oid4vp.jar` |
| Realm | `wallet-demo` |
| Admin user | `admin` / `admin` |
| OIDC client | `wallet-mock` |
| Redirect URIs | `*` |
| Client attributes | `pkce.code.challenge.method=S256` |

### `keycloak-extension-oid4vp`

| Parameter | Value |
|---|---|
| Version | `0.11.1` |
| Provider alias | `oid4vp` |
| `firstBrokerLoginFlowAlias` | `first broker login` |
| `sameDeviceEnabled` | `true` |
| `crossDeviceEnabled` | `false` |
| `walletScheme` | `openid4vp://` |
| `responseMode` | `direct_post` |
| `clientIdScheme` | `plain` |
| `principalAttributes` | `sdjwt_urn_eudi_pid_1:personal_administrative_number` |
| `trustMaterialIdps` | `demo-trust-list` |

The brokered Keycloak username comes from the PID `personal_administrative_number` (a stable identifier), because the ARF PID specimen family name (`'t Hart`) is not a valid Keycloak username.

The DCQL query is generated from the OID4VP mappers on the `oid4vp` provider. Each maps a claim of the `urn:eudi:pid:1` SD-JWT credential (id `sdjwt_urn_eudi_pid_1`) to a user attribute:

| Mapper claim | User attribute |
|---|---|
| `family_name` | `lastName` |
| `given_name` | `firstName` |
| `birthdate` | `birthdate` |

The extension adds the principal claim (`personal_administrative_number`) to the request, so the generated query asks the wallet for those four claims of `urn:eudi:pid:1` in `dc+sd-jwt`.

A separate provider holds the trust material. `trustMaterialIdps` references it:

| Parameter (`demo-trust-list`) | Value |
|---|---|
| `providerId` | `etsi-trust-list` |
| `trustListUrl` | `http://host.docker.internal:8085/api/trustlist` |
| `trustListLoTEType` | `http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList` |

### eudi-dev

| Parameter | Value |
|---|---|
| Wallet store | `~/.eudi-dev/wallet` |
| Wallet base URL during wallet generation | `http://host.docker.internal:8085` |
| Wallet port during presentation | `8085` |
| Trusted list endpoint on host | `http://localhost:8085/api/trustlist` |
| Trusted list endpoint from Docker | `http://host.docker.internal:8085/api/trustlist` |

## Useful overrides

```bash
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=wallet-demo
OIDC_CLIENT_ID=wallet-mock
OIDC_REDIRECT_URI=http://127.0.0.1:18080/callback
OID4VC_WALLET_PORT=8085
```

## Cleanup

```bash
docker compose down -v
eudi wallet remove --all
rm -f wallet-ca-cert.pem wallet-ca-key.pem
```
