# Docker Verifier Testing Guide

The Docker image is built for automated integration tests of OID4VP verifiers. The container runs an EUDI wallet that accepts presentation requests from your verifier.

## Quick start

```bash
docker pull ghcr.io/eudi-dev/eudi-dev:latest
docker run -p 8085:8085 -p 8086:8086 ghcr.io/eudi-dev/eudi-dev
```

The default command starts a headless wallet with PID credentials. It stores state in memory and derives keys from a fixed seed. Each start uses the same keys and CA without a volume (see [Storage](#storage)). Stopping the container discards credentials issued or imported during the run.

Override the command to use any CLI feature:

```bash
echo "eyJhbGci..." | docker run -i ghcr.io/eudi-dev/eudi-dev decode
docker run -i ghcr.io/eudi-dev/eudi-dev validate --trust-list https://example.com/trustlist.jwt < credential.txt
```

## Demo profile

The container also runs the demo profile of the public instance at [eudi-test.dev](https://eudi-test.dev):

```bash
docker run -d --name eudi-demo -p 8085:8085 -p 8086:8086 \
  -v wallet-data:/home/app/.eudi-dev -e EUDI_DEV_STORAGE=file -e EUDI_DEV_SEED= \
  ghcr.io/eudi-dev/eudi-dev:latest \
  wallet serve --demo --port 8085 --base-url http://localhost:8085
```

The demo persists its state in files on the volume and generates its own keys, so its CA stays private and stable across restarts.

`--demo` starts with four PID credentials, HAIP checks in debug mode and OpenID4VCI 1.1 support. It disables administrative operations and resets the wallet hourly. Change the schedule with `--demo-reset`.

Open the wallet at `http://localhost:8085`, the issuer at `/issuer/`, the verifier at `/verifier/` or the decoder at `/decoder/`. HTTPS issuer endpoints use port 8086 and a self-signed certificate.

For a full deployment (TLS termination, rate limiting, usage statistics, persistence), see the compose example in [examples/public-demo](../examples/public-demo/) and [public demo hosting](public-demo.md).

## Storage

The image defaults to `EUDI_DEV_STORAGE=memory` and `EUDI_DEV_SEED=eudi-dev`. It needs no volume, database or writable filesystem. With `--read-only`, the server runs and logs a warning because it cannot register the wallet instance.

To store state on a volume at `/home/app/.eudi-dev`, set `EUDI_DEV_STORAGE=file`.

Pass `-e EUDI_DEV_STORAGE=...` (or `--storage` on the command) to select another backend:

| Value | State lives in |
|-------|----------------|
| `memory` | The process. Lost when the container stops (the image default) |
| `file` | The wallet directory, on a volume mounted at `/home/app/.eudi-dev`. Set `EUDI_DEV_SEED=` as well, so a private CA persists |
| `auto` | Files when a state directory is mounted or configured, otherwise memory |
| `postgres://user:pass@host:5432/db` | Rows in `eudi_dev_state`, with a sequence for write versions. Created on first use |

`eudi wallet use http://localhost:8085` controls the container from the CLI through its HTTP API with any backend (see [remote control](wallet/http-api.md#remote-control)).

### Stateless container

Containers with the same `EUDI_DEV_SEED` derive the same holder, issuer, CA, TLS and role-specific signing keys. Verifiers can keep trusting the CA across restarts without persistent storage. A fresh memory store creates new certificates with unique serial numbers. Their keys and subjects stay the same. File and Postgres storage retain the certificates across restarts.

The image's seed `eudi-dev` is public, so anyone can derive those keys (see [SECURITY.md](../SECURITY.md)). The startup summary shows `Keys: derived from the built-in seed`, and `wallet serve` warns when that seed is used with `--demo` or a persistent backend (`file` or Postgres). Set your own value with `-e EUDI_DEV_SEED=<seed>` (or `--seed`) for a test bench, or an empty value for random keys. `auto` seeds the memory backend only and leaves every other backend with random keys.

```bash
docker run --read-only -p 8085:8085 -p 8086:8086 -e EUDI_DEV_SEED=my-bench ghcr.io/eudi-dev/eudi-dev
```

### Shared database

Containers using the same database and wallet prefix share credentials, keys and the CA. [examples/load-test](../examples/load-test/README.md) runs two wallet servers on one database behind an nginx ingress. It is the target for load and performance tests.

Each server checks revisions at request boundaries and reloads changed state. Saves update changed entities and their section revisions. Writes are atomic per row. Concurrent changes to the same entity can overwrite each other. Browser flows and demo requests stay in memory, so route each flow to the same server. See [the storage design](adr/0016-state-goes-through-one-storage-layer.md) for the schema and reload behavior.

The database stores private keys unencrypted, like the file backend (see [SECURITY.md](../SECURITY.md)). [ADR-0018](adr/0018-postgres-stores-wallet-entities-as-keyed-blobs.md) explains the choice of keyed blobs and its tradeoffs.

## Logs

Set `-e EUDI_DEV_LOG_FORMAT=json` to write one JSON record per line for a log collector (see [JSON logs](wallet/serve.md#json-logs)).

## How it works

1. The container starts with `--pid` (two preloaded EUDI PID credentials, one SD-JWT and one mdoc) and `--auto-accept` (presents matching credentials without user consent)
2. Your verifier sends an OID4VP authorization request to the wallet's `/authorize` endpoint
3. The wallet evaluates the DCQL query, finds matching credentials, creates a VP token, and POSTs it to your verifier's `response_uri`

## Wallet endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/authorize` | GET/POST | OID4VP authorization endpoint, accepting the standard OID4VP query parameters (`client_id`, `response_type`, `dcql_query`, `nonce`, `state`, `response_uri`, `response_mode`, `request_uri`) |
| `/api/trustlist` | GET | Legacy trust list endpoint. Returns the PID trust list when one is registered, otherwise the first available trust list profile |
| `/api/trustlists` | GET | JSON index of all trust list profiles registered in the wallet. Each entry includes a relative `path` plus optional `advertised_url` / legacy `url` |
| `/api/trustlists/<id>` | GET | ETSI trust list JWT for one trust list profile |
| `https://<wallet>:8086/.well-known/openid-credential-issuer` | GET | Issuer metadata with registrar data and a registration certificate in `issuer_info`. JSON by default, access-certificate-signed JWT when the request accepts only `application/jwt` |
| `https://<wallet>:8086/.well-known/jwt-vc-issuer` | GET | JWT VC issuer metadata for wallet-issued SD-JWTs. Exposes the signing key by `kid` and its certificate chain |
| `/api/registrar/wrp` | GET | Registrar-style signed dataset for provider entitlements and `providesAttestations`. Supports query filters such as `identifier`, `entitlement`, and `providesattestation` |
| `/api/credentials` | GET/POST | List all credentials / import a credential |
| `/api/credentials/<id>/status` | GET/POST | Resolve or set the revocation status for a credential |
| `/api/statuslist` | GET | Status List Token on both HTTP and HTTPS. JWT by default, CWT for a client sending `Accept: application/statuslist+cwt` (`--status-list` only controls whether generated credentials reference the list) |
| `/api/templates`, `/api/templates/<name>` | GET/PUT/DELETE | List and manage [credential templates](templates.md) |
| `/api/next-error` | POST/DELETE | Set or clear a one-shot error override |
| `/api/config/preferred-format` | PUT | Set credential format preference (`dc+sd-jwt` / `mso_mdoc` / `jwt_vc_json` / empty) |
| `/api/config` | GET | Instance introspection (PID baseline, directories, URLs, behavior) |
| `/api/shutdown` | POST | Stop the wallet server process |
| `/healthz` | GET | Liveness probe. Answers `200` while the server runs |
| `/readyz` | GET | Readiness probe. Answers `503` while the storage backend is unreachable |

The [HTTP API reference](wallet/http-api.md) also lists certificate retrieval, provider CRLs and trust list history endpoints. See [test certificates](test-certificates.md) for the EUDI profiles and known testing limits.

## Typical verifier integration test flow

1. Start the wallet container
2. Your verifier builds an OID4VP authorization request with a DCQL query for PID attributes
3. Send the request to `http://<wallet>/authorize?client_id=...&response_type=vp_token&response_mode=direct_post&response_uri=http://<your-verifier>/callback&nonce=...&dcql_query=...`
4. The wallet selects matching credentials and POSTs `vp_token` + `state` to your `response_uri`
5. Your verifier validates the VP token's signing chain against the wallet's trust list from `/api/trustlist`
6. For EUDI issuer authorization checks, resolve provider entitlements and attestation types from the signed `/.well-known/openid-credential-issuer` metadata and `/api/registrar/wrp`

Behind Docker port mappings or Testcontainers, resolve the relative `path` from `/api/trustlists` against the URL you used to reach the wallet. `advertised_url` is the wallet's configured issuer URL and can differ from that.

## Docker Compose example

```yaml
services:
  wallet:
    image: ghcr.io/eudi-dev/eudi-dev:latest
    ports:
      - "8085:8085"
      - "8086:8086"
  verifier:
    build: .
    environment:
      WALLET_URL: http://wallet:8085
      # Use the wallet's trust list to validate received VP tokens
      TRUST_LIST_URL: http://wallet:8085/api/trustlist
      # Use signed issuer metadata + registrar data for EUDI issuer authorization checks
      OPENID_CREDENTIAL_ISSUER_URL: https://wallet:8086/.well-known/openid-credential-issuer
      REGISTRAR_URL: https://wallet:8086/api/registrar/wrp
      # Optional: use the wallet's issuer metadata for SD-JWT key discovery
      ISSUER_METADATA_URL: https://wallet:8086/.well-known/jwt-vc-issuer
```

## Testcontainers (Java)

```java
GenericContainer<?> wallet = new GenericContainer<>("ghcr.io/eudi-dev/eudi-dev:latest")
    .withExposedPorts(8085)
    .waitingFor(Wait.forHttp("/api/trustlist").forStatusCode(200));
wallet.start();

String walletUrl = "http://" + wallet.getHost() + ":" + wallet.getMappedPort(8085);

// Send an OID4VP request to the wallet
String authorizeUrl = walletUrl + "/authorize"
    + "?client_id=" + URLEncoder.encode(verifierClientId, UTF_8)
    + "&response_type=vp_token"
    + "&response_mode=direct_post"
    + "&response_uri=" + URLEncoder.encode(callbackUrl, UTF_8)
    + "&nonce=" + nonce
    + "&dcql_query=" + URLEncoder.encode(dcqlQuery, UTF_8);

// The wallet will auto-accept and POST the VP token to your callbackUrl
httpClient.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
    HttpResponse.BodyHandlers.ofString());

// Validate received credentials using the wallet's trust list
String trustListUrl = walletUrl + "/api/trustlist";
```

## Testcontainers (Go)

```go
ctx := context.Background()
wallet, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
    ContainerRequest: testcontainers.ContainerRequest{
        Image:        "ghcr.io/eudi-dev/eudi-dev:latest",
        ExposedPorts: []string{"8085/tcp"},
        WaitingFor:   wait.ForHTTP("/api/trustlist").WithPort("8085"),
    },
    Started: true,
})

walletURL, _ := wallet.Endpoint(ctx, "http")
// Send OID4VP request to walletURL + "/authorize?..."
// Wallet POSTs VP token back to your response_uri
// Validate with trust list from walletURL + "/api/trustlist"
```

## Custom PID claims

The default CMD loads two EUDI PID credentials (SD-JWT + mdoc) with the EUDI PID Rulebook attributes (`given_name`, `family_name`, `birth_date`, `place_of_birth`, `nationality`, etc.). To customize them, mount a folder of [credential templates](templates.md) that overrides the predefined PID templates (or adds your own):

```bash
# my-templates/pid-sdjwt.json overrides the pre-defined PID template
docker run -p 8085:8085 -v ./my-templates:/templates ghcr.io/eudi-dev/eudi-dev \
  wallet serve --auto-accept --pid --port 8085 --templates-dir /templates
```

You can also generate customized PIDs into a mounted data directory first. Mount the parent of `wallet/` so the shared CA persists with the credentials. Select the file backend and an empty seed so the persisted CA is private:

```bash
docker run --rm -v wallet-data:/home/app/.eudi-dev -e EUDI_DEV_STORAGE=file -e EUDI_DEV_SEED= ghcr.io/eudi-dev/eudi-dev \
  issue sdjwt --wallet --template german-pid-sdjwt --claims '{"given_name":"MAX","family_name":"POWER"}'

docker run -p 8085:8085 -v wallet-data:/home/app/.eudi-dev -e EUDI_DEV_STORAGE=file -e EUDI_DEV_SEED= ghcr.io/eudi-dev/eudi-dev \
  wallet serve --auto-accept --port 8085
```

## Testing API

The wallet exposes API endpoints that control its behavior in automated tests.

### Error simulation

Set a one-shot error response. The next OID4VP request returns it, then normal behavior resumes.

```bash
# Set up error for next request
curl -X POST http://localhost:8085/api/next-error \
  -H 'Content-Type: application/json' \
  -d '{"error": "access_denied", "error_description": "Simulated denial"}'

# Clear without consuming
curl -X DELETE http://localhost:8085/api/next-error
```

### Format preference

When the DCQL query matches both SD-JWT and mdoc credentials, choose which format is presented:

```bash
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": "dc+sd-jwt"}'   # or "mso_mdoc" or "" to clear
```

Or set it at startup: `--preferred-format dc+sd-jwt`

### Credential import

The wallet imports SD-JWT (`dc+sd-jwt`), plain JWT VC (`jwt_vc_json`), and mdoc (`mso_mdoc`). Plain JWT VCs are presented unchanged.

```bash
curl -X POST http://localhost:8085/api/credentials -d 'eyJhbGci...'
```

### Status list (revocation)

With `wallet serve --pid`, generated credentials carry a status list reference pointing to `https://<host>:<port+1>/api/statuslist`. `--status-list` adds the reference to every generated credential.

The HTTPS issuer URL uses the same host selection. By default the issuer runs on `https://<host>:<port+1>` and serves `/.well-known/jwt-vc-issuer`, the signed `/.well-known/openid-credential-issuer` endpoint, and `/api/registrar/wrp`.

For verifier tests that need to trust that HTTPS endpoint, export the persisted certificate:

```bash
eudi wallet tls-cert --docker --out wallet-tls-cert.pem
```

To trust every spawned wallet from one root, export the shared wallet CA:

```bash
eudi wallet ca-cert --out wallet-ca-cert.pem
```

The status list URI and issuer host are written into credentials at generation time. When the verifier runs inside Docker and the wallet on the host (or vice versa), use `--docker` (or `--base-url` for a custom URL) so the status list URL, signed issuer metadata, and registrar endpoints are reachable from both sides:

```bash
# Wallet on host, verifier in Docker
eudi wallet serve --pid --auto-accept --docker
```

```yaml
# Docker Compose: both in containers, use the service name
services:
  wallet:
    image: ghcr.io/eudi-dev/eudi-dev:latest
    command: ["wallet", "serve", "--auto-accept", "--pid", "--port", "8085",
              "--base-url", "http://wallet:8085"]
    ports:
      - "8085:8085"
      - "8086:8086"
```

Toggle revocation at runtime:

```bash
# Revoke (status=1)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' -d '{"status": 1}'

# Un-revoke (status=0)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' -d '{"status": 0}'
```

> See [wallet HTTP API](wallet/http-api.md) for the full API and an end-to-end example. The API has no authentication. Keep it inside isolated test networks, or use the `--demo` profile for internet-facing deployments (see [public demo hosting](public-demo.md)).

## Supported response modes

`direct_post` (default) and `direct_post.jwt` (JARM, encrypted to the verifier's ephemeral key from the request object).
