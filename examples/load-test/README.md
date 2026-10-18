# Load test target: two wallet servers, one database, one ingress

Two wallet servers share Postgres behind nginx. Both use the same keys, CA, credentials and activity log. Use this setup to test the wallet under load or as a test wallet for issuers and verifiers.

## Layout

| Service | Role | Host port |
|---------|------|-----------|
| `ingress` | nginx. HTTP round robin over both servers, TLS passthrough for the issuer endpoints | 8080 (HTTP), 8086 (HTTPS issuer endpoints) |
| `wallet-1`, `wallet-2` | `eudi wallet serve --auto-accept --pid` on the `postgres` storage backend | none |
| `db` | Postgres 16 | none |

The wallets advertise `http://localhost:8080` as their base URL and `https://localhost:8086` as their issuer URL, so the status list, issuer metadata and trusted list URLs embedded in credentials point at the ingress.

## Startup

```bash
cd examples/load-test
docker compose up -d
curl -s localhost:8080/api/config | jq '{storage, credential_count}'
docker compose logs ingress | grep upstream=
```

The ingress log shows `upstream=` alternating between the two server addresses. `storage` is `postgres` and `credential_count` is the same on each. `WALLET_TAG=2.4.0 docker compose up -d` pins a release. `docker compose build` builds the image from the working tree. `INGRESS_PORT=18080 docker compose up -d` moves the HTTP host port (the base URL follows it).

## Traffic

Send load to the [wallet HTTP API](../../docs/wallet/http-api.md). A presentation, an import and an issuance are each one request:

```bash
# Present: your verifier sends an OID4VP authorization request, the wallet answers it
curl -s "localhost:8080/authorize?client_id=...&response_type=vp_token&response_mode=direct_post&response_uri=...&nonce=...&dcql_query=..."

# Import a credential
curl -s -X POST localhost:8080/api/credentials --data-binary @credential.txt

# Issue a credential into the shared wallet
curl -s -X POST localhost:8080/api/issue -H 'Content-Type: application/json' -d '{"format":"sdjwt","template":"pid-sdjwt"}'
```

The CLI uses the ingress as a remote wallet:

```bash
eudi wallet use http://localhost:8080
eudi wallet list
eudi wallet logs
```

A browser session stays on one server (the ingress hashes the `eudi_session` cookie), so the wallet UI at `http://localhost:8080` works as usual once it has been opened. A flow that starts with a verifier's or issuer's redirect in a fresh browser can go to either server, so open the UI first.

## Correctness under load

The Go load generator runs issuance, presentation and listing concurrently. It checks that every issued credential appears once, status indices are unique, presentation callbacks arrive and both servers report the same count.

Its verifier callback runs on the host. Containers reach it through `host.docker.internal`.

```bash
go run ./examples/load-test/loadtest -url http://localhost:8080
```

Configure the generator with these flags:

| Flag | Purpose |
| --- | --- |
| `-issuers`, `-issues`, `-presenters`, `-presentations`, `-readers` | Set the load |
| `-callback-port` | Callback port (default `9090`) |
| `-callback-host` | Hostname reachable from containers (default `host.docker.internal`) |
| `-url` | Ingress URL, or comma-separated server URLs used in turn |
| `-servers` | Backend URLs to check directly when a listing misses a credential |

A listing started after successful issuance must include the credential. A missing credential counts as a failure even if the next listing contains it.

## Scale

Add a `wallet-3` service using the existing compose anchor and include it in both nginx upstreams. Servers reload changed sections and save changed rows. Updates to different entities are preserved. Updates to the same entity can overwrite each other. Each browser flow must stay on one server. See [the storage design](../../docs/adr/0018-postgres-stores-wallet-entities-as-keyed-blobs.md).

## Cleanup

```bash
docker compose down -v
```

`-v` removes the database volume and with it the wallet, its keys and its CA.
