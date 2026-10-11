# Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer. Point the wallet at the proxy instead of the real server. Every request and response is captured, classified by protocol step, decoded, and shown in the terminal and a live web dashboard.

```bash
eudi proxy --target http://localhost:8080
eudi proxy --target http://localhost:8080 --port 9090 --dashboard 9091
eudi proxy --target http://localhost:8080 --no-dashboard
```

```
Wallet  <-->  Proxy (:9090)  <-->  Verifier/Issuer (:8080)
                  |
            Live dashboard (:9091)
```

The proxy can launch the target service as a subprocess and scan its output for encryption keys:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
eudi proxy --target http://localhost:3000 -- npm start
```

## Traffic classification

The proxy checks the rules from top to bottom. The first match sets the badge.

| Badge                  | Detected when |
|------------------------|---------------|
| VCI Metadata           | Path contains `.well-known/openid-credential-issuer` |
| OIDC Metadata          | Path contains `.well-known/openid-configuration` |
| VCI Credential Offer   | `credential_offer` or `credential_offer_uri` in query |
| VP Auth Request        | `client_id` and a `response_type` with `vp_token` in query. An `id_token` response type counts with an OID4VP parameter such as `request_uri`, `response_uri` or `dcql_query` |
| OIDC Auth Request      | `client_id`, `redirect_uri` and a `response_type` with `code`, `token` or `id_token` in query, plus the `openid` scope or a `form_post` response mode |
| OIDC Callback          | GET with `code` or `error` in query, or a POST body with `code` or `error` and no `grant_type` |
| VP Request Object      | GET whose response body is a JWT, or a POST body with `wallet_metadata` or `wallet_nonce` (`request_uri_method=post`) |
| VCI Nonce Request      | POST to a path ending in `/nonce` whose response contains `c_nonce` |
| VP Auth Response       | POST body contains `vp_token`, `presentation_submission`, `id_token` or `response` (JARM) |
| OIDC Token Request     | POST to `/protocol/openid-connect/token`, a response with `id_token`, or an `authorization_code` grant with `redirect_uri` |
| VCI Token Request      | POST to a path ending in `/token` |
| VCI Credential Request | POST to a path ending in `/credential` or `/credentials` |

When no rule matches, a request to an endpoint that earlier traffic advertised gets the badge of that endpoint. Metadata, authorization requests and request objects advertise endpoints.

By default only OID4VP/VCI traffic is shown. Other requests (favicon, health checks) are proxied but hidden. `--all-traffic` shows everything.

## Features

- **Decoding**: payloads are decoded inline (SD-JWT, JWT, mdoc, DCQL queries, JWE headers)
- **Credential decode hints**: detected credentials are printed as `eudi decode` commands
- **JARM/JWE decryption**: a `direct_post.jwt` response from the built-in wallet is decrypted
- **Flow correlation**: related protocol steps are grouped by shared `state`/`nonce` values
- **Web dashboard** at `http://localhost:9091` with live SSE updates and HAR export
- **JARM/JWE detection**: shows encrypted response headers and the verifier's ephemeral public key
- **NDJSON output**: `--json` prints one JSON object per line

## Flags

| Flag             | Default | Description                              |
|------------------|---------|------------------------------------------|
| `--target`       | None    | URL of the verifier/issuer (required)    |
| `--port`         | `9090`  | Proxy listen port                        |
| `--dashboard`    | `9091`  | Dashboard listen port                    |
| `--no-dashboard` | `false` | Disable web dashboard                    |
| `--dashboard-base-url` | None | Public dashboard URL when a reverse proxy serves it under a path prefix, such as `https://example.com/eudi-proxy` (see [behind a reverse proxy](reverse-proxy.md#proxy-dashboard)) |
| `--all-traffic`  | `false` | Show all traffic                          |
| `--json`         | `false` | NDJSON output to stdout (global flag)    |
| `-- <command>`   | None    | Launch target as subprocess, scan stdout |

`eudi proxy logs [dashboard-url]` reads the traffic of a running proxy:

| Flag             | Default | Description                                        |
|------------------|---------|----------------------------------------------------|
| `[dashboard-url]`| `http://localhost:9091` | Dashboard of the proxy to read      |
| `-f, --follow`   | `false` | Keep printing as the proxy records traffic         |
| `--json`         | `false` | Print the recorded traffic as JSON (global flag)   |

## Reading a running proxy

Use `eudi proxy logs` to read traffic from a proxy running in a container, in the background or on another machine:

```bash
# a proxy on this machine
eudi proxy logs

# a proxy whose dashboard port is published from a container
eudi proxy logs http://localhost:9091 --follow

# somewhere else entirely
eudi proxy logs https://proxy.internal.example --follow
```

The output matches the proxy's terminal output, with decode links to its dashboard. `--follow` streams new traffic and reconnects after a disconnect or restart. On reconnect, it reads any missed entries still in the proxy's history. `--json` prints the recorded traffic once and cannot be combined with `--follow`.

A proxy started without `--all-traffic` records only OID4VP/VCI requests, so `logs` shows only those.

## Example output

```
━━━ [14:32:05] GET /authorize?client_id=...  ← 200 (45ms)  [VP Auth Request]
    ┌ client_id: did:web:verifier.example
    ┌ response_mode: direct_post.jwt
    ┌ nonce: abc123
    ┌ dcql_query: { "credentials": [...] }

━━━ [14:32:05] GET /request/abc123  ← 200 (12ms)  [VP Request Object]
    ┌ header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
    ┌ payload: { ... }

━━━ [14:32:06] POST /response  ← 200 (89ms)  [VP Auth Response]
    ┌ response_type: JWE (decrypted via debug key)
    ┌ encryption_alg: ECDH-ES
    ┌ response_payload: {"vp_token":{...},"state":"abc123"}
  → eudi decode 'eyJhbGci...'  (vp_token)
```

## JWE decryption

When the built-in wallet (`eudi wallet`) sends an encrypted JARM response (`direct_post.jwt`) through the proxy, the proxy decrypts the payload and shows the contained `vp_token` and `state`.

The wallet puts the AES content encryption key (CEK) in the `X-Debug-JWE-CEK` header. The proxy strips the header before forwarding, so the verifier never sees it. Route the wallet through the proxy:

```
eudi wallet serve                    # wallet sends to response_uri
eudi proxy --target http://verifier  # proxy intercepts, decrypts, forwards
```

### Automatic key detection from service stdout

A third-party wallet sends no debug header. When the verifier service runs as a subprocess (with `--`), the proxy scans its stdout for CEK values and uses them to decrypt JWE responses:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
```

The proxy detects lines like:

- `CEK: <base64url>` or `content encryption key: <base64url>`
- JWK objects containing a `"d"` (private key) parameter

Without a key the proxy shows the JWE header fields only (`alg`, `enc`, `kid`, `epk`).

## Debugging tips

- The wallet logs credentials and encryption keys to stdout for local debugging:
  - `[VP] JWE content encryption key for proxy debugging: <base64url CEK>`
  - `[VP] SD-JWT presentation created: ...`
- Output of a service launched with `--` appears with a `[service]` prefix.
- Pipe `--json` output to `jq`: `eudi proxy --target ... --json | jq '.credentials'`
