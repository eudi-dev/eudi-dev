# Upgrading from 2.x to 3.0

This page lists what you have to change when you move from eudi-dev 2.x to 3.0. Old commands and flags fail with a message that names the new one, so a script that breaks tells you how to fix it. The [changelog](../CHANGELOG.md) has every change, and [What's new in 3.0](whats-new-3.0.md) shows the new features.

## Install and state

| 2.x | 3.0 |
|---|---|
| `go install github.com/dominikschlosser/eudi-dev/v2@latest` | `go install github.com/eudi-dev/eudi-dev/v3@latest` |
| `ghcr.io/dominikschlosser/eudi-dev` | `ghcr.io/eudi-dev/eudi-dev` |
| `brew install dominikschlosser/tap/eudi-dev` | `brew install eudi-dev/tap/eudi-dev` |
| `oid4vc-dev` command | `eudi` |
| `~/.oid4vc-dev` and `OID4VC_DEV_HOME` | `~/.eudi-dev` and `EUDI_DEV_HOME` |

Move an old state directory with `mv ~/.oid4vc-dev ~/.eudi-dev`. A wallet from 2.x keeps its credentials, keys and EAAs. EAAs issued by 2.x stay anchored on the `eaa` list.

## Listen address

The wallet, the decoder and the proxy listen on `127.0.0.1` by default. Before 3.0 they listened on every interface.

- The Docker image sets `EUDI_DEV_LISTEN=0.0.0.0`. Deployments that use the image, in Docker, Kubernetes, the Helm chart or Testcontainers, need no change.
- `--docker` also listens on every interface.
- Do you run the binary in your own container image, or reach it from another machine? Add `--listen 0.0.0.0` or set `EUDI_DEV_LISTEN=0.0.0.0`.

## Commands

| 2.x | 3.0 |
|---|---|
| `eudi serve` | `eudi decoder` |
| `eudi wallet registrar` | `eudi registrar` |
| `eudi wallet catalog` | `eudi catalog` |
| `eudi wallet trust` | `eudi trust` |
| `eudi wallet trust-list --id <list>` | `eudi trust show <list>` |
| `eudi wallet ca-cert` | `eudi trust ca-cert` |
| `eudi wallet present` | `eudi wallet accept` |
| `eudi wallet listen` | `eudi wallet serve --register` |
| `eudi wallet generate-pid` | `eudi issue sdjwt --wallet --pid` or `eudi issue mdoc --wallet --pid` |
| `eudi wallet instances` | `eudi wallet ps` |

## Flags and variables

| 2.x | 3.0 |
|---|---|
| `issue --trust-profile` | `issue --category` (`pid`, `qeaa`, `pub-eaa`, `eaa` or `unlisted`) |
| `issue --trust-list-type` | `issue --trusted-list-type` |
| `issue --trust-entity-name` | `issue --trusted-entity-name` |
| `validate --trust-list` | `validate --trusted-list` |
| `decode --format trustlist` | `decode --format trusted-list` |
| `wallet serve --demo-verifier-trust-anchor` | `wallet serve --demo-verifier-issuer-ca` |
| `EUDI_REMOTE_TIMEOUT` | `EUDI_DEV_REMOTE_TIMEOUT` |
| `PORT` in the Docker image | `EUDI_DEV_PORT` |

Every `wallet serve` flag can now be set as `EUDI_DEV_<FLAG>`. An unknown `EUDI_DEV_` variable stops the server, so check your environment for old or misspelled names.

## HTTP API

- Every error of the wallet, registrar, catalogue and decoder API is `{"error": "<code>", "error_description": "<message>"}`. Plain text errors are gone. Protocol endpoints keep the error format of their spec.
- `trust_profile` is now `category` in `POST /api/issue`. The trust fields use "trusted list" names too.
- The `local` list and provider role are now `eaa`. Use `/api/trustlists/eaa`, `/api/certificates/providers/eaa/...` and `/api/crl/providers/eaa/...`.
- `POST /api/decode` is gone. Use `POST /api/validate`, which takes the same `input`.
- `POST /api/generate-pid` is gone. Use `POST /api/issue` with a PID template, or start the wallet with `--pid`.
- `PUT /api/config/conformance` takes the setting names of `GET /api/config`, such as `validation_mode` and `require_arf`.
- `POST /api/issue` no longer returns `signing_override`.
- `GET /api/registrar/wrp` returns the TS05 v1.5 format.
- The demo verifier returns a result for `GET /verifier/api/requests/{key}` only when `key` is the `transaction_id` or the `response_code`. Poll with the `transaction_id` the request returned.

## Outbound connections

`wallet serve` and the decoder reach public addresses, loopback and their own URLs. Add `--allow-private-networks` (or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`) when your issuer or verifier runs in a private network. The Docker image allows private networks.

## Stricter checks

Some services that passed with 2.x now get findings. Debug mode still finishes the flow and lists them. Strict mode refuses them.

- An expired request object, a wrong `aud` or an expired signer certificate is a finding.
- A malformed `dcql_query` is refused in strict mode.
- An authorization server's `issuer` and the RFC 9207 `iss` must match exactly, also in the trailing slash.
- A request with `response_mode=fragment` needs a `redirect_uri`.
- `validate` exits non-zero for an SD-JWT VC without `typ` `dc+sd-jwt`, a digest mismatch or a credential that is not valid yet.

## Output

`validate`, `wallet deferred check`, `wallet list` and one-shot `wallet accept` print a different `--json` document. `wallet accept` and `wallet scan` exit non-zero when a flow fails or is denied.
