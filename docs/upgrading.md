# Upgrading from 2.x to 3.0.0

This page lists the changes that can break a 2.x setup. Old commands and flags fail and tell you the new name.

For the new features, see [What's new in 3.0.0](whats-new-3.0.md). For all changes, see the [changelog](../CHANGELOG.md).

## Install and state

| 2.x | 3.0.0 |
|---|---|
| `go install github.com/dominikschlosser/eudi-dev/v2@latest` | `go install github.com/eudi-dev/eudi-dev/v3@latest` |
| `ghcr.io/dominikschlosser/eudi-dev` | `ghcr.io/eudi-dev/eudi-dev` |
| `brew install dominikschlosser/tap/eudi-dev` | `brew install eudi-dev/tap/eudi-dev` |
| `oid4vc-dev` command | `eudi` |
| `~/.oid4vc-dev` and `OID4VC_DEV_HOME` | `~/.eudi-dev` and `EUDI_DEV_HOME` |

Move an old state directory with `mv ~/.oid4vc-dev ~/.eudi-dev`. A wallet from 2.x keeps its credentials, keys and EAAs. EAAs issued by 2.x stay anchored on the `eaa` list.

## Listen address

The wallet, the decoder and the proxy listen on `127.0.0.1` by default. Before 3.0.0 they listened on every interface.

- The Docker image sets `EUDI_DEV_LISTEN=0.0.0.0`. Docker and Kubernetes deployments of the image keep working.
- `--docker` also listens on every interface.
- If you run the binary in your own container image or reach it from another machine, add `--listen 0.0.0.0` or set `EUDI_DEV_LISTEN=0.0.0.0`.

The Helm chart and the Testcontainers module for 2.x pass flags that 3.0.0 renamed. Use their versions for eudi-dev 3.0.0.

## Commands

| 2.x | 3.0.0 |
|---|---|
| `eudi serve` | `eudi decoder` |
| `eudi wallet trust-list --id <list>` | `eudi trust show <list>` |
| `eudi wallet trust-list --list` | `eudi trust list` |
| `eudi wallet ca-cert` | `eudi trust ca-cert` |
| `eudi wallet present` | `eudi wallet accept` |
| `eudi wallet listen` | `eudi wallet serve --register` |
| `eudi wallet generate-pid` | `eudi issue sdjwt --wallet --pid` or `eudi issue mdoc --wallet --pid` |
| `eudi wallet instances` | `eudi wallet ps` |

`decoder`, `wallet serve` and `completion` refuse `--json`.

## Flags and variables

| 2.x | 3.0.0 |
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

A CLI command that talks to a running wallet refuses a setting that differs from the wallet's own. Change the setting on `wallet serve` or with `PUT /api/config/conformance`.

## Trusted lists and keys

- Each credential category has its own signing key and trusted list. `wallet serve --issuer-key` and `issuer.pem` sign only PIDs.
- The LoTEType URIs of the wallet's lists changed. Configure your verifier with the lists at `/api/trustlists/<category>`.
- An imported credential is on none of the wallet's lists.
- The decoder no longer trusts the wallet CA or the issuer key. It reads a stored wallet and never creates one.
- A list in DCQL `trusted_authorities` counts only when a known operator signed it.
- `validate --trusted-list` fails on a list without `NextUpdate` or past it.

## HTTP API

- Every error of the wallet, registrar, catalogue and decoder API is `{"error": "<code>", "error_description": "<message>"}`. Protocol endpoints keep the error format of their spec.
- `trust_profile` is now `category` in `POST /api/issue`. The trust fields are now `trusted_list_type` and `trusted_entity_name`.
- The `local` list and provider role are now `eaa`. Use `/api/trustlists/eaa`, `/api/certificates/providers/eaa/...` and `/api/crl/providers/eaa/...`.
- `POST /api/decode` is gone. Use `POST /api/validate`. It takes the same `input`.
- `POST /api/generate-pid` is gone. Use `POST /api/issue` with a PID template, or start the wallet with `--pid`.
- `PUT /api/config/conformance` takes the setting names of `GET /api/config`, such as `validation_mode` and `require_arf`.
- `POST /api/issue` no longer returns `signing_override`.
- `issuer_info` and `verifier_info` carry only the registration certificate.
- The demo verifier returns a result for `GET /verifier/api/requests/{key}` only when `key` is the `transaction_id` or the `response_code`. Poll with the `transaction_id` returned when you create the request.

## Outbound connections

`wallet serve` and the decoder connect to public addresses, loopback and their own URLs. Add `--allow-private-networks` (or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`) when your issuer or verifier runs in a private network. The Docker image allows private networks.

## Stricter checks

Some services that passed with 2.x now get findings. Debug mode still finishes the flow and lists them. Strict mode refuses them.

- An expired request object, a wrong `aud` or an expired signer certificate is a finding.
- A malformed `dcql_query` is refused in strict mode.
- A malformed credential offer is refused in every mode.
- An authorization server's `issuer` and the RFC 9207 `iss` must match exactly, including a trailing slash.
- A request with `response_mode=fragment` needs a `redirect_uri`.
- `validate` exits non-zero for an SD-JWT VC without `typ` `dc+sd-jwt`, a digest mismatch or a credential that is not valid yet.
- The demo verifier and the demo issuer check requests and responses more strictly. See the changelog for details.

## Output

`validate`, `wallet deferred check`, `wallet list` and one-shot `wallet accept` print a different `--json` document. `wallet accept` and `wallet scan` exit non-zero when a flow fails or is denied.
