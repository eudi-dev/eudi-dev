# OIDF conformance runs for the demo issuer and verifier

Test the demo issuer at `/issuer` and verifier at `/verifier` with the official OIDF plans. The suite acts as the wallet. To test `eudi-dev` as the wallet instead, use the [wallet runbook](./conformance-run.md).

Only the wallet goes through certification. These issuer and verifier plans run locally (or on the hosted demo service) as quality checks. The wrapper refuses to run them on the production certification service.

## Test plans

The wrapper starts one wallet server and drives these plans through the official `run-test-plan.py`:

| Plan | Scenarios |
| --- | --- |
| `oid4vci-1_0-issuer-test-plan` | Authorization code initiated by the wallet or issuer, and pre-authorized code |
| `oid4vci-1_0-issuer-haip-test-plan` | SD-JWT VC, authorization code, issuer-initiated |
| `oid4vp-1final-verifier-test-plan` | Signed SD-JWT VC, unsigned SD-JWT VC with `redirect_uri`, and signed mdoc |
| `oid4vp-1final-verifier-haip-test-plan` | SD-JWT VC and mdoc, both `direct_post.jwt` |

The HAIP issuer plan runs only VCI modules. The demo issuer supports PAR, PKCE S256, DPoP and attestation-based client authentication. The plan also appends FAPI2 server modules. These need a full OAuth authorization server, so the wrapper leaves them out.

The wrapper excludes modules for features missing from the demo services, because the official runner counts skips as failures.

Excluded issuer checks cover required key attestations and credential encryption. Batch checks run only in scenarios that supply a batch offer. Signed verifier scenarios exclude `request-uri-method-post` because the demo verifier serves requests through GET.

The harness performs the manual tester steps of the plans:

- it pushes a fresh demo credential offer to the suite's exposed `credential_offer` endpoint whenever an issuer-initiated module waits for one (by value, since a `credential_offer_uri` must be https)
- it signs in at the demo issuer's authorization page as the demo account (alice) and follows the redirect to the suite's callback
- it creates a demo verifier request per verifier module and sends its query string to the suite's authorization endpoint (like a wallet opening an `openid4vp://` link)
- it uploads the screenshot placeholders required by the verifier plans at the end

Verifier modules end in `REVIEW` because the suite cannot observe the verifier's decision. The harness also checks the demo verifier's recorded result. Tampered presentations must be `failed` and valid presentations must be `verified`. A mismatch exits with code 3.

## Prerequisites

The same as for the [wallet runbook](./conformance-run.md#prerequisites): a suite checkout at the documented baseline, with the suite server running on the host.

## Run

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.3.1 \
OIDF_RUN_DIR=/tmp/oidf-demorp-conformance \
  scripts/oidf-demorp-conformance.sh
```

Selected scenarios only (substring match on the scenario slug):

```bash
ONLY_SCENARIOS=vp-verifier-final-sdjwt,vci-issuer-preauth \
  scripts/oidf-demorp-conformance.sh
```

The `--rerun` selector passes through to the official runner exactly as in the wallet runbook.

## HTTPS setup

The verifier plans require the `request_uri` and the `response_uri` to be https, and the HAIP issuer metadata checks require an https credential issuer. The wrapper starts the wallet with an https base URL and `--serve-tls`, so the wallet serves that origin itself over TLS with its own certificate (the suite skips certificate verification on outbound calls).

The suite presents credentials signed under its own CAs to the demo verifier (the `vp-signing` CA from `scripts/certs-keys` for SD-JWT VCs, a built-in mdoc IACA root for mdocs). The wrapper passes both to the wallet as `--demo-verifier-issuer-ca` files, so the demo verifier accepts those chains in addition to the wallet CA. The suite server publishes the IACA root at `/mdoc-iaca-root.pem`. When that endpoint is unavailable, the wrapper extracts the same certificate from the suite source.

The generated configs also pass trust anchors to the suite. The issuer configs set the wallet CA as `credential.trust_anchor_pem`, so the suite validates the demo ticket's certificate chain. The verifier configs set the relying party access CA as `client.request_object_trust_anchor_pem`, because the demo verifier signs its request objects with an access certificate from that CA.

## Environment overrides

The [wallet runbook's suite and server overrides](conformance-run.md#environment-overrides) also apply here. On a loaded machine, set `OIDF_REQUEST_TIMEOUT=60`. Leave `OIDF_KEEP_SUITE_DB` unset for repeated runs, because old results slow the suite and can stall modules.

This wrapper also accepts:

- `OIDF_DEMO_BASE_URL`: the https origin advertised by the demo issuer and verifier. Defaults to `https://localhost:<port+1>`
- `ONLY_SCENARIOS`: comma separated scenario slug substrings to run a subset

`CONFORMANCE_MODE=hosted` needs a publicly reachable `OIDF_DEMO_BASE_URL` (a tunnel with its own TLS terminator), because the hosted suite fetches the demo endpoints itself. Local mode is the supported setup.

## Result artifacts

The wrapper prints the run directory and leaves the same artifacts as the wallet wrapper (`wallet.log`, `runner.log`, `results/` with the exported archives and the generated configs). The runner log also contains the `[verdicts]` block with the demo verifier's outcome per verifier module.
