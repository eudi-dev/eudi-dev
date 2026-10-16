# OIDF Conformance

The harness runs OpenID Foundation wallet plans for OID4VP 1.0, OID4VCI 1.0 and HAIP 1.0 against `eudi-dev`. Separate issuer and verifier plans test the bundled demo services.

The runs test only the selected plans, variants and test conditions. Certificate profiles, trusted lists, registration information, PID rulebooks and other ETSI and ISO requirements need separate checks. See [spec compliance](spec-compliance.md) and [test certificates](test-certificates.md). The suites send no registration certificates, so the runs do not cover the [ARF checks](wallet/presenting.md#arf-checks).

Related docs:

- [Wallet conformance runs](./conformance-run.md)
- [Demo issuer and verifier runs](./conformance-run-demorp.md)
- [Current conformance results](./conformance-results.md)

## Current state

The harness targets a local OpenID Foundation conformance suite server by default. The documented baseline is `release-v5.3.1`. When the server exposes `/api/server`, the wrapper checks that its tag matches the runner/templates tag and fails early on a mismatch.

Current local status:

- The latest full wallet run has 744 modules: 530 `PASSED`, 188 `REVIEW`, 26 `WARNING` and 0 `FAILED`. The warnings are the IACA path length advisory.
- The latest demo issuer and verifier run has 111 modules: 67 `PASSED`, 36 `REVIEW`, 8 `WARNING` and 0 `FAILED`. The warnings concern metadata unknown to the suite's schemas. All 36 verifier decisions match expectations.
- Negative modules can end in `REVIEW` after the expected refusal. The local harness accepts that result only when there are no failing conditions.
- Alpha Final plans use explicit VP module lists. Certifiable HAIP plans run complete and unfiltered.

## Covered plans

The wrapper runs the current Final wallet plans plus the current HAIP wallet plans:

- `oid4vp-1final-wallet-test-plan`
- `oid4vci-1_0-wallet-test-plan`
- `oid4vp-1final-wallet-haip-test-plan`
- `oid4vci-1_0-wallet-haip-test-plan`

Only the two HAIP plans are part of the OIDF certification program. The suite publishes the plain Final wallet plans as alpha tests. On the production certification service, the wrapper runs only the HAIP plans, complete and unfiltered. Local and demo-service runs cover the whole matrix.

## Default matrix

The default run covers every plan variant combination supported by the wallet.

VP Final generates the cross product of credential format (SD-JWT, mdoc), response mode, and the supported prefix and request pairs (36 plans):

- `direct_post` and `direct_post.jwt` with `redirect_uri` (`url_query` and unsigned `request_uri`), `x509_hash` (signed), and `x509_san_dns` (signed)
- `dc_api` and `dc_api.jwt` with `web-origin` (unsigned), `x509_hash` and `x509_san_dns` (signed and multisigned)

VCI Final runs 32 plans covering both credential formats, both grants, both offer delivery methods, immediate and deferred issuance, and plain and encrypted responses. These scenarios use issuer initiation, client attestation, DPoP and scope requests. The mdoc pre-authorized plans use the suite's `rar` variant. Under `simple` the suite always issues the SD-JWT PID in a pre-authorized flow.

The HAIP plans expose fewer selectable variants (the module entries fix the rest):

- VP HAIP: SD-JWT and mdoc with `direct_post.jwt` and `dc_api.jwt`, the latter covering unsigned (no `client_id`), signed `x509_hash`, and multisigned `x509_hash` Browser API modules (4 plans)
- VCI HAIP: SD-JWT and mdoc, each issuer-initiated with the offer `by_value` and `by_reference` and wallet-initiated without an offer, each covering immediate plain, deferred plain, and immediate encrypted responses (6 plans)

The matrix omits the `pre_registered` and `decentralized_identifier` prefixes, `issuer_initiated_dc_api`, `rar` authorization requests in the authorization code flow, and mTLS or `private_key_jwt` client authentication. The wallet uses scope-based authorization. The HAIP plans cover wallet-initiated issuance. The Final issuance matrix uses issuer-initiated flows.

The matrix is fixed in the wrapper. Use the official runner `--rerun` selector for targeted reruns of an already generated matrix, or `ONLY_SCENARIOS` (a comma separated list of slug substrings) to generate and run a subset.

## Harness behavior

[`scripts/oidf-wallet-conformance.sh`](../scripts/oidf-wallet-conformance.sh):

- defaults to `CONFORMANCE_MODE=local`
- targets `https://localhost:8443/` and `https://localhost:8444/` for the local suite and mTLS endpoints
- downloads the latest upstream conformance suite release tarball from GitLab, unless `OIDF_SUITE_DIR` or `OIDF_SUITE_URL` is set
- checks the local suite `/api/server` tag when available and fails early if the running server does not match the runner/templates release
- creates a Python virtualenv for the official runner
- starts `eudi wallet serve` in strict mode with default PID credentials
- configures the wallet's normal OID4VCI authorization code client settings
- runs the official `run-test-plan.py` against the conformance suite server
- forwards `--rerun` to the official runner for targeted plan/module reruns

[`scripts/oidf_wallet_conformance.py`](../scripts/oidf_wallet_conformance.py):

- verifies the extracted suite contains the current Final wallet plans and templates
- reads the wallet's holder binding key from `/api/credentials`
- reads the wallet's issuer signing JWK from `/.well-known/jwt-vc-issuer`
- uses the shared wallet CA as the attestation and trust anchor PEM
- generates per-scenario OIDF config files from the upstream templates
- keeps the VCI suite alias aligned with the configured `redirect_uri` and helper-page paths
- disables the suite's VCI browser helper page and drives the same offer URL directly through the wallet API
- drives Browser API `dc_api` / `dc_api.jwt` presentation requests through the wallet's `/api/dc-api` endpoint
- sets the wallet's conformance mode before each submission through `PUT /api/config/conformance`. Final modules run without HAIP checks and HAIP modules run with them, regardless of the wallet's startup flags
- starts the wallet-initiated VCI modules itself. The suite provides no offer for them, so the harness sends the wallet an offer for the suite's issuer and the configured credential, without `issuer_state`
- passes explicit VP module lists for the alpha Final scenarios and runs the certifiable HAIP plans complete
- monitors waiting modules and automatically submits presentation requests, Browser API requests, credential offers, verifier redirects, and negative-review screenshot placeholders
- prints the created local `plan-detail.html?plan=...` URLs

## Wallet keys

The wallet runs a conformance test with its normal keys:

- its holder key for `private_key_jwt` and for self-issued credentials
- a wallet instance key per authorization server for client attestation and DPoP
- a fresh key for the proofs of each issuance
- its wallet provider signing key and certificate chain for client attestation and key attestation
- its shared wallet CA as the trust anchor

## Suite gaps

The suite issues an authorization code without a user sign-in, so these plans skip the browser sign-in step. Playwright tests that step against the demo issuer. Its login page accepts each pushed `request_uri` only once (RFC 9126 §4).

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
