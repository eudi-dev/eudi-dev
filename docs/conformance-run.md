# OIDF wallet conformance runs

This runbook runs the current OIDF Final and HAIP wallet plans against the local `eudi-dev` testing wallet. Status and result matrix: [Current conformance results](./conformance-results.md). The reverse direction (the suite acting as the wallet against the demo issuer and verifier) has [its own runbook](./conformance-run-demorp.md).

## Prerequisites

You need:

- `go`
- `python3`
- `curl`
- Docker
- Maven
- a local OpenID Foundation conformance suite checkout

The documented suite baseline is `release-v5.3.1`. Use a newer release only when updating the baseline and the [results](./conformance-results.md).

## Local suite

Build the suite from the baseline checkout:

```bash
cd ../conformance-suite
git fetch --tags
git checkout release-v5.3.1
mvn clean package
```

Build it with JDK 21. Newer JDKs report warnings, and the suite compiles with `-Werror`.

Run the suite server **on the host** so it can fetch the wallet's `https://localhost:<port+1>` status list. Inside a container, `localhost` would refer to the container and status checks would fail. The `-nodocker` compose file keeps MongoDB and nginx in Docker while the suite server runs on the host.

The `eudi-dev` wrapper defaults to plain `localhost` URLs, so the server must advertise `localhost` too (the upstream default is `localhost.emobix.co.uk`):

```bash
cd ../conformance-suite
docker compose -f docker-compose-dev-mac-nodocker.yml up --detach

java -jar target/fapi-test-suite.jar \
  --fintechlabs.devmode=true \
  --fintechlabs.startredir=true \
  --fintechlabs.base_url=https://localhost:8443 \
  --fintechlabs.base_mtls_url=https://localhost:8444 \
  --spring.mongodb.uri=mongodb://127.0.0.1:27017/test_suite
```

The wrapper's server variables use the same host:

- `CONFORMANCE_SERVER=https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL=https://localhost:8443/`
- `CONFORMANCE_SERVER_MTLS=https://localhost:8444/`

Check the running suite before starting the wallet run:

```bash
curl -k https://localhost:8443/api/server
```

For the current baseline, the server returns:

```json
{"tag":"release-v5.3.1","version":"5.3.1","revision":"440eec8"}
```

## Wallet matrix

From this repository:

```bash
scripts/oidf-wallet-conformance.sh
```

To keep artifacts in a stable location:

```bash
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

To force the wrapper to use the same checkout as the running local server:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.3.1 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

Compare failures with the latest [conformance results](./conformance-results.md) before treating them as regressions. The baseline lists the known wallet and suite failures and the expected exit status.

## Reruns of selected plans or modules

Pass the official `run-test-plan.py` selector through the wrapper:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.3.1 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-rerun \
  scripts/oidf-wallet-conformance.sh --rerun '1:6,2:6'
```

The selector syntax is the official runner syntax:

- `2` reruns plan 2
- `2:6` reruns one module
- `1:6,2:6` reruns multiple modules

The harness still generates all configs, so plan numbering stays the same. It then runs only the requested plans or modules.

## Result artifacts

The wrapper prints the run directory and leaves these artifacts:

- `wallet.log`: wallet process log
- `runner.log`: mirrored official runner output
- `results/`: exported OIDF result archives
- `results/*-config.json`: generated OIDF config files
- `results/*-wallet-activity.json`: the wallet's activity log per plan (every token and credential request and response with its body). The certification submission asks for this client-side log with the VCI plans

The Python runner also prints the local `plan-detail.html?plan=...` URLs.

Use this query to summarize important runner lines:

```bash
rg -n \
  "Results for \\[[0-9]+\\]|Overall totals|\\*\\* SOME TEST|\\*\\* Exiting|no-claims-in-dcql-query|invalid-client-id-prefix" \
  "$OIDF_RUN_DIR/runner.log"
```

When updating [Current conformance results](./conformance-results.md), include the suite tag, suite revision, wallet mode, run directory, runner log path, result matrix, and any targeted rerun evidence that narrows down a failure.

## Outbound TLS

Strict wallets verify HTTPS certificates by default. The local suite's self-signed nginx certificate has no subject alternative names (SANs), so the wrapper passes `--tls-verify=false` in local mode. Hosted runs verify certificates.

Set `OIDF_TLS_VERIFY=true|false` to override this default. Use `OIDF_TLS_CA=/path/to/dev-ca.pem` to add trusted CA certificates. For verification to pass, the suite certificate must also have a SAN matching its hostname.

## Environment overrides

- `CONFORMANCE_MODE`: `local` (default) or `hosted` for the OIDF hosted service
- `CONFORMANCE_SERVER`: local conformance suite base URL. Defaults to `https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL`: local callback/helper base URL. Defaults to `CONFORMANCE_SERVER`
- `CONFORMANCE_SERVER_MTLS`: local mTLS base URL. Defaults to `https://localhost:8444/`
- `OIDF_WALLET_MODE`: wallet validation mode for the run, `strict` (default) or `debug`. Debug mode fails the negative modules listed in [Current conformance results](./conformance-results.md)
- `PORT`: wallet port. Defaults to a free local port
- `OIDF_RUN_DIR`: keep all runner artifacts in a chosen directory instead of a temp dir
- `OIDF_SUITE_DIR`: use an existing conformance suite checkout for runner/templates instead of downloading the latest release archive
- `OIDF_SUITE_TAG`: expected conformance suite tag when `OIDF_SUITE_DIR` or `OIDF_SUITE_URL` is used
- `OIDF_WALLET_DIR`: reuse a specific wallet store
- `EUDI_DEV_HOME`: home directory of the wrapper's wallet (default `<run dir>/home`, which keeps it out of the instance registry in your own home)
- `EUDI_DEV_STORAGE`: the storage backend of the wallet under test (`file`, the default, `memory`, or a `postgres://` URL). The wrapper passes the environment through to `wallet serve`. Run the matrix once per backend before a release
- `OIDF_WALLET_URL`: an externally managed wallet to test (for example the strict conformance host). The wrapper then drives that wallet over its API instead of starting its own, and fetches the wallet CA from `/api/certificates/ca`
- `OIDF_WALLET_BASE_URL`: public https base URL for the wallet (a tunnel terminating TLS in front of the wallet port). Required for tunnel-based hosted runs because the hosted suite fetches the wallet status list itself
- `OIDF_WALLET_ISSUER_URL`: override the wallet HTTPS issuer URL if needed. Defaults to `OIDF_WALLET_BASE_URL` when that is set
- `OIDF_WALLET_CA_CERT`: override the shared wallet CA PEM path
- `OIDF_VCI_CLIENT_ID`: override the configured OID4VCI client ID
- `OIDF_VCI_REDIRECT_URI`: override the configured OID4VCI redirect URI
- `OIDF_VCI_ALIAS`: convenience alias used by the default `OIDF_VCI_REDIRECT_URI`
- `OIDF_SUITE_URL`: override the suite tarball URL. Defaults to the latest upstream release archive
- `OIDF_VP_MODULES`: comma separated module names to run instead of each VP plan's own list, for targeted reproductions (a plan with one module of interest). Do not use it for certification runs
- `OIDF_MODULE_IDLE_TIMEOUT`: seconds without `run-test-plan.py` output before the harness cancels the stuck modules on the suite (the suite records each as a failure and the plan continues). If the run still produces no output after the cancel, the harness terminates it. Defaults to `180`, set `0` to disable
- `OIDF_REQUEST_TIMEOUT`: seconds the monitor waits for a suite API response. Defaults to `20`, set `60` on a loaded machine
- `EUDI_REMOTE_TIMEOUT`: how long the wallet waits for a counterparty, as a Go duration (`45s`, `2m`). The wrapper sets `120s` because the suite can take tens of seconds to answer under load (the wallet's own default is `15s`). An unparseable value is ignored
- `OIDF_KEEP_SUITE_DB`: set to `1` to keep the local suite database after a run. By default the wrapper drops it, since a database holding many runs slows the server enough to stall a run

## Hosted mode

Hosted mode creates private plans on the OIDF service.

The hosted suite fetches the wallet status list itself, so the wallet needs a public https origin.

The default hosted target is the demo service. Certification runs go to the production service, which needs its own token. The token comes from `OIDF_TOKEN` in `.env` (or export `CONFORMANCE_TOKEN`). Tokens are per instance (a production token returns 401 on the demo host).

On the production service the wrapper runs only the certifiable HAIP plans, complete and unfiltered. The alpha Final plans run against the local suite or the hosted demo service.

### Strict conformance host

The hosted strict wallet at `https://strict.eudi-test.dev` is the certification target. Deploy it with `./deploy.sh strict <tag>` from [`examples/public-demo/`](../examples/public-demo/). Its public proxy allows GET and HEAD, including authorization requests. The harness uses an SSH tunnel for management API operations:

```bash
ssh -N -L 18085:127.0.0.1:18086 root@<host> &

CONFORMANCE_MODE=hosted \
CONFORMANCE_SERVER=https://www.certification.openid.net/ \
OIDF_WALLET_URL=http://127.0.0.1:18085 \
OIDF_WALLET_ISSUER_URL=https://strict.eudi-test.dev \
OIDF_VCI_ALIAS=oid4vc-dev-vci-strict \
OIDF_REQUEST_TIMEOUT=60 \
  scripts/oidf-wallet-conformance.sh
```

The wrapper starts no wallet of its own. It drives the tunneled instance over its API, including the per-module conformance switch. `OIDF_VCI_ALIAS` must match the redirect URI of the deployed wallet (the compose file sets `oid4vc-dev-vci-strict`). It fetches the wallet CA from the wallet's `/api/certificates/ca`. Deploy the release under certification before the run.

### Local wallet through a tunnel

For a local wallet, start a tunnel that terminates TLS in front of the wallet port and pass it as `OIDF_WALLET_BASE_URL`. The wallet then serves its issuer metadata and status list on that origin:

```bash
ngrok http 18085

CONFORMANCE_MODE=hosted \
CONFORMANCE_SERVER=https://www.certification.openid.net/ \
PORT=18085 \
OIDF_WALLET_BASE_URL=https://<tunnel-host> \
OIDF_REQUEST_TIMEOUT=60 \
  scripts/oidf-wallet-conformance.sh
```

Hosted-mode plans are private. Open the printed `plan-detail.html?plan=...` URLs while signed into the OIDF account that owns the bearer token.

To clear the account's plans on the hosted service between attempts:

```bash
scripts/oidf-delete-hosted-plans.sh
```

It deletes every plan owned by the token on `CONFORMANCE_SERVER` (default production). Published plans are immutable. The script lists them and keeps them.
