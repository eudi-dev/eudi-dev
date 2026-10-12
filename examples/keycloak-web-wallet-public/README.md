# Keycloak + public demo wallet (eudi-test.dev)

This example connects local Keycloak issuer and verifier services to the shared wallet at <https://eudi-test.dev>. It reuses the realms, extension, demo UI and scripts from [`keycloak-web-wallet`](../keycloak-web-wallet/README.md).

The public wallet fetches request objects and calls token endpoints from its server, so Keycloak must be reachable from the internet. `start.sh` opens an ngrok tunnel, and `--proxy-headers=xforwarded` lets Keycloak generate public URLs for tunneled requests.

## Requirements

- Docker compose (as in the local example)
- The [ngrok CLI](https://ngrok.com/download) with any account, or your own public https URL that forwards to the local Keycloak (set `KEYCLOAK_PUBLIC_URL` to skip ngrok)

On ngrok's free plan, click through the browser warning page on the first visit. The wallet's server-to-server requests are unaffected. A paid plan removes the warning. See [ngrok's free-plan limits](https://ngrok.com/docs/pricing-limits/free-plan-limits#removing-the-interstitial-page).

## Quick start

```bash
cd examples/keycloak-web-wallet-public
./start.sh
```

Then open the demo UI at <http://localhost:9090>:

- **Issuance**: create an offer, open its wallet link and approve it in the wallet UI. The wallet imports the membership credential.
- **Verification**: choose "Login with wallet". Keycloak opens through the tunnel and offers a wallet link. Approve the PID presentation in the wallet UI. The browser returns to the app. The app shows the ID-token claims.

Stop everything with `docker compose down` and `kill $(cat .ngrok.pid)`.

## Differences from the local example

- **Shared data.** All visitors can see and delete the credentials you issue. Periodic resets remove them. Use test data only.
- **Browser consent.** Approve in the browser that started the flow. The `eudi_session` cookie routes the dialog to that browser. Credentials and activity logs remain shared.
- **Interactive flows.** Use the demo UI and approve consent in the browser. The public wallet requires browser consent for browser flows. The API approval in `demo-issuance.py` and `demo-verification.py` cannot complete them.
- **Trust setup.** Keycloak's default TLS truststore already trusts the public wallet's certificate. The setup script configures `trustListUrl` as `https://eudi-test.dev/api/trustlist` so the verifier can validate wallet-issued credentials. No local CA export is needed.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `WALLET_BASE_URL` | `https://eudi-test.dev` | Public wallet instance used by the example (any `--demo` deployment works, see [docs/public-demo.md](../../docs/public-demo.md)) |
| `KEYCLOAK_PUBLIC_URL` | set by `start.sh` via ngrok | Public origin that forwards to the local Keycloak |
| `NGROK_DOMAIN` | none | Reserved ngrok domain for a stable tunnel URL |
| `KEYCLOAK_PORT` / `APP_PORT` | `9080` / `9090` | Local ports, next free port is picked automatically |

The public wallet resets on its own schedule. Restarting this example does not reset it.
