# Examples

Runnable integration scenarios live under [`examples/`](../examples/README.md).

Each scenario includes pinned versions, compose files, setup scripts and flow diagrams.

## Scenarios

### Keycloak issuer + eudi-dev wallet

Folder: [`examples/keycloak-issuer-wallet`](../examples/keycloak-issuer-wallet/README.md)

Runs Keycloak `26.7.2` as an OpenID4VCI issuer and redeems the offer with an `eudi-dev` wallet.

It includes:

- a Keycloak compose setup
- issuer bootstrap scripts
- a helper to create a pre-authorized credential offer
- a wallet redemption helper

### Keycloak verifier + keycloak-extension-oid4vp

Folder: [`examples/keycloak-verifier-oid4vp`](../examples/keycloak-verifier-oid4vp/README.md)

Runs Keycloak `26.7.2` as an OpenID4VP verifier with `keycloak-extension-oid4vp` and `eudi-dev` as the wallet.

It includes:

- a provider download script for the published extension jar
- wallet generation helpers
- verifier bootstrap scripts
- a headless same-device login test
- a browser-driven command-line flow that works with a registered `eudi-dev` wallet

### Keycloak issuer + verifier demo app

Folder: [`examples/keycloak-issuer-verifier-app`](../examples/keycloak-issuer-verifier-app/README.md)

One Keycloak `26.7.2` instance signs users in with their wallet (`keycloak-extension-oid4vp`, subject-binding model) and issues a membership credential during the first login. Later logins present the PID together with that credential and need no password. A Go relying party runs the login.

It includes:

- a Keycloak compose setup with the OID4VP provider jar, the realm import, and the wallet CA in its truststore
- a static realm with the verifier, the subject-binding first broker login flow, the membership credential scope, and the trust material
- a bootstrap script that adds a CA-issued realm signing key
- a small Go relying party with a wallet sign-in
- HAIP verifier settings using `haip-vp://`, `direct_post.jwt`, and `x509_hash`
- a headless smoke test that runs the first (password plus offer) and second (passwordless) login

### Keycloak + web wallet (web URLs instead of custom schemes)

Folder: [`examples/keycloak-web-wallet`](../examples/keycloak-web-wallet/README.md)

Runs a Keycloak `26.7.2` issuer and verifier, the `eudi-dev` wallet and a demo UI in one compose project. Wallet links use `/authorize` and `/credential-offer` web URLs. Verification starts as a browser OIDC login.

Use this example for container setups, automated tests or platforms without custom URL handlers.

It includes:

- one compose project where all services share one network namespace, so every URL is plain `localhost` for both the host browser and the containers
- a demo UI (port 9090) with localhost wallet links for issuance and an OIDC login for verification
- static issuer and verifier realms reused from the 2 smaller examples, plus an admin-API step that points the verifier's `walletScheme` / `trustListUrl` at the wallet
- headless demos that call `GET /credential-offer` and `GET /authorize`
- automatic export of the wallet CA into Keycloak's truststore for the status list revocation check

### Keycloak + public demo wallet

Folder: [`examples/keycloak-web-wallet-public`](../examples/keycloak-web-wallet-public/README.md)

Runs the web wallet scenario against the public demo at `https://eudi-test.dev` (or any other `--demo` deployment). Keycloak and the demo UI run locally.

It includes:

- a compose project that reuses the realms, extension jar, demo UI, and scripts of `keycloak-web-wallet`
- an ngrok tunnel in front of the local Keycloak, since the public wallet fetches the request object and calls the token endpoint server side (or set `KEYCLOAK_PUBLIC_URL` to your own public URL)
- the same admin-API step pointing the verifier's `walletScheme` / `trustListUrl` at the public wallet

### Load test target

Folder: [`examples/load-test`](../examples/load-test/README.md)

2 wallet servers share one Postgres database behind an nginx ingress. Requests can go to either server, and both serve the same wallet. Use it as the target for load and performance tests of verifiers, issuers and the wallet.

It includes:

- a compose file with Postgres, 2 wallet servers and nginx
- an nginx config with round robin for API clients and a sticky session for browsers
- `loadtest`, a Go load generator that drives issuance, presentation and listing concurrently and checks that nothing was lost
