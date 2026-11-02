# Examples

Runnable integration scenarios live in this directory.

See [docs/examples.md](../docs/examples.md) for an overview.

Each example should be self-contained in its own subfolder and include:

- a short `README.md`
- any compose files, scripts, or fixtures needed to run it
- the exact versions or assumptions used to test the scenario

Examples use fixed ports, demo identities and static Keycloak realms to make setup predictable. Bootstrap scripts add values that are only available at runtime, such as generated keys and trusted list URLs.

The example scripts are written for Bash. On Windows, run them from Git Bash or WSL. The wallet flows run on every platform. They fall back to `eudi wallet accept '<uri>'` when custom URL handlers are unavailable.

## Scenarios

| Folder | Purpose |
|--------|---------|
| `keycloak-issuer-wallet` | Smallest issuer example: one imported realm, one demo user, one credential configuration, and `eudi-dev` as the wallet |
| `keycloak-verifier-oid4vp` | Smallest verifier example: one imported realm plus `keycloak-extension-oid4vp`, using `eudi-dev` as the wallet |
| `keycloak-issuer-verifier-app` | Combined issuance and HAIP verification demo with a small Go app. Uses `haip-vp://`, `direct_post.jwt`, `x509_hash`, and runtime trust material where needed |
| `keycloak-web-wallet` | Issuer, verifier, and the wallet as a web wallet in one Docker compose project with a demo UI. Issuance and verification use web URLs (`/credential-offer`, `/authorize`) in place of custom schemes |
| `keycloak-web-wallet-public` | The `keycloak-web-wallet` scenario against the shared public demo wallet (`https://eudi-test.dev`). An ngrok tunnel exposes the local Keycloak to the public wallet |
| `keycloak-public-demo` | A released Keycloak or a build of your branch as issuer and verifier next to a wallet, with a start page for issuance and wallet sign-in. Runs locally or behind a TLS proxy |
| `public-demo` | Internet-facing shared demo deployment: Caddy with automatic TLS in front of the wallet in `--demo` mode (see [docs/public-demo.md](../docs/public-demo.md)) |
| `kubernetes` | A wallet configured with YAML files in ConfigMaps, without a database or a persistent volume. Variants for a custom Helm chart, Kustomize and the published chart |
| `load-test` | Two wallet servers on one Postgres database behind an nginx ingress. The target for load and performance tests (see [examples/load-test](load-test/README.md)) |
