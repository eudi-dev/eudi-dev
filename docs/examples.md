# Examples

Runnable integration scenarios live under [`examples/`](../examples/README.md).

Each scenario includes pinned versions, compose files, setup scripts and flow diagrams.

## Scenarios

### Keycloak wallet demo

Folder: [`examples/keycloak-public-demo`](../examples/keycloak-public-demo/README.md)

Runs Keycloak `26.8.1` as issuer and OpenID4VP verifier next to an `eudi-dev` wallet, with a start page. It works with a released Keycloak or a build of your own branch. The same setup runs at <https://demo.eudi-test.dev>.

It includes:

- a Keycloak compose setup and a realm script that adapts to what the Keycloak build supports
- issuance through Keycloak's credential offer page, with a key attestation checked against the wallet provider
- a wallet sign-in with Keycloak's own OpenID4VP support, linked to the demo account
- a login theme that matches the wallet
- a deploy script for several Keycloak builds side by side behind a TLS proxy

### Keycloak issuer + verifier demo app

Folder: [`examples/keycloak-issuer-verifier-app`](../examples/keycloak-issuer-verifier-app/README.md)

One Keycloak `26.8.1` instance signs users in with their wallet (`keycloak-extension-oid4vp`, subject-binding model) and issues a membership credential during the first login. Later logins present the PID together with that credential and need no password. A Go relying party runs the login.

It includes:

- a Keycloak compose setup with the OID4VP provider jar, the realm import, and the wallet CA in its truststore
- a static realm with the verifier, the subject-binding first broker login flow, the membership credential scope, and the trust material
- a bootstrap script that adds a CA-issued realm signing key
- a small Go relying party with a wallet sign-in
- HAIP verifier settings using `haip-vp://`, `direct_post.jwt`, and `x509_hash`
- a headless smoke test that runs the first (password plus offer) and second (passwordless) login

### Kubernetes

Folder: [`examples/kubernetes`](../examples/kubernetes/README.md)

Runs a wallet on Kubernetes without a database or a persistent volume. Credential templates, baseline credentials, the attestation catalogue and relying parties are YAML files that become ConfigMaps.

It includes:

- a self-contained Helm chart
- the same deployment with Kustomize
- values for the published Helm chart

### Load test target

Folder: [`examples/load-test`](../examples/load-test/README.md)

2 wallet servers share one Postgres database behind an nginx ingress. Requests can go to either server, and both serve the same wallet. Use it as the target for load and performance tests of verifiers, issuers and the wallet.

It includes:

- a compose file with Postgres, 2 wallet servers and nginx
- an nginx config with round robin for API clients and a sticky session for browsers
- `loadtest`, a Go load generator that drives issuance, presentation and listing concurrently and checks that nothing was lost
