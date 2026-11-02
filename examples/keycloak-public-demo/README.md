# Keycloak wallet demo

This example runs Keycloak as issuer and as OpenID4VP verifier next to an eudi-dev wallet, with a static start page. It works with a released Keycloak image or a build of your own branch.

The start page has three parts, in any order. "How to use" explains the caveats.

- **Get a credential.** Sign in and Keycloak shows a pre-authorized code or authorization code offer as a QR code and a link, through its `verifiable_credential_offer` action. Keycloak requires a key attestation and checks it against the wallet provider.
- **Sign in.** Keycloak offers the password or the wallet. The page then shows the claims from Keycloak's ID token. Keycloak requests the credential with `direct_post.jwt`, checks its issuer and links the login to the demo account.
- **See the configuration.** Open the realm's admin console with the read-only `viewer` account. "Trust & certificates" lists the trusted lists and the issuer's metadata and keys.

## Run it locally

Start a wallet and the stack, then create the realm:

```bash
eudi-dev wallet serve --port 18095 --base-url http://localhost:18095

export KEYCLOAK_ADMIN_PASSWORD=admin WALLET_URL=http://localhost:18095
docker compose up -d
./setup-realm.sh
```

Open <http://localhost:8181>. The setup needs `curl`, `jq` and `openssl`.

Keycloak has no way to accept a wallet it does not know, so `setup-realm.sh` reads the wallet's client ID from `/api/config` and registers a client that authenticates with the wallet attestation. A real issuer cannot do this. Rerun the setup if the wallet provider key changes.

Keys live in `state/`, which `deploy.sh` keeps on the host. All variants share them, so credentials outlive a new realm and one issuer list covers every variant.

## Keycloak versions

| Setting | Default | Purpose |
| --- | --- | --- |
| `KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak:26.8.1` | The image to run |
| `KEYCLOAK_FEATURES` | All features the demo uses | Keycloak refuses to start with a feature it does not know, so older versions need a shorter list |
| `KEYCLOAK_BUILD` | The reported version | The name in the page footer |
| `KEYCLOAK_BUILD_URL` | None | The build's pull request. The page shows it as a headline link |
| `KEYCLOAK_BUILD_TITLE` | The build name | The headline's text, for example the pull request's title |
| `WALLET_SCHEME` | `openid4vp://` | Where Keycloak's wallet sign-in link points |

`setup-realm.sh` reads what the server supports and adapts:

| Keycloak has | Trust | Without it |
| --- | --- | --- |
| `etsi-trust-list` ([keycloak#48106](https://github.com/keycloak/keycloak/issues/48106)) | Fetches the wallet's Wallet Provider list and a list of the demo's issuer CA | Falls back to `default-trust` |
| `default-trust` | Copies the wallet's root CA, the wallet provider key and the issuer CA once | No key attestation, wallet client or wallet sign-in |
| `oid4vp` | | The page hides the login step |
| `attestation-based` client authenticator | | The wallet client is a public client named after the wallet's URL |

The `eudi-dev` login theme in `themes/` matches the wallet.

Keycloak shows offers and wallet sign-ins as standard `openid-credential-offer://` and `openid4vp://` links and QR codes. Scan the QR code with a wallet or paste the link into one. Keycloak versions after 26.8.1 also accept a web address in `WALLET_SCHEME`, for example the wallet's `/authorize` endpoint, which opens a web wallet directly.

With an authorization code offer, the wallet signs in at Keycloak too. Sign in on the start page first and the wallet uses that session. Otherwise, in the same browser, the wallet's sign-in ends the first tab's login, so Keycloak asks for the password there again. The credential is already in the wallet.

The credential uses a Keycloak background and logo from `web/card/`, which the wallet fetches from the start page. `credential-background.png` is Keycloak's own login background.

To run a build of your own branch:

```bash
export KEYCLOAK_DIR=../../../keycloak
./deploy.sh build
./deploy.sh image
KEYCLOAK_IMAGE=keycloak-public-demo:local KEYCLOAK_BUILD=my-branch docker compose up -d
```

## Deploy to a host

Copy `deploy.env.example` to `deploy.env` and fill in the hosts. Git ignores `deploy.env`. Then run `./deploy.sh all`.

`deploy.sh` needs a TLS proxy on the host. The stack joins the proxy's Docker network, `keycloak-public-demo` unless `PROXY_NETWORK` says otherwise. The proxy reaches them as `keycloak-base:8080`, `keycloak-<variant>:8080` and `demo-web:8080`. [`../public-demo/Caddyfile`](../public-demo/Caddyfile) has blocks for this next to the public demo wallet, including the path routing and the page's Content Security Policy.

With `KEYCLOAK_DIR` set, `./deploy.sh all` packs that checkout's distribution into an image, copies it to the host over ssh and shows the branch name in the footer. Otherwise the host pulls `KEYCLOAK_IMAGE`.

## Wallet registration

`RELYING_PARTY_ID` makes setup enrol one access certificate for all variants at the wallet's registrar. That key signs the issuer metadata and the wallet sign-in requests, and the metadata carries the registration certificate as `issuer_info`. Keycloak does not send `verifier_info` yet, so the wallet warns about a missing registration certificate at sign-in.

The wallet needs the registration and the list on every start. See `--relying-parties`, `--catalog`, `--trusted-list` and `--trusted-list-ca` in [`../public-demo/docker-compose.yml`](../public-demo/docker-compose.yml). They live there, so a new variant changes nothing on the wallet.

## Variants

Several Keycloak versions can run side by side, for example a release and a branch:

```bash
./deploy.sh all                      # the base at the root of both sites
VARIANT=my-branch ./deploy.sh all    # at /my-branch/ on both sites
VARIANT=my-branch ./deploy.sh remove
```

A variant reads `deploy.env.my-branch` on top of `deploy.env`, and needs its own `KEYCLOAK_PORT`. Each one is a separate Keycloak with its own data. All share the base's admin password and the one start page container. The page header lists the running variants, from a `variants.json` that `deploy.sh` publishes. Deploy the base first.

## Protection

The deployed demo is public and may run an unreleased build, so:

- **Admin access:** the admin console and master realm are public like on any Keycloak, with brute force protection on the master realm. `deploy.sh` generates the admin password on the host and runs the setup through an ssh tunnel to a port bound to the host's loopback.
- **Read-only console:** the demo realm's console accepts the account `viewer` with password `viewer`. Its roles only allow reading the realm.
- **Isolation:** Keycloak and the start page share a network only with the proxy, so they cannot reach the wallets. Containers drop all capabilities, and have memory, CPU and process limits.
- **Abuse:** the Caddy blocks limit requests per client address, more strictly for tokens, logins and offers, and cap the request body size.
- **Accounts:** registration, password reset, the account console and dynamic client registration are off. The wallet sign-in links to the demo account and cannot create users.
- **Trust:** the wallet sign-in trusts only the issuer CA that `setup-realm.sh` creates, so it is not an official list. The private keys of the CA and the list signer exist only while the script runs.
- **Sessions:** tokens and sessions are short lived.

The demo account is shared and its password is public. Data is test data only.
