# Keycloak wallet demo

This example runs Keycloak as issuer and as OpenID4VP verifier next to an eudi-dev wallet, with a static start page. It works with a released Keycloak image or a build of your own branch.

The start page has three steps:

1. **Get a credential.** Sign in and get a pre-authorized code or authorization code offer. Keycloak requires a key attestation and checks it against the wallet provider.
2. **Log in with the wallet.** Keycloak requests the credential with `direct_post.jwt`, checks its issuer and links the login to the demo account.
3. **See the configuration.** Open the realm's admin console with the read-only `viewer` account.

## Run it locally

Start a wallet and the stack, then create the realm:

```bash
eudi-dev wallet serve --port 18095 --base-url http://localhost:18095

export KEYCLOAK_ADMIN_PASSWORD=admin
docker compose up -d
WALLET_URL=http://localhost:18095 ./setup-realm.sh
```

Open <http://localhost:8181>. The setup needs `curl`, `jq` and `openssl`.

Keycloak has no way to accept a wallet it does not know, so `setup-realm.sh` reads the wallet's client ID from `/api/config` and registers a client that authenticates with the wallet attestation. A real issuer cannot do this. Rerun the setup if the wallet provider key changes.

Each setup creates a new issuer CA, so credentials issued before it fail the wallet login. Delete them and get a new one.

## Keycloak versions

| Setting | Default | Purpose |
| --- | --- | --- |
| `KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak:26.8.1` | The image to run |
| `KEYCLOAK_FEATURES` | All features the demo uses | Keycloak refuses to start with a feature it does not know, so older versions need a shorter list |
| `KEYCLOAK_BUILD` | The reported version | The name in the page footer |
| `WALLET_SCHEME` | See below | Where the wallet login link points |

`setup-realm.sh` reads what the server supports and adapts:

| Keycloak has | Trust | Without it |
| --- | --- | --- |
| `etsi-trust-list` ([keycloak#48106](https://github.com/keycloak/keycloak/issues/48106)) | Fetches the wallet's Wallet Provider list and a list of the demo's issuer CA | Falls back to `default-trust` |
| `default-trust` | Copies the wallet's root CA, the wallet provider key and the issuer CA once | No key attestation, wallet client or wallet login |
| `oid4vp` | | The page hides the login step |
| `attestation-based` client authenticator | | The wallet client is a public client named after the wallet's URL |

Released versions use the standard `openid4vp://` link, because Keycloak 26.8.1 cannot point the link at a web address. Scan the QR code with a wallet or paste the link into one. A build from a checkout reports version `999.*` and links straight to the wallet's `/authorize` endpoint. Set `WALLET_SCHEME` to choose yourself.

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
- **Accounts:** registration, password reset, the account console and dynamic client registration are off. The wallet login links to the demo account and cannot create users.
- **Trust:** the wallet login trusts only the issuer CA that `setup-realm.sh` creates, so it is not an official list. The private keys of the CA and the list signer exist only while the script runs.
- **Sessions:** tokens and sessions are short lived.

The demo account is shared and its password is public. Data is test data only.
