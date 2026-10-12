# Reverse proxy setup

The wallet can run behind a reverse proxy in two ways:

- on its own host, such as `https://eudi.example.com`
- under a path prefix on a shared host, such as `https://example.com/some/context`

The path prefix setup applies to the wallet, its demo issuer and verifier, and the proxy dashboard.

## Base URL

Pass the public URL, including the path prefix, as `--base-url`:

```bash
eudi wallet serve --base-url https://example.com/some/context
```

The wallet builds all of its URLs from this value: the issuer identifier, the endpoints in its metadata, the links in credential offers and presentation requests, and the status list and trusted list URLs. Many of these URLs appear in signed credentials and metadata, so request headers do not change them.

Use an https base URL. With an http base URL, the wallet serves its own issuer on a separate HTTPS port (the wallet port plus one), which your proxy does not cover.

The path prefix must not start with one of the wallet's own paths, such as `/api`, `/issuer` or `/decoder`. `wallet serve` refuses to start with such a base URL.

The wallet binds `127.0.0.1`, which suits a proxy on the same host. A proxy on another host or in another container needs `--listen 0.0.0.0` (see [listen address](wallet/serve.md#listen-address)). The Docker image already binds every interface.

## Proxy routes

Route all requests under the path prefix to the wallet. The proxy can strip the prefix or keep it. The wallet accepts both `/some/context/api/version` and `/api/version`.

Issuance needs a few more routes. The specs put issuer metadata at the root of the host and append the issuer path. For the demo issuer `https://example.com/some/context/issuer`, the metadata URL is `https://example.com/.well-known/openid-credential-issuer/some/context/issuer`. Route these paths to the wallet unchanged:

| Path | Used for |
|------|----------|
| `/.well-known/openid-credential-issuer/some/context/issuer` | Issuance from the demo issuer |
| `/.well-known/oauth-authorization-server/some/context/issuer` | Issuance from the demo issuer |
| `/.well-known/openid-credential-issuer/some/context` | The wallet's own issuer metadata |
| `/.well-known/jwt-vc-issuer/some/context` | Verifiers that look up the wallet's signing key there (only for credentials without an `x5c` certificate chain) |

Presentations don't need these routes.

Requests that bypass the proxy, for example through `kubectl port-forward`, are served at the root.

## Forwarded headers

If the proxy strips the prefix, the wallet receives `/api/version` but still needs the prefix for browser-facing URLs. A redirect to `/decoder/`, for example, has to go to `/some/context/decoder/`. The wallet determines the prefix as follows:

1. If the proxy sends `X-Forwarded-Prefix: /some/context`, the wallet uses that value.
2. Otherwise, if the request's host matches the base URL (`example.com`), the wallet uses the path of the base URL. Most proxies forward the `Host` header, so this usually works without extra configuration.
3. Otherwise the request did not come through the proxy, and the prefix is empty.

The wallet applies the prefix to redirects, to links in its web pages, to links in API responses (such as credential images) and to its session cookie. The cookie path is the prefix, so other apps on the same host do not receive it. The cookie is marked `Secure` when the proxy reports that the browser used https.

The wallet reads the browser's host and scheme from `Forwarded` (RFC 7239), or from `X-Forwarded-Host` and `X-Forwarded-Proto`. If these headers or `X-Forwarded-Prefix` don't match the base URL, the wallet logs a warning for each new value. This usually points to a wrong proxy route or `--base-url`.

None of these headers affect the URLs in credentials, metadata or protocol messages. An `X-Forwarded-Prefix` value that isn't a plain path is ignored.

## Istio example

```yaml
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: eudi-dev
spec:
  hosts: [example.com]
  gateways: [istio-system/public-gateway]
  http:
    - match:
        - uri: { prefix: /.well-known/openid-credential-issuer/some/context }
        - uri: { prefix: /.well-known/oauth-authorization-server/some/context }
        - uri: { prefix: /.well-known/jwt-vc-issuer/some/context }
      route:
        - destination: { host: eudi-dev, port: { number: 8085 } }
    - match:
        - uri: { prefix: /some/context/ }
        - uri: { exact: /some/context }
      rewrite: { uri: / }
      headers:
        request:
          set: { X-Forwarded-Prefix: /some/context }
      route:
        - destination: { host: eudi-dev, port: { number: 8085 } }
```

The `X-Forwarded-Prefix` header is optional here, because the gateway forwards the `Host` header. To keep the prefix in the forwarded path, remove `rewrite`.

## nginx example

```nginx
location /some/context/ {
    proxy_pass http://eudi-dev:8085/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /some/context;
    proxy_buffering off;
}
location ~ ^/\.well-known/(openid-credential-issuer|oauth-authorization-server|jwt-vc-issuer)/some/context {
    proxy_pass http://eudi-dev:8085;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`proxy_buffering off` streams wallet events, such as consent requests, to the browser without delay.

## Proxy dashboard

The dashboard of the [debug proxy](proxy.md) also works under a path prefix. Set its public URL with `--dashboard-base-url`:

```bash
eudi proxy --target http://verifier:8080 --dashboard-base-url https://example.com/eudi-proxy
```

Prefix handling works as described for the wallet. Alternatively, have the proxy send `X-Forwarded-Prefix`. To read the dashboard from the CLI, use the same URL: `eudi proxy logs https://example.com/eudi-proxy`.
