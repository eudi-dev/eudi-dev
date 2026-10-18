# The base URL is the public identity

The wallet can run behind a reverse proxy, either on its own host or under a path prefix on a shared host. The proxy may strip the prefix before forwarding a request or keep it. It also sends headers such as `X-Forwarded-Host` that describe the browser's URL.

## Decision

The wallet takes every signed or published URL from `--base-url` only. This covers issuer identifiers, metadata endpoints, `request_uri`, `response_uri`, the sign-in callback, status list and trusted list URLs, and the names in certificates.

These URLs appear in credentials and certificates that outlive the request, so they must not depend on how a request was routed. Forwarded headers can also be set by any client. Deriving URLs from them would let a client choose what the wallet signs.

Forwarded headers (`X-Forwarded-Prefix`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `Forwarded`) only affect responses to the browser: redirect targets, the `<base href>` of the web pages, links in API responses, and the path and `Secure` flag of the session cookie. If the headers do not match the base URL, the wallet logs a warning.

A forged header can at most redirect the browser to another path on the same site. The wallet only accepts a plain path in `X-Forwarded-Prefix` and never writes a forwarded host into a response.

`internal/publicpath` implements this for the wallet and the proxy dashboard.

## Consequences

Handlers write redirects such as `/decoder/` as if the server ran at the root. `publicpath` adds the prefix.

Web pages and scripts use relative links. A test in `internal/publicpath` fails if a served page links to a path that starts with `/`.

Links in API responses, such as credential image URLs and trusted list paths, include the request's prefix.

`wallet serve` stores its base and issuer URL. It takes them from `--base-url`, or from the stored base URL when the flag is absent. Commands that issue without a running server embed these stored URLs. One-shot commands such as `wallet accept` and `issue --wallet --iss` use their own URLs for that run only and never store them.

The path prefix must not start with one of the server's own paths. With `--base-url https://example.com/api`, the server could not tell whether `/api/version` is its own API or the version endpoint under the prefix. `wallet serve` and `eudi proxy` refuse such a base URL.
