# Every server limits outbound addresses

[ADR 0004](0004-outbound-fetches-are-policed-at-dial-time.md) checks outbound addresses when connecting. Only the public demo used that check. Yet every server fetches URLs from its visitors: `wallet serve` reads credential offers and request URIs, and the decoder of both servers reads the trusted lists, issuer metadata and status lists that an input names. A wallet in a cluster or on a shared host could then reach cloud metadata or internal services for any visitor.

## Decision

`wallet serve` and `decoder` install a policy on startup. By default it allows public addresses and loopback. A developer runs wallet, issuer and verifier on one machine, and loopback keeps that setup working without flags. Private, link local, CGNAT, unique local, unspecified and multicast addresses are refused.

`--allow-private-networks` or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true` lifts the limit for issuers and verifiers on a LAN, in Docker or in a cluster. The Docker image sets the variable, because its verifiers under test run on the Docker host or in other containers.

`--demo` also refuses loopback. It ignores the variable and refuses the flag.

Every policy exempts the operator's destinations at their exact address and port: the server's own origins, the `--trusted-list` URLs and the forward proxy.

## Consequences

A wallet that talks to an issuer on a private network needs the flag. The refusal names it.

A proxied request connects to the proxy only, so the proxy decides where that request goes.

The `validate`, `decode` and other one-shot commands have no limit. Their user supplies every URL.
