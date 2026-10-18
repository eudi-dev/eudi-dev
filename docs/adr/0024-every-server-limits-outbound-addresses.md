# Every server limits outbound addresses

The wallet checks outbound addresses when it connects ([ADR 0004](0004-outbound-fetches-are-policed-at-dial-time.md)). Every server fetches URLs supplied by its visitors: `wallet serve` reads credential offers and request URIs, and the decoder of both servers reads trusted lists, issuer metadata and status lists referenced in its input. Without a limit, a wallet in a cluster or on a shared host could reach cloud metadata or internal services for any visitor.

## Decision

`wallet serve` and `decoder` install a policy on startup. By default it allows public addresses and loopback. A developer runs wallet, issuer and verifier on one machine, and loopback keeps that setup working without flags. Private, link local, CGNAT, unique local, unspecified and multicast addresses are refused.

`--allow-private-networks` or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true` lifts the limit for issuers and verifiers on a LAN, in Docker or in a cluster. The Docker image sets the variable, because its verifiers under test run on the Docker host or in other containers.

`--demo` also refuses loopback. The flag and the variable lift its limit too, loopback included. `wallet serve` then warns at start that the public demo can connect to local and private addresses. A public demo sets `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=false` to keep the limit in the Docker image.

Every policy exempts the operator's destinations at their exact address and port: the server's own origins, the `--trusted-list` URLs and the forward proxy.

## Consequences

A wallet that talks to an issuer on a private network needs the flag. The error message mentions it.

A proxied request connects to the proxy only, so the proxy decides where that request goes.

The `validate`, `decode` and other one-shot commands have no limit. Their user supplies every URL.
