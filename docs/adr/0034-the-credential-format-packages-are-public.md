# The credential format packages are public

Supersedes [ADR-0007](0007-everything-lives-under-internal.md).

Go has no maintained mdoc library, and a library for the SD-JWT VC layer is missing too. Other Go projects need to parse and verify mdoc and SD-JWT VC credentials. eudi-dev tests its parsers and verifiers against real issuers, verifiers and the OpenID conformance suite.

## Decision

`pkg/mdoc`, `pkg/sdjwt` and `pkg/sdjwt/delegate` are importable packages of the module `github.com/eudi-dev/eudi-dev/v3`. Everything else stays under `internal/`.

The packages stay in this module. A separate repository would need its own releases and a copy of the internal helper packages. In one module, a change to a format package and to the wallet lands in one commit and one release. An importer downloads the whole module.

The packages follow these rules:

- The exported API uses only types from the standard library and `pkg/`. `pkg/api_test.go` type-checks every package under `pkg/` and enforces this. A dependency or an internal package can then change without breaking an importer.
- The exported API has no `map[any]any` (raw CBOR decoder output). A caller reads COSE headers through a function such as `Document.IssuerCertificates`. The decoder of eudi-dev reads them from the raw bytes with `internal/cborview`.
- A verification function returns an error. Sentinel errors such as `ErrSignature`, `ErrExpired` and `ErrNotYetValid` let a caller tell the cases apart with `errors.Is`.
- A caller passes the verification key. Whether the key is trusted is the caller's decision.
- The exported API follows semantic versioning with the module version. A breaking change needs a new major version.

The debugging results of eudi-dev live in `internal/verifyreport`. It turns the errors of the packages into a result with a `SignatureValid` flag and lists of errors and warnings. `eudi validate` and the decoder show this result.

`Parse` is strict in both packages. `sdjwt.Parse` rejects an SD-JWT that RFC 9901 §7.1 rejects. `mdoc.Parse` rejects an mdoc when a member required by ISO/IEC 18013-5 is missing or unreadable. `ParseLenient` keeps what it can read and lists the faults in `Deviations`. It is for tools that display a faulty credential, and eudi-dev itself uses it. `Token.Warnings` holds notes that don't stop processing.

`pkg/sdjwt/delegate` implements draft-ietf-oauth-delegate-sd-jwt-00. It is a package of its own because the draft is not final. Its API can change with the draft in a minor release.

## Direction

The client identifier checks of `internal/oid4vp` return warning strings and stay internal. The status list client, the trusted list reader and the type metadata resolver stay internal as well. Their exported functions carry findings and configuration types of this tool. Each one needs the same API review before it moves to `pkg/`.

A wallet server that another program embeds needs a wallet without process-wide state. The runtime registry, the memory store and the active theme exist once per process. A public wallet package comes after that change.

## Consequences

A change to an exported declaration of `pkg/` is a public API change. It needs a changelog entry, and a breaking one waits for the next major version.
