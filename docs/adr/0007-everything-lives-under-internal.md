---
status: accepted (expected to be revisited, see Direction)
---

# Everything lives under internal/

The CLI lives in `cmd/`. Supporting packages live under `internal/`. Only `main.go` and standalone examples sit outside those directories, all as `package main`. External projects cannot import the internal packages. This lets their APIs evolve with the CLI and wallet server without a public compatibility commitment.

## Direction

The format packages may become public libraries, starting with `sdjwt` and `mdoc`. Revisit this decision once their APIs are stable.

## Consequences

Publishing a package requires reviewing its API for external callers. Some interfaces reflect this tool's debugging needs: the client identifier checks in `internal/oid4vp` return warning strings so debug mode can report a finding and continue. Those choices may not suit a library consumer.
