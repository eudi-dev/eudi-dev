# Contributing

## Prerequisites

- **Go 1.26+**
- **Node.js 22+** and npm (for E2E tests only)

## Setup

```bash
git clone https://github.com/dominikschlosser/eudi-dev.git
cd eudi-dev
go build ./...
go test ./...
```

## Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Specific package
go test ./internal/sdjwt/...

# Verbose
go test -v -count=1 ./internal/wallet/...
```

`EUDI_DEV_STORAGE` selects the storage backend for tests. CI runs the tests on file, memory and Postgres storage. To test the other backends locally:

```bash
EUDI_DEV_STORAGE=memory go test ./...
docker run -d --name eudi-pg -e POSTGRES_PASSWORD=pg -e POSTGRES_DB=eudi -p 5432:5432 postgres:16-alpine
EUDI_DEV_STORAGE='postgres://postgres:pg@localhost:5432/eudi?sslmode=disable' go test ./...
```

Each test uses its own wallet directory. Rows from earlier runs stay in the database. Use a fresh database when old rows could affect a measurement.

### E2E Tests

E2E tests use Playwright. Its `webServer` builds the binary and starts `decoder`. The tests run against that live server:

```bash
cd e2e
npm install
npx playwright install --with-deps chromium
npx playwright test
```

[examples/load-test](examples/load-test/README.md) checks correctness under load against two wallet servers on one database.

The Docker specs (`docker.spec.js`) need a running Docker daemon. Skip them with `--grep-invert docker`. The suite's wallet also reads `EUDI_DEV_STORAGE`. CI runs the suite once per backend.

## Code Style

- Run `go vet ./...` before committing
- CI runs `golangci-lint` (errcheck, errorlint, gosec, govet, staticcheck, unused, plus gofmt and goimports as formatters)
- Imports: stdlib first, then external deps, then internal packages (enforced by goimports)
- Use `internal/jsonutil` for type assertions on `map[string]any`
- Defaults (ports, timeouts) go in `internal/config/defaults.go`

## Test Patterns

- Use `t.Helper()` in test helper functions
- Use `mock.GenerateKey()`, `mock.GenerateSDJWT()`, `mock.GenerateMDOC()` for test fixtures
- Table-driven tests with `t.Run()` for multiple cases
- Test files are in the same package as the tested code (`foo_test.go`)

## Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for package layout and data flow.

## Pull Requests

1. Create a feature branch from `main`
2. Ensure `go build ./...`, `go vet ./...`, and `go test ./...` pass
3. One feature or fix per PR
4. Update docs in `docs/` if adding or changing CLI flags

## Sign-off (DCO)

Every commit needs a [Developer Certificate of Origin](https://developercertificate.org/) sign-off. `git commit -s` adds the `Signed-off-by` trailer. Pull requests are checked for it. To sign off an existing branch: `git rebase --signoff main`.

## Releases

A `v*` tag starts the release workflow. It builds the binaries and the Docker image and picks the channels from the version:

| Tag | GitHub release | Docker tags | Homebrew |
|---|---|---|---|
| Newest stable version, such as `v3.0.0` | latest | `v3.0.0`, `latest`, `beta` | updated |
| Older line, such as `v2.6.3` after 3.0.0 | regular | `v2.6.3` | unchanged |
| Prerelease, such as `v3.0.0-beta.1` | prerelease | `v3.0.0-beta.1`, and `beta` while it is the newest version | unchanged |

### Branches

`main` holds the next version. After 3.0.0, `main` collects the changes for 3.1.0 until `v3.1.0` is tagged on it. Betas are tags on `main` too.

A patch for a released version goes on a branch from its tag. For 3.0.1, branch `3.0.x` from `v3.0.0`, fix it there and tag `v3.0.1` on that branch. Then merge the fix back to `main`.
