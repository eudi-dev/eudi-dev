#!/usr/bin/env bash
# Runs the image as Kubernetes runs it in examples/kubernetes: a read-only
# root filesystem, a writable /tmp and the configuration mounted at /config.
# The wallet must load every file, and a CLI command inside the container
# must reach the running wallet.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-eudi-dev:container-config-test}"
NAME="eudi-container-config-test-$$"

if [[ -z "${SKIP_BUILD:-}" ]]; then
  docker build -q -t "$IMAGE" "$PROJECT_DIR" >/dev/null
fi

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then docker logs "$NAME" 2>&1 | tail -50 || true; fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

docker run -d --name "$NAME" --read-only --tmpfs /tmp \
  -v "$PROJECT_DIR/examples/kubernetes/config:/config:ro" \
  -e EUDI_DEV_CONFIG=/config -e EUDI_DEV_DEMO=true \
  -p 127.0.0.1::8085 "$IMAGE" >/dev/null
BASE="http://$(docker port "$NAME" 8085/tcp | head -1)"

for _ in $(seq 60); do
  curl -sf "$BASE/healthz" >/dev/null && break
  sleep 1
done
curl -sf "$BASE/healthz" >/dev/null || fail "the wallet did not start"

api() { curl -sf -H 'Accept: application/json' "$BASE$1"; }

[[ "$(api /api/templates/employee-card | jq -r .configured)" == true ]] || fail "employee-card is not a configured template"
[[ "$(api /api/templates/pid-sdjwt | jq -r .configured)" == true ]] || fail "pid-sdjwt is not a configured template"
api /api/credentials | jq -e 'any(.[]; .id == "employee-alice")' >/dev/null || fail "the credential employee-alice is missing"
api /api/catalog/attestations | jq -e 'any(.[]; .name == "Employee card")' >/dev/null || fail "the catalogue entry is missing"
for id in NLTEST.00000042 NLTEST.00000043; do
  api "/api/registrar/wrp/$id" >/dev/null || fail "the relying party $id is missing"
done

docker exec "$NAME" eudi wallet serve --check >/dev/null || fail "wallet serve --check refused the configuration"

# The home directory is read-only, so the CLI finds the wallet through the
# instance file in /tmp.
output="$(printf 'name: container-check\nformat: sdjwt\nvct: urn:example:container-check:1\nclaims:\n  ok: true\n' |
  docker exec -i "$NAME" eudi templates import - 2>&1)" || fail "templates import failed: $output"
[[ "$output" != *"new wallet in memory"* ]] || fail "the CLI used a memory wallet instead of the server: $output"
api /api/templates/container-check >/dev/null || fail "the imported template did not reach the running wallet"

echo "The container loads the configuration and the CLI reaches its wallet."
