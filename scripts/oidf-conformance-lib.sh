#!/bin/sh

set -e
# Source this file so helpers can read and update the wrapper's global settings.

build_local_eudi_dev() {
  if ! command -v go >/dev/null 2>&1; then
    echo "error: Go is required to build the checked-out eudi-dev binary" >&2
    exit 1
  fi

  LOCAL_EUDI_DEV="$RUN_DIR/eudi-dev"
  echo "Building eudi-dev from the current checkout..."
  (
    cd "$ROOT_DIR"
    go build -o "$LOCAL_EUDI_DEV" .
  )
}

pick_port_pair() {
  python3 - <<'PY'
import socket

def port_free(port: int) -> bool:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True

for _ in range(128):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port < 1024 or port >= 65534:
        continue
    if port_free(port) and port_free(port + 1):
        print(port)
        raise SystemExit(0)

raise SystemExit("failed to find a free local port pair")
PY
}

latest_suite_release() {
  python3 - <<'PY'
import json
import urllib.request

url = "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/releases/permalink/latest"
with urllib.request.urlopen(url, timeout=20) as resp:
    release = json.loads(resp.read().decode("utf-8"))
tag = release.get("tag_name")
if not tag:
    raise SystemExit("latest OIDF conformance-suite release did not expose a tag_name")
for source in release.get("assets", {}).get("sources", []):
    if source.get("format") == "tar.gz" and source.get("url"):
        print(tag, source["url"])
        raise SystemExit(0)
raise SystemExit("latest OIDF conformance-suite release did not expose a tar.gz source archive")
PY
}

fetch_suite_source() {
  if [ -n "${OIDF_SUITE_DIR:-}" ]; then
    SUITE_DIR=$OIDF_SUITE_DIR
    SUITE_TAG=${OIDF_SUITE_TAG:-$(git -C "$SUITE_DIR" describe --tags --always 2>/dev/null || printf unknown)}
    if [ ! -f "$SUITE_DIR/scripts/run-test-plan.py" ]; then
      echo "error: OIDF_SUITE_DIR does not look like a conformance-suite checkout: $SUITE_DIR" >&2
      exit 1
    fi
    echo "Using OIDF conformance-suite source: $SUITE_DIR ($SUITE_TAG)"
    return
  fi

  SUITE_DIR="$RUN_DIR/conformance-suite"
  if [ -n "${OIDF_SUITE_URL:-}" ]; then
    SUITE_URL=$OIDF_SUITE_URL
    SUITE_TAG=${OIDF_SUITE_TAG:-unknown}
  else
    # shellcheck disable=SC2046
    set -- $(latest_suite_release)
    SUITE_TAG=$1
    SUITE_URL=$2
  fi
  mkdir -p "$SUITE_DIR"
  echo "Fetching latest official OIDF conformance-suite source..."
  echo "Suite archive: $SUITE_URL ($SUITE_TAG)"
  curl -fsSL "$SUITE_URL" | tar -xz --strip-components=1 -C "$SUITE_DIR"
}

check_local_conformance_server() {
  server_info=$(curl -kfsS "${CONFORMANCE_SERVER%/}/api/server" 2>/dev/null || true)
  if [ -z "$server_info" ]; then
    if curl -kfsS "${CONFORMANCE_SERVER%/}/api/runner/available" >/dev/null 2>&1; then
      return
    fi
  else
    server_tag=$(printf '%s' "$server_info" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("tag") or "unknown"))')
    echo "Local OIDF conformance-suite server: $server_tag"
    if [ -n "${SUITE_TAG:-}" ] && [ "$SUITE_TAG" != "unknown" ] && [ "$server_tag" != "$SUITE_TAG" ]; then
      cat >&2 <<EOF
error: local OIDF conformance-suite server is $server_tag but runner/templates are $SUITE_TAG

Update and restart the local suite, or set OIDF_SUITE_DIR/OIDF_SUITE_TAG to match the running server.
EOF
      exit 1
    fi
    return
  fi
  cat >&2 <<EOF
error: local OIDF conformance-suite is not reachable at ${CONFORMANCE_SERVER%/}

Start the local suite at the release the runner uses (${SUITE_TAG:-unknown}) first.
The server has to run on the host and advertise localhost, not the upstream
localhost.emobix.co.uk, so the wallet trusts its request_uri over TLS (see
docs/conformance-run.md):
  cd ../conformance-suite
  git fetch --tags
  git checkout ${SUITE_TAG:-<release tag>}
  mvn clean package   # with JDK 21
  docker compose -f docker-compose-dev-mac-nodocker.yml up --detach
  java -jar target/fapi-test-suite.jar --fintechlabs.devmode=true --fintechlabs.base_url=https://localhost:8443 --fintechlabs.base_mtls_url=https://localhost:8444 --spring.mongodb.uri=mongodb://127.0.0.1:27017/test_suite

Override CONFORMANCE_SERVER, CONFORMANCE_SERVER_LOCAL, and CONFORMANCE_SERVER_MTLS if your local suite uses different URLs.
EOF
  exit 1
}

# Clear the local suite database after exporting results. Large histories slow requests
# enough to cause test timeouts. Hosted databases are managed separately.
wipe_local_suite_database() {
  [ "$CONFORMANCE_MODE" = "local" ] || return 0
  [ "${OIDF_KEEP_SUITE_DB:-0}" = "1" ] && return 0
  command -v docker >/dev/null 2>&1 || return 0

  # The local suite reads mongodb://127.0.0.1:27017, so its database lives in
  # the container that publishes that port. Other Mongo containers can match a
  # name pattern too.
  container=${OIDF_SUITE_MONGO_CONTAINER:-$(docker ps --filter publish=27017 --format '{{.Names}}' 2>/dev/null | head -n1)}
  [ -n "$container" ] || return 0

  for shell in mongosh mongo; do
    if docker exec "$container" sh -c "command -v $shell" >/dev/null 2>&1; then
      if docker exec "$container" "$shell" --quiet --eval 'db.getSiblingDB("test_suite").dropDatabase()' >/dev/null 2>&1; then
        echo "Dropped the local suite database in $container"
      else
        echo "warning: could not drop the local suite database in $container" >&2
      fi
      return 0
    fi
  done
}
