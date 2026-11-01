#!/usr/bin/env bash
# Deploys the demo to a host behind a TLS proxy. See deploy.env.example for the settings, which come
# from the environment, from deploy.env here, or from ../public-demo/deploy.env.
#
# VARIANT names an extra Keycloak under /<variant>/ next to the base one, for example a branch. It
# also reads deploy.env.<variant>, and shares the base deployment's admin password and start page.
#
# Usage: [VARIANT=name] ./deploy.sh <command>
#   build    build the distribution of KEYCLOAK_DIR, as of its current working tree
#   image    pack that distribution into an image and load it into Docker, also on DEMO_HOST if set
#   up       copy the stack to DEMO_HOST and start it, keeping the data and the admin password
#   realm    recreate the demo realm on DEMO_HOST
#   all      image if KEYCLOAK_DIR is set, then up and realm
#   remove   stop a variant and delete its data
#   status   container status
#   logs     follow the Keycloak log
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# shellcheck disable=SC1091
[[ -f ../public-demo/deploy.env ]] && source ../public-demo/deploy.env
# shellcheck disable=SC1091
[[ -f deploy.env ]] && source deploy.env

BASE_DIR="${KEYCLOAK_DEMO_DIR:-/opt/keycloak-public-demo}"
DEMO_DIR="${BASE_DIR}"
WEB_DIR="${BASE_DIR}/web"
BUILT_IMAGE=keycloak-public-demo:local
KEYCLOAK_PATH=""

if [[ -n "${VARIANT:-}" ]]; then
  [[ "${VARIANT}" =~ ^[a-z0-9-]+$ ]] || { echo "error: VARIANT allows lowercase letters, digits and dashes" >&2; exit 1; }
  # shellcheck disable=SC1090
  [[ -f "deploy.env.${VARIANT}" ]] && source "deploy.env.${VARIANT}"
  DEMO_DIR="${BASE_DIR}-${VARIANT}"
  WEB_DIR="${BASE_DIR}/web/${VARIANT}"
  KEYCLOAK_PATH="/${VARIANT}"
  KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL:-}${KEYCLOAK_PATH}"
fi
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8180}"

die() { echo "error: $*" >&2; exit 1; }

remote() {
  [[ -n "${DEMO_HOST:-}" ]] || die "DEMO_HOST is not set"
  ssh "${DEMO_HOST}" "cd ${DEMO_DIR} && $*"
}

require_settings() {
  local name
  for name in DEMO_HOST KEYCLOAK_PUBLIC_URL DEMO_ORIGIN WALLET_URL; do
    [[ -n "${!name:-}" ]] || die "${name} is not set, see deploy.env.example"
  done
}

build_distribution() {
  [[ -n "${KEYCLOAK_DIR:-}" ]] || die "KEYCLOAK_DIR is not set"
  (cd "${KEYCLOAK_DIR}" && ./mvnw install -DskipTests -pl quarkus/deployment,quarkus/dist -am)
}

load_image() {
  [[ -n "${KEYCLOAK_DIR:-}" ]] || die "KEYCLOAK_DIR is not set"
  local zip context platform=()
  zip="$(ls "${KEYCLOAK_DIR}"/quarkus/dist/target/keycloak-*.zip | head -1)"
  [[ -n "${zip}" ]] || die "no distribution in ${KEYCLOAK_DIR}, run ./deploy.sh build"
  context="${SCRIPT_DIR}/build"
  rm -rf "${context}"
  mkdir -p "${context}/unpacked"
  unzip -q "${zip}" -d "${context}/unpacked"
  mv "${context}"/unpacked/keycloak-* "${context}/keycloak"
  rm -rf "${context}/unpacked"
  cp Dockerfile "${context}/"
  [[ -z "${DEMO_HOST:-}" ]] || platform=(--platform "linux/$(ssh "${DEMO_HOST}" docker version --format '{{.Server.Arch}}')")
  docker build "${platform[@]}" -t "${BUILT_IMAGE}" "${context}"
  [[ -z "${DEMO_HOST:-}" ]] || docker save "${BUILT_IMAGE}" | gzip | ssh "${DEMO_HOST}" 'gunzip | docker load'
}

# Everything but the admin password follows deploy.env. Variants copy the base password.
write_remote_env() {
  local name
  if [[ -n "${VARIANT:-}" ]]; then
    ssh "${DEMO_HOST}" "grep '^KEYCLOAK_ADMIN_PASSWORD=' ${BASE_DIR}/.env > ${DEMO_DIR}/.env.new && chmod 600 ${DEMO_DIR}/.env.new && mv ${DEMO_DIR}/.env.new ${DEMO_DIR}/.env" \
      || die "deploy the base stack first, it holds the admin password"
  else
    remote "[ -f .env ] || (umask 077; printf 'KEYCLOAK_ADMIN_PASSWORD=%s\n' \"\$(openssl rand -hex 24)\" > .env); sed -i '/^KEYCLOAK_ADMIN_PASSWORD=/!d' .env"
  fi
  [[ -z "${KEYCLOAK_DIR:-}" ]] || KEYCLOAK_IMAGE="${BUILT_IMAGE}"
  {
    echo "COMPOSE_FILE=docker-compose.yml:docker-compose.proxy.yml"
    echo "KEYCLOAK_PORT=${KEYCLOAK_PORT}"
    for name in KEYCLOAK_PUBLIC_URL KEYCLOAK_PATH KEYCLOAK_IMAGE KEYCLOAK_FEATURES PROXY_NETWORK DEMO_PORT VARIANT; do
      [[ -z "${!name:-}" ]] || echo "${name}=${!name}"
    done
  } | remote "cat >> .env"
}

start_stack() {
  require_settings
  ssh "${DEMO_HOST}" "mkdir -p ${DEMO_DIR} ${WEB_DIR}"
  scp -q docker-compose.yml docker-compose.proxy.yml "${DEMO_HOST}:${DEMO_DIR}/"
  scp -qr themes "${DEMO_HOST}:${DEMO_DIR}/"
  # This leaves the files setup-realm.sh generates in place.
  scp -qr web/* "${DEMO_HOST}:${WEB_DIR}/"
  write_remote_env
  local network="${PROXY_NETWORK:-keycloak-public-demo}"
  ssh "${DEMO_HOST}" "docker network inspect ${network} >/dev/null 2>&1 || docker network create ${network} >/dev/null"
  # Docker creates volumes owned by root for images without that directory, and Keycloak runs as uid 1000.
  local volume="$(basename "${DEMO_DIR}")_keycloak-data"
  ssh "${DEMO_HOST}" "docker volume create ${volume} >/dev/null && docker run --rm -v ${volume}:/d alpine chown 1000:1000 /d >/dev/null"
  remote "docker compose up -d --force-recreate ${VARIANT:+keycloak-demo}"
}

wait_for_keycloak() {
  remote "for _ in \$(seq 1 90); do curl -fs -o /dev/null http://127.0.0.1:${KEYCLOAK_PORT}${KEYCLOAK_PATH}/realms/master && exit 0; sleep 2; done; exit 1" \
    || die "Keycloak did not start, see ./deploy.sh logs"
}

# The Keycloak port is bound to the host's loopback, so the setup reaches it through an ssh tunnel.
setup_realm() {
  require_settings
  local password
  mkdir -p build
  wait_for_keycloak
  password="$(remote "sed -n 's/^KEYCLOAK_ADMIN_PASSWORD=//p' .env")"
  ssh -N -L "${KEYCLOAK_PORT}:127.0.0.1:${KEYCLOAK_PORT}" "${DEMO_HOST}" &
  TUNNEL=$!
  trap 'kill "${TUNNEL}" 2>/dev/null || true' EXIT
  sleep 2
  [[ -z "${KEYCLOAK_DIR:-}" ]] || KEYCLOAK_BUILD="${KEYCLOAK_BUILD:-$(git -C "${KEYCLOAK_DIR}" branch --show-current)}"
  KEYCLOAK_BUILD="${KEYCLOAK_BUILD:-}" VARIANT="${VARIANT:-}" KEYCLOAK_URL="http://127.0.0.1:${KEYCLOAK_PORT}${KEYCLOAK_PATH}" KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL}" KEYCLOAK_ADMIN_PASSWORD="${password}" \
    WALLET_URL="${WALLET_URL}" DEMO_ORIGIN="${DEMO_ORIGIN}" ISSUER_LIST_URL="${ISSUER_LIST_URL:-}" WALLET_SCHEME="${WALLET_SCHEME:-}" \
    ISSUER_LIST_FILE="${SCRIPT_DIR}/build/issuers.jwt" WEB_CONFIG_FILE="${SCRIPT_DIR}/build/config.js" ./setup-realm.sh
  ssh "${DEMO_HOST}" "mkdir -p ${WEB_DIR}/trust-lists"
  scp -q build/issuers.jwt "${DEMO_HOST}:${WEB_DIR}/trust-lists/issuers.jwt"
  scp -q build/config.js "${DEMO_HOST}:${WEB_DIR}/config.js"
  publish_variants
}

# The header of the start page lists every deployment with a generated config.js.
publish_variants() {
  ssh "${DEMO_HOST}" "cd ${BASE_DIR}/web && grep -H keycloakVersion config.js */config.js 2>/dev/null" \
    | sed -E 's#^(([^/]*)/)?config\.js: *"keycloakVersion": "([^"]*)".*#\2 \3#' \
    | jq -Rn '[inputs | split(" ") | {path: (if .[0] == "" then "/" else "/" + .[0] + "/" end), label: ("Keycloak " + .[1])}]' \
    > build/variants.json
  scp -q build/variants.json "${DEMO_HOST}:${BASE_DIR}/web/variants.json"
}

remove_variant() {
  [[ -n "${VARIANT:-}" ]] || die "only a VARIANT can be removed"
  remote "docker compose down -v"
  ssh "${DEMO_HOST}" "rm -rf ${DEMO_DIR} ${WEB_DIR}"
  mkdir -p build
  publish_variants
}

case "${1:-}" in
  build) build_distribution ;;
  image) load_image ;;
  up) start_stack ;;
  realm) setup_realm ;;
  remove) remove_variant ;;
  all)
    [[ -z "${KEYCLOAK_DIR:-}" ]] || load_image
    start_stack
    setup_realm
    ;;
  status) remote "docker compose ps --format '{{.Name}} {{.Status}}'" ;;
  logs) remote "docker compose logs -f --tail 100 keycloak-demo" ;;
  *)
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "${BASH_SOURCE[0]}"
    exit 1
    ;;
esac
