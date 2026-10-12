#!/usr/bin/env bash
# Deploy and operate a public demo host (see docs/public-demo.md).
#
# The target is configured, never hardcoded: set DEMO_HOST to an ssh
# destination (a ~/.ssh/config alias, user@host, or just a host). Values can
# live in a local deploy.env next to this script, which is gitignored:
#
#   DEMO_HOST=root@demo.example
#   DEMO_DIR=/opt/eudi-demo          # optional, this is the default
#   DEMO_URL=https://demo.example    # optional, enables the post-deploy check
#   PREVIEW_URL=https://preview.demo.example   # optional, the preview host
#   STRICT_URL=https://strict.demo.example     # optional, the conformance host
#
# Usage: ./deploy.sh <command>
#   setup     install Docker, copy the stack, start it (first deployment)
#   push      copy Caddyfile, compose file and imprint, then apply them
#   update    pull the latest image and restart (no file changes)
#   preview [tag]   run a release on the preview host (default beta, the newest
#             release including betas), leaving the main site as it is
#   promote   move the main site to the release the preview host runs
#   strict [tag]    run a release on the strict conformance host (default
#             latest), the wallet the hosted OIDF suite tests for certification
#   rollback [version]  put the previous release back (or a named one, e.g.
#             v2.0.0). Without an argument it uses the release that was live
#             before the last push or update
#   status    container status and the version the site reports
#   logs [preview|strict]  follow the wallet log (that host's wallet when named)
#   verify    check that the deployed endpoints respond
#   stats     print a usage summary from the access log (pages and API calls)
#   stats-reset     discard the access log and rebuild the report from zero
#   stats-password  generate credentials for the /stats report
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# shellcheck disable=SC1091
[[ -f deploy.env ]] && source deploy.env

DEMO_DIR="${DEMO_DIR:-/opt/eudi-demo}"
COMMAND="${1:-}"

die() { echo "error: $*" >&2; exit 1; }

require_host() {
  [[ -n "${DEMO_HOST:-}" ]] || die "DEMO_HOST is not set. Export it or create deploy.env (see the header of this script)."
}

# Run a command on the demo host inside the stack directory.
remote() {
  ssh "${DEMO_HOST}" "cd ${DEMO_DIR} && $*"
}

compose() {
  remote "docker compose $*"
}

copy_stack() {
  echo "Copying the stack to ${DEMO_HOST}:${DEMO_DIR}..."
  ssh "${DEMO_HOST}" "mkdir -p ${DEMO_DIR}"
  scp -q Caddyfile Dockerfile docker-compose.yml "${DEMO_HOST}:${DEMO_DIR}/"
  # The news snippet and its images. The main wallet shows them to visitors.
  scp -qr news "${DEMO_HOST}:${DEMO_DIR}/"
  # Copy operator details from gitignored imprint.local.html. The repository contains a
  # placeholder, so preserve the host copy when no local file exists.
  if [[ -f imprint.local.html ]]; then
    scp -q imprint.local.html "${DEMO_HOST}:${DEMO_DIR}/imprint.html"
  else
    echo "  no imprint.local.html, keeping the imprint already on the host"
  fi
  # Basic auth credentials for the /stats report live in stats.env, next to
  # the compose file, and never in the repository.
  [[ -f stats.env ]] && scp -q stats.env "${DEMO_HOST}:${DEMO_DIR}/stats.env"
}

deployed_version() {
  [[ -n "${DEMO_URL:-}" ]] || return 0
  curl -fsS --max-time 15 "${DEMO_URL%/}/api/version" 2>/dev/null |
    sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

# Release versions match image tags, allowing the reported version to be restored
# directly.
record_running_version() {
  local version
  version="$(deployed_version)"
  [[ -n "${version}" ]] || return 0
  remote "printf '%s\n' '${version}' > .last-version"
}

previous_version() {
  remote "cat .last-version 2>/dev/null" || true
}

# WALLET_TAG lives in the host's .env, which is where compose reads variables
# for interpolation. Other variables in that file are left alone.
set_wallet_tag() {
  local tag="$1"
  if [[ -z "${tag}" ]]; then
    remote "touch .env && sed -i.bak '/^WALLET_TAG=/d' .env && rm -f .env.bak"
  else
    remote "touch .env && sed -i.bak '/^WALLET_TAG=/d' .env && rm -f .env.bak && printf 'WALLET_TAG=%s\n' '${tag}' >> .env"
  fi
}

# PREVIEW_TAG lives in the same host .env and pins the release the preview host
# runs, independently of the main site's WALLET_TAG.
set_preview_tag() {
  local tag="$1"
  remote "touch .env && sed -i.bak '/^PREVIEW_TAG=/d' .env && rm -f .env.bak && printf 'PREVIEW_TAG=%s\n' '${tag}' >> .env"
}

# Resolve a moving tag such as beta to the preview's actual version, so
# promotion deploys the tested image.
preview_version() {
  [[ -n "${PREVIEW_URL:-}" ]] || return 0
  curl -fsS --max-time 15 "${PREVIEW_URL%/}/api/version" 2>/dev/null |
    sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

# The image uses uid 1000, but Docker creates volumes owned by root. Assign ownership
# before startup.
ensure_preview_volume() {
  remote "docker volume create eudi-demo_wallet-data-preview >/dev/null && docker run --rm -v eudi-demo_wallet-data-preview:/d alpine chown 1000:1000 /d >/dev/null"
}

# STRICT_TAG pins the release the strict conformance host runs, independently
# of the main site and the preview host.
set_strict_tag() {
  local tag="$1"
  remote "touch .env && sed -i.bak '/^STRICT_TAG=/d' .env && rm -f .env.bak && printf 'STRICT_TAG=%s\n' '${tag}' >> .env"
}

strict_version() {
  [[ -n "${STRICT_URL:-}" ]] || return 0
  curl -fsS --max-time 15 "${STRICT_URL%/}/api/version" 2>/dev/null |
    sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

ensure_strict_volume() {
  remote "docker volume create eudi-demo_wallet-data-strict >/dev/null && docker run --rm -v eudi-demo_wallet-data-strict:/d alpine chown 1000:1000 /d >/dev/null"
}

apply_stack() {
  compose "pull -q wallet" >/dev/null
  # Rebuild Caddy when its Dockerfile or rate limiting plugin changes.
  compose "up -d --build --quiet-pull" >/dev/null
  sleep 3
  compose "ps --format '{{.Name}} {{.Status}}'"
  local version
  version="$(deployed_version)"
  if [[ -n "${version}" ]]; then
    echo "Version now live: ${version}"
  fi
  # A missing DEMO_URL skips version reporting without failing deployment.
  return 0
}

# The pin currently in effect on the host, empty when the newest release runs.
current_wallet_tag() {
  remote "sed -n 's/^WALLET_TAG=//p' .env 2>/dev/null" || true
}

# A version pin requires a compose file that reads WALLET_TAG. Update older files that use
# a fixed image tag.
ensure_pinnable_compose() {
  if remote "grep -q WALLET_TAG docker-compose.yml 2>/dev/null"; then
    return 0
  fi
  echo "  the compose file on the host cannot pin a release, copying the current one..."
  scp -q docker-compose.yml "${DEMO_HOST}:${DEMO_DIR}/"
}

case "${COMMAND}" in
  setup)
    require_host
    echo "Installing Docker (skipped when already present)..."
    ssh "${DEMO_HOST}" "command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh"
    copy_stack
    # Docker creates volumes owned by root, while the wallet runs as uid 1000.
    echo "Preparing the wallet data volume..."
    remote "docker volume create eudi-demo_wallet-data >/dev/null && docker run --rm -v eudi-demo_wallet-data:/d alpine chown 1000:1000 /d >/dev/null"
    compose "up -d --build"
    echo
    echo "Deployed. Point your domain's A and AAAA records at this host if you have not yet:"
    ssh "${DEMO_HOST}" "hostname -I 2>/dev/null || true"
    ;;
  push)
    require_host
    record_running_version
    copy_stack
    # Pull before restarting because the updated compose file may use flags missing from
    # the old image.
    apply_stack
    ;;
  update)
    require_host
    record_running_version
    # Clear the rollback pin so update can select the latest release.
    set_wallet_tag ""
    apply_stack
    ;;

  preview)
    require_host
    target="${2:-beta}"
    # Copy the stack so the host has the Caddy preview block and the
    # wallet-preview service, then prepare its data volume.
    copy_stack
    ensure_preview_volume
    set_preview_tag "${target}"
    compose "--profile preview pull -q wallet-preview" >/dev/null
    # Start the preview wallet, leaving production untouched.
    compose "--profile preview up -d --quiet-pull wallet-preview" >/dev/null
    # Reload Caddy to apply the mounted configuration and provision the preview
    # certificate without interrupting the main site.
    compose "exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile" >/dev/null
    sleep 3
    compose "--profile preview ps --format '{{.Name}} {{.Status}}'"
    version="$(preview_version)"
    [[ -n "${version}" ]] && echo "Preview now live: ${version}"
    echo "Try it${PREVIEW_URL:+ at ${PREVIEW_URL}}, then ./deploy.sh promote to move the main site to it."
    ;;

  strict)
    require_host
    target="${2:-latest}"
    # Copy the stack so the host has the Caddy strict block and the
    # wallet-strict service, then prepare its data volume.
    copy_stack
    ensure_strict_volume
    set_strict_tag "${target}"
    compose "--profile strict pull -q wallet-strict" >/dev/null
    # Start the strict wallet, leaving production untouched.
    compose "--profile strict up -d --quiet-pull wallet-strict" >/dev/null
    # A graceful reload applies the new Caddy block with no downtime and
    # provisions the strict host's certificate.
    compose "exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile" >/dev/null
    sleep 3
    compose "--profile strict ps --format '{{.Name}} {{.Status}}'"
    version="$(strict_version)"
    [[ -n "${version}" ]] && echo "Strict conformance host now live: ${version}"
    echo "Run conformance against it${STRICT_URL:+ at ${STRICT_URL}} (see docs/conformance-run.md)."
    ;;

  promote)
    require_host
    target="$(preview_version)"
    [[ -n "${target}" ]] || target="$(remote "sed -n 's/^PREVIEW_TAG=//p' .env 2>/dev/null" || true)"
    [[ -n "${target}" ]] || die "no preview release to promote. Run ./deploy.sh preview <tag> first."
    current="$(deployed_version)"
    if [[ -n "${current}" && "${target}" == "${current}" ]]; then
      die "${target} is already live on the main site."
    fi
    echo "Promoting the main site${current:+ from ${current}} to ${target} (the preview release)..."
    record_running_version
    ensure_pinnable_compose
    set_wallet_tag "${target}"
    if ! compose "pull -q wallet" >/dev/null 2>&1; then
      set_wallet_tag ""
      die "ghcr.io/eudi-dev/eudi-dev:${target} could not be pulled, so nothing was changed."
    fi
    apply_stack
    echo "Main site promoted to ${target}. ./deploy.sh update returns to the newest release."
    ;;

  rollback)
    require_host
    target="${2:-}"
    if [[ -z "${target}" ]]; then
      target="$(previous_version)"
      [[ -n "${target}" ]] || die "no recorded previous version. Pass one: ./deploy.sh rollback v2.0.0"
    fi
    current="$(deployed_version)"
    if [[ -n "${current}" && "${target}" == "${current}" ]]; then
      die "${target} is already live, nothing to roll back to."
    fi
    echo "Rolling back${current:+ from ${current}} to ${target}..."
    record_running_version
    ensure_pinnable_compose
    previous_tag="$(current_wallet_tag)"
    set_wallet_tag "${target}"
    # Pull the requested tag before changing running containers. An unavailable release
    # must leave the demo running.
    if ! compose "pull -q wallet" >/dev/null 2>&1; then
      set_wallet_tag "${previous_tag}"
      die "ghcr.io/eudi-dev/eudi-dev:${target} could not be pulled, so nothing was changed. Check that the release exists."
    fi
    apply_stack
    live="$(deployed_version)"
    if [[ -n "${live}" && "${live}" != "${target}" ]]; then
      die "asked for ${target} but ${live} is live. Check that the tag names a published release (the image is ghcr.io/eudi-dev/eudi-dev:${target}), then ./deploy.sh logs."
    fi
    echo "Rolled back to ${target}. ./deploy.sh update returns to the newest release."
    ;;
  status)
    require_host
    compose "ps --format '{{.Name}} {{.Status}}'"
    version="$(deployed_version)"
    [[ -n "${version}" ]] && echo "Version reported by ${DEMO_URL}: ${version}"
    pversion="$(preview_version)"
    [[ -n "${pversion}" ]] && echo "Version reported by ${PREVIEW_URL}: ${pversion}"
    sversion="$(strict_version)"
    [[ -n "${sversion}" ]] && echo "Version reported by ${STRICT_URL}: ${sversion}"
    ;;
  logs)
    require_host
    # ./deploy.sh logs preview|strict follows that wallet instead of the main one.
    if [[ "${2:-}" == "preview" ]]; then
      compose "--profile preview logs -f --tail 100 wallet-preview"
    elif [[ "${2:-}" == "strict" ]]; then
      compose "--profile strict logs -f --tail 100 wallet-strict"
    else
      compose "logs -f --tail 100 wallet"
    fi
    ;;
  stats)
    require_host
    # GoAccess reads the epoch timestamps. Remove CRLF from its CSV output before parsing.
    summary="$(mktemp)"
    remote "docker compose exec -T stats sh -c 'goaccess /var/log/caddy/access.log --log-format=CADDY --ignore-crawlers -o /tmp/summary.csv >/dev/null 2>&1; cat /tmp/summary.csv'" |
      tr -d '\r' > "${summary}"
    sed -n 's/^"[0-9]*",,"general",,,,,,,,"\([^"]*\)","\([^"]*\)"$/\2 \1/p' "${summary}" |
      grep -E 'requests|visitors|log_size' |
      while read -r name value; do printf '%-18s %s\n' "${name}" "${value}"; done
    echo
    # List API traffic separately because polling would dominate the page counts.
    echo "Top pages (bots excluded, API calls omitted):"
    sed -n 's/^"[0-9]*",,"requests","\([0-9]*\)".*,"\([^"]*\)"$/\1 \2/p' "${summary}" |
      grep -v '/api/' |
      head -10 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done

    api="$(sed -n 's/^"[0-9]*",,"requests","\([0-9]*\)".*,"\([^"]*\)"$/\1 \2/p' "${summary}" | grep '/api/' || true)"
    if [[ -n "${api}" ]]; then
      echo
      echo "Top API calls (bots excluded):"
      echo "${api}" | head -10 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done
      # Separate writes from reads, which mostly come from UI polling.
      writes="$(echo "${api}" | grep -E '^[0-9]+ +(POST|PUT|PATCH|DELETE)\b' || true)"
      if [[ -n "${writes}" ]]; then
        echo
        echo "API calls that changed something:"
        echo "${writes}" | head -10 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done
      fi
    fi
    rm -f "${summary}"
    [[ -n "${DEMO_URL:-}" ]] && echo && echo "Full report: ${DEMO_URL%/}/stats/"
    ;;
  stats-reset)
    require_host
    read -r -p "Discard the access log and every past statistic? [y/N] " confirm
    [[ "${confirm}" =~ ^[yY]$ ]] || die "aborted"
    # Truncate in place and drop the rolled files, then restart Caddy so its
    # log writer starts over from a known size.
    remote "docker compose exec -T caddy sh -c 'rm -f /var/log/caddy/access-*.log*; : > /var/log/caddy/access.log'"
    compose "restart caddy" >/dev/null
    if [[ -n "${DEMO_URL:-}" ]]; then
      # Generate one request because GoAccess skips empty logs and would leave the old
      # report visible.
      curl -fsS -o /dev/null --max-time 15 --retry 5 --retry-delay 2 --retry-connrefused "${DEMO_URL%/}/api/version" || true
    fi
    remote "docker compose exec -T stats sh -c 'goaccess /var/log/caddy/access.log --log-format=CADDY --ignore-crawlers --anonymize-ip --html-report-title=\"Demo usage\" -o /srv/stats/report.html'" >/dev/null 2>&1 || true
    echo "Access log cleared, report rebuilt."
    ;;
  stats-password)
    read -r -p "Username for /stats [admin]: " user
    user="${user:-admin}"
    read -r -s -p "Password: " password
    echo
    hash="$(docker run --rm caddy:2 caddy hash-password --plaintext "${password}")"
    # Compose interpolates env_file values, so a bcrypt hash's "$" has to be
    # written as "$$" to survive into the container.
    escaped="${hash//\$/\$\$}"
    printf 'STATS_USER=%s\nSTATS_PASSWORD_HASH=%s\n' "${user}" "${escaped}" > stats.env
    echo "Wrote stats.env (gitignored). Apply it with: ./deploy.sh push"
    ;;
  verify)
    [[ -n "${DEMO_URL:-}" ]] || die "DEMO_URL is not set, nothing to verify."
    failed=0
    # The main site, and the preview host too when PREVIEW_URL is set.
    for target in "${DEMO_URL}" "${PREVIEW_URL:-}"; do
      [[ -n "${target}" ]] || continue
      echo "${target}:"
      base="${target%/}"
      for path in / /decoder/ /issuer/ /verifier/ /imprint /favicon.svg /logo.svg /api/trustlist; do
        code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "${base}${path}" || echo 000)"
        printf '  %-16s %s\n' "${path}" "${code}"
        [[ "${code}" == "200" ]] || failed=1
      done
    done
    [[ "${failed}" -eq 0 ]] || die "some endpoints did not return 200"
    echo "All endpoints healthy."
    ;;
  *)
    # Print the header comment block as usage.
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "${BASH_SOURCE[0]}"
    exit 1
    ;;
esac
