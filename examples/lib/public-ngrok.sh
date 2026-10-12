#!/usr/bin/env bash

EXAMPLE_NGROK_PIDS=()
EXAMPLE_NGROK_LOGS=()
EXAMPLE_ENV_LOADED=false

example_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

example_find_sandbox_pem() {
  local repo_root="$1"
  local example_root="${2:-}"
  local candidate
  local candidates=()

  if [[ -n "${EXAMPLES_SANDBOX_PEM:-}" ]]; then
    candidates+=("${EXAMPLES_SANDBOX_PEM}")
  fi
  if [[ -n "${SANDBOX_PEM:-}" ]]; then
    candidates+=("${SANDBOX_PEM}")
  fi
  if [[ -n "${SANDBOX_DIR:-}" ]]; then
    candidates+=("${SANDBOX_DIR%/}/sandbox-ngrok-combined.pem")
  fi

  if [[ -n "${example_root}" ]]; then
    candidates+=("${example_root%/}/sandbox/sandbox-ngrok-combined.pem")
  fi
  candidates+=(
    "${repo_root}/sandbox/sandbox-ngrok-combined.pem"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

example_find_sandbox_verifier_info() {
  local repo_root="$1"
  local example_root="${2:-}"
  local candidate
  local candidates=()

  if [[ -n "${EXAMPLES_SANDBOX_VERIFIER_INFO:-}" ]]; then
    candidates+=("${EXAMPLES_SANDBOX_VERIFIER_INFO}")
  fi
  if [[ -n "${SANDBOX_VERIFIER_INFO:-}" ]]; then
    candidates+=("${SANDBOX_VERIFIER_INFO}")
  fi
  if [[ -n "${VERIFIER_INFO:-}" ]]; then
    candidates+=("${VERIFIER_INFO}")
  fi
  if [[ -n "${SANDBOX_DIR:-}" ]]; then
    candidates+=("${SANDBOX_DIR%/}/sandbox-verifier-info.json")
  fi

  if [[ -n "${example_root}" ]]; then
    candidates+=("${example_root%/}/sandbox/sandbox-verifier-info.json")
  fi
  candidates+=(
    "${repo_root}/sandbox/sandbox-verifier-info.json"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

example_detect_ngrok_domain_from_pem() {
  local pem_file="$1"

  if [[ ! -f "${pem_file}" ]] || ! command -v openssl >/dev/null 2>&1; then
    return 1
  fi

  openssl x509 -in "${pem_file}" -noout -ext subjectAltName 2>/dev/null \
    | grep -o 'DNS:[^, ]*' \
    | head -n 1 \
    | cut -d: -f2
}

example_default_ngrok_domain() {
  local repo_root="$1"
  local example_root="${2:-}"
  local explicit_domain="${3:-}"
  local pem_file

  if [[ -n "${explicit_domain}" ]]; then
    printf '%s\n' "${explicit_domain}"
    return 0
  fi

  pem_file="$(example_find_sandbox_pem "${repo_root}" "${example_root}" || true)"
  if [[ -z "${pem_file}" ]]; then
    return 1
  fi

  example_detect_ngrok_domain_from_pem "${pem_file}"
}

example_load_env_files() {
  local env_file

  if [[ "${EXAMPLE_ENV_LOADED}" == "true" ]]; then
    return 0
  fi

  for env_file in "$@"; do
    if [[ -f "${env_file}" ]]; then
      set -a
      # shellcheck source=/dev/null
      source "${env_file}"
      set +a
    fi
  done

  EXAMPLE_ENV_LOADED=true
}

example_env_keycloak_ngrok_domain() {
  local value

  for value in \
    "${KEYCLOAK_NGROK_DOMAIN:-}" \
    "${NGROK_DOMAIN:-}"
  do
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi
  done

  return 1
}

example_env_app_ngrok_domain() {
  if [[ -n "${APP_NGROK_DOMAIN:-}" ]]; then
    printf '%s\n' "${APP_NGROK_DOMAIN}"
    return 0
  fi

  return 1
}

example_port_is_listening() {
  local port="$1"

  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return
  fi

  if command -v ss >/dev/null 2>&1; then
    ss -ltn "( sport = :${port} )" 2>/dev/null | tail -n +2 | grep -q .
    return
  fi

  if command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | grep -E "[\\.:]${port}[[:space:]].*LISTEN" >/dev/null
    return
  fi

  echo "Missing required command: lsof, ss, or netstat" >&2
  exit 1
}

example_resolve_free_port() {
  local preferred_port="$1"
  local label="${2:-local}"
  local candidate

  if ! example_port_is_listening "${preferred_port}"; then
    printf '%s\n' "${preferred_port}"
    return 0
  fi

  for candidate in $(seq $((preferred_port + 1)) $((preferred_port + 50))); do
    if ! example_port_is_listening "${candidate}"; then
      echo "${label} port ${preferred_port} is already in use, using ${candidate} instead." >&2
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  echo "Could not find a free ${label} port near ${preferred_port}. Set the port explicitly and retry." >&2
  exit 1
}

example_wait_for_ngrok_url() {
  local local_port="$1"
  local api_port
  local public_url

  for _ in $(seq 1 120); do
    for api_port in 4040 4041 4042 4043 4044 4045; do
      public_url="$(
        curl -fsS "http://127.0.0.1:${api_port}/api/tunnels" 2>/dev/null \
          | jq -r --arg port ":${local_port}" '
              .tunnels[]
              | select(.proto == "https" and ((.config.addr // "") | contains($port)))
              | .public_url
            ' 2>/dev/null \
          | head -n 1
      )"
      if [[ -n "${public_url}" ]] && [[ "${public_url}" != "null" ]]; then
        printf '%s\n' "${public_url}"
        return 0
      fi
    done
    sleep 0.25
  done

  return 1
}

example_start_ngrok_tunnel() {
  local label="$1"
  local local_port="$2"
  local domain="${3:-}"
  local log_file
  local public_url
  local -a args

  example_require_cmd ngrok
  example_require_cmd curl
  example_require_cmd jq

  log_file="$(mktemp -t "${label}.ngrok.XXXXXX.log")"
  args=(http "${local_port}" --log=stdout --log-format=json)
  if [[ -n "${domain}" ]]; then
    args+=("--url=${domain}")
  fi

  nohup ngrok "${args[@]}" >"${log_file}" 2>&1 &
  EXAMPLE_NGROK_PIDS+=("$!")
  EXAMPLE_NGROK_LOGS+=("${log_file}")

  public_url="$(example_wait_for_ngrok_url "${local_port}" || true)"
  if [[ -z "${public_url}" ]]; then
    echo "Failed to obtain ngrok URL for ${label} on localhost:${local_port}. See ${log_file}" >&2
    exit 1
  fi

  printf '%s\n' "${public_url}"
}

example_stop_ngrok() {
  local pid
  local log_file

  for pid in "${EXAMPLE_NGROK_PIDS[@]}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done

  for log_file in "${EXAMPLE_NGROK_LOGS[@]}"; do
    if [[ -n "${log_file}" ]]; then
      rm -f "${log_file}" 2>/dev/null || true
    fi
  done
}

example_write_keycloak_public_override() {
  local target_path="$1"
  local public_url="$2"

  cat >"${target_path}" <<EOF
services:
  keycloak:
    environment:
      KC_HOSTNAME: "${public_url}"
      KC_PROXY_HEADERS: xforwarded
EOF
}
