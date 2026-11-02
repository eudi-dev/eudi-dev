#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-app-demo}"
KEYCLOAK_SIGNING_KEY_PATH="${KEYCLOAK_SIGNING_KEY_PATH:-${SCENARIO_DIR}/keycloak-signing-key.pem}"
KEYCLOAK_SIGNING_CERT_PATH="${KEYCLOAK_SIGNING_CERT_PATH:-${SCENARIO_DIR}/keycloak-signing-cert.pem}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq
need openssl

curl_common() {
  if [[ "${KEYCLOAK_BASE_URL}" == https://* ]] && [[ -n "${KEYCLOAK_CA_CERT:-}" ]] && [[ -f "${KEYCLOAK_CA_CERT}" ]]; then
    curl --cacert "${KEYCLOAK_CA_CERT}" "$@"
  else
    curl "$@"
  fi
}

wait_for_endpoint() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl_common -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Keycloak did not become ready at ${url}" >&2
  exit 1
}

admin_token() {
  curl_common -fsS \
    -X POST "${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-Proto: https" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=${KEYCLOAK_ADMIN}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    | jq -er '.access_token'
}

api() {
  local method="$1"
  local path="$2"
  shift 2
  curl_common -fsS -X "$method" \
    "${KEYCLOAK_BASE_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Forwarded-Proto: https" \
    "$@"
}

api_json() {
  local method="$1"
  local path="$2"
  local payload="$3"
  curl_common -fsS -X "$method" \
    "${KEYCLOAK_BASE_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Forwarded-Proto: https" \
    -H "Content-Type: application/json" \
    --data-binary @- <<<"$payload"
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Required file not found: $path" >&2
    exit 1
  fi
}

realm_id() {
  api GET "/admin/realms/${KEYCLOAK_REALM}" | jq -er '.id'
}

# Keycloak requires a CA-issued certificate for SD-JWT signing, so the demo CA signs the
# realm key.
configure_static_realm_signing_key() {
  local realm_id_value="$1"
  local cert_b64 existing_id
  cert_b64="$(openssl x509 -outform DER -in "${KEYCLOAK_SIGNING_CERT_PATH}" | base64 | tr -d '\n')"
  existing_id="$(
    api GET "/admin/realms/${KEYCLOAK_REALM}/components?type=org.keycloak.keys.KeyProvider" \
      | jq -er --arg cert_b64 "$cert_b64" '
          map(select(.providerId == "rsa"))[]
          | select((.config.certificate[0] // "") | gsub("-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|[\\n\\r ]"; "") == $cert_b64)
          | .id
        ' 2>/dev/null | head -n 1 || true
  )"
  if [[ -n "${existing_id}" ]]; then
    return 0
  fi

  api_json POST "/admin/realms/${KEYCLOAK_REALM}/components" \
    "$(jq -cn \
      --arg parent_id "${realm_id_value}" \
      --rawfile private_key "${KEYCLOAK_SIGNING_KEY_PATH}" \
      --rawfile certificate "${KEYCLOAK_SIGNING_CERT_PATH}" \
      '{
        name: "static-rsa-signing-key",
        providerId: "rsa",
        providerType: "org.keycloak.keys.KeyProvider",
        parentId: $parent_id,
        config: {
          priority: ["1000"],
          enabled: ["true"],
          active: ["true"],
          algorithm: ["RS256"],
          privateKey: [$private_key],
          certificate: [$certificate]
        }
      }')" >/dev/null

  while read -r generated_id; do
    if [[ -n "${generated_id}" ]]; then
      api DELETE "/admin/realms/${KEYCLOAK_REALM}/components/${generated_id}" >/dev/null
    fi
  done < <(
    api GET "/admin/realms/${KEYCLOAK_REALM}/components?type=org.keycloak.keys.KeyProvider" \
      | jq -r '.[] | select(.providerId == "rsa-generated") | .id'
  )
}

assert_static_realm_signing_key_active() {
  local expected_cert active_cert
  expected_cert="$(openssl x509 -outform DER -in "${KEYCLOAK_SIGNING_CERT_PATH}" | base64 | tr -d '\n')"
  active_cert="$(
    api GET "/admin/realms/${KEYCLOAK_REALM}/keys" \
      | jq -er '.keys[] | select(.algorithm == "RS256" and .status == "ACTIVE") | .certificate' \
      | head -n 1
  )"
  if [[ "${active_cert}" != "${expected_cert}" ]]; then
    echo "Expected static Keycloak RS256 signing certificate to be active, but a different certificate is active." >&2
    exit 1
  fi
}

set_realm_ssl_required() {
  local realm_name="$1"
  local ssl_required="$2"
  local realm_rep
  realm_rep="$(api GET "/admin/realms/${realm_name}")"
  api_json PUT "/admin/realms/${realm_name}" \
    "$(printf '%s' "$realm_rep" | jq -c --arg ssl_required "$ssl_required" '.sslRequired = $ssl_required')" >/dev/null
}

"${SCENARIO_DIR}/scripts/generate-keycloak-signing-cert.sh"
require_file "${KEYCLOAK_SIGNING_KEY_PATH}"
require_file "${KEYCLOAK_SIGNING_CERT_PATH}"
require_file "${SCENARIO_DIR}/providers/keycloak-extension-oid4vp.jar"

echo "Waiting for Keycloak at ${KEYCLOAK_BASE_URL}..."
wait_for_endpoint "${KEYCLOAK_BASE_URL}/realms/master"
wait_for_endpoint "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"
ADMIN_TOKEN="$(admin_token)"

REALM_ID="$(realm_id)"

echo "Importing persistent CA-issued RS256 realm signing key..."
configure_static_realm_signing_key "${REALM_ID}"
assert_static_realm_signing_key_active

echo "Allowing the master admin UI over HTTP for the local demo..."
set_realm_ssl_required "master" "NONE"

echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  app_client=wallet-app"
echo "  vci_client=wallet-vci"
echo "  credential_configuration_id=membership-credential"
echo "  first_broker_flow=oid4vp first broker login"
