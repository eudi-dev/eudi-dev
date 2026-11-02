#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROVIDERS_DIR="${SCENARIO_DIR}/providers"

KEYCLOAK_OID4VP_VERSION="${KEYCLOAK_OID4VP_VERSION:-0.16.1}"
KEYCLOAK_OID4VP_GROUP_PATH="${KEYCLOAK_OID4VP_GROUP_PATH:-de/arbeitsagentur/opdt}"
KEYCLOAK_OID4VP_ARTIFACT="${KEYCLOAK_OID4VP_ARTIFACT:-keycloak-extension-oid4vp}"
KEYCLOAK_OID4VP_BASE_URL="${KEYCLOAK_OID4VP_BASE_URL:-https://repo1.maven.org/maven2}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl

mkdir -p "${PROVIDERS_DIR}"

JAR_NAME="${KEYCLOAK_OID4VP_ARTIFACT}.jar"
JAR_URL="${KEYCLOAK_OID4VP_BASE_URL}/${KEYCLOAK_OID4VP_GROUP_PATH}/${KEYCLOAK_OID4VP_ARTIFACT}/${KEYCLOAK_OID4VP_VERSION}/${KEYCLOAK_OID4VP_ARTIFACT}-${KEYCLOAK_OID4VP_VERSION}.jar"
JAR_PATH="${PROVIDERS_DIR}/${JAR_NAME}"

echo "Downloading ${KEYCLOAK_OID4VP_ARTIFACT} ${KEYCLOAK_OID4VP_VERSION}..."
curl -fsSLo "${JAR_PATH}" "${JAR_URL}"

echo "Saved:"
echo "  ${JAR_PATH}"
