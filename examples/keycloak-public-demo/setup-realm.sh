#!/usr/bin/env bash
# Recreates the wallet-demo realm through the admin API and writes the files the start page serves.
# It reads what this Keycloak supports from the server info, so any recent version works.
#
# Usage: KEYCLOAK_ADMIN_PASSWORD=... WALLET_URL=... ./setup-realm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KC="${KEYCLOAK_URL:-http://localhost:8180}"
PUBLIC_URL="${KEYCLOAK_PUBLIC_URL:-${KC}}"
PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:?}"
WALLET="${WALLET_URL:?}"
# Keycloak fetches both lists itself, so they need addresses that work from inside its container.
WALLET_LIST_URL="${WALLET_LIST_URL:-${WALLET}/api/trustlists/wallet-provider}"
DEMO_ORIGIN="${DEMO_ORIGIN:-http://localhost:8181}"
DEMO_PATH="/${VARIANT:+${VARIANT}/}"
ISSUER_LIST_URL="${ISSUER_LIST_URL:-http://demo-web:8080/trust-lists/issuers.jwt}"
ISSUER_LIST_FILE="${ISSUER_LIST_FILE:-${SCRIPT_DIR}/web/trust-lists/issuers.jwt}"
WEB_CONFIG_FILE="${WEB_CONFIG_FILE:-${SCRIPT_DIR}/web/config.js}"
REALM=wallet-demo
CLIENT=demo
CREDENTIAL=demo-membership
USERNAME=demo@example.com
LOTE_WALLET=http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList
SERVICE_ISSUANCE=http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance
LOTE_ISSUERS="${DEMO_ORIGIN}/LoTEType/DemoIssuersList"
SERVICE_ISSUERS="${DEMO_ORIGIN}/SvcType/DemoIssuer/Issuance"
# The keys all variants share, so credentials and the one issuer list outlive a new realm.
STATE_DIR="${STATE_DIR:-${SCRIPT_DIR}/state}"

admin_token() {
  curl -fsS "${KC}/realms/master/protocol/openid-connect/token" \
    --data-urlencode grant_type=password --data-urlencode client_id=admin-cli \
    --data-urlencode username=admin --data-urlencode "password=${PASSWORD}" | jq -r .access_token
}

admin() {
  local method="$1" path="$2" body="${3:-}"
  curl -sS --fail-with-body -X "${method}" "${KC}/admin/realms${path}" -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' ${body:+-d "${body}"}
}

server_has() {
  jq -e "$1" <<< "${SERVER_INFO}" >/dev/null
}

read_capabilities() {
  SERVER_INFO="$(curl -fsS "${KC}/admin/serverinfo" -H "Authorization: Bearer ${TOKEN}")"
  TRUST=none
  ATTESTERS=wallet-providers
  server_has '.identityProviders | any(.id == "default-trust")' && TRUST=default-trust
  server_has '.identityProviders | any(.id == "etsi-trust-list")' && TRUST=etsi-trust-list
  WALLET_LOGIN=false
  [[ "${TRUST}" != none ]] && server_has '.identityProviders | any(.id == "oid4vp")' && WALLET_LOGIN=true
  ATTESTED_CLIENT=false
  [[ "${TRUST}" != none ]] && server_has '.providers["client-authenticator"].providers | has("attestation-based")' && ATTESTED_CLIENT=true
  echo "Trust: ${TRUST}, wallet login: ${WALLET_LOGIN}, attested wallet client: ${ATTESTED_CLIENT}"
}

create_realm() {
  admin DELETE "/${REALM}" >/dev/null 2>&1 || true
  admin POST "" "$(jq -n --arg realm "${REALM}" '{
    realm: $realm, enabled: true, verifiableCredentialsEnabled: true, loginTheme: "eudi-dev", defaultSignatureAlgorithm: "ES256",
    sslRequired: "external", registrationAllowed: false, resetPasswordAllowed: false, editUsernameAllowed: false,
    accessTokenLifespan: 120, ssoSessionIdleTimeout: 600, ssoSessionMaxLifespan: 1800,
    offlineSessionIdleTimeout: 600, eventsEnabled: false, adminEventsEnabled: false
  }')"
}

base64url() {
  base64 | tr -d '\n=' | tr '/+' '_-'
}

ensure_keys() {
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"
  local host
  host="$(sed -E 's#^[a-z]+://([^:/]+).*#\1#' <<< "${PUBLIC_URL}")"
  [[ -f "${STATE_DIR}/list.key" ]] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${STATE_DIR}/list.key" -out "${STATE_DIR}/list.pem" -subj "/O=Keycloak Demo/CN=Keycloak Demo List Signer" -days 3650 2>/dev/null
  [[ -f "${STATE_DIR}/issuer-ca.key" ]] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${STATE_DIR}/issuer-ca.key" -out "${STATE_DIR}/issuer-ca.pem" -subj "/O=Keycloak Demo/CN=Keycloak Demo Issuer CA" -days 3650 2>/dev/null
  [[ ! -f "${STATE_DIR}/issuer.key" ]] || return 0
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "${STATE_DIR}/issuer.key"
  local request
  request="$(mktemp)"
  openssl req -new -key "${STATE_DIR}/issuer.key" -subj "/O=Keycloak Demo/CN=${host}" -out "${request}"
  openssl x509 -req -in "${request}" -CA "${STATE_DIR}/issuer-ca.pem" -CAkey "${STATE_DIR}/issuer-ca.key" -CAcreateserial -days 825 \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectAltName=DNS:%s\n' "${host}") \
    -out "${STATE_DIR}/issuer.pem" 2>/dev/null
  rm -f "${request}"
}

# Publishes the issuer CA in an ETSI TS 119 602 list of this demo's own scheme, so the wallet login
# trusts it the same way a verifier trusts a real issuer.
create_issuer_list() {
  local input signature next_update issued entity
  ISSUER_LIST_SIGNER="$(cat "${STATE_DIR}/list.pem")"
  ISSUER_CA="$(cat "${STATE_DIR}/issuer-ca.pem")"
  issued="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # A static list has no operator to reissue it, so it stays valid until the next setup is due.
  next_update="$(date -u -v+1y +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)"
  entity="$(printf '%s\n' "${ISSUER_CA}" | sed '/-----/d' | tr -d '\n')"
  input="$(jq -cn --arg signer "$(sed '/-----/d' "${STATE_DIR}/list.pem" | tr -d '\n')" '{alg: "ES256", typ: "JWT", x5c: [$signer]}' | tr -d '\n' | base64url).$(jq -cn --arg type "${LOTE_ISSUERS}" --arg issued "${issued}" \
    --arg next "${next_update}" --arg service "${SERVICE_ISSUERS}" --arg cert "${entity}" '{LoTE: {
      ListAndSchemeInformation: {LoTEVersionIdentifier: 1, LoTESequenceNumber: 1, LoTEType: $type,
        ListIssueDateTime: $issued, NextUpdate: $next,
        SchemeOperatorName: [{lang: "en", value: "Keycloak Demo"}]},
      TrustedEntitiesList: [{
        TrustedEntityInformation: {TEName: [{lang: "en", value: "Keycloak Demo"}]},
        TrustedEntityServices: [{ServiceInformation: {
          ServiceName: [{lang: "en", value: "Keycloak demo credentials"}],
          ServiceTypeIdentifier: $service,
          ServiceDigitalIdentity: {X509Certificates: [{val: $cert}]}}}]}]}}' | tr -d '\n' | base64url)"
  # JWS ES256 uses the two integers as fixed width values, while openssl writes them as DER.
  signature="$(printf '%s' "${input}" | openssl dgst -sha256 -sign "${STATE_DIR}/list.key" -binary \
    | openssl asn1parse -inform DER | sed -n 's/.*INTEGER *:\(.*\)/\1/p' \
    | while read -r integer; do printf '%64s' "${integer}" | tr ' ' 0; done | xxd -r -p | base64url)"
  mkdir -p "$(dirname "${ISSUER_LIST_FILE}")"
  printf '%s.%s' "${input}" "${signature}" > "${ISSUER_LIST_FILE}"
}

# Keycloak imports the key with this certificate, and the highest priority signs by default.
import_key() {
  local name="$1" priority="$2" key="$3" certificate="$4" realm_id private public
  private="$(openssl pkey -in "${key}" -outform DER | base64 | tr -d '\n')"
  public="$(openssl pkey -in "${key}" -pubout -outform DER | base64 | tr -d '\n')"
  realm_id="$(admin GET "/${REALM}" | jq -r .id)"
  admin POST "/${REALM}/components" "$(jq -n --arg name "${name}" --arg priority "${priority}" --arg parent "${realm_id}" --arg private "${private}" --arg public "${public}" \
    --arg certificate "$(openssl x509 -in "${certificate}" -outform DER | base64 | tr -d '\n')" '{
    name: $name, parentId: $parent, providerId: "ecdsa-generated",
    providerType: "org.keycloak.keys.KeyProvider",
    config: {
      priority: [$priority], enabled: ["true"], active: ["true"], algorithm: ["ES256"], keyUse: ["SIG"],
      ecdsaPrivateKey: [$private], ecdsaPublicKey: [$public], ecdsaEllipticCurveKey: ["P-256"],
      certificate: [$certificate]
    }
  }')"
}

key_id() {
  admin GET "/${REALM}/keys" | jq -r --arg certificate "$(openssl x509 -in "$1" -outform DER | base64 | tr -d '\n')" \
    '.keys[] | select(.certificate == $certificate) | .kid'
}

# HAIP 1.0 forbids a self-signed signing certificate, so credentials are signed under the demo's CA.
create_signing_key() {
  import_key issuer-signing-key 200 "${STATE_DIR}/issuer.key" "${STATE_DIR}/issuer.pem"
  ISSUER_KEY_ID="$(key_id "${STATE_DIR}/issuer.pem")"
}

# The wallet's registrar issues an access certificate for one key, which all variants share. It
# signs the issuer metadata and the wallet login's request objects. Credentials stay under the
# demo's CA, because an access CA does not anchor them.
create_access_key() {
  [[ -n "${RELYING_PARTY_ID:-}" ]] || return 0
  [[ -f "${STATE_DIR}/access.key" ]] || openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
    | openssl pkcs8 -topk8 -nocrypt -out "${STATE_DIR}/access.key"
  if ! openssl x509 -in "${STATE_DIR}/access.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
    local request
    request="$(mktemp)"
    openssl req -new -key "${STATE_DIR}/access.key" -subj "/" -out "${request}"
    jq -n --arg id "${RELYING_PARTY_ID}" --arg service "${RELYING_PARTY_SERVICE}" --rawfile csr "${request}" \
      '{identifier: $id, serviceIdentifier: $service, csr: $csr}' \
      | curl -fsS -X POST "${WALLET}/api/registrar/access-certificates" -H 'Content-Type: application/json' -d @- \
      | jq -er .certificate > "${STATE_DIR}/access.pem"
    rm -f "${request}"
  fi
  import_key access-signing-key 300 "${STATE_DIR}/access.key" "${STATE_DIR}/access.pem"
}

sign_issuer_metadata() {
  [[ -n "${RELYING_PARTY_ID:-}" ]] || return 0
  local issuer_info realm
  issuer_info="$(curl -fsS "${WALLET}/api/registrar/registration-certificates?identifier=${RELYING_PARTY_ID}" \
    | jq -er '[.[] | select(.issuerInfo)][0].issuerInfo')"
  realm="$(admin GET "/${REALM}")"
  admin PUT "/${REALM}" "$(jq --arg issuer_info "${issuer_info}" \
    '.attributes += {"oid4vci.signed_metadata.alg": "ES256", "oid4vci.issuer_info": $issuer_info}' <<< "${realm}")"
}

jwt_part() {
  cut -d. -f"$1" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | base64 -d
}

create_trust_provider() {
  local alias="$1" list_url="$2" signer="$3" lote="$4" service="$5" anchors="$6"
  if [[ "${TRUST}" == etsi-trust-list ]]; then
    admin POST "/${REALM}/identity-provider/instances" "$(jq -n --arg alias "${alias}" --arg url "${list_url}" \
      --arg signer "${signer}" --arg lote "${lote}" --arg service "${service}" '{
      alias: $alias, providerId: "etsi-trust-list", enabled: true,
      config: {trustListUrl: $url, trustListSigningCertificates: $signer, trustListLoteType: $lote, trustListServiceTypes: $service}
    }')"
  else
    admin POST "/${REALM}/identity-provider/instances" "$(jq -n --arg alias "${alias}" --arg anchors "${anchors}" '{
      alias: $alias, providerId: "default-trust", enabled: true,
      config: {useX509: "true", trustedCertificates: $anchors}
    }')"
  fi
}

# Without the ETSI provider Keycloak gets the wallet's root CA directly, which it can only check
# against self-signed roots. The ETSI lists hold the subordinate CA instead.
create_trust_providers() {
  [[ "${TRUST}" != none ]] || return 0
  local signer anchor
  signer="$(curl -fsS "${WALLET}/api/trustlists/wallet-provider" | jwt_part 1 | jq -r '.x5c[0]' | fold -w 64 | sed -e '1i\
-----BEGIN CERTIFICATE-----' -e '$a\
-----END CERTIFICATE-----')"
  anchor="$(curl -fsS "${WALLET}/api/certificates/ca")"
  create_trust_provider wallet-providers "${WALLET_LIST_URL}" "${signer}" "${LOTE_WALLET}" "${SERVICE_ISSUANCE}" "${anchor}"
  create_trust_provider demo-issuers "${ISSUER_LIST_URL}" "${ISSUER_LIST_SIGNER}" "${LOTE_ISSUERS}" "${SERVICE_ISSUERS}" "${ISSUER_CA}"
  [[ "${TRUST}" == default-trust ]] && create_attester_provider
  return 0
}

# Keycloak releases look up the attester of a client attestation by kid and ignore its x5c, so they
# need the wallet provider's key itself. The wallet's kid is the RFC 7638 thumbprint of that key.
create_attester_provider() {
  local certificate point x y kid
  certificate="$(curl -fsS "${WALLET}/api/trustlists/wallet-provider" | jwt_part 2 | jq -r --arg service "${SERVICE_ISSUANCE}" \
    '[.LoTE.TrustedEntitiesList[].TrustedEntityServices[].ServiceInformation | select(.ServiceTypeIdentifier == $service)
      | .ServiceDigitalIdentity.X509Certificates[].val][0]')"
  point="$(mktemp)"
  base64 -d <<< "${certificate}" | openssl x509 -inform DER -pubkey -noout | openssl pkey -pubin -outform DER | tail -c 64 > "${point}"
  x="$(head -c 32 "${point}" | base64url)"
  y="$(tail -c 32 "${point}" | base64url)"
  rm -f "${point}"
  kid="$(printf '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' "${x}" "${y}" | openssl dgst -sha256 -binary | base64url)"
  admin POST "/${REALM}/identity-provider/instances" "$(jq -n --arg x "${x}" --arg y "${y}" --arg kid "${kid}" '{
    alias: "wallet-attesters", providerId: "default-trust", enabled: true,
    config: {useJwksUrl: "false", publicKeySignatureVerifier: ({keys: [{kty: "EC", crv: "P-256", x: $x, y: $y, kid: $kid, use: "sig", alg: "ES256"}]} | tojson)}
  }')"
  ATTESTERS=wallet-attesters
}

create_credential() {
  local attestation=false
  [[ "${TRUST}" != none ]] && attestation=true
  admin POST "/${REALM}/client-scopes" "$(jq -n --arg id "${CREDENTIAL}" --arg attestation "${attestation}" \
    --arg images "${DEMO_ORIGIN}${DEMO_PATH}card/" --arg signing_key "${ISSUER_KEY_ID}" '{
    name: $id, protocol: "oid4vc",
    attributes: {
      "vc.credential_configuration_id": $id, "vc.credential_identifier": $id, "vc.format": "dc+sd-jwt",
      "vc.verifiable_credential_type": $id, "vc.key_attestations_required": $attestation, "include.in.token.scope": "true",
      "vc.binding_required": "true", "vc.binding_required_proof_types": "jwt",
      "vc.cryptographic_binding_methods_supported": "jwk", "vc.credential_signing_alg": "ES256", "vc.signing_key_id": $signing_key,
      "vc.display": ([{
        name: "Keycloak Demo Pass", locale: "en", text_color: "#ffffff", background_color: "#2b2b2b",
        logo: {uri: ($images + "credential-logo.png"), alt_text: "Keycloak in the eudi-dev wallet"},
        background_image: {uri: ($images + "credential-background.png")}
      }] | tojson)
    },
    protocolMappers: [
      {name: "email", protocol: "oid4vc", protocolMapper: "oid4vc-user-attribute-mapper",
       config: {"claim.name": "email", "userAttribute": "email"}},
      {name: "firstName", protocol: "oid4vc", protocolMapper: "oid4vc-user-attribute-mapper",
       config: {"claim.name": "firstName", "userAttribute": "firstName"}},
      {name: "lastName", protocol: "oid4vc", protocolMapper: "oid4vc-user-attribute-mapper",
       config: {"claim.name": "lastName", "userAttribute": "lastName"}}
    ]
  }')"
}

create_client() {
  local client_id scope_id trust_attributes='{}'
  [[ "${TRUST}" != none ]] && trust_attributes='{"oid4vci.attester_trust_idps": "wallet-providers"}'
  admin POST "/${REALM}/clients" "$(jq -n --arg id "${CLIENT}" --arg origin "${DEMO_ORIGIN}" --arg path "${DEMO_PATH}" --argjson trust "${trust_attributes}" '{
    clientId: $id, publicClient: true, standardFlowEnabled: true, implicitFlowEnabled: false,
    directAccessGrantsEnabled: false, serviceAccountsEnabled: false, protocol: "openid-connect",
    redirectUris: [($origin + $path)], webOrigins: [$origin],
    protocolMappers: [{name: "sign-in method", protocol: "openid-connect", protocolMapper: "oidc-usersessionmodel-note-mapper",
      config: {"user.session.note": "sign_in_method", "claim.name": "sign_in_method", "jsonType.label": "String", "id.token.claim": "true"}}],
    attributes: ({"oid4vci.enabled": "true", "pkce.code.challenge.method": "S256", "post.logout.redirect.uris": ($origin + $path)} + $trust)
  }')"
  client_id="$(admin GET "/${REALM}/clients?clientId=${CLIENT}" | jq -r '.[0].id')"
  scope_id="$(admin GET "/${REALM}/client-scopes" | jq -r --arg id "${CREDENTIAL}" '.[] | select(.name == $id) | .id')"
  admin PUT "/${REALM}/clients/${client_id}/optional-client-scopes/${scope_id}"

  # Keycloak authenticates this client with the wallet attestation. A real issuer cannot know this
  # value in advance, so reading it here only works for a wallet we control. The start page binds
  # its offers to this client. Without attestation the wallet identifies itself with its origin.
  local wallet_client="${WALLET}" client='{"publicClient": true}'
  if [[ "${ATTESTED_CLIENT}" == true ]]; then
    wallet_client="$(curl -fsS "${WALLET}/api/config" | jq -er .attestation_client_id)"
    client='{"publicClient": false, "clientAuthenticatorType": "attestation-based"}'
    trust_attributes="$(jq -n --arg attesters "${ATTESTERS}" '{"oid4vci.attester_trust_idps": "wallet-providers", "attester_trust_idps": $attesters}')"
  fi
  admin POST "/${REALM}/clients" "$(jq -n --arg id "${wallet_client}" --arg wallet "${WALLET}" --arg origin "${DEMO_ORIGIN}" --arg path "${DEMO_PATH}" \
    --argjson client "${client}" --argjson trust "${trust_attributes}" '$client + {
    clientId: $id, standardFlowEnabled: true, implicitFlowEnabled: false,
    directAccessGrantsEnabled: false, serviceAccountsEnabled: false, protocol: "openid-connect",
    redirectUris: [($wallet + "/callback"), ($origin + $path)], webOrigins: [$origin],
    attributes: ({"oid4vci.enabled": "true"} + $trust)
  }')"
  client_id="$(admin GET "/${REALM}/clients?clientId=${wallet_client}" | jq -r '.[0].id')"
  admin PUT "/${REALM}/clients/${client_id}/optional-client-scopes/${scope_id}"
  WALLET_CLIENT="${wallet_client}"
}

write_page_config() {
  local version imprint=""
  # A build from a checkout reports a placeholder version, so KEYCLOAK_BUILD names it instead.
  version="${KEYCLOAK_BUILD:-$(jq -r .systemInfo.version <<< "${SERVER_INFO}")}"
  curl -fsS "${WALLET}/api/config" | jq -e .imprint >/dev/null && imprint="${WALLET}/imprint"
  mkdir -p "$(dirname "${WEB_CONFIG_FILE}")"
  jq -n --arg keycloak "${PUBLIC_URL}" --arg keycloakVersion "${version}" --arg wallet "${WALLET}" --arg walletClient "${WALLET_CLIENT}" \
    --arg demoUser "${USERNAME}" --arg imprint "${imprint}" --arg trust "${TRUST}" --arg keycloakBuildUrl "${KEYCLOAK_BUILD_URL:-}" \
    --arg keycloakBuildTitle "${KEYCLOAK_BUILD_TITLE:-}" \
    '{$keycloak, $keycloakVersion, $keycloakBuildUrl, $keycloakBuildTitle, $wallet, $walletClient, $demoUser, $imprint, $trust}' \
    | { printf 'const CONFIG = '; cat; } > "${WEB_CONFIG_FILE}"
}

create_user() {
  local user_id
  admin POST "/${REALM}/users" "$(jq -n --arg u "${USERNAME}" '{
    username: $u, email: $u, emailVerified: true, firstName: "Demo", lastName: "User", enabled: true,
    credentials: [{type: "password", value: "demo", temporary: false}]
  }')"
  user_id="$(admin GET "/${REALM}/users?exact=true&username=${USERNAME}" | jq -r '.[0].id')"
  admin POST "/${REALM}/users/${user_id}/vc/credentials" "$(jq -n --arg id "${CREDENTIAL}" '{credentialScopeName: $id}')" >/dev/null
}

# A read-only account, because its password is public. Maintainers see the configuration in the
# admin console and cannot change it.
create_viewer() {
  local user_id client_id roles
  admin POST "/${REALM}/users" '{
    "username": "viewer", "email": "viewer@example.com", "emailVerified": true, "firstName": "Read", "lastName": "Only",
    "enabled": true, "credentials": [{"type": "password", "value": "viewer", "temporary": false}]
  }'
  user_id="$(admin GET "/${REALM}/users?exact=true&username=viewer" | jq -r '.[0].id')"
  client_id="$(admin GET "/${REALM}/clients?clientId=realm-management" | jq -r '.[0].id')"
  roles="$(admin GET "/${REALM}/clients/${client_id}/roles" | jq -c '[.[] | select(.name | IN(
    "view-realm", "view-clients", "view-users", "view-identity-providers", "view-authorization",
    "query-realms", "query-clients", "query-users", "query-groups"))]')"
  admin POST "/${REALM}/users/${user_id}/role-mappings/clients/${client_id}" "${roles}"
}

# Only the demo account holds a credential this realm trusts. The flow links to that account and
# can never create one, so a wallet login cannot fill the database.
create_login_flow() {
  [[ "${WALLET_LOGIN}" == true ]] || return 0
  admin POST "/${REALM}/authentication/flows" '{"alias":"wallet login","providerId":"basic-flow","topLevel":true,"builtIn":false}'
  local provider
  for provider in idp-detect-existing-broker-user idp-auto-link; do
    admin POST "/${REALM}/authentication/flows/wallet%20login/executions/execution" "$(jq -n --arg p "${provider}" '{provider: $p}')"
  done
  local executions
  executions="$(admin GET "/${REALM}/authentication/flows/wallet%20login/executions" | jq -c '.[] | .requirement = "REQUIRED"')"
  while read -r execution; do
    admin PUT "/${REALM}/authentication/flows/wallet%20login/executions" "${execution}"
  done <<< "${executions}"
}

create_wallet_login() {
  [[ "${WALLET_LOGIN}" == true ]] || return 0
  local query
  query="$(jq -cn --arg vct "${CREDENTIAL}" '{credentials: [{id: "membership", format: "dc+sd-jwt",
    meta: {vct_values: [$vct]}, claims: [{path: ["email"]}, {path: ["firstName"]}, {path: ["lastName"]}]}]}')"
  admin POST "/${REALM}/identity-provider/instances" "$(jq -n --arg query "${query}" --arg scheme "${WALLET_SCHEME:-openid4vp://}" '{
    alias: "oid4vp", displayName: "EUDI wallet", providerId: "oid4vp", enabled: true,
    firstBrokerLoginFlowAlias: "wallet login",
    config: {dcqlQuery: $query, principalAttribute: "email", trustMaterialIdps: "demo-issuers", walletScheme: $scheme, responseMode: "direct_post.jwt", syncMode: "FORCE"}
  }')"
  # A session note, unlike a user attribute, describes only this sign-in.
  admin POST "/${REALM}/identity-provider/instances/oid4vp/mappers" '{
    "name": "sign-in method", "identityProviderAlias": "oid4vp", "identityProviderMapper": "hardcoded-user-session-attribute-idp-mapper",
    "config": {"attribute": "sign_in_method", "attribute.value": "wallet", "syncMode": "INHERIT"}
  }' >/dev/null
  local target
  for target in email firstName lastName; do
    admin POST "/${REALM}/identity-provider/instances/oid4vp/mappers" "$(jq -n --arg target "${target}" '{
      name: $target, identityProviderAlias: "oid4vp", identityProviderMapper: "oid4vp-sd-jwt-user-attribute-idp-mapper",
      config: {claim: $target, "user.attribute": $target}
    }')" >/dev/null
  done
}

# A shared account must not be editable, so the password stays the one the start page shows.
disable_account_console() {
  local name id representation
  for name in account account-console; do
    id="$(admin GET "/${REALM}/clients?clientId=${name}" | jq -r '.[0].id')"
    representation="$(admin GET "/${REALM}/clients/${id}" | jq '.enabled = false')"
    admin PUT "/${REALM}/clients/${id}" "${representation}"
  done
}

# The master realm is public like on any Keycloak, so its login needs guessing protection.
protect_master_realm() {
  admin PUT /master '{"bruteForceProtected":true,"permanentLockout":false,"failureFactor":10,"maxFailureWaitSeconds":900}'
}

TOKEN="$(admin_token)"
read_capabilities
protect_master_realm
ensure_keys
create_realm
create_signing_key
create_access_key
create_issuer_list
create_trust_providers
create_credential
create_client
create_user
create_viewer
create_login_flow
create_wallet_login
disable_account_console
sign_issuer_metadata
write_page_config
echo "Realm ${REALM} is ready."
