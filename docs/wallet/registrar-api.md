# Registrar API walkthrough

This walkthrough registers a verifier and an issuer with the wallet's [registrar](registrar.md) over the HTTP API. Then it sends requests and offers signed with these certificates to a wallet running with `--arf`. The requests use `curl`, `jq` and `openssl`. The responses come from a wallet started like this:

```bash
eudi wallet serve --pid --arf --auto-accept
```

The wallet API is on port 8085 and its issuer endpoints are on port 8086. Long values such as certificates and JWTs are shortened with `...`. Identifiers, dates and status list entries differ on your wallet.

## Signing helpers

A verifier signs its request objects and an issuer its metadata, both with ES256. Any JOSE library works. The shell functions below use only `openssl`:

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# sign_es256 KEY HEADER PAYLOAD prints a compact JWS.
sign_es256() {
  local input sig
  input="$(printf '%s' "$2" | b64url).$(printf '%s' "$3" | b64url)"
  # openssl writes a DER signature. JWS needs r and s as 32 bytes each (RFC 7518 §3.4).
  sig=$(printf '%s' "$input" | openssl dgst -sha256 -sign "$1" | openssl asn1parse -inform DER |
    awk -F: '/INTEGER/ {printf "%064s", $NF}' | tr ' ' 0 | xxd -r -p | b64url)
  printf '%s.%s' "$input" "$sig"
}

# x5c turns PEM certificates into the JSON strings of an x5c header.
x5c() { awk '/BEGIN/ {c=""} !/-----/ {c=c $0} /END/ {printf "%s\"%s\"", (n++ ? "," : ""), c}' "$1"; }
```

## A verifier

### 1. Registration

The registration follows the TS05 data model. The intended use lists which credentials and claims the verifier may request. Here it is the birth date from the EUDI PID.

```bash
curl -s -X POST localhost:8085/api/registrar/wrp -H 'Content-Type: application/json' -d '{
  "tradeName": "Example Shop",
  "legalPerson": { "legalName": ["Example Shop B.V."] },
  "country": "NL",
  "services": [{
    "serviceTradeName": "Example Shop",
    "serviceIdentifier": "checkout",
    "intendedUses": [{
      "intendedUseIdentifier": "age-check",
      "purpose": [{ "lang": "en", "content": "Check that you are of age" }],
      "credentials": [{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:1"] },
        "claims": [{ "path": ["birthdate"] }]
      }]
    }]
  }]
}'
```

The registrar answers `201` with the stored registration. It assigned the identifier and filled in the defaults: the supervisory authority, the support and privacy policy URLs, and the `Service_Provider` entitlement.

```json
{
  "identifier": [
    { "identifier": "NLTEST.79AA013C47925C7B", "type": "http://data.europa.eu/eudi/id/EUID" }
  ],
  "legalPerson": { "legalName": ["Example Shop B.V."] },
  "country": "NL",
  "tradeName": "Example Shop",
  "isPSB": false,
  "supervisoryAuthority": {
    "name": "Test Supervisory Authority",
    "country": "NL",
    "email": ["dpa@eudi-test.dev"],
    "formURI": ["https://localhost:8086/supervisory-authority"]
  },
  "registryURI": "https://localhost:8086/api/registrar/wrp/NLTEST.79AA013C47925C7B",
  "services": [{
    "serviceTradeName": "Example Shop",
    "serviceIdentifier": "checkout",
    "supportURI": "https://localhost:8086/support",
    "srvDescription": [[{ "lang": "en", "content": "Example Shop" }]],
    "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
    "isIntermediary": false,
    "intendedUses": [{
      "intendedUseIdentifier": "age-check",
      "purpose": [{ "lang": "en", "content": "Check that you are of age" }],
      "privacyPolicy": [{
        "policyURI": "https://localhost:8086/privacy-policy",
        "type": "http://data.europa.eu/eudi/policy/privacy-policy"
      }],
      "createdAt": "2026-10-09",
      "credentials": [{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:1"] },
        "claims": [{ "path": ["birthdate"] }]
      }]
    }]
  }]
}
```

### 2. Access certificate

Create a P-256 key and a certificate signing request. You keep the private key.

```bash
ID=NLTEST.79AA013C47925C7B
openssl ecparam -name prime256v1 -genkey -noout -out verifier.key
openssl req -new -key verifier.key -subj "/" -out verifier.csr

jq -n --arg id "$ID" --rawfile csr verifier.csr \
  '{identifier: $id, serviceIdentifier: "checkout", csr: $csr, dnsNames: ["shop.example"]}' |
  curl -s -X POST localhost:8085/api/registrar/access-certificates -H 'Content-Type: application/json' -d @- > access.json
jq -r .certificate access.json > verifier.pem
```

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIID...",
  "chain": "-----BEGIN CERTIFICATE-----\nMIID...",
  "clientIds": [
    "x509_hash:B66d9xqUjxD5LWKSQpF7hk3MG2Y8hv9zAS9tlbqUJHs",
    "x509_san_dns:shop.example"
  ]
}
```

The chain holds the access certificate and the relying party access CA. That CA is the trust anchor, and a request object must not carry it in `x5c` (HAIP 1.0 §5). So the request uses `certificate` alone. The certificate carries the registered identity:

```text
subject=C=NL, O=Example Shop B.V., OU=checkout, CN=Example Shop, organizationIdentifier=NTRNL-NLTEST.79AA013C47925C7B
issuer=C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
X509v3 Subject Alternative Name: DNS:shop.example, URI:https://localhost:8086/support
X509v3 Certificate Policies: Policy: 0.4.0.194118.1.2
```

`clientIds` has the client identifiers: `x509_hash` for the certificate and `x509_san_dns` for each DNS name (OpenID4VP 1.0 §5.9.3).

### 3. Registration certificate

```bash
curl -s -X POST localhost:8085/api/registrar/registration-certificates -H 'Content-Type: application/json' \
  -d "{\"identifier\": \"$ID\", \"intendedUseIdentifier\": \"age-check\"}" > registration.json
```

```json
{
  "registrationCertificate": "eyJhbGciOiJFUzI1NiIsImlh...",
  "verifierInfo": "[{\"format\":\"registration_cert\",\"data\":\"ZXlKaGJHY2lPaUpGVXpJ...\"}]"
}
```

`verifierInfo` is a JSON string. Its content is the value of the `verifier_info` request parameter (OpenID4VP 1.0 §5.1). It has one `registration_cert` element (ETSI TS 119 472-2 RO-13 as adapted by CIR (EU) 2026/1731 Annex XII). Its data is the base64url encoding of the certificate (RO-16).

The payload of the certificate (ETSI TS 119 475 V1.2.1, typ `rc-wrp+jwt`) looks like this:

```json
{
  "sub": "NTRNL-NLTEST.79AA013C47925C7B",
  "sub_ln": "Example Shop B.V.",
  "name": "Example Shop",
  "country": "NL",
  "intended_use_id": "age-check",
  "purpose": [{ "lang": "en", "value": "Check that you are of age" }],
  "credentials": [{
    "format": "dc+sd-jwt",
    "meta": { "vct_values": ["urn:eudi:pid:1"] },
    "claim": [{ "path": ["birthdate"] }]
  }],
  "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
  "privacy_policy": "https://localhost:8086/privacy-policy",
  "support_uri": "https://localhost:8086/support",
  "srv_description": [[{ "lang": "en", "value": "Example Shop" }]],
  "supervisory_authority": {
    "name": "Test Supervisory Authority",
    "country": "NL",
    "email": "dpa@eudi-test.dev",
    "uri": "https://localhost:8086/supervisory-authority"
  },
  "registry_uri": "https://localhost:8086/api/registrar/wrp/NLTEST.79AA013C47925C7B",
  "policy_id": ["0.4.0.19475.3.1"],
  "certificate_policy": "https://github.com/eudi-dev/eudi-dev/blob/main/docs/test-certificates.md",
  "status": { "status_list": { "idx": 47187, "uri": "https://localhost:8086/api/registrar/status-list" } },
  "jti": "74f297f5-363e-482c-bb2f-33736e19b7ee",
  "iat": 1791563942,
  "exp": 1807115942
}
```

### 4. Request to the wallet

Sign a request object with the verifier key. Put the access certificate in `x5c` and the registration certificate in `verifier_info`. The `response_uri` is your verifier's endpoint.

```bash
CLIENT_ID=$(jq -r '.clientIds[0]' access.json)
HEADER='{"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":['"$(x5c verifier.pem)"']}'
PAYLOAD=$(jq -cn --arg client_id "$CLIENT_ID" --argjson verifier_info "$(jq -r .verifierInfo registration.json)" '{
  client_id: $client_id,
  response_type: "vp_token",
  response_mode: "direct_post",
  response_uri: "https://shop.example/response",
  nonce: "n-0S6_WzA2Mj",
  state: "af0ifjsldkj",
  verifier_info: $verifier_info,
  dcql_query: {credentials: [{id: "pid", format: "dc+sd-jwt",
    meta: {vct_values: ["urn:eudi:pid:1"]}, claims: [{path: ["birthdate"]}]}]}
}')
REQUEST=$(sign_es256 verifier.key "$HEADER" "$PAYLOAD")

jq -n --arg uri "openid4vp://authorize?client_id=$(jq -rn --arg v "$CLIENT_ID" '$v|@uri')&request=$REQUEST" '{uri: $uri}' |
  curl -s -X POST localhost:8085/api/presentations -H 'Content-Type: application/json' -d @-
```

The access certificate chains to the relying party access CA on the wallet's `access-ca` list. The registration certificate chains to the registrar CA on the wallet's `registrar` list. The request asks only for registered claims. The wallet therefore presents the PID and posts the response to `response_uri`:

```json
{
  "status": "submitted",
  "vp_token_keys": ["pid"],
  "redirect_uri": "https://shop.example/done",
  "response": {
    "status_code": 200,
    "body": "{\"redirect_uri\":\"https://shop.example/done\"}",
    "redirect_uri": "https://shop.example/done"
  }
}
```

### 5. Request beyond the registration

Add `family_name` to the DCQL query, sign again and send it. In debug mode the wallet still presents. The response has the same fields as above and adds `findings`:

```json
{
  "status": "submitted",
  "findings": [
    "ARF RPRC_21: the request asks for family_name of urn:eudi:pid:1. The registration certificate does not register it (over-asking)"
  ]
}
```

In strict mode (`wallet --mode strict serve` or `PUT /api/config/conformance` with `{"validation_mode": "strict"}`) the wallet refuses. The verifier authenticated with a trusted access certificate, so the wallet sends the verifier an `access_denied` error:

```json
{
  "status": "refused",
  "error": "access_denied",
  "error_description": "The request does not meet the ARF registration rules: ARF RPRC_21: the request asks for family_name of urn:eudi:pid:1. The registration certificate does not register it (over-asking)",
  "redirect_uri": "https://shop.example/done"
}
```

The verifier receives the same error at its `response_uri`:

```text
error=access_denied&error_description=The+request+does+not+meet+the+ARF+registration+rules...&state=af0ifjsldkj
```

## An issuer

### 1. Registration

An issuer lists its attestation types. Without an entitlement, the registrar takes the entitlement of each type's category from the catalogue. `urn:example:diploma:1` has no catalogue entry, so it is an EAA and the issuer gets `Non_Q_EAA_Provider`.

```bash
curl -s -X POST localhost:8085/api/registrar/wrp -H 'Content-Type: application/json' -d '{
  "tradeName": "Example University",
  "legalPerson": { "legalName": ["Example University"] },
  "country": "NL",
  "services": [{
    "serviceTradeName": "Example University",
    "serviceIdentifier": "diplomas",
    "providesAttestations": [{ "format": "dc+sd-jwt", "type": "urn:example:diploma:1" }]
  }]
}' > issuer-record.json
```

The service in the answer:

```json
{
  "serviceTradeName": "Example University",
  "serviceIdentifier": "diplomas",
  "supportURI": "https://localhost:8086/support",
  "srvDescription": [[{ "lang": "en", "content": "Example University" }]],
  "entitlements": ["https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"],
  "providesAttestations": [{ "format": "dc+sd-jwt", "type": "urn:example:diploma:1" }],
  "isIntermediary": false
}
```

### 2. Certificates

The access certificate request works as for a verifier. The registration certificate request gives the service instead of an intended use:

```bash
ID=NLTEST.4D1BB6AFA1D92DE9
openssl ecparam -name prime256v1 -genkey -noout -out issuer.key
openssl req -new -key issuer.key -subj "/" -out issuer.csr
jq -n --arg id "$ID" --rawfile csr issuer.csr '{identifier: $id, serviceIdentifier: "diplomas", csr: $csr}' |
  curl -s -X POST localhost:8085/api/registrar/access-certificates -H 'Content-Type: application/json' -d @- > issuer-access.json
jq -r .certificate issuer-access.json > issuer.pem

curl -s -X POST localhost:8085/api/registrar/registration-certificates -H 'Content-Type: application/json' \
  -d "{\"identifier\": \"$ID\", \"serviceIdentifier\": \"diplomas\"}" > issuer-registration.json
```

The answer has `registrationCertificate` and `issuerInfo`. `issuerInfo` is a JSON string with the `issuer_info` array. It has one `registration_cert` element with the plain JWT (ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI):

```json
[{ "format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiIsImlh..." }]
```

The certificate has `entitlements` and `provides_attestations` instead of an intended use:

```json
{
  "sub": "NTRNL-NLTEST.4D1BB6AFA1D92DE9",
  "name": "Example University",
  "entitlements": ["https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"],
  "provides_attestations": [{ "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:diploma:1"] } }]
}
```

### 3. Signed issuer metadata

Put `issuer_info` at the top level of the Credential Issuer Metadata. Sign the metadata with the issuer key and the access certificate in `x5c` (OpenID4VCI 1.0 §12.2.3, ETSI TS 119 472-3 §4.2.2). The trust anchor stays out of `x5c` (HAIP 1.0 §4.1). The signed metadata needs `sub`, the Credential Issuer Identifier, and `iat`.

```bash
ISSUER=https://university.example
METADATA=$(jq -c --arg iss "$ISSUER" --argjson info "$(jq -r .issuerInfo issuer-registration.json)" -n '{
  credential_issuer: $iss,
  credential_endpoint: ($iss + "/credential"),
  issuer_info: $info,
  credential_configurations_supported: {diploma: {format: "dc+sd-jwt", vct: "urn:example:diploma:1",
    cryptographic_binding_methods_supported: ["jwk"], credential_signing_alg_values_supported: ["ES256"],
    proof_types_supported: {jwt: {proof_signing_alg_values_supported: ["ES256"]}}}}
}')
PAYLOAD=$(jq -c --argjson iat "$(date +%s)" '. + {sub: .credential_issuer, iat: $iat}' <<< "$METADATA")
sign_es256 issuer.key '{"alg":"ES256","typ":"openidvci-issuer-metadata+jwt","x5c":['"$(x5c issuer.pem)"']}' "$PAYLOAD" > metadata.jwt
```

Serve `metadata.jwt` at `/.well-known/openid-credential-issuer` with the content type `application/jwt` when the request's `Accept` header includes `application/jwt`. With `--arf` the wallet sends this header.

### 4. Credential offer

Send the wallet an offer:

```bash
OFFER=$(jq -cn --arg iss "$ISSUER" '{credential_issuer: $iss, credential_configuration_ids: ["diploma"],
  grants: {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "code-123"}}}')
jq -n --arg uri "openid-credential-offer://?credential_offer=$(jq -rn --arg v "$OFFER" '$v|@uri')" '{uri: $uri}' |
  curl -s -X POST localhost:8085/api/offers -H 'Content-Type: application/json' -d @-
```

Before it requests the token, the wallet checks the signed metadata. The access certificate must chain to a CA on the wallet's `access-ca` list. The registration certificate must chain to a CA on the wallet's `registrar` list, list the offered type and give the issuer the entitlement of the type's category (see [ARF checks for issuers](issuing.md#arf-checks)).

The offer above passes. An offer for a type missing from the registration certificate gets a finding. In debug mode it is a warning in the activity log:

```text
ARF RPRC_23 and ISSU_34b: the issuer's registration certificate does not list urn:example:badge:1 in provides_attestations
```

In strict mode the wallet refuses the offer before it requests a token:

```json
{
  "error": "invalid_request",
  "error_description": "the issuer does not authenticate as the ARF requires: ARF RPRC_23 and ISSU_34b: the issuer's registration certificate does not list urn:example:badge:1 in provides_attestations"
}
```

### 5. PID request before issuance

An issuer that checks your identity before issuance also acts as a verifier. CIR (EU) 2025/848 Annex I keeps all entitlements and intended uses of a party in one registration, so add an intended use to the service from step 1 (TS05 v1.5 §2.4.1). `PUT /wrp` replaces the whole record, so send the stored record back with the new intended use.

```bash
jq '.services[0].intendedUses = [{
  purpose: [{lang: "en", content: "Checks who you are before a diploma is issued"}],
  credentials: [{format: "dc+sd-jwt", meta: {vct_values: ["urn:eudi:pid:1"]},
    claims: [{path: ["given_name"]}, {path: ["family_name"]}]}]
}]' issuer-record.json |
  curl -s -X PUT localhost:8085/api/registrar/wrp -H 'Content-Type: application/json' -H 'Accept: application/json' -d @- > issuer-updated.json
```

The service keeps its provider entitlement and gets `Service_Provider`:

```json
{
  "entitlements": [
    "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider",
    "https://uri.etsi.org/19475/Entitlement/Service_Provider"
  ],
  "intendedUses": [{
    "intendedUseIdentifier": "8605a76b61c33a6c",
    "purpose": [{ "lang": "en", "content": "Checks who you are before a diploma is issued" }],
    ...
  }]
}
```

The certificate of a service lists its entitlements, so the registrar revoked the certificate from step 2. Request a new one for the service and one for the intended use. Put the new `issuerInfo` in the metadata and sign it again as in step 3.

```bash
curl -s -X POST localhost:8085/api/registrar/registration-certificates -H 'Content-Type: application/json' \
  -d "{\"identifier\": \"$ID\", \"serviceIdentifier\": \"diplomas\"}" > issuer-registration.json
USE=$(jq -r '.data.services[0].intendedUses[0].intendedUseIdentifier' issuer-updated.json)
curl -s -X POST localhost:8085/api/registrar/registration-certificates -H 'Content-Type: application/json' \
  -d "{\"identifier\": \"$ID\", \"intendedUseIdentifier\": \"$USE\"}" > identity-check.json
```

The CLI adds the intended use and issues its certificate in one step: `eudi registrar verifiers add --to $ID --purpose "Checks who you are before a diploma is issued" --dcql pid.json` prints the `verifier_info` value. `eudi registrar registration-cert --identifier $ID --provider` then prints the new `issuer_info`.

The answer has `verifierInfo` like a verifier's. Sign the request as in [step 4 of the verifier](#4-request-to-the-wallet), with the issuer's key and access certificate:

```bash
CLIENT_ID=$(jq -r '.clientIds[0]' issuer-access.json)
HEADER='{"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":['"$(x5c issuer.pem)"']}'
PAYLOAD=$(jq -cn --arg client_id "$CLIENT_ID" --argjson verifier_info "$(jq -r .verifierInfo identity-check.json)" '{
  client_id: $client_id,
  response_type: "vp_token",
  response_mode: "direct_post",
  response_uri: "https://university.example/response",
  nonce: "n-0S6_WzA2Mj",
  state: "af0ifjsldkj",
  verifier_info: $verifier_info,
  dcql_query: {credentials: [{id: "pid", format: "dc+sd-jwt",
    meta: {vct_values: ["urn:eudi:pid:1"]}, claims: [{path: ["given_name"]}, {path: ["family_name"]}]}]}
}')
REQUEST=$(sign_es256 issuer.key "$HEADER" "$PAYLOAD")
```

The wallet checks this request like any other verifier request. The access certificate and the registration certificate identify the same relying party (RPRC_17a), so the wallet presents the PID.

## Certificates from another registrar

The wallet anchors access certificates and registration certificates only through its `access-ca` and `registrar` lists. To test certificates from your own registrar, put its CAs on these lists:

```bash
eudi trust add-ca --list access-ca --name "My Registrar Access CA" --ca my-access-ca.pem
eudi trust add-ca --list registrar --name "My Registrar" --ca my-registrar-ca.pem
```

Or use the API. It answers `201` with the entity and its `id`:

```bash
jq -n --rawfile ca my-registrar-ca.pem '{list: "registrar", name: "My Registrar", certificates: $ca}' |
  curl -s -X POST localhost:8085/api/trust/entities -H 'Content-Type: application/json' -d @-
```

A CA on the `registrar` list anchors the registration certificates and their status list. See [trusted lists](serve.md#trusted-lists) for the other lists and for external lists.
