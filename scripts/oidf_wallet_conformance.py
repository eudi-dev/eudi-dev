#!/usr/bin/env python3

import argparse
import base64
import copy
import json
import os
import queue
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


MODULE_ID_RE = re.compile(r"Created test module, new id:\s*([A-Za-z0-9]+)")
RUNNING_MODULE_RE = re.compile(r"Running test module:\s*([^\[]+)(.*)$")
VARIANT_RE = re.compile(r"\[([^=\]]+)=([^\]]*)\]")
PLAN_URL_RE = re.compile(r"(https://[^\s]+plan-detail\.html\?plan=[A-Za-z0-9]+)")
RUNNING_PLAN_CONFIG_RE = re.compile(r"Running plan '.+?' with configuration file '(.+?)'")
RESULTS_SAVED_RE = re.compile(r'results saved to "(.+?)"')
IMPLICIT_SUBMIT_RE = re.compile(r"xhr\.open\('POST',\s*([\"'])(.+?)\1", re.DOTALL)
JSON_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9._-]+\.json)\}")
TERMINAL_STATES = {"FINISHED", "INTERRUPTED"}
WALLET_MODE = os.environ.get("OIDF_WALLET_MODE", "strict")
POLL_INTERVAL = 1.0
REQUEST_TIMEOUT = int(os.environ.get("OIDF_REQUEST_TIMEOUT", "20"))
DEFAULT_MODULE_IDLE_TIMEOUT = 180
SCREENSHOT_DATA_URL = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WnRk9sAAAAASUVORK5CYII="
)


@dataclass(frozen=True)
class PlanScenario:
    slug: str
    kind: str
    template_relpath: str
    plan_name: str
    variant: dict[str, str]
    credential_kind: str
    requires_haip: bool = False


@dataclass(frozen=True)
class WalletMaterials:
    holder_jwk: dict
    issuer_jwk: dict
    ca_pem: str
    # The release under test, shown in the plan description.
    version: str


@dataclass(frozen=True)
class WalletSubmissionResult:
    completed: bool
    retryable: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the official OIDF Final and HAIP wallet plans against the local wallet")
    parser.add_argument("--suite-dir", required=True, help="Path to the extracted official OIDF conformance suite")
    parser.add_argument("--wallet-url", required=True, help="Base URL of the local wallet server")
    parser.add_argument("--wallet-issuer-url", required=True, help="HTTPS issuer URL served by the local wallet")
    parser.add_argument("--wallet-ca-cert", required=True, help="Path to the shared wallet CA PEM")
    parser.add_argument("--vci-client-id", required=True, help="OID4VCI authorization-code client_id to configure in the suite")
    parser.add_argument("--vci-redirect-uri", required=True, help="OID4VCI authorization-code redirect_uri to configure in the suite")
    parser.add_argument("--results-dir", required=True, help="Directory for exported official runner results")
    parser.add_argument("--runner-log", required=True, help="Path for mirrored official runner stdout")
    parser.add_argument(
        "--rerun",
        help="Pass through to the official OIDF runner, e.g. 2 or 2:6 or 1:6,2:6",
        default=None,
    )
    parser.add_argument(
        "--skip-variant",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Leave out the plans whose variant has this value, e.g. request_method=request_uri_unsigned (repeatable)",
    )
    return parser.parse_args()


def api_request(
    base_url: str,
    token: str | None,
    method: str,
    path: str,
    body: bytes | None = None,
    content_type: str | None = None,
):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
        data = resp.read()
        response_content_type = resp.headers.get("Content-Type", "")
        if "application/json" in response_content_type:
            return json.loads(data.decode("utf-8"))
        return data.decode("utf-8")


def request_json(url: str, context: ssl.SSLContext | None = None):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=context) as resp:
        return json.loads(resp.read().decode("utf-8"))


def conformance_api_context() -> ssl.SSLContext | None:
    if os.environ.get("CONFORMANCE_DEV_MODE") or os.environ.get("DISABLE_SSL_VERIFY"):
        return ssl._create_unverified_context()
    return None


def parse_running_module_line(line: str) -> dict:
    match = RUNNING_MODULE_RE.search(line)
    if not match:
        return {}
    return {
        "test_name": match.group(1).strip(),
        "variant": {key: value for key, value in VARIANT_RE.findall(match.group(2))},
    }


def merge_variants(*variants: dict | None) -> dict:
    merged = {}
    for variant in variants:
        if isinstance(variant, dict):
            merged.update(variant)
    return merged


def wallet_request(wallet_url: str, method: str, path: str, payload: dict | None = None, extra_headers: dict[str, str] | None = None):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    url = wallet_url.rstrip("/") + "/" + path.lstrip("/")
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        data = resp.read()
        return json.loads(data.decode("utf-8")) if data else None


def export_wallet_activity(wallet_url: str, output: Path, clear: bool) -> None:
    """Export the wallet activity for this plan and clear it before the next plan reaches the log limit."""
    try:
        entries = wallet_request(wallet_url, "GET", "/api/log?view=activity")
        output.write_text(json.dumps(entries, indent=1))
        if clear:
            wallet_request(wallet_url, "DELETE", "/api/log")
        print(f"[monitor] saved the wallet activity log to {output.name}", flush=True)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"[monitor] wallet activity log export failed: {exc}", flush=True)


def should_retry_wallet_submission(status_code: int, body: str) -> bool:
    if status_code not in {502, 503, 504}:
        return False
    lowered = body.lower()
    return "temporarily unavailable" in lowered or "timeout" in lowered or "timed out" in lowered


def verify_suite_support(suite_dir: Path) -> None:
    required = [
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vp-wallet-test-config-dcql-sdjwt.json",
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vp-wallet-test-config-dcql-mdoc.json",
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vci-wallet-test-config-plain.json",
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vci-wallet-test-config-haip.json",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vp1finalwallet" / "VP1FinalWalletTestPlan.java",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vci10wallet" / "VCIWalletTestPlan.java",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vp1finalwallet" / "VP1FinalWalletTestPlanHaip.java",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vci10wallet" / "VCIWalletTestPlanHaip.java",
    ]
    missing = [path for path in required if not path.exists()]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise FileNotFoundError(f"the extracted OIDF suite is missing required Final plan files:\n{formatted}")


VP_FINAL_RESPONSE_MODES = ("direct_post", "direct_post.jwt")
VP_FINAL_DCAPI_RESPONSE_MODES = ("dc_api", "dc_api.jwt")

# Supported prefix and request method combinations depend on the response mode. URL query
# delivery applies outside DC API, while multisigned requests apply inside it (OID4VP 1.0
# Appendix A.3.2). This matrix excludes preregistered clients and DIDs.
VP_FINAL_REDIRECT_COMBOS = (
    ("redirect_uri", "url_query"),
    ("redirect_uri", "request_uri_unsigned"),
    ("x509_hash", "request_uri_signed"),
    ("x509_san_dns", "request_uri_signed"),
)
VP_FINAL_DCAPI_COMBOS = (
    ("web-origin", "request_uri_unsigned"),
    ("x509_hash", "request_uri_signed"),
    ("x509_san_dns", "request_uri_signed"),
    ("x509_hash", "request_uri_multisigned"),
    ("x509_san_dns", "request_uri_multisigned"),
)

VP_SLUG_TOKENS = {
    "redirect_uri": "redirect",
    "web-origin": "origin",
    "x509_hash": "hash",
    "x509_san_dns": "sandns",
    "url_query": "query",
    "request_uri_unsigned": "unsigned",
    "request_uri_signed": "signed",
    "request_uri_multisigned": "multisigned",
    "direct_post": "direct-post",
    "direct_post.jwt": "direct-post-jwt",
    "dc_api": "dc-api",
    "dc_api.jwt": "dc-api-jwt",
}

VP_TEMPLATES = {
    "sdjwt": "scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
    "mdoc": "scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc.json",
}
VP_FORMAT_VARIANTS = {"sdjwt": "sd_jwt_vc", "mdoc": "iso_mdl"}


def vp_final_scenarios() -> list[PlanScenario]:
    """Every OID4VP Final wallet plan variant combination the wallet supports."""
    scenarios = []
    families = (
        (VP_FINAL_REDIRECT_COMBOS, VP_FINAL_RESPONSE_MODES),
        (VP_FINAL_DCAPI_COMBOS, VP_FINAL_DCAPI_RESPONSE_MODES),
    )
    for kind in ("sdjwt", "mdoc"):
        for combos, response_modes in families:
            for prefix, method in combos:
                for response_mode in response_modes:
                    slug = "vp-final-{}-{}-{}-{}".format(
                        kind, VP_SLUG_TOKENS[prefix], VP_SLUG_TOKENS[method], VP_SLUG_TOKENS[response_mode]
                    )
                    scenarios.append(
                        PlanScenario(
                            slug=slug,
                            kind="vp",
                            template_relpath=VP_TEMPLATES[kind],
                            plan_name="oid4vp-1final-wallet-test-plan",
                            variant={
                                "vp_profile": "plain_vp",
                                "credential_format": VP_FORMAT_VARIANTS[kind],
                                "client_id_prefix": prefix,
                                "request_method": method,
                                "response_mode": response_mode,
                            },
                            credential_kind=kind,
                        )
                    )
    return scenarios


VCI_FORMAT_VARIANTS = {"sdjwt": "sd_jwt_vc", "mdoc": "mdoc"}
VCI_SLUG_TOKENS = {
    "authorization_code": "authcode",
    "pre_authorization_code": "preauth",
    "by_value": "byval",
    "by_reference": "byref",
    "immediate": "immediate",
    "deferred": "deferred",
    "plain": "plain",
    "encrypted": "encrypted",
}


def vci_authorization_request_type(kind: str, grant: str) -> str:
    """Pick the suite's authorization_request_type variant for a Final VCI plan.

    A pre-authorized flow has no authorization request, so the suite fills in the
    requested credential itself. Under "simple" it injects the scope eudi.pid.1
    (VCIInjectRequestScopePreAuthorizedCodeFlow in release-v5.3.1), which maps to
    the SD-JWT PID, so an mdoc offer gets an SD-JWT token response. Under "rar" it
    injects the offered credential_configuration_id."""
    if kind == "mdoc" and grant == "pre_authorization_code":
        return "rar"
    return "simple"


def vci_final_scenarios() -> list[PlanScenario]:
    """Build supported OID4VCI Final variants.

    These flows start from an issuer offer and use client attestation, DPoP and scope authorization."""
    scenarios = []
    for kind in ("sdjwt", "mdoc"):
        for grant in ("authorization_code", "pre_authorization_code"):
            for offer in ("by_value", "by_reference"):
                for mode in ("immediate", "deferred"):
                    for encryption in ("plain", "encrypted"):
                        slug = "vci-final-{}-{}-{}-{}-{}".format(
                            kind, VCI_SLUG_TOKENS[grant], VCI_SLUG_TOKENS[offer],
                            VCI_SLUG_TOKENS[mode], VCI_SLUG_TOKENS[encryption]
                        )
                        scenarios.append(
                            PlanScenario(
                                slug=slug,
                                kind="vci",
                                template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json",
                                plan_name="oid4vci-1_0-wallet-test-plan",
                                variant={
                                    "client_auth_type": "client_attestation",
                                    "fapi_request_method": "unsigned",
                                    "sender_constrain": "dpop",
                                    "authorization_request_type": vci_authorization_request_type(kind, grant),
                                    "fapi_profile": "vci",
                                    "vci_grant_type": grant,
                                    # Pre-authorized offers are issuer initiated because
                                    # they have no authorization endpoint to start from.
                                    "vci_authorization_code_flow_variant": "issuer_initiated",
                                    "vci_credential_offer_variant": offer,
                                    "credential_format": VCI_FORMAT_VARIANTS[kind],
                                    "vci_credential_issuance_mode": mode,
                                    "vci_credential_encryption": encryption,
                                },
                                credential_kind=kind,
                            )
                        )
    return scenarios


def final_scenarios() -> list[PlanScenario]:
    import os as _os
    _only = _os.environ.get("ONLY_SCENARIOS", "")
    scenarios = vp_final_scenarios() + vci_final_scenarios()
    scenarios.extend(
        [
            PlanScenario(
                slug="vp-haip-sdjwt-direct-post-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "sd_jwt_vc",
                    "response_mode": "direct_post.jwt",
                },
                credential_kind="sdjwt",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vp-haip-mdoc-direct-post-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "iso_mdl",
                    "response_mode": "direct_post.jwt",
                },
                credential_kind="mdoc",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vp-haip-sdjwt-dc-api-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "sd_jwt_vc",
                    "response_mode": "dc_api.jwt",
                },
                credential_kind="sdjwt",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vp-haip-mdoc-dc-api-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "iso_mdl",
                    "response_mode": "dc_api.jwt",
                },
                credential_kind="mdoc",
                requires_haip=True,
            ),
            # Cover HAIP formats and issuer or wallet initiated flows. The plan fixes
            # client attestation and DPoP and includes immediate, deferred and encrypted
            # issuance as modules.
            *[
                PlanScenario(
                    slug="vci-haip-{}-{}".format(kind, VCI_SLUG_TOKENS[offer]),
                    kind="vci",
                    template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-haip.json",
                    plan_name="oid4vci-1_0-wallet-haip-test-plan",
                    variant={
                        "vci_authorization_code_flow_variant": "issuer_initiated",
                        "vci_credential_offer_variant": offer,
                        "credential_format": VCI_FORMAT_VARIANTS[kind],
                    },
                    credential_kind=kind,
                    requires_haip=True,
                )
                for kind in ("sdjwt", "mdoc")
                for offer in ("by_value", "by_reference")
            ],
            *[
                PlanScenario(
                    slug="vci-haip-{}-wallet-initiated".format(kind),
                    kind="vci",
                    template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-haip.json",
                    plan_name="oid4vci-1_0-wallet-haip-test-plan",
                    variant={
                        "vci_authorization_code_flow_variant": "wallet_initiated",
                        "credential_format": VCI_FORMAT_VARIANTS[kind],
                    },
                    credential_kind=kind,
                    requires_haip=True,
                )
                for kind in ("sdjwt", "mdoc")
            ],
        ]
    )
    if _only:
        scenarios = [sc for sc in scenarios if any(w in sc.slug for w in _only.split(","))]
    return scenarios


def decode_jwt_payload(jwt: str) -> dict | None:
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None


def browser_request_origin(browser_request: dict) -> str | None:
    if not isinstance(browser_request, dict):
        return None
    digital = browser_request.get("digital")
    if not isinstance(digital, dict):
        return None
    requests = digital.get("requests")
    if not isinstance(requests, list) or not requests:
        return None
    first = requests[0]
    if not isinstance(first, dict):
        return None
    data = first.get("data")
    client_id = None
    expected_origins = None
    if isinstance(data, dict):
        if isinstance(data.get("client_id"), str):
            client_id = data["client_id"]
        expected_origins = data.get("expected_origins")
        if isinstance(data.get("request"), str):
            payload = decode_jwt_payload(data["request"])
            if isinstance(payload, dict) and isinstance(payload.get("client_id"), str):
                client_id = payload["client_id"]
    if isinstance(data, str):
        payload = decode_jwt_payload(data)
        if isinstance(payload, dict) and isinstance(payload.get("client_id"), str):
            client_id = payload["client_id"]
    if isinstance(client_id, str) and client_id.startswith("web-origin:"):
        return client_id[len("web-origin:") :]
    if isinstance(expected_origins, list) and expected_origins:
        first_origin = expected_origins[0]
        if isinstance(first_origin, str) and first_origin:
            return first_origin
    return None


def origin_from_submit_url(submit_url: str) -> str | None:
    parsed = urllib.parse.urlsplit(submit_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def build_vp_dcql_query(credential_kind: str) -> dict:
    if credential_kind == "mdoc":
        return {
            "credentials": [
                {
                    "id": "pid",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "eu.europa.ec.eudi.pid.1",
                    },
                    "claims": [
                        {"path": ["eu.europa.ec.eudi.pid.1", "given_name"]},
                        {"path": ["eu.europa.ec.eudi.pid.1", "family_name"]},
                    ],
                }
            ]
        }
    return {
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["urn:eudi:pid:1"],
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                ],
            }
        ]
    }


def conformance_server_host() -> str:
    base_url = os.environ.get("CONFORMANCE_SERVER_LOCAL") or os.environ.get("CONFORMANCE_SERVER") or "https://demo.certification.openid.net/"
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.hostname:
        return parsed.hostname
    return "demo.certification.openid.net"


def load_config_template(source: Path) -> dict:
    raw = source.read_text()

    def replace_placeholder(match: re.Match[str]) -> str:
        name = match.group(1)
        candidate = source.parents[1] / "certs-keys" / name
        if not candidate.exists():
            raise FileNotFoundError(f"template placeholder {name} does not exist at {candidate}")
        return candidate.read_text().strip()

    expanded = JSON_PLACEHOLDER_RE.sub(replace_placeholder, raw)
    return json.loads(expanded)


def ssl_context_for_ca(ca_path: Path) -> ssl.SSLContext:
    # Add the wallet CA to system roots. Hosted runs also need the public tunnel's
    # certificate to remain trusted.
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=str(ca_path))
    context.check_hostname = False
    return context


def public_jwk(jwk: dict) -> dict:
    return {key: value for key, value in jwk.items() if key not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}}


def signs_for_provider_role(jwk: dict, role: str) -> bool:
    """Tell whether the JWK's certificate was issued by the wallet's provider CA of role.

    The certificate's caIssuers URL (RFC 5280 §4.2.2.1) names that CA as
    /api/certificates/providers/<role>/<country>.der."""
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID

    x5c = jwk.get("x5c") or []
    if not x5c:
        return False
    cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return False
    return any(
        desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        and f"/api/certificates/providers/{role}/" in urllib.parse.urlparse(desc.access_location.value).path
        for desc in aia
    )


def fetch_wallet_materials(wallet_url: str, wallet_issuer_url: str, wallet_ca_cert: Path) -> WalletMaterials:
    credentials = wallet_request(wallet_url, "GET", "/api/credentials")
    holder_jwk = None
    for credential in credentials:
        # The listing carries a claim_count, not the claims, so the holder
        # binding key is read from the per-credential detail.
        claims = credential.get("claims")
        if not claims:
            cred_id = credential.get("id")
            if cred_id:
                detail = wallet_request(wallet_url, "GET", f"/api/credentials/{cred_id}")
                claims = detail.get("claims")
        cnf = (claims or {}).get("cnf", {})
        candidate = cnf.get("jwk")
        if isinstance(candidate, dict):
            holder_jwk = candidate
            break
    if holder_jwk is None:
        raise RuntimeError("wallet did not expose a holder cnf.jwk in /api/credentials")

    issuer_meta = request_json(
        wallet_issuer_url.rstrip("/") + "/.well-known/jwt-vc-issuer",
        context=ssl_context_for_ca(wallet_ca_cert),
    )
    keys = [key for key in issuer_meta.get("jwks", {}).get("keys", []) if isinstance(key, dict)]
    # The wallet signs each credential category with its own key. The configs
    # use the PID provider's key.
    pid_keys = [key for key in keys if signs_for_provider_role(key, "pid")]
    if len(pid_keys) != 1:
        raise RuntimeError(f"wallet issuer metadata did not expose exactly one PID provider JWK: {keys!r}")

    version = str(wallet_request(wallet_url, "GET", "/api/version").get("version", ""))
    return WalletMaterials(
        holder_jwk=public_jwk(holder_jwk),
        issuer_jwk=public_jwk(pid_keys[0]),
        ca_pem=wallet_ca_cert.read_text(),
        version=version.removeprefix("v"),
    )


def credential_chain_der(detail: dict) -> list[bytes]:
    """Read the x5c or COSE x5chain in leaf to issuer order."""
    raw = detail.get("raw")
    if not isinstance(raw, str) or not raw:
        return []
    fmt = str(detail.get("format", ""))
    try:
        if "sd-jwt" in fmt or "jwt" in fmt:
            header_b64 = raw.split("~")[0].split(".")[0]
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
            x5c = header.get("x5c") or []
            return [base64.b64decode(cert) for cert in x5c]
        import cbor2  # noqa: PLC0415 (installed into the runner venv)

        padded = raw + "=" * (-len(raw) % 4)
        issuer_signed = cbor2.loads(base64.urlsafe_b64decode(padded))
        issuer_auth = issuer_signed["issuerAuth"]
        for header_map in (cbor2.loads(issuer_auth[0]) if issuer_auth[0] else {}, issuer_auth[1] or {}):
            chain = header_map.get(33)
            if chain is None:
                continue
            return chain if isinstance(chain, list) else [chain]
    except Exception:  # noqa: BLE001
        return []
    return []


def chains_to_wallet_ca(chain_der: list[bytes], ca_pem: str) -> bool:
    from cryptography import x509

    if not chain_der:
        return False
    try:
        chain = [x509.load_der_x509_certificate(cert) for cert in chain_der]
        ca = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
        if chain[-1] != ca:
            chain.append(ca)
        for child, parent in zip(chain, chain[1:]):
            if not parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                return False
            child.verify_directly_issued_by(parent)
        return True
    except Exception:  # noqa: BLE001
        return False


def baseline_credential_ids(wallet_url: str, wallet_ca_cert: Path) -> set[str]:
    """Find credentials signed under the wallet CA.

    A persistent wallet may contain credentials from earlier suite runs. Those use the suite CA and must be removed before presentation tests that trust the wallet CA."""
    ca_pem = wallet_ca_cert.read_text()
    baseline = set()
    for credential in wallet_request(wallet_url, "GET", "/api/credentials"):
        cred_id = credential.get("id")
        if not cred_id:
            continue
        detail = wallet_request(wallet_url, "GET", f"/api/credentials/{cred_id}")
        chain = credential_chain_der(detail)
        if not chains_to_wallet_ca(chain, ca_pem):
            continue
        baseline.add(cred_id)
    return baseline


def purge_issued_credentials(wallet_url: str, baseline_ids: set[str]) -> int:
    """Keep only the wallet baseline before each module.

    Credentials from issuance tests can match the same PID query but use a different CA. Presenting them would fail the next module's trust check for an unrelated reason."""
    try:
        credentials = wallet_request(wallet_url, "GET", "/api/credentials")
    except Exception as exc:  # noqa: BLE001
        print(f"[monitor] could not list credentials to purge: {exc}", flush=True)
        return 0
    removed = 0
    for credential in credentials:
        cred_id = credential.get("id")
        if not cred_id or cred_id in baseline_ids:
            continue
        # A successful delete answers 204 with no body. wallet_request would fail
        # on it because json.loads rejects an empty body.
        url = wallet_url.rstrip("/") + f"/api/credentials/{cred_id}"
        try:
            req = urllib.request.Request(url, method="DELETE")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT):
                removed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[monitor] could not delete credential {cred_id}: {exc}", flush=True)
    return removed


def wallet_run_suffix(args: argparse.Namespace) -> str:
    """Returns a token unique to this run, taken from the wallet's port."""
    port = urllib.parse.urlparse(args.wallet_url).port
    return str(port) if port else "local"


def create_vp_config(args: argparse.Namespace, suite_dir: Path, scenario: PlanScenario, materials: WalletMaterials, output: Path) -> None:
    config = load_config_template(suite_dir / scenario.template_relpath)
    # Include the wallet port in the alias so separate runs do not take over each
    # other's suite configuration.
    config["alias"] = f"oid4vc-dev-{scenario.slug}-{wallet_run_suffix(args)}"
    config["description"] = f"eudi-dev wallet {materials.version}"
    config.setdefault("client", {})
    config["client"]["dcql"] = build_vp_dcql_query(scenario.credential_kind)
    if scenario.requires_haip or scenario.variant.get("client_id_prefix") == "x509_san_dns":
        # Use the configured client_id for x509_san_dns, including DC API variants without
        # a response_uri.
        config["client"]["client_id"] = conformance_server_host()
    if scenario.variant.get("request_method") == "url_query":
        # URL query requests have no request_uri to observe. Configure the wallet's
        # reachable authorization endpoint so the suite can deliver the request directly.
        config.setdefault("server", {})
        config["server"]["authorization_endpoint"] = args.wallet_issuer_url.rstrip("/") + "/authorize"
    response_mode = scenario.variant.get("response_mode", "")
    if response_mode.endswith(".jwt"):
        config["client"]["authorization_encrypted_response_alg"] = "ECDH-ES"
        config["client"]["authorization_encrypted_response_enc"] = "A128GCM"
    if scenario.variant.get("request_method") == "request_uri_multisigned" or scenario.requires_haip:
        secondary_jwks = copy.deepcopy(config["client"].get("jwks", {"keys": []}))
        keys = secondary_jwks.get("keys", [])
        if keys and isinstance(keys[0], dict) and isinstance(keys[0].get("kid"), str):
            keys[0]["kid"] = keys[0]["kid"] + "-second"
        # For x509_hash, the suite derives the second signer's client_id from its
        # certificate.
        config["client2"] = {"jwks": secondary_jwks}
        if "client_id" in config["client"]:
            config["client2"]["client_id"] = config["client"]["client_id"]
    if scenario.requires_haip:
        config.setdefault("credential", {})
        config["credential"]["trust_anchor_pem"] = materials.ca_pem
        config["credential"]["status_list_trust_anchor_pem"] = materials.ca_pem
    with output.open("w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def create_vci_config(args: argparse.Namespace, suite_dir: Path, scenario: PlanScenario, materials: WalletMaterials, output: Path) -> None:
    config = load_config_template(suite_dir / scenario.template_relpath)
    redirect_uri = args.vci_redirect_uri
    parsed_redirect = urllib.parse.urlsplit(redirect_uri)
    if not parsed_redirect.path.endswith("/callback"):
        raise ValueError(f"VCI redirect_uri must end with /callback: {redirect_uri}")
    alias_prefix = parsed_redirect.path[: -len("/callback")].rstrip("/")
    alias = alias_prefix.rsplit("/", 1)[-1]
    if not alias:
        raise ValueError(f"VCI redirect_uri must include an alias path segment before /callback: {redirect_uri}")

    config["alias"] = alias
    config["description"] = f"eudi-dev wallet {materials.version}"
    config["waitTimeoutSeconds"] = 10
    config["maxWaitForAdditionalRequestSeconds"] = 20

    offer_path = parsed_redirect.path[: -len("/callback")] + "/credential_offer"
    credential_offer_endpoint = urllib.parse.urlunsplit(
        (parsed_redirect.scheme, parsed_redirect.netloc, offer_path, "", "")
    )

    config.setdefault("client", {})
    config["client"]["client_id"] = args.vci_client_id
    config["client"]["redirect_uri"] = redirect_uri
    config["client"]["jwks"] = {"keys": [materials.holder_jwk]}

    config.setdefault("server", {})
    config.setdefault("credential", {})
    config.setdefault("vci", {})
    config.setdefault("client_attestation", {})
    config["vci"]["credential_offer_endpoint"] = credential_offer_endpoint
    if scenario.credential_kind == "mdoc":
        # The attestation proof configuration issues one credential per attested key,
        # covering key attestation and batch issuance together (Appendix F.3).
        config["vci"]["credential_configuration_id"] = "eu.europa.ec.eudi.pid.mdoc.1.attestation.keyattest"
    else:
        config["vci"]["credential_configuration_id"] = "eu.europa.ec.eudi.pid.1"
    config["client_attestation"]["issuer"] = args.wallet_issuer_url
    config["client_attestation"]["trust_anchor"] = materials.ca_pem
    config["client_attestation"]["attester_jwks"] = {"keys": [materials.issuer_jwk]}
    config["client_attestation"]["key_attestation_jwks"] = {"keys": [materials.issuer_jwk]}
    config["client_attestation"]["key_attestation_trust_anchor_pem"] = materials.ca_pem
    config["vci"]["client_attestation_issuer"] = args.wallet_issuer_url
    config["vci"]["client_attestation_trust_anchor"] = materials.ca_pem
    config["vci"]["client_attester_keys_jwks"] = {"keys": [materials.issuer_jwk]}
    config["vci"]["key_attestation_jwks"] = {"keys": [materials.issuer_jwk]}
    config["vci"]["key_attestation_trust_anchor_pem"] = materials.ca_pem
    config["browser"] = []

    with output.open("w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def create_config(args: argparse.Namespace, suite_dir: Path, results_dir: Path, scenario: PlanScenario, materials: WalletMaterials) -> Path:
    output = results_dir / f"{scenario.slug}-config.json"
    if scenario.kind == "vp":
        create_vp_config(args, suite_dir, scenario, materials, output)
    elif scenario.kind == "vci":
        create_vci_config(args, suite_dir, scenario, materials, output)
    else:
        raise RuntimeError(f"unknown scenario kind {scenario.kind}")
    return output


VP_FINAL_MODULE_HAPPY_FLOW = "oid4vp-1final-wallet-happy-flow"
VP_FINAL_MODULE_ALTERNATE_HAPPY_FLOW = "oid4vp-1final-wallet-alternate-happy-flow"
VP_FINAL_MODULE_REQUEST_URI_METHOD_POST = "oid4vp-1final-wallet-request-uri-method-post"
VP_FINAL_MODULE_FEWER_CLAIMS = "oid4vp-1final-wallet-fewer-claims-than-available"
VP_FINAL_MODULE_OPTIONAL_CREDENTIAL_SET = "oid4vp-1final-wallet-optional-credential-set"
VP_FINAL_MODULE_NO_CLAIMS = "oid4vp-1final-wallet-no-claims-in-dcql-query"
VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID = "oid4vp-1final-wallet-negative-test-response-uri-not-client-id"
VP_FINAL_MODULE_INVALID_REQUEST_SIGNATURE = "oid4vp-1final-wallet-negative-test-invalid-request-object-signature"
VP_FINAL_MODULE_MULTISIGNED_ONE_INVALID = "oid4vp-1final-wallet-multisigned-one-invalid-signature"
VP_FINAL_MODULE_MISMATCHED_CLIENT_ID = "oid4vp-1final-wallet-negative-test-mismatched-client-id"
VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST = "oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post"
VP_FINAL_MODULE_MISSING_NONCE = "oid4vp-1final-wallet-negative-test-missing-nonce"
VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS = "oid4vp-1final-wallet-negative-test-wrong-expected-origins"
VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX = "oid4vp-1final-wallet-negative-test-invalid-client-id-prefix"
VP_FINAL_MODULE_UNKNOWN_TRANSACTION_DATA = "oid4vp-1final-wallet-negative-test-unknown-transaction-data-type"
VP_FINAL_MODULE_IGNORES_UNUSABLE_ENCRYPTION_KEY = "oid4vp-1final-wallet-ignores-unusable-encryption-key"

VP_FINAL_MODULES = (
    VP_FINAL_MODULE_HAPPY_FLOW,
    VP_FINAL_MODULE_ALTERNATE_HAPPY_FLOW,
    VP_FINAL_MODULE_IGNORES_UNUSABLE_ENCRYPTION_KEY,
    VP_FINAL_MODULE_REQUEST_URI_METHOD_POST,
    VP_FINAL_MODULE_FEWER_CLAIMS,
    VP_FINAL_MODULE_OPTIONAL_CREDENTIAL_SET,
    VP_FINAL_MODULE_NO_CLAIMS,
    VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID,
    VP_FINAL_MODULE_INVALID_REQUEST_SIGNATURE,
    VP_FINAL_MODULE_MULTISIGNED_ONE_INVALID,
    VP_FINAL_MODULE_MISMATCHED_CLIENT_ID,
    VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST,
    VP_FINAL_MODULE_MISSING_NONCE,
    VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS,
    VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX,
    VP_FINAL_MODULE_UNKNOWN_TRANSACTION_DATA,
)


def vp_modules_for_scenario(scenario: PlanScenario) -> tuple[str, ...] | None:
    if scenario.kind != "vp":
        return None

        # OIDF_VP_MODULES limits each VP plan to named modules for focused reproductions.
    forced = os.environ.get("OIDF_VP_MODULES", "")
    if forced:
        return tuple(name.strip() for name in forced.split(",") if name.strip())

    # Certification runs use complete HAIP plans. The suite defines applicable modules, so
    # apply no additional filter.
    if scenario.requires_haip:
        return None

    modules = list(VP_FINAL_MODULES)
    variant = scenario.variant
    response_mode = variant.get("response_mode", "")
    request_method = variant.get("request_method", "")
    client_id_prefix = variant.get("client_id_prefix", "")

    # The module's own @VariantNotApplicableWhen: an unsigned DC API request
    # carries no client_id to corrupt (OID4VP 1.0 Appendix A.2).
    if response_mode in {"dc_api", "dc_api.jwt"} and request_method == "request_uri_unsigned":
        modules.remove(VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX)

    if response_mode in {"direct_post", "dc_api"}:
        # @VariantNotApplicable: the unencrypted modes never advertise an
        # encryption key, so there is no unusable-key scenario to test.
        modules.remove(VP_FINAL_MODULE_IGNORES_UNUSABLE_ENCRYPTION_KEY)
    if response_mode in {"direct_post", "dc_api"}:
        # The alternate module always replaces the encrypted-response setup. The
        # unencrypted response modes have no such setup.
        modules.remove(VP_FINAL_MODULE_ALTERNATE_HAPPY_FLOW)
    if client_id_prefix != "redirect_uri" and response_mode not in {"dc_api", "dc_api.jwt"}:
        modules.remove(VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID)
    if request_method in {"request_uri_unsigned", "url_query"}:
        modules.remove(VP_FINAL_MODULE_INVALID_REQUEST_SIGNATURE)
    if request_method != "request_uri_multisigned":
        modules.remove(VP_FINAL_MODULE_MULTISIGNED_ONE_INVALID)
    if response_mode in {"dc_api", "dc_api.jwt"}:
        modules.remove(VP_FINAL_MODULE_REQUEST_URI_METHOD_POST)
        modules.remove(VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID)
        modules.remove(VP_FINAL_MODULE_MISMATCHED_CLIENT_ID)
        modules.remove(VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST)
    elif request_method in {"url_query", "request_uri_multisigned"}:
        # @VariantNotApplicable: the mismatched-client-id module corrupts the
        # request object of a single signed request delivered by reference.
        modules.remove(VP_FINAL_MODULE_MISMATCHED_CLIENT_ID)
    # @VariantNotApplicable: expected_origins only exists in encrypted Browser
    # API requests that are signed (unsigned requests carry no
    # expected_origins to falsify).
    if not (response_mode == "dc_api.jwt" and request_method in {"request_uri_signed", "request_uri_multisigned"}):
        if VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS in modules:
            modules.remove(VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS)
    if request_method == "url_query":
        # These negative modules create screenshot placeholders when request_uri is
        # fetched. URL query requests have no such fetch and would wait forever. The
        # request_uri variants cover them instead.
        for module in (
            VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID,
            VP_FINAL_MODULE_MISSING_NONCE,
            VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX,
            VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST,
            VP_FINAL_MODULE_UNKNOWN_TRANSACTION_DATA,
        ):
            if module in modules:
                modules.remove(module)

    return tuple(modules)


def scenario_plan_arg(scenario: PlanScenario) -> str:
    variant_suffix = "".join(f"[{key}={value}]" for key, value in scenario.variant.items())
    module_names = vp_modules_for_scenario(scenario)
    module_suffix = ""
    if module_names:
        module_suffix = ":" + ",".join(module_names)
    return f"{scenario.plan_name}{variant_suffix}{module_suffix}"



def official_runner_args(
    runner_path: Path,
    results_dir: Path,
    config_jobs: list[tuple[PlanScenario, Path]],
    rerun: str | None = None,
) -> list[str]:
    args = [sys.executable, str(runner_path), "--export-dir", str(results_dir), "--no-parallel"]
    if rerun:
        args.extend(["--rerun", rerun])
    for scenario, config_path in config_jobs:
        args.extend([scenario_plan_arg(scenario), str(config_path)])
    return args


def reader_thread(stream, line_queue: queue.Queue[str]) -> None:
    try:
        for line in iter(stream.readline, ""):
            line_queue.put(line)
    finally:
        stream.close()


def capture_wallet_screenshot(wallet_url: str) -> str | None:
    """Capture the wallet rejection UI as a PNG data URL. Return None when capture fails."""
    script = Path(__file__).with_name("oidf_capture_screenshot.js")
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as handle:
        out_path = Path(handle.name)
    try:
        subprocess.run(
            ["node", str(script), wallet_url, str(out_path)],
            check=True,
            capture_output=True,
            timeout=45,
        )
        encoded = base64.b64encode(out_path.read_bytes()).decode("ascii")
        return "data:image/png;base64," + encoded
    except Exception as exc:  # noqa: BLE001
        print(f"[monitor] wallet screenshot capture failed: {exc}", flush=True)
        return None
    finally:
        out_path.unlink(missing_ok=True)


def upload_placeholder(base_url: str, token: str | None, module_id: str, placeholder: str, wallet_url: str | None = None) -> None:
    image = capture_wallet_screenshot(wallet_url) if wallet_url else None
    if wallet_url and not image:
        raise RuntimeError(f"no wallet error screenshot available for {module_id}")
    kind = "wallet error screenshot" if image else "screenshot placeholder"
    api_request(
        base_url,
        token,
        "POST",
        f"api/log/{module_id}/images/{placeholder}",
        body=(image or SCREENSHOT_DATA_URL).encode("utf-8"),
        content_type="text/plain;charset=utf-8",
    )
    print(f"[monitor] uploaded {kind} for {module_id}: {placeholder}", flush=True)


def follow_redirect(redirect_uri: str) -> None:
    # Short timeout on purpose: the caller retries, and the module only waits
    # 30 seconds for the redirect to be opened.
    timeout = min(REQUEST_TIMEOUT, 10)
    parsed = urllib.parse.urlsplit(redirect_uri)
    request_uri = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    req = urllib.request.Request(request_uri, method="GET")
    with urllib.request.urlopen(req, timeout=timeout, context=conformance_api_context()) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    if not parsed.fragment:
        return

    match = IMPLICIT_SUBMIT_RE.search(body)
    if not match:
        raise RuntimeError("implicit callback page did not expose an implicitSubmitUrl")

    submit_url = match.group(2).replace("\\/", "/")
    submit_req = urllib.request.Request(
        submit_url,
        data=("#" + parsed.fragment).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(submit_req, timeout=timeout, context=conformance_api_context()):
        pass


def wallet_api_path_for_request(request_url: str) -> str:
    parsed = urllib.parse.urlsplit(request_url)
    if parsed.scheme in {"openid-credential-offer", "haip-vci", "eu-eaa-offer"}:
        return "/api/offers"
    if parsed.scheme in {"openid4vp", "eudi-openid4vp", "haip-vp", "eu-eaap"}:
        return "/api/presentations"
    query = urllib.parse.parse_qs(parsed.query)
    if "credential_offer" in query or "credential_offer_uri" in query or "credential_offer" in parsed.path:
        return "/api/offers"
    return "/api/presentations"


# Read the transaction code from the suite offer description. A real wallet asks the user,
# but this automated flow must supply it to redeem the offer (OpenID4VCI 1.0 §6.1).
TX_CODE_IN_DESCRIPTION = re.compile(r"<(\d{4,12})>")


def tx_code_from_offer(request_url: str) -> str | None:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(request_url).query)
    raw = (query.get("credential_offer") or [None])[0]
    if raw:
        try:
            offer = json.loads(raw)
        except (TypeError, ValueError):
            return None
    else:
        # Suite offer URLs remain readable after fetching, so resolving one here does not
        # consume it.
        offer_uri = (query.get("credential_offer_uri") or [None])[0]
        if not offer_uri:
            return None
        try:
            offer = request_json(offer_uri, context=conformance_api_context())
        except Exception:  # noqa: BLE001
            return None
    grants = offer.get("grants")
    if not isinstance(grants, dict):
        return None
    grant = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    if not isinstance(grant, dict):
        return None
    tx_code = grant.get("tx_code")
    if not isinstance(tx_code, dict):
        return None
    match = TX_CODE_IN_DESCRIPTION.search(str(tx_code.get("description", "")))
    if match:
        return match.group(1)
    # When no code is provided, send one of the declared length so the issuer tests a
    # wrong code.
    length = tx_code.get("length")
    return "0" * length if isinstance(length, int) and 0 < length <= 12 else None


def set_wallet_conformance(wallet_url: str, mode: str, requires_haip: bool) -> None:
        # Changing validation mode requires management access. Demo mode rejects it.
    try:
        wallet_request(wallet_url, "PUT", "/api/config/conformance", {"validation_mode": mode, "require_haip": bool(requires_haip)})
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"could not set wallet conformance (HTTP {exc.code}): {body}\n"
            "The wallet under test must be a locally-hosted instance (not --demo)."
        )


def submit_wallet_request(
    wallet_url: str,
    request_url: str,
    requires_haip: bool = False,
    test_name: str | None = None,
    api_path: str | None = None,
    payload: dict | None = None,
) -> WalletSubmissionResult:
    api_path = api_path or wallet_api_path_for_request(request_url)
    # The non-HAIP modules must run without HAIP and the HAIP modules with it,
    # so set the wallet's own conformance for this submission first.
    set_wallet_conformance(wallet_url, WALLET_MODE, requires_haip)
    payload = payload or {"uri": request_url}
    tx_code = tx_code_from_offer(request_url)
    if tx_code:
        payload["tx_code"] = tx_code
        print(f"[monitor] offer declares a transaction code, submitting {tx_code}", flush=True)
    for attempt in range(1, 6):
        try:
            result = wallet_request(wallet_url, "POST", api_path, payload)
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if should_retry_wallet_submission(exc.code, body):
                if attempt < 5:
                    print(
                        f"[monitor] wallet request not ready yet for {request_url}: "
                        f"HTTP {exc.code}, retrying ({attempt}/5)",
                        flush=True,
                    )
                    time.sleep(0.4 * attempt)
                    continue
                print(
                    f"[monitor] wallet request still not ready for {request_url}: "
                    f"HTTP {exc.code}, deferring to next poll",
                    flush=True,
                )
                return WalletSubmissionResult(completed=False, retryable=True)
            print(f"[monitor] wallet rejected request {request_url}: HTTP {exc.code} {body}", flush=True)
            return WalletSubmissionResult(completed=True, retryable=False)

    print(f"[monitor] submitted {api_path} request to wallet: {request_url}", flush=True)
    response = result.get("response", {})
    redirect_uri = response.get("redirect_uri")
    if redirect_uri:
        # The suite expects the redirect within 30 seconds. Short retries fit this
        # deadline even when individual requests stall.
        for attempt in range(1, 4):
            try:
                follow_redirect(redirect_uri)
                print(f"[monitor] followed verifier redirect_uri: {redirect_uri}", flush=True)
                break
            except Exception as exc:  # noqa: BLE001
                if attempt < 3:
                    print(f"[monitor] retrying verifier redirect_uri ({attempt}/3): {exc}", flush=True)
                    continue
                print(f"[monitor] failed to follow redirect_uri {redirect_uri}: {exc}", flush=True)
    return WalletSubmissionResult(completed=True, retryable=False)


def module_test_name(info: dict, state: dict) -> str | None:
    test_name = info.get("testName")
    if isinstance(test_name, str) and test_name:
        return test_name
    test_name = state.get("test_name")
    if isinstance(test_name, str) and test_name:
        return test_name
    return None


def module_variant(info: dict, state: dict) -> dict:
    return merge_variants(state.get("variant"), info.get("variant"))


def fapi_vci_credential_configuration_id(variant: dict) -> str | None:
    credential_format = variant.get("credential_format")
    if credential_format == "sd_jwt_vc":
        return "eu.europa.ec.eudi.pid.1"
    if credential_format == "mdoc":
        return "eu.europa.ec.eudi.pid.mdoc.1"
    return None


def module_credential_offer_endpoint(info: dict, state: dict) -> str | None:
    config = info.get("config")
    if isinstance(config, dict):
        vci = config.get("vci")
        if isinstance(vci, dict):
            endpoint = vci.get("credential_offer_endpoint")
            if isinstance(endpoint, str) and endpoint:
                return endpoint
    endpoint = state.get("credential_offer_endpoint")
    if isinstance(endpoint, str) and endpoint:
        return endpoint
    base_url = info.get("baseUrl")
    if not isinstance(base_url, str) or not base_url:
        base_url = state.get("base_url")
    if isinstance(base_url, str) and base_url:
        return base_url.rstrip("/") + "/credential_offer"
    return None


def synthetic_vci_offer_url(info: dict, state: dict) -> str | None:
    """Start wallet initiated issuance against the suite issuer.

    The suite provides no offer for this variant. Supply one with its issuer and credential configuration but no issuer_state. Issuer initiated variants instead use the suite offer and preserve its issuer_state."""
    variant = module_variant(info, state)
    if variant.get("fapi_profile") not in {"vci", "vci_haip"}:
        return None
    if variant.get("vci_authorization_code_flow_variant") != "wallet_initiated":
        return None
    credential_offer_endpoint = module_credential_offer_endpoint(info, state)
    if not credential_offer_endpoint:
        return None
    credential_configuration_id = module_credential_configuration_id(info) or fapi_vci_credential_configuration_id(variant)
    if not credential_configuration_id:
        return None
    credential_issuer = credential_offer_endpoint.removesuffix("/credential_offer").rstrip("/") + "/"
    offer = {
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [credential_configuration_id],
        "grants": {
            "authorization_code": {},
        },
    }
    encoded_offer = urllib.parse.quote(json.dumps(offer, separators=(",", ":")), safe="")
    return f"{credential_offer_endpoint}?credential_offer={encoded_offer}"


def module_credential_configuration_id(info: dict) -> str | None:
    config = info.get("config")
    vci = config.get("vci") if isinstance(config, dict) else None
    configuration_id = vci.get("credential_configuration_id") if isinstance(vci, dict) else None
    return configuration_id if isinstance(configuration_id, str) and configuration_id else None


def submit_synthetic_vci_offer(wallet_url: str, info: dict, state: dict) -> None:
    offer_url = synthetic_vci_offer_url(info, state)
    variant = module_variant(info, state)
    if (
        not offer_url
        and variant.get("vci_authorization_code_flow_variant") == "wallet_initiated"
        and not state.get("logged_synthetic_skip")
    ):
        state["logged_synthetic_skip"] = True
        print(
            "[monitor] wallet-initiated module is waiting, but no synthetic offer could be built "
            f"(baseUrl={info.get('baseUrl') or state.get('base_url')!r}, variant={variant!r})",
            flush=True,
        )
    if not offer_url or state.get("submitted_synthetic_offer"):
        return
    # The wallet starts this flow itself, so the offer carries only the issuer and the configurations.
    offer = json.loads(urllib.parse.parse_qs(urllib.parse.urlsplit(offer_url).query)["credential_offer"][0])
    result = submit_wallet_request(
        wallet_url,
        offer_url,
        state.get("requires_haip", False),
        state.get("test_name"),
        api_path="/api/issuance",
        payload={"issuer": offer["credential_issuer"], "credential_configuration_ids": offer["credential_configuration_ids"]},
    )
    if result.completed or not result.retryable:
        state["submitted_synthetic_offer"] = True


def submit_browser_api_request(wallet_url: str, browser_request: dict, submit_url: str, requires_haip: bool = False, test_name: str | None = None) -> WalletSubmissionResult:
    set_wallet_conformance(wallet_url, WALLET_MODE, requires_haip)
    extra_headers = {}
    # Use the submit URL as Origin, matching the browser page served by the suite.
    # Request-controlled client_id or expected_origins values must not choose the
    # audience.
    origin = origin_from_submit_url(submit_url)
    if not origin:
        origin = browser_request_origin(browser_request)
    if origin:
        extra_headers["Origin"] = origin

    for attempt in range(1, 6):
        try:
            result = wallet_request(wallet_url, "POST", "/api/dc-api", browser_request, extra_headers=extra_headers)
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if should_retry_wallet_submission(exc.code, body):
                if attempt < 5:
                    print(
                        f"[monitor] browser request not ready yet for {submit_url}: "
                        f"HTTP {exc.code}, retrying ({attempt}/5)",
                        flush=True,
                    )
                    time.sleep(0.4 * attempt)
                    continue
                print(
                    f"[monitor] browser request still not ready for {submit_url}: "
                    f"HTTP {exc.code}, deferring to next poll",
                    flush=True,
                )
                return WalletSubmissionResult(completed=False, retryable=True)
            print(f"[monitor] wallet rejected browser request for {submit_url}: HTTP {exc.code} {body}", flush=True)
            error_message = body.strip() or f"wallet request failed with HTTP {exc.code}"
            exception_payload = {
                "exception": {
                    "name": "NotAllowedError",
                    "message": error_message,
                }
            }
            req = urllib.request.Request(
                submit_url,
                data=json.dumps(exception_payload).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
                resp.read()
            print(f"[monitor] submitted Digital Credentials API exception to suite: {submit_url}", flush=True)
            return WalletSubmissionResult(completed=True, retryable=False)

    req = urllib.request.Request(
        submit_url,
        data=json.dumps(result).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
        resp.read()
    print(f"[monitor] submitted Digital Credentials API result to suite: {submit_url}", flush=True)
    return WalletSubmissionResult(completed=True, retryable=False)


def handle_module(base_url: str, token: str | None, wallet_url: str, module_id: str, state: dict) -> None:
    info = api_request(base_url, token, "GET", f"api/info/{module_id}")
    if info.get("status") in TERMINAL_STATES:
        state["terminal"] = True
        return
    logs = api_request(base_url, token, "GET", f"api/log/{module_id}")

    for entry in logs:
        entry_base_url = entry.get("baseUrl")
        if isinstance(entry_base_url, str) and entry_base_url:
            state["base_url"] = entry_base_url
            break

    submit_synthetic_vci_offer(wallet_url, info, state)

    browser_entries = []
    browser = info.get("browser")
    if isinstance(browser, dict):
        browser_entries.extend(browser.get("browserApiRequests", []))

    pending_submit_url = None
    for entry in logs:
        browser_api_submit = entry.get("browser_api_submit")
        if isinstance(browser_api_submit, dict):
            submit_url = browser_api_submit.get("fullUrl")
            if isinstance(submit_url, str) and submit_url:
                pending_submit_url = submit_url

        if entry.get("msg") == "Calling browser API":
            browser_request = entry.get("request")
            if pending_submit_url and isinstance(browser_request, dict):
                browser_entries.append(
                    {
                        "submitUrl": pending_submit_url,
                        "request": copy.deepcopy(browser_request),
                    }
                )
                pending_submit_url = None

    for entry in browser_entries:
        submit_url = entry.get("submitUrl")
        browser_request = entry.get("request")
        if submit_url and browser_request and submit_url not in state["submitted_browser_api_requests"]:
            result = submit_browser_api_request(wallet_url, browser_request, submit_url, state.get("requires_haip", False), state.get("test_name"))
            if result.completed or not result.retryable:
                state["submitted_browser_api_requests"].add(submit_url)
            else:
                return

    for entry in logs:
        request_url = entry.get("redirect_to") or entry.get("credential_offer_redirect_url")
        if request_url and request_url not in state["submitted_urls"]:
            result = submit_wallet_request(wallet_url, request_url, state.get("requires_haip", False), state.get("test_name"))
            if result.completed or not result.retryable:
                state["submitted_urls"].add(request_url)
            else:
                return

    # The suite can expose an upload placeholder before the wallet has received
    # this request. Capturing then would show the preceding module's error.
    if state["submitted_urls"] or state["submitted_browser_api_requests"] or state.get("submitted_synthetic_offer"):
        for entry in logs:
            placeholder = entry.get("upload")
            if placeholder and placeholder not in state["uploaded_placeholders"]:
                upload_placeholder(base_url, token, module_id, placeholder, wallet_url)
                state["uploaded_placeholders"].add(placeholder)


def main() -> int:
    args = parse_args()
    suite_dir = Path(args.suite_dir).resolve()
    results_dir = Path(args.results_dir)
    runner_log = Path(args.runner_log)
    runner_path = suite_dir / "scripts" / "run-test-plan.py"

    base_url = os.environ["CONFORMANCE_SERVER"]
    token = os.environ.get("CONFORMANCE_TOKEN")

    verify_suite_support(suite_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    materials = fetch_wallet_materials(args.wallet_url, args.wallet_issuer_url, Path(args.wallet_ca_cert))
    baseline_ids = baseline_credential_ids(args.wallet_url, Path(args.wallet_ca_cert))
    removed = purge_issued_credentials(args.wallet_url, baseline_ids)
    if removed:
        print(f"[runner] cleared {removed} foreign credential(s) left by earlier runs", flush=True)
    # Each plan's activity log is exported when the plan ends, so the log
    # starts empty.
    wallet_request(args.wallet_url, "DELETE", "/api/log")
    scenarios = final_scenarios()
    if "www.certification.openid.net" in base_url:
        # Run only certification plans on the production service. Final alpha plans use
        # the local suite or hosted demo service.
        scenarios = [scenario for scenario in scenarios if scenario.requires_haip]
        print("[runner] production certification service: running the certifiable HAIP plans only", flush=True)
    for skip in args.skip_variant:
        key, _, value = skip.partition("=")
        kept = [scenario for scenario in scenarios if scenario.variant.get(key) != value]
        print(f"[runner] left out {len(scenarios) - len(kept)} plan(s) with {key}={value}", flush=True)
        scenarios = kept
    config_jobs = [(scenario, create_config(args, suite_dir, results_dir, scenario, materials)) for scenario in scenarios]
    config_variants = {config_path.name: scenario.variant for scenario, config_path in config_jobs}

    print("[runner] detected OIDF Final wallet plans in the extracted suite", flush=True)
    for scenario, config_path in config_jobs:
        print(f"[runner] scheduled {scenario_plan_arg(scenario)} using {config_path.name}", flush=True)

    cmd = official_runner_args(runner_path, results_dir, config_jobs, args.rerun)
    proc = subprocess.Popen(
        cmd,
        cwd=suite_dir / "scripts",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    line_queue: queue.Queue[str] = queue.Queue()
    thread = threading.Thread(target=reader_thread, args=(proc.stdout, line_queue), daemon=True)
    thread.start()

    module_state: dict[str, dict] = {}
    plan_urls: list[str] = []
    pending_module_requires_haip = False
    pending_module_context: dict = {}
    current_plan_variant: dict = {}
    current_plan_stem = ""
    idle_timeout = int(os.environ.get("OIDF_MODULE_IDLE_TIMEOUT", str(DEFAULT_MODULE_IDLE_TIMEOUT)))
    last_runner_output = time.monotonic()

    with runner_log.open("w") as log_file:
        while True:
            try:
                while True:
                    line = line_queue.get_nowait()
                    last_runner_output = time.monotonic()
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    log_file.write(line)
                    log_file.flush()
                    if line.startswith("20") and "Running test module:" in line:
                        pending_module_requires_haip = "haip" in line.lower()
                        pending_module_context = parse_running_module_line(line)
                        pending_module_context["variant"] = merge_variants(
                            current_plan_variant,
                            pending_module_context.get("variant"),
                        )
                    plan_config_match = RUNNING_PLAN_CONFIG_RE.search(line)
                    if plan_config_match:
                        config_name = Path(plan_config_match.group(1)).name
                        current_plan_variant = config_variants.get(config_name, {})
                        current_plan_stem = config_name.removesuffix("-config.json")
                    if RESULTS_SAVED_RE.search(line) and current_plan_stem:
                        export_wallet_activity(args.wallet_url, results_dir / f"{current_plan_stem}-wallet-activity.json", clear=True)
                    match = MODULE_ID_RE.search(line)
                    if match:
                        module_id = match.group(1)
                        if module_id not in module_state:
                            removed = purge_issued_credentials(args.wallet_url, baseline_ids)
                            if removed:
                                print(
                                    f"[monitor] cleared {removed} credential(s) issued by earlier "
                                    f"modules before {module_id}",
                                    flush=True,
                                )
                        module_state.setdefault(
                            module_id,
                            {
                                "submitted_urls": set(),
                                "submitted_browser_api_requests": set(),
                                "uploaded_placeholders": set(),
                                "terminal": False,
                                "requires_haip": pending_module_requires_haip,
                                "submitted_synthetic_offer": False,
                                "logged_synthetic_skip": False,
                                "test_name": pending_module_context.get("test_name"),
                                "variant": pending_module_context.get("variant", {}),
                            },
                        )
                        pending_module_requires_haip = False
                        pending_module_context = {}
                    plan_match = PLAN_URL_RE.search(line)
                    if plan_match:
                        plan_url = plan_match.group(1)
                        if plan_url not in plan_urls:
                            plan_urls.append(plan_url)
            except queue.Empty:
                pass

            for module_id, state in module_state.items():
                if state["terminal"]:
                    continue
                try:
                    handle_module(base_url, token, args.wallet_url, module_id, state)
                except Exception as exc:  # noqa: BLE001
                    print(f"[monitor] failed to monitor module {module_id}: {exc}", flush=True)

            if proc.poll() is not None and line_queue.empty() and not thread.is_alive():
                break

            if proc.poll() is None and idle_timeout > 0 and time.monotonic() - last_runner_output > idle_timeout:
                # Cancel stalled modules first. The suite marks them INTERRUPTED so the
                # runner can continue. Terminate the run only if it remains unresponsive.
                stalled = [
                    module_id
                    for module_id, state in module_state.items()
                    if not state["terminal"] and not state.get("cancelled")
                ]
                if stalled:
                    for module_id in stalled:
                        module_state[module_id]["cancelled"] = True
                        try:
                            api_request(base_url, token, "DELETE", f"api/runner/{module_id}")
                            print(
                                f"[monitor] no run-test-plan output for {idle_timeout}s; "
                                f"cancelled stuck module {module_id} so the plan can continue",
                                flush=True,
                            )
                        except Exception as exc:  # noqa: BLE001
                            print(f"[monitor] could not cancel stuck module {module_id}: {exc}", flush=True)
                    last_runner_output = time.monotonic()
                    continue
                active_modules = [module_id for module_id, state in module_state.items() if not state["terminal"]]
                active = ", ".join(active_modules) if active_modules else "unknown"
                print(
                    f"[monitor] no run-test-plan output for {idle_timeout}s; "
                    f"terminating stuck conformance run. Active modules: {active}",
                    flush=True,
                )
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                return 124

            time.sleep(POLL_INTERVAL)

    if plan_urls:
        print("[runner] OIDF plan URLs:", flush=True)
        for plan_url in plan_urls:
            print(f"[runner]   {plan_url}", flush=True)

    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
