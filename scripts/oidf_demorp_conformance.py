#!/usr/bin/env python3

"""Run OIDF issuer and verifier plans against the local demo services.

The suite acts as the wallet. The harness provides offers, signs in at the issuer and submits verifier requests. It supplies screenshot placeholders and reads the demo verifier verdict because the suite ends verifier modules in REVIEW regardless of that result."""

import argparse
import html
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue

from oidf_wallet_conformance import (
    DEFAULT_MODULE_IDLE_TIMEOUT,
    IMPLICIT_SUBMIT_RE,
    MODULE_ID_RE,
    PLAN_URL_RE,
    POLL_INTERVAL,
    REQUEST_TIMEOUT,
    RUNNING_PLAN_CONFIG_RE,
    TERMINAL_STATES,
    api_request,
    conformance_api_context,
    load_config_template,
    merge_variants,
    parse_running_module_line,
    reader_thread,
    upload_placeholder,
    wallet_request,
)


LOGIN_REQUEST_URI_RE = re.compile(r'name="request_uri" value="([^"]+)"')

# VCIWaitForCredentialOffer logs this message each time a module starts
# waiting for a credential offer at its exposed endpoint.
OFFER_WAIT_LOG_MESSAGE = "Waiting for call to credential offer endpoint, see exposed values."

VCI_ISSUER_TEMPLATE = "scripts/test-configs-rp-against-op/vci-issuer-test-config-client_attestation-client-auth-dpop.json"
VP_VERIFIER_TEMPLATE = "scripts/test-configs-rp-against-op/vp-verifier-test-config.json"

# The issuer plans request the demo ticket. The verifier plans request the
# country independent PID, which the suite holds as SD-JWT VC and mdoc.
DEMO_CREDENTIAL_CONFIGURATION_ID = "demo-ticket"
PID_VCT = "urn:eudi:pid:1"

# Use a test P-256 key for the second client. The suite proof generator requires it for
# ES256, but its template provides RSA.
CLIENT2_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "alg": "ES256",
    "use": "sig",
    "kid": "oid4vc-dev-client2-key",
    "x": "btnDDXeuncQEdFkr9Artq7yeXh9jQST3MyT3adfuyB8",
    "y": "ryI9n8rupqN8Mc3FrSQP_w8bM__1N4pSsZtl6jim-9Y",
    "d": "o1Xkxk1VljoIATthykO90JPrnul7ZFCZBfyXmrijyRM",
}


@dataclass(frozen=True)
class DemoScenario:
    slug: str
    kind: str  # "vci" or "vp"
    plan_name: str
    variant: dict[str, str]
    # modules limits the run to these test names. None runs the whole plan.
    modules: tuple[str, ...] | None = None
    # offer_query configures issuer initiated offers. None selects wallet initiated
    # issuance without an offer.
    offer_query: str | None = None
    # request_body creates the demo verifier request of a vp scenario
    # (POST /verifier/api/requests).
    request_body: dict | None = None


VCI_ISSUER_MODULE_BATCH = "oid4vci-1_0-issuer-batch-issuance"

# Exclude unsupported key attestation and credential encryption modules. They
# would skip themselves, which run-test-plan records as failure.
VCI_ISSUER_MODULES = (
    "oid4vci-1_0-issuer-metadata-test",
    "oid4vci-1_0-issuer-metadata-test-signed",
    "oid4vci-1_0-issuer-happy-flow",
    "oid4vci-1_0-issuer-happy-flow-additional-requests",
    "oid4vci-1_0-issuer-happy-flow-multiple-clients",
    "oid4vci-1_0-issuer-happy-flow-skip-notification",
    VCI_ISSUER_MODULE_BATCH,
    "oid4vci-1_0-issuer-fail-invalid-nonce",
    "oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature",
    "oid4vci-1_0-issuer-fail-invalid-client-attestation-signature",
    "oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature",
    "oid4vci-1_0-issuer-fail-client-attestation-exp-in-past",
    "oid4vci-1_0-issuer-fail-client-attestation-no-sub",
    "oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud",
    "oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key",
    "oid4vci-1_0-issuer-fail-missing-proof",
    "oid4vci-1_0-issuer-fail-unknown-credential-configuration",
    "oid4vci-1_0-issuer-fail-unknown-credential-identifier",
    "oid4vci-1_0-issuer-fail-on-access-token-in-query",
)


def vci_issuer_modules(flow_variant: str) -> tuple[str, ...]:
    """Wallet initiated issuance has no offer requesting a batch, so the demo issues one credential and the batch module skips."""
    modules = VCI_ISSUER_MODULES
    if flow_variant == "wallet_initiated":
        modules = tuple(m for m in modules if m != VCI_ISSUER_MODULE_BATCH)
    return modules


VP_VERIFIER_MODULE_HAPPY_FLOW = "oid4vp-1final-verifier-happy-flow"
VP_VERIFIER_MODULE_MINIMAL_CNF_JWK = "oid4vp-1final-verifier-minimal-cnf-jwk"
VP_VERIFIER_MODULE_REQUEST_URI_METHOD_POST = "oid4vp-1final-verifier-request-uri-method-post"
VP_VERIFIER_MODULE_REQUEST_URI_FETCHED_TWICE = "oid4vp-1final-verifier-request-uri-fetched-twice"
VP_VERIFIER_MODULE_INVALID_SESSION_TRANSCRIPT = "oid4vp-1final-verifier-invalid-session-transcript"

VP_VERIFIER_MODULES = (
    VP_VERIFIER_MODULE_HAPPY_FLOW,
    VP_VERIFIER_MODULE_MINIMAL_CNF_JWK,
    VP_VERIFIER_MODULE_REQUEST_URI_METHOD_POST,
    VP_VERIFIER_MODULE_REQUEST_URI_FETCHED_TWICE,
    VP_VERIFIER_MODULE_INVALID_SESSION_TRANSCRIPT,
    "oid4vp-1final-verifier-invalid-kb-jwt-signature",
    "oid4vp-1final-verifier-invalid-credential-signature",
    "oid4vp-1final-verifier-invalid-sd-hash",
    "oid4vp-1final-verifier-invalid-kb-jwt-nonce",
    "oid4vp-1final-verifier-invalid-kb-jwt-aud",
    "oid4vp-1final-verifier-kb-jwt-iat-in-past",
    "oid4vp-1final-verifier-kb-jwt-iat-in-future",
)

# The SD-JWT tampering modules carry @VariantNotApplicable for iso_mdl, and
# the session transcript module is the one mdoc-only negative test. The
# minimal cnf.jwk module is SD-JWT only as well.
VP_SDJWT_ONLY_MODULES = frozenset(
    module
    for module in VP_VERIFIER_MODULES
    if module
    not in {
        VP_VERIFIER_MODULE_HAPPY_FLOW,
        VP_VERIFIER_MODULE_REQUEST_URI_METHOD_POST,
        VP_VERIFIER_MODULE_REQUEST_URI_FETCHED_TWICE,
        VP_VERIFIER_MODULE_INVALID_SESSION_TRANSCRIPT,
    }
)


def vp_modules_for_variant(variant: dict[str, str]) -> tuple[str, ...]:
    """Mirrors the modules' @VariantNotApplicable annotations. The HAIP plan
    pins request_method to request_uri_signed, so an absent value counts as
    signed."""
    modules = list(VP_VERIFIER_MODULES)
    if variant.get("credential_format") == "iso_mdl":
        modules = [m for m in modules if m not in VP_SDJWT_ONLY_MODULES]
    else:
        modules.remove(VP_VERIFIER_MODULE_INVALID_SESSION_TRANSCRIPT)
    if variant.get("request_method") == "url_query":
        # With the request in the query string there is no request_uri to
        # fetch twice.
        modules.remove(VP_VERIFIER_MODULE_REQUEST_URI_FETCHED_TWICE)
    else:
        # The demo serves request objects through GET. The POST module would skip, which
        # the runner treats as failure.
        modules.remove(VP_VERIFIER_MODULE_REQUEST_URI_METHOD_POST)
    return tuple(modules)


def vp_scenario(slug: str, plan_name: str, variant: dict[str, str], request_body: dict) -> DemoScenario:
    return DemoScenario(
        slug=slug,
        kind="vp",
        plan_name=plan_name,
        variant=variant,
        modules=vp_modules_for_variant(variant),
        request_body=request_body,
    )


PID_SDJWT_REQUEST = {"type": "pid", "format": "sd-jwt"}
PID_MDOC_REQUEST = {"type": "pid", "format": "mdoc"}
# Use the custom builder for unsigned redirect_uri requests. The PID preset always signs
# (OpenID4VP 1.0 §5.9.3).
PID_SDJWT_UNSIGNED_REQUEST = {
    "type": "custom",
    "client_id_scheme": "redirect_uri",
    "credentials": [
        {
            "format": "dc+sd-jwt",
            "vct": PID_VCT,
            "claims": [["given_name"], ["family_name"]],
        }
    ],
}


def demo_scenarios() -> list[DemoScenario]:
    vci_base = {
        "authorization_request_type": "simple",
        "client_auth_type": "client_attestation",
        "fapi_request_method": "unsigned",
        "sender_constrain": "dpop",
        "fapi_profile": "vci",
        "credential_format": "sd_jwt_vc",
        "vci_credential_encryption": "plain",
        "openid": "plain_oauth",
        "fapi_response_mode": "plain_response",
    }
    vp_plain_base = {
        "vp_profile": "plain_vp",
        "credential_format": "sd_jwt_vc",
        "client_id_prefix": "x509_hash",
        "request_method": "request_uri_signed",
        "response_mode": "direct_post.jwt",
    }
    scenarios = [
        DemoScenario(
            slug="vci-issuer-authcode-wallet-initiated",
            kind="vci",
            plan_name="oid4vci-1_0-issuer-test-plan",
            variant=vci_base
            | {
                "vci_grant_type": "authorization_code",
                "vci_authorization_code_flow_variant": "wallet_initiated",
            },
            modules=vci_issuer_modules("wallet_initiated"),
        ),
        DemoScenario(
            slug="vci-issuer-authcode-issuer-initiated",
            kind="vci",
            plan_name="oid4vci-1_0-issuer-test-plan",
            variant=vci_base
            | {
                "vci_grant_type": "authorization_code",
                "vci_authorization_code_flow_variant": "issuer_initiated",
            },
            modules=vci_issuer_modules("issuer_initiated"),
            offer_query="grant=authorization_code&batch=8",
        ),
        DemoScenario(
            slug="vci-issuer-preauth",
            kind="vci",
            plan_name="oid4vci-1_0-issuer-test-plan",
            variant=vci_base
            | {
                "vci_grant_type": "pre_authorization_code",
                # A pre-authorized offer is always issuer initiated: the suite
                # refuses the wallet_initiated pairing outright.
                "vci_authorization_code_flow_variant": "issuer_initiated",
            },
            modules=vci_issuer_modules("issuer_initiated"),
            offer_query="batch=8",
        ),
        # Run the VCI modules. The appended FAPI2 plans require a fuller authorization
        # server. Other variants are fixed by module group, and the runner uses the first
        # group containing each module.
        DemoScenario(
            slug="vci-issuer-haip",
            kind="vci",
            plan_name="oid4vci-1_0-issuer-haip-test-plan",
            variant={
                "credential_format": "sd_jwt_vc",
                "vci_authorization_code_flow_variant": "issuer_initiated",
            },
            modules=vci_issuer_modules("issuer_initiated"),
            offer_query="grant=authorization_code&batch=8",
        ),
        vp_scenario(
            "vp-verifier-final-sdjwt",
            "oid4vp-1final-verifier-test-plan",
            dict(vp_plain_base),
            PID_SDJWT_REQUEST,
        ),
        vp_scenario(
            "vp-verifier-final-sdjwt-unsigned",
            "oid4vp-1final-verifier-test-plan",
            vp_plain_base | {"client_id_prefix": "redirect_uri", "request_method": "url_query"},
            PID_SDJWT_UNSIGNED_REQUEST,
        ),
        vp_scenario(
            "vp-verifier-final-mdoc",
            "oid4vp-1final-verifier-test-plan",
            vp_plain_base | {"credential_format": "iso_mdl"},
            PID_MDOC_REQUEST,
        ),
        # The HAIP plan pins vp_profile, client_id_prefix and request_method,
        # and direct_post is not applicable under HAIP.
        vp_scenario(
            "vp-verifier-haip-sdjwt",
            "oid4vp-1final-verifier-haip-test-plan",
            {"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"},
            PID_SDJWT_REQUEST,
        ),
        vp_scenario(
            "vp-verifier-haip-mdoc",
            "oid4vp-1final-verifier-haip-test-plan",
            {"credential_format": "iso_mdl", "response_mode": "direct_post.jwt"},
            PID_MDOC_REQUEST,
        ),
    ]
    only = os.environ.get("ONLY_SCENARIOS", "")
    if only:
        scenarios = [sc for sc in scenarios if any(w in sc.slug for w in only.split(","))]
    return scenarios


def scenario_plan_arg(scenario: DemoScenario) -> str:
    variant_suffix = "".join(f"[{key}={value}]" for key, value in scenario.variant.items())
    module_suffix = ""
    if scenario.modules:
        module_suffix = ":" + ",".join(scenario.modules)
    return f"{scenario.plan_name}{variant_suffix}{module_suffix}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the official OIDF issuer and verifier plans against the demo issuer and verifier"
    )
    parser.add_argument("--suite-dir", required=True, help="Path to the extracted official OIDF conformance suite")
    parser.add_argument("--wallet-url", required=True, help="HTTP base URL of the local wallet server (harness control)")
    parser.add_argument("--demo-base-url", required=True, help="HTTPS base URL the demo issuer and verifier advertise")
    parser.add_argument("--wallet-ca-cert", required=True, help="Path to the shared wallet CA PEM")
    parser.add_argument("--access-ca-cert", required=True, help="Path to the relying party access CA PEM")
    parser.add_argument("--results-dir", required=True, help="Directory for exported official runner results")
    parser.add_argument("--runner-log", required=True, help="Path for mirrored official runner stdout")
    parser.add_argument(
        "--rerun",
        help="Pass through to the official OIDF runner, e.g. 2 or 2:6 or 1:6,2:6",
        default=None,
    )
    return parser.parse_args()


def scenario_alias(args: argparse.Namespace, scenario: DemoScenario) -> str:
    """Include the wallet port in the suite alias to prevent separate runs from replacing each other's configuration."""
    port = urllib.parse.urlparse(args.wallet_url).port
    return f"oid4vc-dev-{scenario.slug}-{port or 'local'}"


def create_vci_config(args: argparse.Namespace, suite_dir: Path, scenario: DemoScenario, output: Path) -> None:
    config = load_config_template(suite_dir / VCI_ISSUER_TEMPLATE)
    config["alias"] = scenario_alias(args, scenario)
    config["description"] = f"oid4vc-dev demo issuer ({scenario.slug})"
    config.setdefault("vci", {})
    config["vci"]["credential_issuer_url"] = args.demo_base_url.rstrip("/") + "/issuer"
    config["vci"]["credential_configuration_id"] = DEMO_CREDENTIAL_CONFIGURATION_ID
    ca_pem = Path(args.wallet_ca_cert).read_text()
    config.setdefault("credential", {})
    config["credential"]["trust_anchor_pem"] = ca_pem
    config["credential"]["status_list_trust_anchor_pem"] = ca_pem
    config.setdefault("client2", {})
    config["client2"]["jwks"] = {"keys": [CLIENT2_JWK]}
    # The harness signs in at the demo issuer's authorization page itself, so
    # the suite's scripted browser has nothing to do.
    config["browser"] = []
    with output.open("w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def create_vp_config(args: argparse.Namespace, suite_dir: Path, scenario: DemoScenario, output: Path) -> None:
    config = load_config_template(suite_dir / VP_VERIFIER_TEMPLATE)
    config["alias"] = scenario_alias(args, scenario)
    config["description"] = f"oid4vc-dev demo verifier ({scenario.slug})"
    # The demo verifier signs its request objects with an access certificate
    # from the relying party access CA, which HAIP requires the suite to be
    # given as the trust anchor.
    config.setdefault("client", {})
    config["client"].pop("client_id", None)
    config["client"]["request_object_trust_anchor_pem"] = Path(args.access_ca_cert).read_text()
    # The harness uploads the verification-evidence placeholder itself.
    config["browser"] = []
    with output.open("w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def create_config(args: argparse.Namespace, suite_dir: Path, results_dir: Path, scenario: DemoScenario) -> Path:
    output = results_dir / f"{scenario.slug}-config.json"
    if scenario.kind == "vci":
        create_vci_config(args, suite_dir, scenario, output)
    else:
        create_vp_config(args, suite_dir, scenario, output)
    return output


def module_base_url(alias: str) -> str:
    server = os.environ.get("CONFORMANCE_SERVER_LOCAL") or os.environ["CONFORMANCE_SERVER"]
    return server.rstrip("/") + "/test/a/" + alias


def suite_get(url: str) -> None:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
        resp.read()


def deliver_credential_offer(wallet_url: str, scenario: DemoScenario, alias: str) -> None:
    """Send a new offer by value to the suite credential_offer endpoint. The suite requires HTTPS for offers by reference."""
    created = wallet_request(wallet_url, "POST", f"/issuer/api/offers?{scenario.offer_query}")
    offer = wallet_request(wallet_url, "GET", "/issuer/offer/" + created["id"])
    encoded = urllib.parse.quote(json.dumps(offer, separators=(",", ":")), safe="")
    suite_get(f"{module_base_url(alias)}/credential_offer?credential_offer={encoded}")
    print(f"[monitor] delivered demo credential offer {created['id']} to {alias}", flush=True)


def submit_verifier_request(wallet_url: str, scenario: DemoScenario, alias: str) -> str:
    """Create a demo verifier request and submit it to the suite authorization endpoint. Return the transaction ID that reads the verdict."""
    created = wallet_request(
        wallet_url, "POST", "/verifier/api/requests", scenario.request_body
    )
    query = urllib.parse.urlsplit(created["scheme_uri"]).query
    suite_get(f"{module_base_url(alias)}/authorize?{query}")
    print(f"[monitor] delivered demo verifier request {created['id']} to {alias}", flush=True)
    return created["transaction_id"]


def unverified_opener() -> urllib.request.OpenerDirector:
    # Local redirects cross the wallet and suite TLS origins, whose certificates are not
    # in the system truststore.
    context = ssl._create_unverified_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))


def complete_demo_login(authorize_url: str) -> None:
    """Sign in as the demo account and follow the authorization callback.

    The suite callback page normally posts its URL fragment to the submission endpoint. Reproduce that POST, including an empty fragment for query responses, to advance the module."""
    opener = unverified_opener()
    with opener.open(authorize_url, timeout=REQUEST_TIMEOUT) as resp:
        page = resp.read().decode("utf-8", errors="replace")
        page_url = resp.geturl()
    match = LOGIN_REQUEST_URI_RE.search(page)
    if not match:
        raise RuntimeError(f"the demo authorization page at {authorize_url} shows no login form")
    form = urllib.parse.urlencode(
        {
            "username": "alice",
            "password": "alice",
            "request_uri": html.unescape(match.group(1)),
        }
    )
    submit = urllib.parse.urljoin(page_url, "authorize")
    req = urllib.request.Request(
        submit,
        data=form.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
        callback_page = resp.read().decode("utf-8", errors="replace")
        callback_url = resp.geturl()
    submit_match = IMPLICIT_SUBMIT_RE.search(callback_page)
    if not submit_match:
        raise RuntimeError(f"the suite callback page at {callback_url} exposed no implicit submission URL")
    fragment = urllib.parse.urlsplit(callback_url).fragment
    submit_req = urllib.request.Request(
        submit_match.group(2).replace("\\/", "/"),
        data=(("#" + fragment) if fragment else "").encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    with opener.open(submit_req, timeout=REQUEST_TIMEOUT) as resp:
        resp.read()
    print(f"[monitor] completed demo issuer sign-in for {authorize_url}", flush=True)


# A verifier module whose name marks a tampered presentation passes only when
# the demo verifier refuses it, so its expected demo verdict is failed.
_VP_REJECTION_MARKERS = ("invalid-", "kb-jwt-iat-")


def expected_demo_outcome(test_name: str) -> str:
    if any(marker in test_name for marker in _VP_REJECTION_MARKERS):
        return "failed"
    return "verified"


@dataclass
class VerifierVerdict:
    test_name: str
    module_result: str
    demo_status: str
    demo_error: str

    def acceptable(self) -> bool:
        if self.module_result == "SKIPPED":
            return True
        return self.demo_status == expected_demo_outcome(self.test_name)


def collect_verifier_verdict(wallet_url: str, state: dict, info: dict) -> VerifierVerdict | None:
    request_id = state.get("demo_request_id")
    if not request_id:
        return None
    try:
        status = wallet_request(wallet_url, "GET", "/verifier/api/requests/" + request_id)
    except Exception as exc:  # noqa: BLE001
        status = {"status": "unknown", "error": str(exc)}
    return VerifierVerdict(
        test_name=state.get("test_name") or "unknown",
        module_result=str(info.get("result") or ""),
        demo_status=str(status.get("status") or "unknown"),
        demo_error=str(status.get("error") or ""),
    )


def handle_module(
    base_url: str,
    token: str | None,
    wallet_url: str,
    module_id: str,
    state: dict,
    verdicts: list[VerifierVerdict],
) -> None:
    scenario: DemoScenario | None = state.get("scenario")
    alias: str | None = state.get("alias")
    info = api_request(base_url, token, "GET", f"api/info/{module_id}")
    logs = api_request(base_url, token, "GET", f"api/log/{module_id}")
    status = info.get("status", "")

    if scenario and alias and scenario.kind == "vp" and status == "WAITING" and not state["request_submitted"]:
        state["request_submitted"] = True
        state["demo_request_id"] = submit_verifier_request(wallet_url, scenario, alias)

    # Create an offer for each logged wait. Some modules run twice and pre-authorized
    # codes can only be redeemed once.
    if scenario and alias and scenario.kind == "vci" and scenario.offer_query:
        waits = sum(1 for entry in logs if entry.get("msg") == OFFER_WAIT_LOG_MESSAGE)
        while state["offers_delivered"] < waits:
            state["offers_delivered"] += 1
            deliver_credential_offer(wallet_url, scenario, alias)

    for entry in logs:
        redirect_to = entry.get("redirect_to")
        if (
            isinstance(redirect_to, str)
            and "/issuer/authorize" in redirect_to
            and redirect_to not in state["handled_redirects"]
        ):
            state["handled_redirects"].add(redirect_to)
            try:
                complete_demo_login(redirect_to)
            except Exception as exc:  # noqa: BLE001
                print(f"[monitor] demo issuer sign-in failed for {redirect_to}: {exc}", flush=True)

        placeholder = entry.get("upload")
        if placeholder and placeholder not in state["uploaded_placeholders"]:
            state["uploaded_placeholders"].add(placeholder)
            upload_placeholder(base_url, token, module_id, placeholder)

    if status in TERMINAL_STATES:
        state["terminal"] = True
        if scenario and scenario.kind == "vp":
            verdict = collect_verifier_verdict(wallet_url, state, info)
            if verdict:
                verdicts.append(verdict)


def report_verifier_verdicts(verdicts: list[VerifierVerdict]) -> int:
    if not verdicts:
        return 0
    print("[verdicts] demo verifier outcome per module:", flush=True)
    mismatches = 0
    for verdict in verdicts:
        expected = expected_demo_outcome(verdict.test_name)
        marker = "ok"
        if not verdict.acceptable():
            marker = f"MISMATCH (expected {expected})"
            mismatches += 1
        line = (
            f"[verdicts]   {verdict.test_name} [{verdict.module_result}]: "
            f"demo verifier {verdict.demo_status} - {marker}"
        )
        if verdict.demo_error:
            line += f" ({verdict.demo_error})"
        print(line, flush=True)
    if mismatches:
        print(f"[verdicts] {mismatches} module(s) ended with an unexpected demo verifier verdict", flush=True)
    return mismatches


def runner_args(runner_path: Path, results_dir: Path, config_jobs, rerun: str | None) -> list[str]:
    cmd = [sys.executable, str(runner_path), "--export-dir", str(results_dir), "--no-parallel"]
    if rerun:
        cmd.extend(["--rerun", rerun])
    for scenario, config_path in config_jobs:
        cmd.extend([scenario_plan_arg(scenario), str(config_path)])
    return cmd


def main() -> int:
    args = parse_args()
    suite_dir = Path(args.suite_dir).resolve()
    results_dir = Path(args.results_dir)
    runner_log = Path(args.runner_log)
    runner_path = suite_dir / "scripts" / "run-test-plan.py"

    base_url = os.environ["CONFORMANCE_SERVER"]
    token = os.environ.get("CONFORMANCE_TOKEN")

    results_dir.mkdir(parents=True, exist_ok=True)
    scenarios = demo_scenarios()
    config_jobs = [(scenario, create_config(args, suite_dir, results_dir, scenario)) for scenario in scenarios]
    scenarios_by_config = {config_path.name: scenario for scenario, config_path in config_jobs}
    aliases_by_config = {config_path.name: scenario_alias(args, scenario) for scenario, config_path in config_jobs}

    for scenario, config_path in config_jobs:
        print(f"[runner] scheduled {scenario_plan_arg(scenario)} using {config_path.name}", flush=True)

    cmd = runner_args(runner_path, results_dir, config_jobs, args.rerun)
    proc = subprocess.Popen(
        cmd,
        cwd=suite_dir / "scripts",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    line_queue: Queue[str] = Queue()
    thread = threading.Thread(target=reader_thread, args=(proc.stdout, line_queue), daemon=True)
    thread.start()

    module_state: dict[str, dict] = {}
    verdicts: list[VerifierVerdict] = []
    plan_urls: list[str] = []
    current_scenario: DemoScenario | None = None
    current_alias: str | None = None
    pending_module_context: dict = {}
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
                    plan_config_match = RUNNING_PLAN_CONFIG_RE.search(line)
                    if plan_config_match:
                        config_name = Path(plan_config_match.group(1)).name
                        current_scenario = scenarios_by_config.get(config_name)
                        current_alias = aliases_by_config.get(config_name)
                    if line.startswith("20") and "Running test module:" in line:
                        pending_module_context = parse_running_module_line(line)
                    match = MODULE_ID_RE.search(line)
                    if match:
                        module_state.setdefault(
                            match.group(1),
                            {
                                "scenario": current_scenario,
                                "alias": current_alias,
                                "test_name": pending_module_context.get("test_name"),
                                "variant": merge_variants(
                                    current_scenario.variant if current_scenario else {},
                                    pending_module_context.get("variant"),
                                ),
                                "offers_delivered": 0,
                                "request_submitted": False,
                                "demo_request_id": None,
                                "handled_redirects": set(),
                                "uploaded_placeholders": set(),
                                "terminal": False,
                            },
                        )
                        pending_module_context = {}
                    plan_match = PLAN_URL_RE.search(line)
                    if plan_match and plan_match.group(1) not in plan_urls:
                        plan_urls.append(plan_match.group(1))
            except Empty:
                pass

            for module_id, state in module_state.items():
                if state["terminal"]:
                    continue
                try:
                    handle_module(base_url, token, args.wallet_url, module_id, state, verdicts)
                except Exception as exc:  # noqa: BLE001
                    print(f"[monitor] failed to monitor module {module_id}: {exc}", flush=True)

            if proc.poll() is not None and line_queue.empty() and not thread.is_alive():
                break

            if proc.poll() is None and idle_timeout > 0 and time.monotonic() - last_runner_output > idle_timeout:
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
                report_verifier_verdicts(verdicts)
                return 124

            time.sleep(POLL_INTERVAL)

    if plan_urls:
        print("[runner] OIDF plan URLs:", flush=True)
        for plan_url in plan_urls:
            print(f"[runner]   {plan_url}", flush=True)

    mismatches = report_verifier_verdicts(verdicts)
    runner_status = proc.wait()
    if runner_status:
        return runner_status
    return 3 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
