#!/usr/bin/env python3
import base64
import hashlib
import html.parser
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path


KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://127.0.0.1:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "wallet-demo")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "wallet-mock")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://127.0.0.1:18080/callback")
EUDI_DEV_PORT = int(os.environ.get("EUDI_DEV_PORT", "8085"))
BROKER_USERNAME_PREFIX = os.environ.get("BROKER_USERNAME_PREFIX", "wallet-user")

SCRIPT_DIR = Path(__file__).resolve().parent
SCENARIO_DIR = SCRIPT_DIR.parent


class LinkByIDParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        attr_map = dict(attrs)
        element_id = attr_map.get("id")
        href = attr_map.get("href")
        if element_id and href:
            self.links[element_id] = href


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "GET").upper(),
                "inputs": [],
            }
            return
        if tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attr_map.get("name", ""),
                    "type": attr_map.get("type", "text"),
                    "value": attr_map.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def random_token(length):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def random_pkce_verifier():
    raw = os.urandom(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def resolve_oid4vc_dev_command():
    for name in ("eudi", "eudi-dev"):
        path_bin = shutil.which(name)
        if path_bin:
            return [path_bin], None

    fail("Unable to resolve eudi in PATH. Install it first or run ./start.sh.")


def fetch(cookie_jar, url, method="GET", data=None, headers=None):
    with tempfile.NamedTemporaryFile() as header_file, tempfile.NamedTemporaryFile() as body_file:
        cmd = [
            "curl",
            "-sS",
            "-D",
            header_file.name,
            "-o",
            body_file.name,
            "-b",
            cookie_jar,
            "-c",
            cookie_jar,
            "-X",
            method,
            url,
        ]

        for key, value in (headers or {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        if data is not None:
            cmd.extend(["--data", urllib.parse.urlencode(data)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            fail(f"HTTP request failed for {url}:\n{result.stderr}".rstrip())

        header_text = Path(header_file.name).read_text()
        body = Path(body_file.name).read_text()

    header_blocks = [block for block in re.split(r"\r?\n\r?\n", header_text.strip()) if block.strip()]
    last_block = header_blocks[-1] if header_blocks else ""
    header_lines = last_block.splitlines()
    status_line = header_lines[0] if header_lines else "HTTP/1.1 000"
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError):
        status = 0

    parsed_headers = {}
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed_headers[key.strip()] = value.strip()

    return status, parsed_headers, body


def parse_link(html_text, element_id, base_url):
    parser = LinkByIDParser()
    parser.feed(html_text)
    href = parser.links.get(element_id)
    if not href:
        return None
    return urllib.parse.urljoin(base_url, href)


def parse_first_broker_form(html_text, base_url):
    parser = FormParser()
    parser.feed(html_text)
    for form in parser.forms:
        names = {item["name"] for item in form["inputs"] if item["name"]}
        if {"username", "email", "firstName", "lastName"} & names:
            action = urllib.parse.urljoin(base_url, form["action"] or base_url)
            fields = {}
            for item in form["inputs"]:
                name = item["name"]
                if not name:
                    continue
                if item["type"] in {"hidden", "text", "email"}:
                    fields[name] = item["value"]
            return action, form["method"], fields
    return None, None, None


def extract_redirect_uri(wallet_output):
    matches = re.findall(r"https?://[^\s\"']+/broker/oid4vp/endpoint/complete-auth\?[^\s\"']+", wallet_output)
    if not matches:
        return None
    return matches[-1]


def decode_jwt_payload(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    raw = base64.urlsafe_b64decode(payload + padding)
    return json.loads(raw.decode("utf-8"))


def run_wallet_accept(wallet_url):
    cmd, cwd = resolve_oid4vc_dev_command()
    full_cmd = cmd + [
        "wallet",
        "accept",
        "--auto-accept",
        "--docker",
        "--port",
        str(EUDI_DEV_PORT),
        wallet_url,
    ]
    result = subprocess.run(
        full_cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    output = strip_ansi((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
    if result.returncode != 0:
        fail(f"eudi wallet accept failed:\n{output}".rstrip())
    redirect_uri = extract_redirect_uri(output)
    if not redirect_uri:
        fail(f"Could not extract Keycloak redirect URI from wallet output:\n{output}".rstrip())
    return redirect_uri, output.strip()


def build_authorize_url(state, code_challenge):
    query = urllib.parse.urlencode(
        {
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?{query}"


def follow_complete_auth(cookie_jar, start_url):
    current_url = start_url
    callback_url = None

    for _ in range(10):
        status, headers, body = fetch(cookie_jar, current_url)
        location = headers.get("Location") or headers.get("location")
        if 300 <= status < 400 and location:
            next_url = urllib.parse.urljoin(current_url, location)
            if next_url.startswith(OIDC_REDIRECT_URI):
                callback_url = next_url
                break
            current_url = next_url
            continue

        form_action, form_method, fields = parse_first_broker_form(body, current_url)
        if form_action:
            suffix = f"{BROKER_USERNAME_PREFIX}-{int(time.time())}"
            fields.update(
                {
                    "username": fields.get("username") or suffix,
                    "email": fields.get("email") or f"{suffix}@example.com",
                    "firstName": fields.get("firstName") or "Wallet",
                    "lastName": fields.get("lastName") or "User",
                }
            )
            status, headers, body = fetch(
                cookie_jar,
                form_action,
                method=form_method,
                data=fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            location = headers.get("Location") or headers.get("location")
            if 300 <= status < 400 and location:
                next_url = urllib.parse.urljoin(form_action, location)
                if next_url.startswith(OIDC_REDIRECT_URI):
                    callback_url = next_url
                    break
                current_url = next_url
                continue
            fail("First broker login form submission did not redirect to the callback URL.")

        fail(
            "Keycloak did not return a first-broker-login form or callback redirect.\n"
            f"Last URL: {current_url}\n"
            f"HTTP status: {status}\n"
            f"Page excerpt: {body[:500]}"
        )

    if not callback_url:
        fail("Did not reach the callback redirect after completing the OID4VP flow.")
    return callback_url


def exchange_code(code, code_verifier):
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    status, _, body = fetch(
        os.devnull,
        token_url,
        method="POST",
        data={
            "grant_type": "authorization_code",
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        fail(f"Authorization code exchange failed ({status}):\n{body}".rstrip())
    return json.loads(body)


def main():
    state = f"s-{random_token(12)}"
    code_verifier = random_pkce_verifier()
    code_challenge = pkce_challenge(code_verifier)
    with tempfile.NamedTemporaryFile() as cookie_jar_file:
        cookie_jar = cookie_jar_file.name

        print(f"Starting login against {KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}")
        authorize_url = build_authorize_url(state, code_challenge)
        status, _, body = fetch(cookie_jar, authorize_url)
        if status != 200:
            fail(f"Authorization endpoint returned {status} instead of the login page.")

        broker_link = parse_link(body, "social-oid4vp", authorize_url)
        if not broker_link:
            fail("Could not find the oid4vp identity-provider button on the Keycloak login page.")

        print("Opening Keycloak's wallet login page...")
        status, _, body = fetch(cookie_jar, broker_link)
        if status != 200:
            fail(f"OID4VP broker page returned {status}.")

        wallet_url = parse_link(body, "oid4vp-open-wallet", broker_link)
        if not wallet_url:
            fail("Could not find the same-device wallet link on the OID4VP broker page.")

        print("Submitting the presentation with eudi-dev...")
        redirect_uri, wallet_output = run_wallet_accept(wallet_url)
        print(wallet_output)

        print("Completing the broker flow in the original browser session...")
        callback_url = follow_complete_auth(cookie_jar, redirect_uri)
        parsed_callback = urllib.parse.urlparse(callback_url)
        callback_params = urllib.parse.parse_qs(parsed_callback.query)
        code = callback_params.get("code", [None])[0]
        returned_state = callback_params.get("state", [None])[0]
        if not code:
            fail(f"Callback redirect did not contain an authorization code: {callback_url}")
        if returned_state != state:
            fail(f"State mismatch after login: expected {state}, got {returned_state}")

        print("Exchanging the authorization code...")
        token_response = exchange_code(code, code_verifier)
        id_token_claims = decode_jwt_payload(token_response.get("id_token", ""))

        print()
        print("Success:")
        print(f"  callback={callback_url}")
        print(f"  access_token={token_response.get('access_token', '')[:24]}...")
        if id_token_claims:
            subject = id_token_claims.get("sub", "")
            preferred_username = id_token_claims.get("preferred_username", "")
            print(f"  id_token.sub={subject}")
            if preferred_username:
                print(f"  id_token.preferred_username={preferred_username}")


if __name__ == "__main__":
    main()
