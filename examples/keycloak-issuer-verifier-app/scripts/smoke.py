#!/usr/bin/env python3
"""Check login with a membership credential.

The first login combines a PID presentation with password sign-in and issues a membership credential containing an opaque subject. The second login presents both credentials and uses that subject to identify the account without a password."""
import base64
import hashlib
import html.parser
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "wallet-app-demo")
APP_CLIENT_ID = os.environ.get("APP_CLIENT_ID", "wallet-app")
REDIRECT_URI = os.environ.get("SMOKE_REDIRECT_URI", "http://127.0.0.1:19099/callback")
WALLET_API = os.environ.get("WALLET_API", f"http://localhost:{os.environ.get('EUDI_DEV_PORT', '8087')}")
MEMBERSHIP_VCT = os.environ.get("MEMBERSHIP_VCT", "https://credentials.example.com/membership")
DEMO_USERNAME = os.environ.get("OID4VCI_USER", "alice")
DEMO_PASSWORD = os.environ.get("OID4VCI_USER_PASSWORD", "alice")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def wallet_post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        WALLET_API + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def wallet_get(path):
    with urllib.request.urlopen(WALLET_API + path, timeout=30) as resp:
        return json.loads(resp.read())


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("id") and a.get("href"):
            self.links[a["id"]] = a["href"]
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "GET").upper(), "inputs": []}
        if tag == "input" and self._form is not None:
            self._form["inputs"].append(
                {"name": a.get("name", ""), "type": a.get("type", "text"), "value": a.get("value", "")}
            )

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse(body):
    p = Page()
    p.feed(body)
    return p


def fetch(jar, url, method="GET", data=None):
    with tempfile.NamedTemporaryFile() as hf, tempfile.NamedTemporaryFile() as bf:
        cmd = ["curl", "-sS", "-D", hf.name, "-o", bf.name, "-b", jar, "-c", jar, "-X", method, url]
        if data is not None:
            cmd += ["--data", urllib.parse.urlencode(data), "-H", "Content-Type: application/x-www-form-urlencoded"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            fail(f"curl {url}: {result.stderr}")
        headers = Path(hf.name).read_text()
        body = Path(bf.name).read_text()
    blocks = [b for b in re.split(r"\r?\n\r?\n", headers.strip()) if b.strip()]
    lines = blocks[-1].splitlines() if blocks else []
    status = 0
    if lines:
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            status = 0
    location = None
    for line in lines[1:]:
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
    return status, location, body


def follow(jar, url, max_hops=12):
    for _ in range(max_hops):
        status, location, body = fetch(jar, url)
        if 300 <= status < 400 and location:
            nxt = urllib.parse.urljoin(url, location)
            if nxt.startswith(REDIRECT_URI):
                return nxt, 0, ""
            url = nxt
            continue
        return url, status, body
    fail(f"too many redirects at {url}")


def pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def open_wallet_link(jar):
    """Start an authorization request and return the wallet deep link on the broker page."""
    state = base64.urlsafe_b64encode(os.urandom(9)).decode()
    _, challenge = pkce()
    query = urllib.parse.urlencode(
        {
            "client_id": APP_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    authorize = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?{query}"
    status, _, body = fetch(jar, authorize)
    if status != 200:
        fail(f"authorization endpoint returned {status}")
    page = parse(body)
    idp = page.links.get("social-oid4vp") or next((h for i, h in page.links.items() if "oid4vp" in i.lower()), None)
    if not idp:
        fail("no oid4vp identity-provider link on the login page")
    status, location, body = fetch(jar, urllib.parse.urljoin(authorize, idp))
    if 300 <= status < 400 and location:
        _, _, body = fetch(jar, urllib.parse.urljoin(authorize, location))
    page = parse(body)
    wallet_link = page.links.get("oid4vp-open-wallet")
    if not wallet_link:
        fail("no same-device wallet link on the broker page")
    return wallet_link


def present(wallet_link):
    resp = wallet_post("/api/presentations", {"uri": wallet_link, "auto_accept": True})
    container = resp.get("response", resp)
    if isinstance(container, dict):
        if container.get("redirect_uri"):
            return container["redirect_uri"]
        raw = container.get("body")
        if isinstance(raw, str) and raw.strip().startswith("{"):
            try:
                return json.loads(raw).get("redirect_uri")
            except json.JSONDecodeError:
                pass
    fail(f"wallet presentation returned no redirect_uri: {json.dumps(resp)[:400]}")


def first_login():
    print("First login: the wallet holds the PID alone")
    jar = tempfile.NamedTemporaryFile(delete=False).name
    wallet_link = open_wallet_link(jar)
    url, _, body = follow(jar, present(wallet_link))
    page = parse(body)
    fields_present = {i["name"] for f in page.forms for i in f["inputs"]}
    if "password" not in fields_present:
        fail(f"expected a password form after the PID-only presentation, got: {body[:300]}")
    form = next(f for f in page.forms if any(i["name"] == "password" for i in f["inputs"]))
    fields = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
    fields.update({"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
    action = urllib.parse.urljoin(url, form["action"] or url)
    status, location, body = fetch(jar, action, method=form["method"], data=fields)
    if 300 <= status < 400 and location:
        url, status, body = follow(jar, urllib.parse.urljoin(action, location))

    print("Signed in with a password, accepting the in-login credential offer")
    page = parse(body)
    offer_link = page.links.get("credential-offer-uri-link")
    if not offer_link:
        fail(f"no credential-offer link on the required-action page: {body[:300]}")
    wallet_post("/api/offers", {"uri": offer_link})
    cont = page.links.get("continue-vc-offer")
    if cont:
        callback, _, _ = follow(jar, urllib.parse.urljoin(url, cont))
    else:
        form = page.forms[0] if page.forms else fail("no continue affordance on the offer page")
        action = urllib.parse.urljoin(url, form["action"] or url)
        fields = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
        _, location, _ = fetch(jar, action, method=form["method"], data=fields)
        callback = urllib.parse.urljoin(action, location) if location else ""
        if callback and not callback.startswith(REDIRECT_URI):
            callback, _, _ = follow(jar, callback)
    if not (callback and callback.startswith(REDIRECT_URI) and "code=" in callback):
        fail(f"first login did not reach the callback with a code: {callback}")

    creds = wallet_get("/api/credentials")
    items = creds if isinstance(creds, list) else creds.get("credentials", [])
    membership = [c for c in items if (c.get("vct") or c.get("type")) == MEMBERSHIP_VCT]
    if not membership:
        fail("the membership credential was not issued into the wallet")
    print(f"  membership credential issued: {membership[0]['id']}")


def second_login():
    print("Second login: the wallet holds the PID and the membership credential")
    jar = tempfile.NamedTemporaryFile(delete=False).name
    wallet_link = open_wallet_link(jar)
    url, status, body = follow(jar, present(wallet_link))
    if url.startswith(REDIRECT_URI) and "code=" in url:
        print("  signed in without a password")
        return
    if "password" in {i["name"] for f in parse(body).forms for i in f["inputs"]}:
        fail("second login asked for a password: the membership subject did not sign the user in")
    fail(f"second login did not complete: status={status} url={url[:90]}")


def main():
    first_login()
    second_login()
    print("\nSubject-binding login verified end to end.")


if __name__ == "__main__":
    main()
