#!/bin/sh
# Delete unpublished plans owned by the token's account. Published plans are immutable and
# remain on the service.
set -eu

unset CDPATH
ROOT_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd)

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$ROOT_DIR/.env"
  set +a
fi

CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://www.certification.openid.net/}
if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
  CONFORMANCE_TOKEN=${OIDF_TOKEN:-}
fi
if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
  echo "error: set OIDF_TOKEN in .env or export CONFORMANCE_TOKEN" >&2
  exit 1
fi

export CONFORMANCE_SERVER CONFORMANCE_TOKEN

exec python3 - <<'PY'
import json
import os
import urllib.request

base = os.environ["CONFORMANCE_SERVER"].rstrip("/")
token = os.environ["CONFORMANCE_TOKEN"]


def request(method: str, path: str):
    req = urllib.request.Request(base + path, method=method)
    req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        return e.code, None


PAGE = 100
plans = []
while True:
    status, page = request("GET", f"/api/plan?draw=1&start={len(plans)}&length={PAGE}")
    if status != 200 or page is None:
        raise SystemExit(f"error: listing plans failed with HTTP {status}")
    data = page.get("data", [])
    plans.extend(data)
    if len(data) < PAGE:
        break

# The listing is read whole first because every deletion shifts the pages.
deleted = kept = 0
for plan in plans:
    plan_id = plan["_id"]
    name = plan.get("planName", "?")
    status, _ = request("DELETE", f"/api/plan/{plan_id}")
    if status == 204:
        deleted += 1
        print(f"deleted {plan_id} ({name})")
    elif status == 405:
        kept += 1
        print(f"kept {plan_id} ({name}): the plan is published and immutable")
    else:
        raise SystemExit(f"error: deleting plan {plan_id} failed with HTTP {status}")

print(f"{deleted} plan(s) deleted, {kept} kept on {base}")
PY
