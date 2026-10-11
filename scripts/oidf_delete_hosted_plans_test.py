import json
import os
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCRIPT = Path(__file__).with_name("oidf-delete-hosted-plans.sh")


class FakeSuite:
    """Lists plans in pages and refuses to delete a published one."""

    def __init__(self, published: int, drafts: int):
        self.plans = [{"_id": f"pub-{i}", "published": True} for i in range(published)]
        self.plans += [{"_id": f"draft-{i}", "published": False} for i in range(drafts)]

    def handler(self):
        suite = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                query = parse_qs(urlparse(self.path).query)
                start, length = int(query["start"][0]), int(query["length"][0])
                body = json.dumps({"data": suite.plans[start : start + length]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_DELETE(self):
                plan_id = self.path.rsplit("/", 1)[-1]
                plan = next(p for p in suite.plans if p["_id"] == plan_id)
                if plan["published"]:
                    self.send_response(405)
                else:
                    suite.plans.remove(plan)
                    self.send_response(204)
                self.end_headers()

        return Handler


class DeleteHostedPlansTests(unittest.TestCase):
    def test_deletes_every_draft_behind_more_than_one_page_of_published_plans(self):
        suite = FakeSuite(published=150, drafts=30)
        server = HTTPServer(("127.0.0.1", 0), suite.handler())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)

        env = dict(os.environ, CONFORMANCE_SERVER=f"http://127.0.0.1:{server.server_port}/", CONFORMANCE_TOKEN="t")
        out = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, check=True).stdout

        self.assertEqual([p["_id"] for p in suite.plans], [f"pub-{i}" for i in range(150)])
        self.assertIn("30 plan(s) deleted, 150 kept", out)


if __name__ == "__main__":
    unittest.main()
