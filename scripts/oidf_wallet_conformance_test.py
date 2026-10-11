import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import oidf_wallet_conformance as oidf
from oidf_wallet_conformance import PlanScenario, scenario_plan_arg


class ScenarioPlanArgTests(unittest.TestCase):
    def test_final_signed_direct_post_omits_inapplicable_modules(self):
        scenario = PlanScenario(
            slug="vp-final-sdjwt-signed-direct-post",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post",
            },
            credential_kind="sdjwt",
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn(":oid4vp-1final-wallet-happy-flow", plan_arg)
        self.assertIn("oid4vp-1final-wallet-request-uri-method-post", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-alternate-happy-flow", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-negative-test-response-uri-not-client-id", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-multisigned-one-invalid-signature", plan_arg)
        # unencrypted response mode: no encryption key to test against
        self.assertNotIn("oid4vp-1final-wallet-ignores-unusable-encryption-key", plan_arg)
        self.assertIn("oid4vp-1final-wallet-negative-test-invalid-client-id-prefix", plan_arg)

    def test_haip_plans_run_complete(self):
        # The certifiable HAIP plans carry no module filter: the suite's plan
        # definition decides what runs, and a certification run covers the
        # whole plan.
        scenario = PlanScenario(
            slug="vp-haip-sdjwt-dc-api-jwt",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-haip-test-plan",
            variant={
                "credential_format": "sd_jwt_vc",
                "response_mode": "dc_api.jwt",
            },
            credential_kind="sdjwt",
            requires_haip=True,
        )
        plan_arg = scenario_plan_arg(scenario)
        self.assertEqual(
            plan_arg,
            "oid4vp-1final-wallet-haip-test-plan[credential_format=sd_jwt_vc][response_mode=dc_api.jwt]",
        )

    def test_final_redirect_uri_direct_post_keeps_applicable_response_uri_negative_test(self):
        scenario = PlanScenario(
            slug="vp-final-sdjwt-unsigned-direct-post",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "redirect_uri",
                "request_method": "request_uri_unsigned",
                "response_mode": "direct_post",
            },
            credential_kind="sdjwt",
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn("oid4vp-1final-wallet-negative-test-response-uri-not-client-id", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-negative-test-invalid-request-object-signature", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-multisigned-one-invalid-signature", plan_arg)

    def test_final_direct_post_jwt_includes_unusable_encryption_key_module(self):
        scenario = PlanScenario(
            slug="vp-final-sdjwt-signed-direct-post-jwt",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post.jwt",
            },
            credential_kind="sdjwt",
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn("oid4vp-1final-wallet-ignores-unusable-encryption-key", plan_arg)


class PurgeIssuedCredentialsTests(unittest.TestCase):
    """Issuance credentials persist between plans but do not chain to the wallet CA trusted by presentation tests."""

    def _run(self, listed, baseline):
        deleted = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_list(wallet_url, method, path, *args, **kwargs):
            self.assertEqual((method, path), ("GET", "/api/credentials"))
            return listed

        def fake_urlopen(req, timeout=None):
            self.assertEqual(req.get_method(), "DELETE")
            deleted.append(req.full_url.rsplit("/", 1)[-1])
            return FakeResponse()

        with mock.patch.object(oidf, "wallet_request", fake_list), mock.patch.object(
            oidf.urllib.request, "urlopen", fake_urlopen
        ):
            removed = oidf.purge_issued_credentials("http://wallet.test", baseline)
        return removed, deleted

    def test_keeps_the_baseline_and_removes_what_the_suite_issued(self):
        listed = [{"id": "base-sdjwt"}, {"id": "base-mdoc"}, {"id": "suite-1"}, {"id": "suite-2"}]

        removed, deleted = self._run(listed, {"base-sdjwt", "base-mdoc"})

        self.assertEqual(removed, 2)
        self.assertEqual(sorted(deleted), ["suite-1", "suite-2"])

    def test_a_clean_wallet_is_left_alone(self):
        listed = [{"id": "base-sdjwt"}]

        removed, deleted = self._run(listed, {"base-sdjwt"})

        self.assertEqual(removed, 0)
        self.assertEqual(deleted, [])


class ScreenshotEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "submitted_urls": set(),
            "submitted_browser_api_requests": set(),
            "uploaded_placeholders": set(),
        }
        self.logs = [{"upload": "error-photo"}, {"redirect_to": "openid4vp://request"}]
        self.error = "nonce is required"
        self.images = []

    def submit(self, *args):
        self.error = "client_id uses an unsupported prefix"
        return oidf.WalletSubmissionResult(completed=True, retryable=False)

    def poll(self, submit=None, upload=None):
        with mock.patch.object(oidf, "api_request", side_effect=[{"status": "WAITING"}, self.logs]), mock.patch.object(
            oidf, "submit_wallet_request", side_effect=submit or self.submit
        ), mock.patch.object(
            oidf, "upload_placeholder", side_effect=upload or (lambda *args: self.images.append(self.error))
        ):
            oidf.handle_module("https://suite/", None, "http://wallet", "module", self.state)

    def test_captures_current_rejection_after_submission(self):
        self.poll()
        self.poll()
        self.assertEqual(self.images, ["client_id uses an unsupported prefix"])

    def test_waits_for_retryable_submission(self):
        self.poll(submit=lambda *args: oidf.WalletSubmissionResult(completed=False, retryable=True))
        self.assertEqual(self.images, [])
        self.poll()
        self.assertEqual(self.images, ["client_id uses an unsupported prefix"])

    def test_waits_for_request_when_placeholder_arrives_first(self):
        self.logs = [{"upload": "error-photo"}]
        self.poll()
        self.assertEqual(self.images, [])
        self.logs.append({"redirect_to": "openid4vp://request"})
        self.poll()
        self.assertEqual(self.images, ["client_id uses an unsupported prefix"])

    def test_retries_failed_capture_or_upload(self):
        with self.assertRaises(RuntimeError):
            self.poll(upload=mock.Mock(side_effect=RuntimeError("capture failed")))
        self.assertEqual(self.state["uploaded_placeholders"], set())
        self.poll()
        self.assertEqual(self.images, ["client_id uses an unsupported prefix"])

    def test_capture_failure_does_not_upload_placeholder_image(self):
        with mock.patch.object(oidf, "capture_wallet_screenshot", return_value=None), mock.patch.object(
            oidf, "api_request"
        ) as api:
            with self.assertRaises(RuntimeError):
                oidf.upload_placeholder("https://suite/", None, "module", "error-photo", "http://wallet")
        api.assert_not_called()

    def test_terminal_module_stops_before_submissions_and_screenshots(self):
        for status in ("FINISHED", "INTERRUPTED"):
            with self.subTest(status=status), mock.patch.object(oidf, "api_request", return_value={"status": status}) as api:
                state = {"terminal": False}
                oidf.handle_module("https://suite/", None, "http://wallet", "module", state)
                self.assertTrue(state["terminal"])
                api.assert_called_once_with("https://suite/", None, "GET", "api/info/module")


class CredentialChainTests(unittest.TestCase):
    def setUp(self):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self.encoding = serialization.Encoding
        self.keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
                 for name in ('root', 'provider', 'signer')]
        self.certs = []
        now = datetime.datetime.now(datetime.timezone.utc)
        for index in range(3):
            parent = max(0, index - 1)
            cert = (x509.CertificateBuilder()
                    .subject_name(names[index]).issuer_name(names[parent])
                    .public_key(self.keys[index].public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=30))
                    .add_extension(x509.BasicConstraints(ca=index < 2, path_length=None), critical=True)
                    .sign(self.keys[parent], hashes.SHA256()))
            self.certs.append(cert)
        self.chain = [cert.public_bytes(self.encoding.DER) for cert in reversed(self.certs)]
        self.root = self.certs[0].public_bytes(self.encoding.PEM).decode()

    def test_accepts_the_provider_intermediate(self):
        self.assertTrue(oidf.chains_to_wallet_ca(self.chain[:-1], self.root))
        self.assertTrue(oidf.chains_to_wallet_ca(self.chain, self.root))

    def test_accepts_direct_root_signing(self):
        self.assertTrue(oidf.chains_to_wallet_ca(self.chain[1:2], self.root))

    def test_rejects_missing_or_wrong_issuer(self):
        self.assertFalse(oidf.chains_to_wallet_ca(self.chain[:1], self.root))
        self.assertFalse(oidf.chains_to_wallet_ca([], self.root))
        self.assertFalse(oidf.chains_to_wallet_ca(list(reversed(self.chain)), self.root))

    def test_reads_the_sdjwt_chain(self):
        import base64
        import json
        header = {'x5c': [base64.b64encode(cert).decode() for cert in self.chain[:-1]]}
        encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
        self.assertEqual(oidf.credential_chain_der({'format': 'dc+sd-jwt', 'raw': encoded+'.e30.signature~'}), self.chain[:-1])

    def test_reads_the_mdoc_chain(self):
        import base64
        import cbor2
        for certificates in (self.chain[:-1], self.chain[0]):
            raw = cbor2.dumps({'issuerAuth': [b'', {33: certificates}, b'', b'']})
            encoded = base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
            expected = certificates if isinstance(certificates, list) else [certificates]
            self.assertEqual(oidf.credential_chain_der({'format': 'mso_mdoc', 'raw': encoded}), expected)


class ProviderRoleTests(unittest.TestCase):
    """The PID key is the one whose certificate the PID provider CA issued."""

    def jwk(self, ca_issuers):
        import base64
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'signer')])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=30)))
        if ca_issuers:
            builder = builder.add_extension(x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(ca_issuers))
            ]), critical=False)
        der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        return {'kty': 'EC', 'x5c': [base64.b64encode(der).decode()]}

    def test_matches_the_role_of_the_issuing_ca(self):
        self.assertTrue(oidf.signs_for_provider_role(self.jwk('https://w.example/api/certificates/providers/pid/DE.der'), 'pid'))
        self.assertFalse(oidf.signs_for_provider_role(self.jwk('https://w.example/api/certificates/providers/eaa/NL.der'), 'pid'))
        self.assertFalse(oidf.signs_for_provider_role(self.jwk(None), 'pid'))
        self.assertFalse(oidf.signs_for_provider_role({'kty': 'EC'}, 'pid'))


class WalletActivityExportTests(unittest.TestCase):
    def test_exports_activity_payloads_and_clears_the_log(self):
        entries = [{
            "action": "issuance", "details": {"event": "deferred_credential_response", "status_code": 200},
            "payload": {"label": "Response", "encrypted": True, "wire": "encrypted-response",
                        "body": '{"credentials":[{"credential":"issued-instance"}]}'},
        }]
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                response = entries if self.path == "/api/log?view=activity" else [{"action": "issuance"}]
                self.wfile.write(json.dumps(response).encode())

            def do_DELETE(self):
                requests.append(self.path)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "activity.json"
                oidf.export_wallet_activity(f"http://127.0.0.1:{server.server_port}", output, clear=True)
                self.assertEqual(json.loads(output.read_text()), entries)
                self.assertEqual(requests, ["/api/log?view=activity", "/api/log"])
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
