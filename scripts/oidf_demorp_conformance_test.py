import io
import unittest
import urllib.parse
from unittest import mock

import oidf_demorp_conformance as demorp
from oidf_demorp_conformance import (
    DemoScenario,
    VerifierVerdict,
    expected_demo_outcome,
    scenario_plan_arg,
    vp_modules_for_variant,
)


class VpModuleSelectionTests(unittest.TestCase):
    def test_sdjwt_variant_runs_the_tampering_modules_and_no_session_transcript(self):
        modules = vp_modules_for_variant(
            {"credential_format": "sd_jwt_vc", "request_method": "request_uri_signed"}
        )
        self.assertIn("oid4vp-1final-verifier-invalid-sd-hash", modules)
        self.assertIn("oid4vp-1final-verifier-minimal-cnf-jwk", modules)
        self.assertIn("oid4vp-1final-verifier-request-uri-fetched-twice", modules)
        self.assertNotIn("oid4vp-1final-verifier-invalid-session-transcript", modules)
        # The demo verifier serves its request objects over GET, so the
        # request_uri_method=post module would skip itself.
        self.assertNotIn("oid4vp-1final-verifier-request-uri-method-post", modules)

    def test_mdoc_variant_runs_the_session_transcript_module_only(self):
        modules = vp_modules_for_variant(
            {"credential_format": "iso_mdl", "request_method": "request_uri_signed"}
        )
        self.assertIn("oid4vp-1final-verifier-happy-flow", modules)
        self.assertIn("oid4vp-1final-verifier-invalid-session-transcript", modules)
        self.assertNotIn("oid4vp-1final-verifier-invalid-sd-hash", modules)
        self.assertNotIn("oid4vp-1final-verifier-minimal-cnf-jwk", modules)
        self.assertNotIn("oid4vp-1final-verifier-invalid-kb-jwt-signature", modules)

    def test_url_query_variant_has_no_request_uri_to_refetch(self):
        modules = vp_modules_for_variant(
            {"credential_format": "sd_jwt_vc", "request_method": "url_query"}
        )
        self.assertNotIn("oid4vp-1final-verifier-request-uri-fetched-twice", modules)
        self.assertIn("oid4vp-1final-verifier-happy-flow", modules)
        # With the whole request in the query string the module runs (and
        # skips nothing), since it never needs to fetch a request_uri.
        self.assertIn("oid4vp-1final-verifier-request-uri-method-post", modules)


class ScenarioPlanArgTests(unittest.TestCase):
    def test_haip_issuer_plan_selects_the_vci_modules_and_leaves_pinned_variants_out(self):
        scenario = next(sc for sc in demorp.demo_scenarios() if sc.slug == "vci-issuer-haip")
        plan_arg = scenario_plan_arg(scenario)
        self.assertTrue(plan_arg.startswith("oid4vci-1_0-issuer-haip-test-plan["))
        # Pinned per module group inside the plan, so passing them again would
        # be refused by the suite.
        self.assertNotIn("vci_grant_type", plan_arg)
        self.assertNotIn("fapi_profile", plan_arg)
        self.assertIn(":oid4vci-1_0-issuer-metadata-test,", plan_arg)
        self.assertNotIn("fapi2-security-profile", plan_arg)

    def test_plain_issuer_plan_carries_the_full_variant_set(self):
        scenario = next(
            sc for sc in demorp.demo_scenarios() if sc.slug == "vci-issuer-authcode-wallet-initiated"
        )
        plan_arg = scenario_plan_arg(scenario)
        for expected in (
            "[fapi_profile=vci]",
            "[client_auth_type=client_attestation]",
            "[sender_constrain=dpop]",
            "[vci_grant_type=authorization_code]",
            "[vci_authorization_code_flow_variant=wallet_initiated]",
            "[openid=plain_oauth]",
            "[fapi_response_mode=plain_response]",
        ):
            self.assertIn(expected, plan_arg)

    def test_issuer_modules_leave_out_what_the_demo_does_not_offer(self):
        modules = demorp.vci_issuer_modules("issuer_initiated")
        self.assertIn("oid4vci-1_0-issuer-batch-issuance", modules)
        # The demo signs its metadata when asked for application/jwt. It
        # requires no key attestation and advertises no credential encryption,
        # so these would skip themselves.
        self.assertIn("oid4vci-1_0-issuer-metadata-test-signed", modules)
        self.assertNotIn("oid4vci-1_0-issuer-fail-invalid-key-attestation-signature", modules)
        self.assertNotIn("oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm", modules)
        # Without an offer there is no batch to ask for.
        self.assertNotIn("oid4vci-1_0-issuer-batch-issuance", demorp.vci_issuer_modules("wallet_initiated"))


class ExpectedDemoOutcomeTests(unittest.TestCase):
    def test_tampering_modules_expect_the_demo_verifier_to_refuse(self):
        for name in (
            "oid4vp-1final-verifier-invalid-sd-hash",
            "oid4vp-1final-verifier-invalid-kb-jwt-aud",
            "oid4vp-1final-verifier-kb-jwt-iat-in-future",
            "oid4vp-1final-verifier-invalid-session-transcript",
        ):
            self.assertEqual(expected_demo_outcome(name), "failed")

    def test_positive_modules_expect_a_verified_presentation(self):
        for name in (
            "oid4vp-1final-verifier-happy-flow",
            "oid4vp-1final-verifier-minimal-cnf-jwk",
            "oid4vp-1final-verifier-request-uri-fetched-twice",
        ):
            self.assertEqual(expected_demo_outcome(name), "verified")

    def test_a_skipped_module_carries_no_verdict_expectation(self):
        verdict = VerifierVerdict(
            test_name="oid4vp-1final-verifier-request-uri-method-post",
            module_result="SKIPPED",
            demo_status="expired",
            demo_error="",
        )
        self.assertTrue(verdict.acceptable())


class OfferDeliveryTests(unittest.TestCase):
    def test_the_offer_travels_by_value_to_the_suite_endpoint(self):
        scenario = DemoScenario(
            slug="vci-issuer-preauth",
            kind="vci",
            plan_name="oid4vci-1_0-issuer-test-plan",
            variant={},
            offer_query="batch=8",
        )
        offer = {
            "credential_issuer": "https://localhost:19002/issuer",
            "credential_configuration_ids": ["demo-ticket"],
            "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "abc"}},
        }
        calls = []

        def fake_wallet_request(wallet_url, method, path, payload=None, **kwargs):
            calls.append((method, path))
            if method == "POST":
                return {"id": "offer-1"}
            return offer

        delivered = []
        with mock.patch.object(demorp, "wallet_request", fake_wallet_request), mock.patch.object(
            demorp, "suite_get", delivered.append
        ), mock.patch.dict(demorp.os.environ, {"CONFORMANCE_SERVER": "https://localhost:8443/"}):
            demorp.deliver_credential_offer("http://wallet.test", scenario, "alias-1")

        self.assertEqual(calls[0], ("POST", "/issuer/api/offers?batch=8"))
        self.assertEqual(calls[1], ("GET", "/issuer/offer/offer-1"))
        self.assertEqual(len(delivered), 1)
        url = urllib.parse.urlsplit(delivered[0])
        self.assertTrue(delivered[0].startswith("https://localhost:8443/test/a/alias-1/credential_offer?"))
        query = urllib.parse.parse_qs(url.query)
        self.assertIn("credential_offer", query)
        self.assertIn("pre-authorized_code", query["credential_offer"][0])


class VerifierRequestTests(unittest.TestCase):
    def test_the_authorization_request_query_reaches_the_suite_authorize_endpoint(self):
        scenario = DemoScenario(
            slug="vp-verifier-final-sdjwt",
            kind="vp",
            plan_name="oid4vp-1final-verifier-test-plan",
            variant={},
            request_body={"type": "pid", "format": "sd-jwt"},
        )

        def fake_wallet_request(wallet_url, method, path, payload=None, **kwargs):
            self.assertEqual((method, path), ("POST", "/verifier/api/requests"))
            self.assertEqual(payload, {"type": "pid", "format": "sd-jwt"})
            return {
                "id": "req-1",
                "transaction_id": "tx-1",
                "scheme_uri": "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Flocalhost%3A19002%2Fverifier%2Frequest%2Freq-1",
            }

        delivered = []
        with mock.patch.object(demorp, "wallet_request", fake_wallet_request), mock.patch.object(
            demorp, "suite_get", delivered.append
        ), mock.patch.dict(demorp.os.environ, {"CONFORMANCE_SERVER": "https://localhost:8443/"}):
            request_id = demorp.submit_verifier_request("http://wallet.test", scenario, "alias-2")

        self.assertEqual(request_id, "tx-1")
        self.assertEqual(
            delivered,
            [
                "https://localhost:8443/test/a/alias-2/authorize?"
                "client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Flocalhost%3A19002%2Fverifier%2Frequest%2Freq-1"
            ],
        )


class DemoLoginTests(unittest.TestCase):
    def test_the_login_signs_in_and_completes_the_implicit_submission(self):
        login_page = (
            '<form method="POST" action="authorize">'
            '<input type="hidden" name="request_uri" value="urn:ietf:params:oauth:request_uri:xyz">'
            "</form>"
        )
        # What the suite's callback answers with: the implicit-submission page
        # whose script POSTs the URL fragment to the submission endpoint.
        callback_page = "<script>xhr.open('POST', \"https://localhost:8443/test/a/alias/implicit/abc\", true);</script>"
        requests = []

        class FakeResponse(io.BytesIO):
            def __init__(self, body, url):
                super().__init__(body)
                self._url = url

            def geturl(self):
                return self._url

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def open(self, req, timeout=None):
                if isinstance(req, str):
                    requests.append(("GET", req, None))
                    return FakeResponse(login_page.encode(), req)
                requests.append((req.get_method(), req.full_url, req.data))
                if req.full_url.endswith("/authorize"):
                    # The login redirect lands on the suite callback.
                    return FakeResponse(
                        callback_page.encode(),
                        "https://localhost:8443/test/a/alias/callback?code=c&state=s",
                    )
                return FakeResponse(b"", req.full_url)

        with mock.patch.object(demorp, "unverified_opener", FakeOpener):
            demorp.complete_demo_login("https://localhost:19002/issuer/authorize?request_uri=urn%3Axyz")

        self.assertEqual(requests[0][0], "GET")
        method, url, body = requests[1]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://localhost:19002/issuer/authorize")
        form = urllib.parse.parse_qs(body.decode())
        self.assertEqual(form["username"], ["alice"])
        self.assertEqual(form["password"], ["alice"])
        self.assertEqual(form["request_uri"], ["urn:ietf:params:oauth:request_uri:xyz"])
        method, url, body = requests[2]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://localhost:8443/test/a/alias/implicit/abc")
        # A query-mode callback has no fragment, and the page posts the empty
        # hash.
        self.assertEqual(body, b"")


if __name__ == "__main__":
    unittest.main()
