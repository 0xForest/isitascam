"""Exercise both provider contracts and the streamed verdict without external traffic."""

import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

import app
import enrichment_http
import reputation
from assessment import assess


HOST = "public.example.com"
URL = "https://public.example.com/path?ticket=private"


def dns_answer(ip):
    return {"Status": 0, "TC": False, "Question": [{"name": HOST, "type": 1}],
            "Answer": [{"name": HOST, "type": 1, "data": ip}]}


class ReputationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.object(reputation, "SITE_AGE_ENABLED", False))
        self.enterContext(patch.object(enrichment_http, "retry_at", {}))
        self.enterContext(patch.object(reputation, "DNS_ENABLED", True))
        self.enterContext(patch.object(reputation, "URLHAUS_KEY", "test-key"))
        self.enterContext(patch.object(app.urlscanner, "ENABLED", False))
        self.enterContext(patch.object(app.openrouter, "API_KEY", ""))

    def transport(self, handler):
        client = httpx.AsyncClient
        return patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(handler), **kw))

    async def test_recent_certificate_requires_matching_recent_domain_registration(self):
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(days=4)).isoformat()
        old = (now - timedelta(days=400)).isoformat()
        wildcard = "*.example.co.uk"
        certs = [{"match": wildcard, "not_before": recent}]
        event = {"eventAction": "registration", "eventDate": recent}
        record = {"objectClassName": "domain", "ldhName": "EXAMPLE.CO.UK", "events": [event]}
        calls = []
        host = "offers.example.co.uk"

        def provider(request):
            calls.append(request.url.host)
            if request.url.host == "api.ctlogs.dev":
                self.assertEqual(request.headers["Authorization"], "Bearer test-ct-key")
                self.assertFalse(request.url.query)
                if request.url.path == f"/v1/domain/{host}":
                    return httpx.Response(200, json={"rows": []})
                self.assertEqual(request.url.path, f"/v1/domain/{wildcard}")
                return httpx.Response(200, json={"rows": certs})
            self.assertNotIn("Authorization", request.headers)
            if request.url.host == "data.iana.org":
                return httpx.Response(200, json={"services": [[["uk"], ["https://registry.example/rdap/"]]]})
            self.assertEqual(str(request.url), "https://registry.example/rdap/domain/example.co.uk")
            return httpx.Response(200, json=record)

        with (self.transport(provider), patch.object(reputation, "rdap_refresh_after", 0),
              patch.object(reputation, "CTLOGS_KEY", "test-ct-key"),
              patch.object(reputation, "rdap_registries", {}), patch.object(reputation, "SITE_AGE_ENABLED", True),
              patch.object(reputation, "DNS_ENABLED", False), patch.object(reputation, "URLHAUS_KEY", "")):
            frames = [f async for f in app.assessment_updates(f"https://{host}/private?pin=1234", "", "", "", False)]
            final = frames[-1]
            self.assertIn("domain was registered", final["quick_check"]["site_age_note"])
            self.assertEqual(final["quick_check"]["flagged_sources"], [])
            self.assertEqual(final["verdict"], "Unclear")
            self.assertEqual(calls, ["api.ctlogs.dev", "api.ctlogs.dev", "data.iana.org", "registry.example"])
            async with httpx.AsyncClient() as client:
                event["eventDate"] = old  # Renewal on an established domain.
                self.assertEqual((await reputation.site_age(client, host))[0], "known")
                event["eventAction"] = "last changed"
                self.assertEqual((await reputation.site_age(client, host))[0], "unknown")
                record.update(ldhName="different.co.uk", events=[{"eventAction": "registration", "eventDate": recent}])
                self.assertEqual((await reputation.site_age(client, host))[0], "unknown")
                calls.clear()
                certs[0]["not_before"] = old
                self.assertEqual((await reputation.site_age(client, host))[0], "known")
                certs.clear()
                self.assertEqual((await reputation.site_age(client, host))[0], "unknown")
                self.assertEqual((await reputation.site_age(client, "tenant.vercel.app"))[0], "unknown")
                self.assertEqual(calls, ["api.ctlogs.dev"] * 4)

    async def test_ctlogs_exact_lookup_and_failures(self):
        host = "example.org"
        calls = []
        old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        def provider(request):
            calls.append(str(request.url))
            self.assertNotIn("Authorization", request.headers)
            return response

        with self.transport(provider), patch.object(reputation, "CTLOGS_KEY", ""):
            for response, status in [
                (httpx.Response(200, json={"rows": [{"match": host, "not_before": old}]}), "known"),
                (httpx.Response(200, json={"rows": [{"match": "other.org", "not_before": old}]}), "unknown"),
                (httpx.Response(200, json={"rows": None}), "unavailable"),
                (httpx.Response(401), "unavailable"),
                (httpx.Response(429, headers={"Retry-After": "60"}), "unavailable"),
            ]:
                self.assertEqual((await reputation.lookup("Site age", reputation.site_age, host))[0], status)
            self.assertEqual(calls, ["https://api.ctlogs.dev/v1/domain/example.org"] * 5)
            self.assertEqual((await reputation.lookup("Site age", reputation.site_age, host))[0], "unavailable")
            self.assertEqual(len(calls), 5)

    async def test_dns_requires_policy_evidence(self):
        sinkhole = dns_answer("0.0.0.0")
        cases = [
            ({**sinkhole, "Comment": ["EDE(16): Censored"]}, "flagged"),
            (sinkhole, "unknown"),
            ({**sinkhole, "Comment": ["EDE(16): Censored"],
              "Answer": [{"name": "unrelated.example.com", "type": 1, "data": "0.0.0.0"}]}, "unknown"),
            (dns_answer("192.0.2.10"), "no_match"),
            ({**sinkhole, "Status": 3, "Answer": []}, "unknown"),
            ({**sinkhole, "Status": 2}, "unavailable"),
            ({**sinkhole, "TC": True}, "unavailable"),
            ({**sinkhole, "Question": []}, "unavailable"),
        ]
        for body, expected in cases:
            with self.subTest(expected=expected), self.transport(lambda _: httpx.Response(200, json=body)):
                status, _ = await reputation.lookup("Cloudflare DNS", reputation.cloudflare_dns, HOST)
                self.assertEqual(status, expected)

    async def test_urlhaus_requires_matching_url_and_malware_record(self):
        record = {"query_status": "ok", "url": URL, "threat": "malware_download", "url_status": "online"}
        for body, expected, detail in [
            (record, "flagged", "online"),
            ({**record, "url_status": "offline"}, "flagged", "previously"),
            ({**record, "url_status": "unknown"}, "flagged", "previously"),
            ({**record, "url": URL + "x"}, "unavailable", "unavailable"),
            ({"query_status": "invalid_url"}, "unavailable", "unavailable"),
            ({"query_status": "no_results"}, "no_match", "no malware-download record"),
        ]:
            with self.subTest(body=body), self.transport(lambda _: httpx.Response(200, json=body)):
                status, message = await reputation.lookup("URLhaus", reputation.urlhaus, URL)
                self.assertEqual(status, expected)
                self.assertIn(detail, message)

    async def test_public_entry_points_send_minimum_data_and_skip_ineligible_links(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.host == "security.cloudflare-dns.com":
                self.assertEqual(request.method, "GET")
                self.assertEqual(dict(request.url.params), {"name": HOST, "type": "A"})
                self.assertFalse(request.content)
                self.assertNotIn("Auth-Key", request.headers)
                return httpx.Response(200, json=dns_answer("192.0.2.10"))
            self.assertEqual(str(request.url), "https://urlhaus-api.abuse.ch/v1/url/")
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.headers["Auth-Key"], "test-key")
            self.assertEqual(parse_qs(request.content.decode()), {"url": [URL]})
            return httpx.Response(429)

        origin = "http://localhost"
        text = f"see {URL}#secret then https://another.example.com/other"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url=origin,
                                     headers={"Origin": origin, "Content-Type": "text/plain"}) as client:
            with self.transport(handler):
                for view in ({"X-Assessment-View": "web"}, {"X-Scan-Preview": "1", "Accept": "application/x-ndjson"}):
                    response = await client.post("/assess", content=text, headers=view)
                    response.raise_for_status()
                    result = json.loads(response.text.splitlines()[-1])
                    self.assertEqual(result["verdict"], "Unclear")
                    self.assertIn("did not flag", result["direct_findings"][0])
                    self.assertIn("URLhaus reputation check was unavailable", result["limitations"])
                    self.assertEqual(result["reasons"], [])
                for message in ("A text without links", "http://127.0.0.1/x", "https://test.invalid/x",
                                "https://user:password@public.example.com/"):
                    response = await client.post("/assess", content=message)
                    self.assertEqual(response.json()["verdict"], "Unclear")
                with patch.object(reputation, "URLHAUS_KEY", ""):
                    response = await client.post("/assess", content=text)
                    self.assertNotIn("URLhaus", response.text)
        self.assertEqual(len(requests), 4)  # The second URLhaus lookup was rate limited locally.

    async def test_flag_survives_slow_second_provider_and_ai_review(self):
        slow = asyncio.Event()
        model = asyncio.Event()
        blocked = {**dns_answer("0.0.0.0"), "Comment": ["EDE(16): Censored"]}
        async def handler(request):
            if request.method == "GET":
                return httpx.Response(200, json=blocked)
            await slow.wait()
            return httpx.Response(200, content=b"unparseable")

        async def analyze(*args, **kwargs):
            await model.wait()
            return {"signals": [{"code": "misleading_link", "evidence": [HOST]}], "verdict": "Suspicious", "evidence_status": "assessable"}

        with self.transport(handler), patch.object(app.openrouter, "analyze", analyze):
            updates = app.assessment_updates("Please check " + URL, "key", "model", "prompt", False)
            self.assertEqual(len((await anext(updates))["pending"]), 2)
            flagged = await asyncio.wait_for(anext(updates), 1)
            self.assertEqual(flagged["verdict"], "Unclear")
            self.assertEqual(flagged["pending"], ["URLhaus"])
            self.assertFalse(flagged["ai_reviews"])
            slow.set()
            self.assertIn("Context analysis", (await anext(updates))["pending"])
            model.set()
            final = await anext(updates)
            self.assertEqual(final["pending"], [])
            self.assertEqual(final["direct_findings"], flagged["direct_findings"])
            self.assertEqual(final["ai_reviews"][0]["signals"][0]["code"], "misleading_link")
            self.assertIn("unavailable", final["limitations"])
            await updates.aclose()

    async def test_one_context_opinion_can_disagree_with_a_provider(self):
        blocked = {**dns_answer("0.0.0.0"), "Comment": ["EDE(16): Censored"]}
        calls = []
        text = "A warning about this link: " + URL
        async def handler(request):
            if request.url.host == "security.cloudflare-dns.com":
                return httpx.Response(200, json=blocked)
            if request.url.host == "urlhaus-api.abuse.ch":
                return httpx.Response(200, json={"query_status": "no_results"})
            submitted = json.loads(json.loads(request.content)["messages"][1]["content"])
            calls.append(submitted["review_stage"])
            self.assertEqual(submitted["message"], text)
            self.assertEqual(submitted["checked_url"], URL)
            dns, haus = submitted["source_reports"]
            self.assertEqual((dns["provider"], dns["status"]), ("Cloudflare DNS", "flagged"))
            self.assertEqual((haus["provider"], haus["status"]), ("URLhaus", "no_match"))
            self.assertNotIn("test-key", str(submitted))
            reply = {"verdict": "Unclear", "evidence_status": "assessable",
                     "signals": [{"code": "provider_warning", "evidence": [dns["detail"]]}]}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(reply)}}]})

        with self.transport(handler):
            frames = [f async for f in app.assessment_updates(text, "key", "model", "prompt", False, web_view=True)]
        self.assertEqual(calls, ["context"])
        self.assertEqual(frames[-1]["verdict"], "Unclear")
        signal, = frames[-1]["ai_reviews"][0]["signals"]
        self.assertEqual(signal["evidence"], frames[-1]["direct_findings"][:1])
        self.assertEqual(signal["evidence_source"], "Source report")

    async def test_failed_scan_keeps_reputation_results_and_skips_site_review(self):
        origin = "http://localhost"
        text = "Enter your password at " + URL
        for has_dns_record in (False, True):
            with self.subTest(has_dns_record=has_dns_record):
                stages = []
                async def provider(request):
                    if request.url.host == "security.cloudflare-dns.com":
                        if not has_dns_record:
                            raise httpx.ReadTimeout("private provider details")
                        return httpx.Response(200, json=dns_answer("192.0.2.10"))
                    if request.url.host == "urlhaus-api.abuse.ch":
                        return httpx.Response(429)
                    self.assertEqual(request.url.host, "openrouter.ai")
                    stages.append("unexpected AI request")
                    return httpx.Response(500)

                async def broken_scanner(*args, **kwargs):
                    raise ExceptionGroup("private provider details", [RuntimeError("private scanner response")])

                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url=origin) as client:
                    with (self.transport(provider), patch.object(app.openrouter, "API_KEY", "synthetic"),
                          patch.object(app.openrouter, "MODEL", "test/model"), patch.object(app.urlscanner, "ENABLED", True),
                          patch.object(app.urlscanner, "lookup", broken_scanner), self.assertLogs("uvicorn.error", "INFO") as logs):
                        headers = {"Origin": origin, "Content-Type": "text/plain"}
                        if has_dns_record:
                            headers["Accept"] = "application/x-ndjson"
                        response = await client.post("/assess", headers=headers, content=text)
                response.raise_for_status()
                final = json.loads(response.text.splitlines()[-1])
                self.assertEqual(final.get("pending", []), [])
                self.assertEqual(final["verdict"], "Unclear")
                self.assertFalse(final["ai_reviews"])
                self.assertEqual(stages, [])
                self.assertEqual(final["ai_capture_note"], "Screenshot not available for this URL.")
                self.assertIn("rate limit", final["limitations"])
                self.assertIn("Cloudflare scan context was unavailable", final["limitations"])
                self.assertEqual(len(final["direct_findings"]), int(has_dns_record))
                self.assertNotIn("private provider details", response.text + repr(logs.output))
                self.assertNotIn("private scanner response", response.text + repr(logs.output))

    def test_only_flagged_reports_can_ground_provider_warnings(self):
        reports = [{"provider": "URLhaus", "status": "no_match", "detail": "No record."}]
        opinion = {"verdict": "Likely scam", "evidence_status": "assessable",
                   "signals": [{"code": "provider_warning", "evidence": ["No record."]}]}
        with self.assertRaises(ValueError):
            app.openrouter.validate(json.dumps(opinion), URL, reports=reports)
        opinion["signals"] = []
        with self.assertRaises(ValueError):
            app.openrouter.validate(json.dumps(opinion), URL, reports=reports)
        opinion["verdict"] = "Safe"
        with self.assertRaises(ValueError):
            app.openrouter.validate(json.dumps(opinion), URL, reports=reports)

    async def test_quick_first_impression_precedes_url_result_without_changing_ai_verdict(self):
        text = "Notice: ENTER your card details for a redelivery fee. " + URL
        async def handler(request):
            if request.method == "GET":
                return httpx.Response(200, json={**dns_answer("0.0.0.0"), "Comment": ["EDE(16): Censored"]})
            return httpx.Response(503)
        with self.transport(handler):
            frames = [frame async for frame in app.assessment_updates(text, "", "", "", False)]
        first, final = frames[0], frames[-1]
        self.assertEqual(first["quick_check"]["phrases"], ["enter your card details", "redelivery fee"])
        self.assertEqual(first["quick_check"]["wording_score"], 40)
        self.assertEqual(first["quick_check"]["flagged_sources"], [])
        self.assertEqual(final["quick_check"]["flagged_sources"], ["Cloudflare DNS"])
        self.assertEqual(final["quick_check"]["unavailable_sources"], ["URLhaus"])
        self.assertEqual(final["verdict"], "Unclear")
        self.assertFalse(app.quick_phrases("Please enter your passwordless account."))

    async def test_local_wording_score_through_assessment(self):
        cases = [
            ("Payment received. PAYMENT SUCCESSFUL. Do not click. Gift cards available in store. "
             "Each update costs £3. Never share your sign-in code.", [], 0),
            ("Payment received. PAY the recruitment fee. Pay the recruitment fee!",
             ["pay the recruitment fee"], 60),
            ("click here to claim your tax refund immediately", ["click here to claim your tax refund", "immediately"], 30),
            ("Send me the gift-card numbers. Payment successful.", ["send me the gift card numbers"], 55),
            ("Do not click here to claim your tax refund. Don’t pay the interview fee. "
             "Never send me your online banking password. Reply with your PIN.", ["reply with your pin"], 60),
            ("payment now now now", ["payment", "now"], 12),
            ("Repayment, clickbait and nowhere.", [], 0),
            ("click here to claim. Your tax refund arrived.", ["click"], 5),
            ("pay https://example.com/gift-card/payment now", ["now"], 2),
        ]
        with patch.object(reputation, "host_providers", return_value={}), patch.object(reputation, "url_providers", return_value={}):
            for message, phrases, score in cases:
                with self.subTest(message=message):
                    frames = [frame async for frame in app.assessment_updates(message, "", "", "", False)]
                    self.assertEqual(frames[0]["quick_check"]["phrases"], phrases)
                    self.assertEqual(frames[0]["quick_check"]["wording_score"], score)
                    self.assertFalse(frames[-1]["ai_reviews"])

    async def test_radar_labels_and_spamhaus_network_evidence(self):
        drop_fetches = []
        address = "11.12.13.14"
        async def handler(req):
            if req.url.host == "api.cloudflare.com":
                self.assertEqual(req.url.path, "/client/v4/radar/ranking/domain/" + HOST)
                self.assertEqual(req.headers["Authorization"], "Bearer radar")
                return httpx.Response(200, json={"success": True, "result": {"details_0": {"categories": [{"name": "Shopping"}]}}})
            if req.url.host == "cloudflare-dns.com":
                self.assertEqual(req.url.params["name"], HOST)
                return httpx.Response(200, json=dns_answer(address))
            self.assertEqual(str(req.url), "https://www.spamhaus.org/drop/drop_v4.json")
            self.assertNotIn("Authorization", req.headers)
            drop_fetches.append(True)
            return httpx.Response(200, text='{"cidr":"11.12.13.0/24"}\n{"type":"metadata","records":1}')
        with (self.transport(handler), patch.object(reputation, "RADAR_TOKEN", "radar"),
              patch.object(reputation, "drop_networks", ()), patch.object(reputation, "drop_refresh_after", 0)):
            self.assertEqual(await reputation.lookup("Cloudflare Radar", reputation.radar_categories, HOST),
                             ("known", "Cloudflare Radar categories for the checked hostname: Shopping."))
            self.assertEqual((await reputation.lookup("Spamhaus DROP", reputation.spamhaus_drop, HOST))[0], "flagged")
            address = "8.8.8.8"
            self.assertEqual((await reputation.lookup("Spamhaus DROP", reputation.spamhaus_drop, HOST))[0], "no_match")
            address = "127.0.0.1"
            self.assertEqual((await reputation.lookup("Spamhaus DROP", reputation.spamhaus_drop, HOST))[0], "unknown")
        self.assertEqual(len(drop_fetches), 1)

    async def test_first_update_for_redelivery_example_precedes_external_checks(self):
        message = "Example Logistics: URGENT!!! Pay R49,99 for redelivery. https://bit.ly/example-fixture"
        updates = app.assessment_updates(message, "", "", "", True, web_view=True)
        try:
            initial = await anext(updates)
            quick = initial["quick_check"]
            self.assertEqual(quick["phrases"], ["urgent", "redelivery"])
            self.assertEqual(quick["links"], ["https://bit.ly/example-fixture"])
            self.assertEqual(quick["checked_host"], "bit.ly")
            self.assertTrue(quick["shortened"])
            self.assertFalse(initial["ai_reviews"])
            self.assertFalse(quick["flagged_sources"])
        finally:
            await updates.aclose()

    async def test_slow_query_times_out_and_releases_request(self):
        finished = asyncio.Event()
        async def hang(client, target):
            try:
                await asyncio.Event().wait()
            finally:
                finished.set()
        with patch.object(reputation, "TIMEOUT", 0.1):
            result = await asyncio.wait_for(reputation.lookup("URLhaus", hang, URL), 1)
        self.assertTrue(finished.is_set())
        self.assertEqual(assess(URL, reputation_checks=[result])["verdict"], "Unclear")
