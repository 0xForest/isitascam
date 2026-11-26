"""External report contracts and background submission lifecycle, using local transports."""

import asyncio
import base64
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

import app
import enrichment_http
import background_scans as jobs
import reputation as rep

URL = "https://public.example.com/Case?ticket=private"
SCAN_ID = "00000000-0000-4000-8000-000000000001"
TASK = {"url": URL, "uuid": SCAN_ID, "time": "2026-11-24T09:00:00Z"}
MISSING = {"error": {"code": "NotFoundError"}}


class ReportsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.object(rep, "SITE_AGE_ENABLED", False))
        self.enterContext(patch.object(enrichment_http, "retry_at", {}))
        for key in ("GOOGLE_KEY", "VT_KEY", "URLSCAN_KEY", "URLHAUS_KEY"):
            self.enterContext(patch.object(rep, key, ""))
        self.enterContext(patch.object(rep, "DNS_ENABLED", False))
        self.enterContext(patch.object(rep, "google_cache", {}))
        self.enterContext(patch.object(rep, "VT_SUBMIT", True))
        self.enterContext(patch.object(rep, "URLSCAN_SUBMIT", True))
        self.enterContext(patch.object(app.urlscanner, "ENABLED", False))
        self.addAsyncCleanup(jobs.shutdown)

    def transport(self, handler):
        client = httpx.AsyncClient
        return patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(handler), **kw))

    async def test_google_threats_and_misses_cache_until_provider_deadline(self):
        calls = []
        def handler(request):
            self.assertEqual(request.url.host, "safebrowsing.googleapis.com")
            self.assertEqual(request.url.path, "/v5/urls:search")
            self.assertEqual(dict(request.url.params), {"urls": URL})
            self.assertEqual(request.headers["X-Goog-Api-Key"], "google")
            calls.append(request)
            record = {"cacheDuration": "10.5s"}
            if len(calls) == 1:
                record["threats"] = [{"url": "public.example.com/", "threatTypes": ["SOCIAL_ENGINEERING"]}]
            return httpx.Response(200, json=record)
        with self.transport(handler), patch.object(rep, "GOOGLE_KEY", "google"), patch.object(rep, "monotonic") as clock:
            for now, flagged in ((0, True), (10, True), (11, False), (20, False)):
                clock.return_value = now
                frames = [x async for x in app.assessment_updates(URL + "#secret", "", "", "", False)]
                result = frames[-1]
                self.assertEqual("google_warning" in result, flagged)
                self.assertEqual(result["verdict"], "Unclear")
                self.assertNotIn("private", repr(rep.google_cache))
                if flagged:
                    self.assertIn(result["google_warning"], result["direct_findings"])
        self.assertEqual(len(calls), 2)

    async def test_google_binary_hit_and_miss(self):
        # The v5 endpoint returns protobuf for both a listed URL and a cached miss.
        duration = b"\x12\x03\x08\xac\x02"
        hit = b"\x0a\x0c\x0a\x06a.test\x12\x02\x01\x04" + duration
        for body, expected in ((duration, "no_match"), (hit, "flagged"), (b"", "unavailable")):
            rep.google_cache.clear()
            with self.transport(lambda _: httpx.Response(200, content=body, headers={"Content-Type": "application/x-protobuf"})):
                status, _ = await rep.lookup("Google Safe Browsing", rep.google_safe_browsing, URL)
                self.assertEqual(status, expected)

    async def test_virustotal_reads_existing_engine_votes(self):
        stats = {"malicious": 2, "suspicious": 1, "undetected": 6, "harmless": 70}
        attributes = {"last_analysis_stats": stats, "url": URL, "last_analysis_date": 1763942400}
        def handler(req):
            self.assertEqual(req.url.host, "www.virustotal.com")
            self.assertEqual(req.method, "GET")
            self.assertEqual(req.headers["x-apikey"], "vt")
            identifier = req.url.path.rsplit("/", 1)[1]
            self.assertEqual(base64.urlsafe_b64decode(identifier + "==").decode(), URL)
            return httpx.Response(200, json={"data": {"type": "url", "attributes": attributes}})
        with self.transport(handler), patch.object(rep, "VT_KEY", "vt"):
            status, detail = await rep.lookup("VirusTotal", rep.virustotal, URL)
            self.assertEqual(status, "flagged")
            self.assertIn("2 engines", detail)
            stats.update(malicious=0, suspicious=0)
            self.assertEqual((await rep.lookup("VirusTotal", rep.virustotal, URL))[0], "known")
            attributes["url"] = URL.lower()
            self.assertEqual((await rep.lookup("VirusTotal", rep.virustotal, URL))[0], "unknown")
        self.assertFalse(jobs.recent)

    async def test_urlscan_looks_up_the_matching_historical_report(self):
        calls = []
        rows = [{"task": {**TASK, "url": URL.lower()}}, {"task": TASK}]
        report = {"task": TASK, "verdicts": {"overall": {"malicious": True}}}
        def handler(req):
            self.assertEqual(req.headers["API-Key"], "us")
            self.assertEqual(req.method, "GET")
            calls.append(req.url.path)
            if req.url.path == "/api/v1/search/":
                self.assertEqual(req.url.params["q"], f'task.url.keyword:"{URL}"')
                return httpx.Response(200, json={"results": rows, "total": 8, "has_more": True})
            self.assertEqual(req.url.path, f"/api/v1/result/{SCAN_ID}/")
            return httpx.Response(200, json=report)
        with self.transport(handler), patch.object(rep, "URLSCAN_KEY", "us"):
            status, detail = await rep.lookup("urlscan.io", rep.urlscan, URL)
            self.assertEqual(status, "flagged")
            self.assertIn("2026-11-24", detail)
            report.clear()
            status, detail = await rep.lookup("urlscan.io", rep.urlscan, URL)
            self.assertEqual(status, "known")
            self.assertIn("unavailable", detail)
            rows.pop()
            self.assertEqual((await rep.lookup("urlscan.io", rep.urlscan, URL))[0], "unknown")
        self.assertEqual(len(calls), 5)
        self.assertFalse(jobs.recent)

    async def test_confirmed_misses_finish_while_submissions_are_still_in_flight(self):
        posts = []
        both_started = asyncio.Event()
        release = asyncio.Event()
        async def handler(req):
            is_vt = req.url.host == "www.virustotal.com"
            if req.method == "GET":
                return httpx.Response(404, json=MISSING) if is_vt else httpx.Response(200, json={"results": [], "total": 0})
            if is_vt:
                self.assertEqual(req.url.path, "/api/v3/urls")
                self.assertEqual(parse_qs(req.content.decode()), {"url": [URL]})
            else:
                self.assertEqual(req.url.path, "/api/v1/scan/")
                self.assertEqual(json.loads(req.content), {"url": URL, "visibility": "private"})
            posts.append(req.url.host)
            if len(posts) == 2:
                both_started.set()
            await release.wait()
            return httpx.Response(200, json={"data": {"type": "analysis", "id": "receipt"}} if is_vt else {"uuid": SCAN_ID})
        origin = "http://localhost"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url=origin,
                                     headers={"Origin": origin, "Content-Type": "text/plain"}) as browser:
            with (self.transport(handler), patch.object(rep, "VT_KEY", "vt"), patch.object(rep, "URLSCAN_KEY", "us"),
                  patch.object(app.openrouter, "API_KEY", "")):
                for headers in ({}, {"Accept": "application/x-ndjson"}):
                    response = await asyncio.wait_for(browser.post("/assess", content="See " + URL + "#fragment", headers=headers), 1)
                    final = json.loads(response.text.splitlines()[-1])
                    self.assertEqual(final["verdict"], "Unclear")
                    self.assertEqual(len(final["direct_findings"]), 2)
                    self.assertTrue(all("queued" in row for row in final["direct_findings"]))
                await asyncio.wait_for(both_started.wait(), 1)
                self.assertEqual(len(jobs.active), 2)
                release.set()
                await asyncio.gather(*jobs.active)
        self.assertEqual(len(posts), 2)

    async def test_failures_and_lookup_only_mode_never_submit(self):
        for provider, query in (("VirusTotal", rep.virustotal), ("urlscan.io", rep.urlscan)):
            for code, payload in ((404, {"error": {"code": "Other"}}), (401, {}), (200, {}),
                                  (200, {"results": [], "total": 2}),
                                  (200, {"results": [], "total": 0, "error": "quota"}), (429, {})):
                with self.subTest(provider=provider, code=code), self.transport(lambda _: httpx.Response(code, json=payload)):
                    self.assertIn((await rep.lookup(provider, query, URL))[0], ("unavailable", "unknown"))
        with (patch.object(rep, "VT_SUBMIT", False), patch.object(rep, "URLSCAN_SUBMIT", False),
              self.transport(lambda req: httpx.Response(404, json=MISSING) if req.url.host == "www.virustotal.com"
                             else httpx.Response(200, json={"results": [], "total": 0}))):
            for query in (rep.virustotal, rep.urlscan):
                self.assertEqual((await rep.lookup("test", query, URL))[0], "no_match")
        self.assertFalse(jobs.recent)

    async def test_quota_cooldown_skips_submissions_and_expires_without_blocking_other_sources(self):
        now = 100
        methods = []
        def handler(req):
            methods.append(req.method)
            if len(methods) == 1:
                return httpx.Response(429, headers={"Retry-After": "12"})
            return httpx.Response(200, json={"record": "available"})
        async def read(client, url):
            await rep.read_record(client, "GET", "https://api.example.com/report")
            return "known", "Existing report."
        async def submit(client, url):
            await rep.read_record(client, "POST", "https://api.example.com/scan")
        with self.transport(handler), patch.object(enrichment_http, "monotonic", lambda: now):
            self.assertEqual((await rep.lookup("Provider A", read, URL))[0], "unavailable")
            now = 111
            await jobs.send("Provider A", URL, submit)
            self.assertEqual((await rep.lookup("Provider A", read, URL))[0], "unavailable")
            self.assertEqual(methods, ["GET"])
            self.assertEqual((await rep.lookup("Provider B", read, URL))[0], "known")
            now = 112
            self.assertEqual((await rep.lookup("Provider A", read, URL))[0], "known")
        self.assertEqual(methods, ["GET", "GET", "GET"])

    def test_retry_after_parses_http_dates_and_handles_malformed_or_missing_headers(self):
        with patch.object(enrichment_http, "time", return_value=0):
            self.assertEqual(enrichment_http.retry_delay("Thu, 01 Jan 1970 00:02:00 GMT"), 120)
            for value in (None, "bad date"):
                self.assertEqual(enrichment_http.retry_delay(value), 60)
            self.assertEqual(enrichment_http.retry_delay("99999999"), 86_400)

    async def test_shutdown_cancels_bounded_submissions(self):
        entered = asyncio.Event()
        stopped = asyncio.Event()
        async def hang(client, target):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        for i in range(8):
            self.assertIn("queued", jobs.enqueue("urlscan.io", URL + str(i), hang))
        self.assertIn("busy", jobs.enqueue("urlscan.io", URL + "other", hang))
        await entered.wait()
        await jobs.shutdown()
        self.assertTrue(stopped.is_set())
        self.assertFalse(jobs.active)
        self.assertFalse(jobs.recent)
