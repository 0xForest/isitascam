"""Cloudflare and OpenRouter use simulated transports; no live scans are submitted."""

import asyncio
import base64
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

import openrouter
import reputation
import urlscanner as cf
from assessment import assess


class ScannerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.object(cf, "LIVE_SCREENSHOTS", False))
        self.enterContext(patch.object(reputation, "SITE_AGE_ENABLED", False))
        self.enterContext(patch.object(reputation, "DNS_ENABLED", False))
        self.enterContext(patch.object(reputation, "URLHAUS_KEY", ""))

    def test_sign_in_placeholders_are_available_as_page_evidence(self):
        page = cf.PageText()
        page.feed('<h1>Sign in</h1><input placeholder="Email address" value="private">'
                  '<input type="password" placeholder="Password" value="secret">'
                  '<input type="hidden" placeholder="ignored"><input hidden placeholder="ignored">')
        self.assertEqual(page.words, ["Sign in", "Email address", "Password", "[password field]"])

    async def test_live_capture_uses_one_pair_and_preserves_historical_report_dates(self):
        import app
        root = "https://shop.example.com/"
        url = root + "auth?token=private"
        scan = cf.Scan("site homepage", "2025-01-01", ["Phishing"], True, dom_path="dom/archive", image_path="screenshots/archive.png")
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes(13)).decode()
        live = {"content": "<html><body>Current page</body></html>", "screenshot": png}
        snapshot = {"success": True, "result": live, "meta": {"finalUrl": "https://checkout.example.net/"}}
        client = httpx.AsyncClient
        requests = []
        def provider(request):
            requests.append(request)
            if request.url.path.endswith("/browser-rendering/snapshot"):
                self.assertEqual(json.loads(request.content)["url"], root)
                self.assertEqual(json.loads(request.content)["formats"], ["content", "screenshot"])
                return response
            if "/dom/" in request.url.path:
                return httpx.Response(200, text="<body>Archived page</body>")
            return httpx.Response(200, content=base64.b64decode(png))

        with (patch.object(cf, "LIVE_SCREENSHOTS", True), patch.object(cf, "SCREENSHOTS", True),
              patch.object(cf, "ENABLED", True), patch.object(cf, "lookup", new_callable=AsyncMock) as lookup,
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw))):
            for response, scope, expected_calls, fresh in [
                (httpx.Response(200, json=snapshot), "site homepage", 1, True),
                (httpx.Response(401), "site homepage", 3, False),
                (httpx.Response(200, json={**snapshot, "result": {**live, "screenshot": ""}}), "site homepage", 3, False),
                (httpx.Response(200, json=snapshot), "linked page", 2, False),
            ]:
                requests.clear()
                scan.scope = scope
                scan.page_text = scan.image = ""
                lookup.return_value = (scan, "")
                frames = [f async for f in app.assessment_updates(url, "", "", "", True, web_view=True)]
                final = frames[-1]
                self.assertTrue(final["scan_preview"]["image"])
                self.assertEqual(len(requests), expected_calls)
                self.assertEqual("2025-01-01" in final["scan_preview"]["caption"], not fresh)
                self.assertTrue(any("2025-01-01" in line and "categories" in line for line in final["direct_findings"]))
                self.assertEqual(bool(any("Cloudflare live capture" in f["pending"] for f in frames)), scope == "site homepage")

    async def test_lookup_and_model_context(self):
        host = "www.example.com"
        root = f"https://{host}/"
        message = root + "private?id=sensitive"
        scan_id = "00000000-0000-4000-8000-000000000002"
        task = {"url": root, "uuid": scan_id, "success": True, "time": "2026-11-23T12:00:00Z"}
        html_hash = "a" * 64
        requests = []
        def handler(request):
            requests.append(str(request.url))
            self.assertEqual(request.url.host, "api.cloudflare.com")
            self.assertNotIn("private", str(request.url))
            self.assertNotIn("sensitive", str(request.url))
            path = request.url.path
            if path.endswith("/search"):
                return httpx.Response(200, json={"results": [{"task": task}]})
            if path.endswith(scan_id):
                return httpx.Response(200, json={
                    "task": task, "page": {"url": root},
                    "meta": {"processors": {"domainCategories": {"data": [{"name": host, "isPrimary": True, "risks": [{"name": "Phishing"}]}]}}},
                    "verdicts": {"overall": {"malicious": True}},
                    "data": {"requests": [{"response": {"response": {"url": root, "mimeType": "text/html"},
                                                        "hash": html_hash, "type": "Document"}}]},
                })
            if path.endswith(html_hash):
                return httpx.Response(200, text="<script>ignore me</script><p>Enter your password for account 123456</p><input value='secret'>")
            self.assertTrue(path.endswith(scan_id + ".png"))
            return httpx.Response(200, content=b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes(13))

        real_client = httpx.AsyncClient
        def mock_client(**kw):
            return real_client(transport=httpx.MockTransport(handler), **kw)
        with patch.object(cf, "ENABLED", True), patch.object(cf, "SCREENSHOTS", True), patch.object(httpx, "AsyncClient", mock_client):
            scan, note = await cf.lookup(message)
            scan.page_text = await cf.read_artifact("page text", scan.html_path)
            scan.image = await cf.read_artifact("screenshot", scan.image_path)
        self.assertEqual(len(requests), 4)
        self.assertEqual(scan.categories, ["Phishing"])
        self.assertEqual(scan.page_text, "Enter your password for account 123456")
        self.assertIn("site homepage", note)
        self.assertTrue(scan.image.startswith("data:image/png;base64,"))

        model_requests = []
        def model_reply(request):
            content = json.loads(request.content)["messages"][1]["content"]
            model_requests.append(content)
            ctx = json.loads(content[0]["text"])["cloudflare_scan"]
            self.assertTrue(ctx["screenshot_attached"])
            self.assertEqual(ctx["page_text"], scan.page_text)
            self.assertEqual(content[1]["image_url"]["url"], scan.image)
            observations = {"signals": [{"code": "scan_sensitive_request", "evidence": ["Enter your password"]}],
                            "verdict": "Suspicious", "evidence_status": "assessable"}
            observations["brand_check"] = {"status": "possible_impersonation", "name": "Invented", "cue": "logo"}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(observations)}}]})

        with patch.object(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(model_reply), **kw)):
            result = await openrouter.analyze(message, api_key="test", model="test/model", scan=scan)
        self.assertEqual(len(model_requests), 1)
        self.assertIn("brand_check", result)
        assessment = assess(message, result, scan, with_context=True)
        self.assertEqual(assessment["verdict"], "Suspicious")
        self.assertIn("Captured page text", assessment["reasons"][0])
        with self.assertRaises(ValueError):
            openrouter.validate(json.dumps({"signals": [{"code": "credentials_requested", "evidence": [scan.page_text]}],
                                            "verdict": "Suspicious", "evidence_status": "assessable"}), message, scan)

    async def test_redirected_homepage_report_reaches_web_and_model(self):
        import app
        url = "https://store.example.com/"
        landed = "https://payments.example.net/login"
        scan_id = "00000000-0000-4000-8000-000000000003"
        other_id = "00000000-0000-4000-8000-000000000004"
        task = {"url": url.rstrip("/"), "uuid": scan_id, "success": True, "time": "2026-01-02T01:00:00Z",
                "options": {"screenshotsResolutions": ["mobile"]}, "visibility": "Public"}
        report = {"task": task, "page": {"url": landed, "title": "Example payments"},
                  "verdicts": {"overall": {"malicious": True, "categories": None, "tags": ["Credential collection"]}},
                  "meta": {"processors": {
                      "phishing": {"data": ["Example impersonation"]}, "phishing_v2": None,
                      "urlCategories": {"data": [{"name": landed, "risks": [{"name": "Phishing"}]},
                                                 {"name": "tracker.example.org", "risks": [{"name": "Unrelated"}]}]}}}}
        png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes(1_550_000)
        image = "data:image/png;base64," + base64.b64encode(png).decode()
        requests = []
        def provider(request):
            if request.url.host == "api.cloudflare.com":
                path = request.url.path
                if path.endswith("/search"):
                    query = request.url.params["q"]
                    self.assertIn(f'task.url:"{url}"', query)
                    self.assertIn(f'task.url:"{url.rstrip("/")}"', query)
                    self.assertNotIn("date:", query)
                    return httpx.Response(200, json={"results": [
                        {"task": {**task, "url": landed}}, {"task": {**task, "uuid": other_id}}, {"task": task}]})
                if path.endswith("/result/" + other_id):
                    return httpx.Response(200, json={**report, "task": {**task, "url": landed, "uuid": other_id}})
                if path.endswith("/result/" + scan_id):
                    return httpx.Response(200, json=report)
                if path.endswith(f"/dom/{scan_id}"):
                    return httpx.Response(200, text="<body>Example payments password form</body>")
                self.assertTrue(path.endswith(f"/screenshots/{scan_id}.png"))
                self.assertEqual(request.url.params["resolution"], "mobile")
                return httpx.Response(200, content=png)
            self.assertEqual(request.url.host, "openrouter.ai")
            content = json.loads(request.content)["messages"][1]["content"]
            payload = json.loads(content[0]["text"])
            requests.append(payload)
            self.assertEqual(content[1]["image_url"]["url"], image)
            self.assertEqual(payload["input_type"], "url")
            self.assertEqual(payload["cloudflare_scan"]["landing_host"], "payments.example.net")
            self.assertEqual(payload["cloudflare_scan"]["categories"], ["Phishing"])
            self.assertIn("phishing: Example impersonation", payload["cloudflare_scan"]["indicators"])
            self.assertEqual(payload["source_reports"][0]["status"], "no_match")
            opinion = {"verdict": "Likely scam", "evidence_status": "assessable", "signals": [
                {"code": "observation", "label": "Credential collection identified", "source": "scan_record",
                 "evidence": ["Verdict tags: Credential collection"]},
                {"code": "observation", "label": "Branded credential form", "source": "screenshot",
                 "evidence": ["Example payments password form"]}],
                "request_details": {"claimed_sender": "store"}}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(opinion)}}]})

        client = httpx.AsyncClient
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SCREENSHOTS", True),
              patch.object(reputation, "host_providers", return_value={}),
              patch.object(reputation, "url_providers", return_value={"Example list": None}),
              patch.object(reputation, "lookup", AsyncMock(return_value=("no_match", "No previous detection."))),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw))):
            frames = [f async for f in app.assessment_updates(url, "key", "model", "prompt", True, web_view=True)]
        self.assertEqual(len(requests), 1)
        self.assertTrue(any(f.get("scan_preview", {}).get("image") == image for f in frames))
        final = frames[-1]
        self.assertEqual(final["cloudflare_report_id"], scan_id)
        self.assertEqual(final["input_type"], "url")
        self.assertIn("link unopened", final["next_step"])
        self.assertIn("2026-01-02", final["ai_reviews"][0]["title"])
        self.assertEqual(final["verdict"], "Likely scam")
        review, = final["ai_reviews"]
        self.assertEqual(review["request_details"], {})
        self.assertEqual([s["evidence_source"] for s in review["signals"]],
                         ["Cloudflare scan record", "AI reading of screenshot"])

    async def test_exported_public_scan_fields_and_artifact_fallbacks(self):
        # Synthetic fixture matching the Cloudflare report schema.
        url = "https://shop.example.com/"
        scan_id = "00000000-0000-4000-8000-000000000005"
        digest = "a" * 64
        task = {"uuid": scan_id, "url": url, "success": True, "time": "2026-11-25T12:00:00Z",
                "visibility": "public", "domURL": "advertised", "options": {"screenshotsResolutions": ["desktop", "mobile", "tablet"]}}
        risks = ["Newly Seen Domains", "Security Risks", "New Domains", "Security Risks"]
        domain_rows = [{"name": "assets.example.net", "isPrimary": False},
                       {"name": "shop.example.com", "isPrimary": True, "risks": [{"name": x} for x in risks]}]
        report = {"task": task, "page": {"url": url, "title": "EXAMPLE STORE 👑"},
                  "verdicts": {"overall": {"malicious": False, "hasVerdicts": False, "tags": [], "categories": []}},
                  "meta": {"processors": {"domainCategories": {"data": domain_rows}, "phishing": {"data": []},
                                         "urlCategories": {"data": [{"name": url, "risks": [], "content": []}]}}},
                  "data": {"requests": [{"response": {"type": "document", "contentAvailable": True, "hash": digest,
                                                      "response": {"url": url, "mimeType": "text/html"}}}]}}
        requested = []
        def handler(request):
            self.assertEqual(request.url.host, "api.cloudflare.com")
            requested.append(request.url)
            if request.url.path.endswith("/dom/" + scan_id):
                return httpx.Response(400, json={"message": "DOM not available to account."})
            if request.url.path.endswith(digest):
                return httpx.Response(200, text="<main>Example offer</main>")
            if request.url.params.get("resolution") == "mobile":
                return httpx.Response(200, content=b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes(13))
            return httpx.Response(404)
        client = httpx.AsyncClient
        with (patch.object(cf, "SCREENSHOTS", True),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(handler), **kw))):
            scan = cf.read_report(report, scan_id, "linked page")
            self.assertEqual(scan.categories, list(dict.fromkeys(risks)))
            self.assertIsNone(scan.malicious)
            self.assertEqual(scan.indicators, [])
            signal = {"evidence": ["New Domains"], "code": "scan_threat_category"}
            with self.assertRaises(ValueError):
                openrouter.check_signal(signal, url, scan, ())
            openrouter.check_signal({**signal, "code": "observation", "source": "scan_record",
                                     "label": "Limited domain history"}, url, scan, ())
            self.assertEqual(scan.title, "EXAMPLE STORE 👑")
            self.assertEqual(scan.report_id, scan_id)
            self.assertEqual(scan.dom_path, f"dom/{scan_id}")
            self.assertEqual(scan.html_path, f"responses/{digest}")
            self.assertEqual(await cf.read_artifact("page text", scan.dom_path, scan.html_path), "Example offer")
            self.assertTrue((await cf.read_artifact("screenshot", scan.image_path, *scan.image_alternates)).startswith("data:image/png"))
            self.assertEqual([u.params.get("resolution") for u in requested], [None, None, "desktop", "mobile"])

    async def test_italian_store_review_rechecks_ungrounded_message_codes_once(self):
        url = "https://store.example.com/"
        scan = cf.Scan("linked page", "2026-11-25", ["New Domains"], None, page_text=(
            "Gift card Negozio Esempio -60% 60 € 150 € · risparmi 90 € Tre passaggi, nessun checkout sul sito "
            "Concludi su Telegram Il carrello genera il riepilogo e ti porta in chat con il nostro bot: "
            "lì concordi il pagamento e ricevi i codici su Telegram entro massimo 24 ore dal pagamento."
        ), image="data:image/png;base64,fixture")
        initial = {"verdict": "Likely scam", "evidence_status": "assessable", "signals": [
            {"code": "unexpected_payment_requested", "evidence": ["Gift card Negozio Esempio -60%", "60 €  ~150 €~ · risparmi 90 €"]},
            {"code": "unverified_contact_requested", "evidence": ["Concludi su Telegram"]},
            {"code": "pressure_or_threat", "evidence": ["entro massimo 24 ore dal pagamento"]},
            {"code": "secrecy_or_process_bypass", "evidence": ["nessun checkout sul sito", "concludi su Telegram"]}],
            "request_details": {"method": "Telegram chat with bot"}}
        grounded = {**initial, "signals": [
            {"code": "observation", "source": "page_text", "label": "Large discount on gift cards",
             "evidence": ["60 € 150 € · risparmi 90 €"], "english_meaning": "€60 for €150 of value, a saving of €90."},
            {"code": "observation", "source": "page_text", "label": "Private payment before delivery",
             "evidence": ["lì concordi il pagamento e ricevi i codici su Telegram entro massimo 24 ore dal pagamento"],
             "english_meaning": "Payment is arranged there and codes arrive on Telegram within 24 hours after payment."}]}
        real_client = httpx.AsyncClient
        for correction in (grounded, initial):
            requests = []
            def provider(request):
                system, submission = json.loads(request.content)["messages"]
                payload = json.loads(submission["content"][0]["text"])
                self.assertEqual(submission["content"][1]["image_url"]["url"], scan.image)
                self.assertEqual(payload["cloudflare_scan"]["page_text"], scan.page_text)
                self.assertEqual(payload["response_language"], "English")
                self.assertNotIn("pressure_or_threat", payload["allowed_signal_codes"])
                if requests:
                    self.assertIn("Reassess independently", system["content"])
                    self.assertEqual(payload, requests[0])
                requests.append(payload)
                opinion = initial if len(requests) == 1 else correction
                return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(opinion)}}]})
            with patch.object(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(provider), **kw)):
                result = await openrouter.analyze(url, scan=scan, api_key="test", model="demo")
            self.assertEqual(len(requests), 2)
            if correction is initial:
                self.assertIsNone(result)
                continue
            for web in (True, False):
                review, = assess(url, result, scan, web_view=web)["ai_reviews"]
                self.assertEqual(review["verdict"], "Likely scam")
                self.assertFalse(review["request_details"])
                self.assertEqual(review["signals"][1]["evidence_source"], "Captured page text")
                self.assertEqual(review["signals"][1]["english_meaning"], grounded["signals"][1]["english_meaning"])

    def test_translation_cannot_substitute_for_evidence_or_add_chat_contacts(self):
        message = "Envía el código"
        signal = {"code": "verification_code_requested", "evidence": [message], "english_meaning": "Contact https://example.com"}
        reply = {"signals": [signal], "verdict": "Suspicious", "evidence_status": "assessable"}
        validated = openrouter.validate(json.dumps(reply), message)
        self.assertNotIn("english_meaning", assess(message, validated)["ai_reviews"][0]["signals"][0])
        signal["english_meaning"] = {"bad": "shape"}
        validated = openrouter.validate(json.dumps(reply), message)
        self.assertNotIn("english_meaning", validated["signals"][0])
        signal.update(english_meaning=message, evidence=["Send the code"])
        with self.assertRaises(openrouter.UnsupportedFindings):
            openrouter.validate(json.dumps(reply), message)

    def test_custom_findings_require_evidence_from_the_named_source(self):
        url = "https://store.example.com/"
        scan = cf.Scan("linked page", "2026-01-02", [], None, page_text="Email only", image="fixture")
        observation = {"code": "observation", "label": "Visible site name", "source": "input", "evidence": ["store"]}
        reply = {"verdict": "Unclear", "evidence_status": "insufficient", "signals": [
            observation, {**observation, "source": "page_text"}, {**observation, "evidence": ["imaginary"]},
            {**observation, "source": "screenshot"}, {**observation, "label": "Visit https://example.com"}]}
        result = openrouter.validate(json.dumps(reply), url, scan, image_sent=False)
        self.assertEqual(result["signals"], [observation])
        self.assertEqual(result["omitted_signals"], 4)

    def test_routine_url_requires_wording_from_the_exact_captured_page(self):
        url = "https://example.com/help"
        reply = json.dumps({"verdict": "Looks routine", "signals": [], "evidence_status": "assessable",
                            "routine_evidence": "Opening hours"})
        scan = cf.Scan("linked page", "2026-11-25", [], None, page_text="Opening hours and directions")
        reviewed = openrouter.validate(reply, url, scan)
        self.assertIn("captured page wording", assess(url, reviewed, scan)["ai_reviews"][0]["note"])
        scan.scope = "site homepage"
        for context in (scan, None):
            with self.assertRaises(ValueError):
                openrouter.validate(reply, url, context)

    def test_bare_url_review_states_what_could_be_examined(self):
        opinion = {"signals": [], "verdict": "Unclear", "evidence_status": "insufficient"}
        url = "example.com"
        data = assess(url, opinion, reputation_checks=[("no_match", "No prior flags")], with_context=True)
        self.assertEqual(data["input_type"], "url")
        self.assertEqual(data["ai_reviews"][0]["title"], "URL with source reports")
        self.assertIn("no captured page", data["ai_reviews"][0]["note"])
        self.assertEqual(assess("Check https://example.com/", opinion)["input_type"], "message")
        scan = cf.Scan("linked page", "2026-01-02", [], True, image="fixture")
        review, = assess(url, opinion, scan)["ai_reviews"]
        self.assertIn("scan metadata", review["note"])
        self.assertIn("independent source flagged", review["note"])

    async def test_visual_brand_result_is_scoped_to_the_image_and_does_not_set_verdict(self):
        import app
        capture = cf.Scan("site homepage", "2026-11-23", [], None, page_text="Account sign-in", image="data:image/png;base64,fixture")
        brand = {"status": "possible_impersonation", "name": "Example Bank", "cue": "branded_form"}
        sent = []
        def handler(request):
            body = json.loads(request.content)["messages"][1]["content"]
            opinion = {"signals": [], "verdict": "Unclear", "evidence_status": "insufficient"}
            if isinstance(body, list):
                self.assertEqual(body[1]["image_url"]["url"], capture.image)
                opinion["brand_check"] = brand
            sent.append(isinstance(body, list))
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(opinion)}}]})
        client = httpx.AsyncClient
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "lookup", AsyncMock(return_value=(capture, ""))),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(handler), **kw))):
            frames = [f async for f in app.assessment_updates("https://example.com/a", "key", "model", openrouter.PROMPT, True)]
        self.assertEqual(sent, [True])
        self.assertEqual(frames[-1]["brand_check"], {**brand, "date": capture.date, "scope": capture.scope})
        self.assertEqual(frames[-1]["verdict"], "Unclear")
        self.assertFalse(frames[-1]["quick_check"]["phrases"])
        base = {"verdict": "Unclear", "evidence_status": "assessable", "signals": []}
        for value in ({"status": "no_clear_brand", "cue": None, "name": None}, {**brand, "name": "<script>"}, None):
            outcome = openrouter.validate(json.dumps({**base, "brand_check": value}), "message", capture, image_sent=True)
            self.assertEqual(outcome.get("brand_check"), {"status": "no_clear_brand"} if value and not value["name"] else None)
            self.assertEqual(outcome["verdict"], "Unclear")

    async def test_rejected_text_evidence_does_not_discard_brand_visual_finding(self):
        import app
        url = "https://signin.example.com/"
        brand = {"status": "possible_impersonation", "name": "Example Telecom", "cue": "wordmark"}
        scan = cf.Scan("linked page", "2026-11-24", ["Phishing"], True, page_text="EXAMPLE TELECOM SIGN IN SIGN IN",
                       indicators=["Verdict categories: phishing"], image="data:image/png;base64,fixture")
        bad = {"verdict": "Likely scam", "evidence_status": "assessable", "brand_check": brand, "signals": [
            {"code": "scan_threat_category", "evidence": ["Verdict categories: phishing"]},
            {"code": "provider_warning", "evidence": ["Cloudflare\x19s security DNS blocks the hostname."]},
            {"code": "observation", "source": "page_text", "label": "Account credential form",
             "evidence": ["EXAMPLE TELECOM SIGN IN", "Email address Password SIGN IN"]}]}
        good = {**bad, "signals": [{"code": "scan_threat_category", "evidence": ["Phishing"]}]}
        del good["brand_check"]
        client = httpx.AsyncClient
        for retry in (bad, good, None):
            replies = iter((bad, retry))
            def provider(request):
                payload = json.loads(request.content)
                self.assertEqual(payload["messages"][1]["content"][1]["image_url"]["url"], scan.image)
                variants = payload["response_format"]["json_schema"]["schema"]["properties"]["signals"]["items"]["anyOf"]
                sources = {v["properties"]["code"]["enum"][0]: v["properties"]["evidence"]["items"].get("enum")
                           for v in variants}
                self.assertEqual(sources["scan_threat_category"], ["Phishing"])
                self.assertEqual(sources["provider_warning"], ["Cloudflare flagged the linked page as malicious at scan time."])
                raw = next(replies)
                if raw is None:
                    raise httpx.ReadTimeout("provider timeout")
                return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(raw)}}]})

            with (self.subTest(retry=retry), patch.object(cf, "ENABLED", True),
                  patch.object(cf, "lookup", AsyncMock(return_value=(scan, ""))),
                  patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw))):
                frames = [f async for f in app.assessment_updates(url, "key", "model", "prompt", True, web_view=True)]
                final = frames[-1]
                self.assertEqual(final["brand_check"], {**brand, "scope": scan.scope, "date": scan.date})
                self.assertFalse(final["pending"])
                if retry is good:
                    self.assertEqual(final["verdict"], "Likely scam")
                    self.assertEqual(final["ai_reviews"][0]["signals"][0]["evidence"], ["Phishing"])
                else:
                    self.assertFalse(final["ai_reviews"])
                    self.assertEqual(final["verdict"], "Unclear")
                    self.assertTrue(final["can_retry_review"])
                    if retry is None:
                        self.assertEqual(final["review_note"], "The review took too long. You can run the check again.")

    def test_scan_retains_only_signals_grounded_in_the_right_source(self):
        message = "Send a password"
        scan = cf.Scan("site homepage", "2026-11-23", ["Phishing and Fraud"], True, page_text="Enter payment details")
        rows = [
            {"code": "credentials_requested", "evidence": ["not in message"]},
            {"code": "scan_threat_category", "evidence": ["flagged_malicious"]},
            {"code": "scan_threat_category", "evidence": ["Phishing"]},
            {"code": "scan_threat_category", "evidence": ["Phishing and Fraud"]},
            {"code": "scan_sensitive_request", "evidence": ["Enter payment details"]},
        ]
        def validate(signals):
            return openrouter.validate(json.dumps({"signals": signals, "verdict": "Suspicious", "evidence_status": "assessable"}), message, scan)
        checked = validate(rows)
        self.assertEqual(checked["omitted_signals"], 3)
        data = assess(message, checked, scan, with_context=True, web_view=True)
        review, = data["ai_reviews"]
        self.assertIn("site homepage", review["title"])
        self.assertIn(scan.date, review["title"])
        self.assertEqual([s["evidence_source"] for s in review["signals"]], ["Domain category", "Captured page text"])
        self.assertEqual([s["evidence"] for s in review["signals"]], [r["evidence"] for r in rows[-2:]])
        self.assertEqual(review["note"], "")
        self.assertEqual(data["scope_note"], f"Page evidence covers the homepage as captured on {scan.date}.")
        self.assertEqual(len(data["direct_findings"]), 3)
        self.assertIn("Phishing and Fraud", data["direct_findings"][0])
        with self.assertRaises(ValueError):
            validate(rows[:3])

    async def test_miss_and_optional_submission(self):
        reply = AsyncMock(return_value=b'{"results":[]}')
        with patch.object(cf, "ENABLED", True), patch.object(cf, "fetch", reply), patch.object(cf, "SUBMIT", False):
            scan, _ = await cf.lookup("https://example.com/path?token=abc")
            self.assertIsNone(scan)
            reply.assert_awaited_once()
        reply.reset_mock()
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "fetch", reply), patch.object(cf, "SUBMIT", True),
              patch.object(cf.background_scans, "enqueue", return_value="Queued.") as enqueue):
            scan, note = await cf.lookup("https://example.com/path?token=abc")
        self.assertIsNone(scan)
        self.assertIn("Queued", note)
        enqueue.assert_called_once_with("Cloudflare", "https://example.com/", cf.submit_homepage)
        reply.assert_awaited_once()

    async def test_search_error_is_never_an_empty_search(self):
        error = AsyncMock(return_value=b'{"success":false,"errors":[{"message":"over quota"}],"results":[]}')
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "fetch", error), patch.object(cf, "SUBMIT", True),
              patch.object(cf.background_scans, "enqueue") as enqueue):
            scan, note = await cf.lookup("https://example.com")
        self.assertIsNone(scan)
        self.assertIn("unavailable", note)
        enqueue.assert_not_called()

    async def test_one_check_follows_queued_report_then_waits_for_both_artifacts(self):
        import app
        self.addAsyncCleanup(cf.background_scans.shutdown)
        root = "https://www.example.com/"
        scan_id = "00000000-0000-4000-8000-000000000002"
        artifact = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes(13)
        posted = []
        polls = []
        release_html = asyncio.Event()
        image_attempts = []
        model = AsyncMock(return_value={"signals": [], "verdict": "Unclear", "evidence_status": "assessable",
                                       "brand_check": {"status": "no_clear_brand"}})

        async def provider(req):
            self.assertEqual(req.url.host, "api.cloudflare.com")
            self.assertNotIn("secret", str(req.url))
            path = req.url.path
            if req.method == "POST":
                posted.append(json.loads(req.content))
                return httpx.Response(200, json={"uuid": scan_id})
            if path.endswith("/search"):
                return httpx.Response(200, json={"results": []})
            if path.endswith("/result/" + scan_id):
                polls.append(True)
                if len(polls) <= 2:
                    return httpx.Response(404 if len(polls) == 1 else 202)
                if len(polls) == 3:
                    return httpx.Response(200, json={"task": {"status": "Processing", "url": root}})
                return httpx.Response(200, json={"task": {"url": root, "success": True, "time": "2026-11-25T10:00:00Z"}})
            if path.endswith("/dom/" + scan_id):
                await release_html.wait()
                return httpx.Response(200, text="<head><title>Header</title></head><body>Pay in chat</body>")
            self.assertTrue(path.endswith("/screenshots/" + scan_id + ".png"))
            image_attempts.append(True)
            return httpx.Response(404) if len(image_attempts) == 1 else httpx.Response(200, content=artifact)

        client = httpx.AsyncClient
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SCREENSHOTS", True), patch.object(cf, "SUBMIT", True),
              patch.object(cf, "POLL_SECONDS", 0.001), patch.object(openrouter, "analyze", model),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw))):
            frames = []
            async with asyncio.timeout(2):
                async for frame in app.assessment_updates(root + "private?secret=1", "key", "model", "prompt", True, web_view=True):
                    frames.append(frame)
                    if frame.get("scan_preview", {}).get("image"):
                        model.assert_not_awaited()
                        self.assertIn("Cloudflare page text", frame["pending"])
                        release_html.set()
            self.assertTrue(any("Cloudflare scan" in f["pending"] and "automatically" in f["capture_note"] for f in frames))
            self.assertTrue(all(f["pending"] for f in frames[:-1]))
            self.assertFalse(frames[-1]["pending"])
            self.assertEqual(sum("scan_preview" in f for f in frames), 1)
            model.assert_awaited_once()
            scan = model.await_args.kwargs["scan"]
            self.assertEqual(scan.page_text, "Pay in chat")
            self.assertTrue(scan.image.startswith("data:image/png;base64,"))
            self.assertEqual(frames[-1]["brand_check"], {"status": "no_clear_brand", "scope": "site homepage", "date": "2026-11-25"})
        self.assertEqual(posted, [{"url": root, "visibility": "Unlisted", "screenshotsResolutions": ["desktop"]}])
        self.assertEqual(len(polls), 4)

    async def test_finished_reset_produces_no_screenshot_and_only_reviews_submitted_wording(self):
        import app
        self.addAsyncCleanup(cf.background_scans.shutdown)
        root = "https://in.run/"
        link = root + "test"
        scan_id = "00000000-0000-4000-8000-000000000002"
        detail = "net::ERR_CONNECTION_RESET at https://example.com/private-scanner-detail"
        paths = []
        def provider(request):
            paths.append(request.url.path)
            if request.url.path.endswith("/search"):
                return httpx.Response(200, json={"results": []})
            if request.method == "POST":
                self.assertEqual(json.loads(request.content)["url"], root)
                return httpx.Response(200, json={"uuid": scan_id})
            self.assertTrue(request.url.path.endswith("/result/" + scan_id))
            return httpx.Response(200, json={"task": {"url": root, "uuid": scan_id, "status": "finished",
                                  "success": False, "errors": [{"code": 5026, "detail": detail}]}})

        model = AsyncMock(return_value={"verdict": "Suspicious", "evidence_status": "assessable", "signals": [
            {"code": "pressure_or_threat", "evidence": ["payment today"]}]})
        client = httpx.AsyncClient
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SUBMIT", True), patch.object(cf, "SCREENSHOTS", True),
              patch.object(reputation, "host_providers", return_value={"Cloudflare DNS": None}),
              patch.object(reputation, "url_providers", return_value={}),
              patch.object(reputation, "lookup", AsyncMock(return_value=("flagged", "Link warning."))),
              patch.object(openrouter, "analyze", model),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw)),
              self.assertLogs("uvicorn.error", level="INFO") as logs):
            for message in (link, "MUNICIPAL FINES: A speeding violation requires payment today. View details: " + link):
                frames = [f async for f in app.assessment_updates(message, "key", "model", "prompt", True, web_view=True)]
                final = frames[-1]
                self.assertFalse(final["pending"])
                self.assertEqual(final["capture_failure"], "connection_reset")
                self.assertIn("connection closed", final["capture_note"])
                self.assertIn("site homepage", final["capture_note"])
                self.assertEqual(final["ai_capture_note"], "Screenshot not available for this URL.")
                self.assertNotIn("can_retry_capture", final)
                self.assertEqual(final["quick_check"]["flagged_sources"], ["Cloudflare DNS"])
                self.assertNotIn("private-scanner-detail", str(frames))
                self.assertFalse(any("scan_preview" in f for f in frames))
                if message == link:
                    model.assert_not_awaited()
                    self.assertFalse(final["ai_reviews"])
                else:
                    model.assert_awaited_once()
                    self.assertNotIn("scan", model.await_args.kwargs)
                    self.assertEqual(final["ai_reviews"][0]["wording_only"], True)
        self.assertEqual(sum(path.endswith("/scan") for path in paths), 1)
        self.assertEqual(sum(path.endswith("/" + scan_id) for path in paths), 2)
        self.assertIn("reason=connection_reset", str(logs.output))
        self.assertNotIn("private-scanner-detail", str(logs.output))

    async def test_failed_report_checks_target_and_only_exposes_known_errors(self):
        root = "https://example.com/"
        scan_id = "00000000-0000-4000-8000-000000000002"
        task = {"uuid": scan_id, "url": root, "status": "finished", "success": False,
                "errors": [{"detail": "Private upstream error"}]}
        report = json.dumps({"task": task}).encode()
        search = json.dumps({"results": [{"task": task}]}).encode()
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SUBMIT", False),
              patch.object(cf, "fetch", AsyncMock(side_effect=[search, report, report, report]))):
            failed, note = await cf.lookup(root)
            self.assertEqual(failed.reason, "scan_failed")
            self.assertNotIn("upstream", note)
            for expected_id, url in (("other-id", root), (scan_id, root + "other")):
                with self.assertRaisesRegex(ValueError, "target mismatch"):
                    await cf.matching_report(None, expected_id, url, "linked page", cf.logger)

    async def test_retry_after_pending_deadline_reuses_submission(self):
        import app
        self.addAsyncCleanup(cf.background_scans.shutdown)
        root = "https://example.com/"
        scan_id = "00000000-0000-4000-8000-000000000002"
        ready = False
        submissions = 0
        model = AsyncMock(return_value=None)

        def provider(req):
            nonlocal submissions
            if req.method == "POST":
                submissions += 1
                return httpx.Response(200, json={"uuid": scan_id})
            if req.url.path.endswith("/search"):
                return httpx.Response(200, json={"results": []})
            if not ready:
                return httpx.Response(404)
            if req.url.path.endswith("/result/" + scan_id):
                return httpx.Response(200, json={"task": {"url": root, "time": "2026-11-25T10:00:00Z", "success": True}})
            if req.url.path.endswith("/dom/" + scan_id):
                return httpx.Response(200, text="<body>Terms of sale</body>")
            return httpx.Response(200, content=b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes(13))

        client = httpx.AsyncClient
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SUBMIT", True), patch.object(cf, "SCREENSHOTS", True),
              patch.object(cf, "REPORT_WAIT_SECONDS", .1), patch.object(openrouter, "analyze", model),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw))):
            async def check():
                return [f async for f in app.assessment_updates(root, "key", "model", "prompt", True, web_view=True)]
            first = (await check())[-1]
            model.assert_not_awaited()
            self.assertTrue(first["can_retry_capture"])
            self.assertIn("still pending", first["capture_note"])
            ready = True
            second = await check()
            self.assertTrue(any(f.get("scan_preview", {}).get("image") for f in second))
            model.assert_awaited_once()
            self.assertNotIn("can_retry_capture", second[-1])
        self.assertEqual(submissions, 1)

    async def test_missing_either_artifact_withholds_website_review(self):
        import app
        for text, image, missing in [("", "fixture", "the page itself was unavailable"), ("Terms of sale", "", "Screenshot not available for this URL.")]:
            scan = cf.Scan("linked page", "2026-11-25", [], None, page_text=text, image=image)
            with (self.subTest(missing=missing), patch.object(cf, "ENABLED", True), patch.object(cf, "SCREENSHOTS", True),
                  patch.object(cf, "lookup", AsyncMock(return_value=(scan, ""))), patch.object(openrouter, "analyze", AsyncMock()) as model):
                frames = [f async for f in app.assessment_updates("https://example.com/", "key", "model", "prompt", True, web_view=True)]
                self.assertIn(missing, frames[-1]["ai_capture_note"])
                self.assertFalse(frames[-1]["pending"])
                self.assertTrue(frames[-1]["can_retry_capture"])
                model.assert_not_awaited()

    async def test_textless_html_and_screenshot_reach_the_model_together(self):
        import app
        scan = cf.Scan("site homepage", "2026-11-25", [], None, dom_path="dom/report", html_path="responses/page",
                       image="data:image/png;base64,fixture")

        def handle(request):
            if request.url.path.endswith("/dom/report"):
                return httpx.Response(400, json={"message": "DOM not available to account."})
            if request.url.path.endswith("/responses/page"):
                return httpx.Response(200, text="<html><body><div id='app'></div><script>mount()</script></body></html>")
            self.assertEqual(request.url.host, "openrouter.ai")
            content = json.loads(request.content)["messages"][1]["content"]
            context = json.loads(content[0]["text"])["cloudflare_scan"]
            self.assertEqual(context["page_text"], "")
            self.assertEqual(context["scope"], "site homepage")
            self.assertEqual(content[1]["image_url"]["url"], scan.image)
            reply = {"verdict": "Unclear", "signals": [], "evidence_status": "insufficient"}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(reply)}}]})

        client = httpx.AsyncClient
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SCREENSHOTS", True),
              patch.object(cf, "lookup", AsyncMock(return_value=(scan, ""))),
              patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(handle), **kw))):
            frames = [f async for f in app.assessment_updates("https://example.com/auth", "key", "model", "prompt", True)]
        final = frames[-1]
        self.assertEqual(final["ai_reviews"][0]["verdict"], "Unclear")
        self.assertIn("captured site homepage had no readable body text", final["review_note"])
        self.assertNotIn("ai_capture_note", final)

    async def test_image_rejection_does_not_send_a_text_only_website_review(self):
        scan = cf.Scan("linked page", "2026-11-25", [], None, page_text="Terms of sale", image="fixture")
        requests = []
        def provider(req):
            requests.append(json.loads(req.content)["messages"][1]["content"])
            return httpx.Response(415)
        client = httpx.AsyncClient
        with patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw)):
            self.assertIsNone(await openrouter.analyze("https://example.com", scan=scan, api_key="key", model="model"))
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][1]["image_url"]["url"], "fixture")

    async def test_structured_output_fallback_keeps_both_artifacts(self):
        scan = cf.Scan("linked page", "2026-11-25", [], None, page_text="Terms of sale", image="fixture")
        requests = []
        def provider(req):
            body = json.loads(req.content)
            requests.append(body)
            if "response_format" in body:
                schema = body["response_format"]["json_schema"]["schema"]
                self.assertIn("brand_check", schema["required"])
                return httpx.Response(400, json={"error": {"message": "Unsupported response_format"}})
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({
                "verdict": "Unclear", "signals": [], "brand_check": {"status": "no_clear_brand", "name": None, "cue": None},
                "evidence_status": "insufficient"
            })}}]})
        client = httpx.AsyncClient
        with patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw)):
            result = await openrouter.analyze("https://example.com", scan=scan, api_key="key", model="model")
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]["messages"], requests[1]["messages"])
        self.assertTrue(result["image_sent"])
        self.assertEqual(result["brand_check"]["status"], "no_clear_brand")

    async def test_fines_message_recovers_from_invalid_context_response(self):
        import app
        message = "MUNICIPAL FINES: A speeding violation requires payment today. View details: https://in.run/example-fixture"
        scan = cf.Scan("site homepage", "2026-11-26", [], None, page_text="Create a short URL", image="fixture")
        reply = {"verdict": "Suspicious", "evidence_status": "assessable", "signals": [
            {"code": "pressure_or_threat", "evidence": ["requires payment today"], "risk_action": "send_money"}]}
        brand = {"status": "no_clear_brand", "name": None, "cue": None}
        client = httpx.AsyncClient
        for recovered in (True, False):
            requests = []
            def provider(request):
                body = json.loads(request.content)
                content = body["messages"][1]["content"]
                fields = body["response_format"]["json_schema"]["schema"]["properties"]
                requests.append(content)
                if len(requests) == 1:
                    self.assertEqual(json.loads(content[0]["text"])["cloudflare_scan"]["page_text"], scan.page_text)
                    self.assertEqual(content[1]["image_url"]["url"], scan.image)
                    self.assertIn("brand_check", fields)
                    self.assertIn("request_details", fields)
                    raw = json.dumps({**reply, "invalid_field": True, "brand_check": brand})
                else:
                    self.assertEqual(len(requests), 2)
                    wording = json.loads(content)
                    self.assertEqual(wording["message"], message)
                    self.assertEqual(wording["review_stage"], "message")
                    self.assertNotIn("cloudflare_scan", wording)
                    self.assertNotIn("scan_threat_category", wording["allowed_signal_codes"])
                    self.assertNotIn("brand_check", fields)
                    # A quotation from the shortener homepage cannot ground a message-only warning.
                    raw = json.dumps(reply if recovered else {**reply, "signals": [
                        {"code": "pressure_or_threat", "evidence": [scan.page_text]}]})
                    raw = f"```json\n{raw}\n```"
                return httpx.Response(200, json={"choices": [{"message": {"content": raw}}]})

            with (self.subTest(recovered=recovered), patch.object(cf, "ENABLED", True),
                  patch.object(cf, "lookup", AsyncMock(return_value=(scan, ""))),
                  patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(provider), **kw)),
                  self.assertLogs(openrouter.logger, level="INFO") as logs):
                frames = [frame async for frame in app.assessment_updates(message, "key", "model", openrouter.PROMPT, True, web_view=True)]
                final = frames[-1]
                self.assertEqual(len(requests), 2)
                self.assertTrue(final["quick_check"]["shortened"])
                self.assertEqual(final["brand_check"]["status"], "no_clear_brand")
                self.assertIn("detail=invalid_assessment_schema", "\n".join(logs.output))
                if recovered:
                    review, = final["ai_reviews"]
                    self.assertEqual(review["stage"], "message")
                    self.assertTrue(review["wording_only"])
                    self.assertEqual(final["verdict"], "Suspicious")
                    self.assertIn("payment", final["next_step"])
                    self.assertIn("destination remains unverified", final["scope_note"])
                else:
                    self.assertEqual(final["ai_reviews"], [])
                    self.assertIn("shortened link hides its destination", final["review_note"])
                    self.assertIn("detail=no_grounded_signals", "\n".join(logs.output))

    async def test_missing_scan_verdict_remains_unknown(self):
        report = {"task": {"success": True, "time": "2026-11-23T12:00:00Z"}}
        with patch.object(cf, "SCREENSHOTS", False):
            scan = cf.read_report(report, "id", "linked page")
            self.assertIsNone(scan.malicious)
            with self.assertRaises(ValueError):
                cf.read_report({**report, "errors": ["quota"]}, "id", "linked page")

    async def test_background_submission_sends_only_an_unlisted_homepage(self):
        def handler(request):
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.host, "api.cloudflare.com")
            self.assertTrue(request.url.path.endswith("/urlscanner/v2/scan"))
            self.assertEqual(request.headers["Authorization"], "Bearer synthetic")
            self.assertEqual(json.loads(request.content), {"url": "https://example.com/", "visibility": "Unlisted"})
            return httpx.Response(200, json={"uuid": "00000000-0000-4000-8000-000000000002"})
        with patch.object(cf, "TOKEN", "synthetic"):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                await cf.submit_homepage(client, "https://example.com/")

    async def test_both_channel_entry_points_keep_scan_provenance(self):
        import app
        scan = cf.Scan("site homepage", "2026-11-23", ["Phishing"], True, page_text="Sign in", image="fixture")
        origin = "http://localhost"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url=origin) as client:
            with (
                patch.object(app.urlscanner, "ENABLED", True),
                patch.object(app.urlscanner, "lookup", AsyncMock(return_value=(scan, "Cloudflare scanned the site homepage."))),
                patch.object(app.openrouter, "analyze", AsyncMock(return_value=None)) as model,
                patch.object(openrouter, "API_KEY", "fake"),
                patch.object(openrouter, "MODEL", "test/model"),
            ):
                text = "https://example.com/path"
                for channel in ({"X-Assessment-View": "web"}, {"X-Scan-Preview": "1"}):
                    response = await client.post("/assess", content=text, headers={"Origin": origin, "Content-Type": "text/plain", **channel})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["verdict"], "Unclear")
                    self.assertIn("homepage", response.json()["reasons"][0])
                    self.assertIn("homepage", response.json()["limitations"])
                    self.assertEqual(response.json()["scan_preview"]["image"], scan.image)
                self.assertIs(model.await_args.kwargs["scan"], scan)

    async def test_web_preview_is_optional_and_reports_missing_images(self):
        import app
        origin = "http://localhost"
        headers = {"Origin": origin, "Content-Type": "text/plain", "X-Scan-Preview": "1"}
        scan = cf.Scan("site homepage", "2026-11-23", [], False, image="data:image/png;base64,abcd")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url=origin) as browser:
            with (
                patch.object(app.urlscanner, "ENABLED", True),
                patch.object(app.urlscanner, "lookup", AsyncMock(return_value=(scan, "Report available."))),
                patch.object(app.openrouter, "analyze", AsyncMock(return_value=None)),
            ):
                response = await browser.post("/assess", content="https://example.com", headers=headers)
                preview = response.json()["scan_preview"]
                self.assertEqual(preview["image"], scan.image)
                self.assertIn("site homepage on 2026-11-23", preview["caption"])
                self.assertIn("img-src data:", response.headers["content-security-policy"])
                self.assertEqual(response.headers["cache-control"], "no-store")
                scan.image = ""
                for enabled, wording in [(True, "unavailable"), (False, "disabled")]:
                    with patch.object(cf, "SCREENSHOTS", enabled):
                        preview = (await browser.post("/assess", content="https://example.com", headers=headers)).json()["scan_preview"]
                        self.assertIsNone(preview["image"])
                        self.assertIn(wording, preview["caption"])

    async def test_reserved_example_skips_cloudflare_and_explains_why(self):
        with patch.object(cf, "ENABLED", True), patch.object(cf, "fetch", new_callable=AsyncMock) as fetch:
            with self.assertLogs(cf.logger, level="INFO") as logs:
                scan, note = await cf.lookup("Visit https://parcel-redelivery.example/confirm.")
            self.assertIsNone(scan)
            self.assertIn("Cloudflare lookup skipped", note)
            self.assertIn("reason=no_eligible_hostname", logs.output[0])
            self.assertNotIn("parcel-redelivery", logs.output[0])
            fetch.assert_not_awaited()
        self.assertIsNotNone(cf.target_urls("https://example.com/"))

    def test_standalone_domain_checks_the_homepage_without_sending_the_path(self):
        self.assertEqual(cf.target_urls("  x.co/123?token=abc  "),
                         ("x.co", "https://x.co/123?token=abc", "https://x.co/"))
        self.assertIsNone(cf.target_urls("mailbox@example.com"))
        self.assertIsNone(cf.target_urls("Notes about attachment.pdf"))
        self.assertIsNone(cf.target_urls("host.internal/private"))

    def test_ineligible_links(self):
        for message in ["no link", "http://localhost/", "http://10.0.0.1/",
                        "https://user:pass@example.com/x", "http://host.internal/"]:
            self.assertIsNone(cf.target_urls(message))

    async def test_capture_streams_before_ai_and_survives_a_failed_review(self):
        import app
        message = "Go to https://example.com/login"
        scan = cf.Scan("linked page", "2026-11-23", ["Phishing"], True, page_text="Sign in", image="data:image/png;base64,test")
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "lookup", AsyncMock(return_value=(scan, "Report available."))),
              patch.object(openrouter, "analyze", AsyncMock(return_value=None)) as model):
            updates = app.assessment_updates(message, "key", "model", "prompt", True, web_view=True)
            self.assertEqual((await anext(updates))["pending"], ["Cloudflare lookup"])
            snapshot = await anext(updates)
            self.assertEqual(snapshot["pending"], ["Context analysis"])
            self.assertEqual(snapshot["scan_preview"]["image"], scan.image)
            self.assertEqual(snapshot["brand_check"]["status"], "checking")
            final = await anext(updates)
            self.assertEqual(final["pending"], [])
            self.assertEqual(final["brand_check"]["status"], "unavailable")
            self.assertIn("did not complete", final["limitations"])
            self.assertEqual(final["direct_findings"], snapshot["direct_findings"])
            self.assertNotIn("scan_preview", final)
            model.assert_awaited_once()
            await updates.aclose()

    async def test_report_categories_then_image_then_page_text_before_final_review(self):
        import app
        scan = cf.Scan("linked page", "2026-11-25", ["Shopping"], False,
                       image_path="screenshots/example.png", html_path="responses/example")
        gates = {kind: asyncio.Event() for kind in ("screenshot", "page text")}
        async def download(kind, path, **kwargs):
            await gates[kind].wait()
            return "data:image/png;base64,sample" if kind == "screenshot" else "Order history"
        async def analyze(message, *, scan, **kwargs):
            self.assertTrue(scan.image)
            self.assertEqual(scan.page_text, "Order history")
            return {"verdict": "Unclear", "signals": [], "evidence_status": "assessable"}
        with (patch.object(cf, "ENABLED", True), patch.object(cf, "SCREENSHOTS", True),
              patch.object(cf, "lookup", AsyncMock(return_value=(scan, "Dated report."))),
              patch.object(cf, "read_artifact", download), patch.object(openrouter, "analyze", analyze)):
            updates = app.assessment_updates("https://example.com", "key", "model", "prompt", True)
            await anext(updates)
            report = await anext(updates)
            self.assertEqual(set(report["pending"]), {"Cloudflare page text", "Cloudflare screenshot"})
            self.assertIn("Shopping", report["direct_findings"][0])
            self.assertFalse(report["quick_check"]["flagged_sources"])
            self.assertNotIn("scan_preview", report)
            gates["screenshot"].set()
            image = await anext(updates)
            self.assertTrue(image["scan_preview"]["image"])
            self.assertEqual(image["brand_check"]["status"], "waiting")
            gates["page text"].set()
            reviewing = await anext(updates)
            self.assertEqual(reviewing["pending"], ["Context analysis"])
            self.assertIn("readable page text", reviewing["direct_findings"][1])
            self.assertNotIn("scan_preview", reviewing)
            self.assertEqual((await anext(updates))["pending"], [])
            await updates.aclose()

    async def test_closing_updates_cancels_pending_providers(self):
        import app
        started = []
        stopped = []
        async def hang(*args, **kwargs):
            started.append(True)
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append(True)
        with patch.object(cf, "ENABLED", True), patch.object(cf, "lookup", hang), patch.object(openrouter, "analyze", hang):
            updates = app.assessment_updates("https://example.com", "key", "model", "prompt", False)
            await anext(updates)
            await asyncio.sleep(0)
            self.assertEqual(len(started), 1)
            with self.assertLogs("uvicorn.error", level="INFO") as logs:
                await updates.aclose()
            self.assertEqual(stopped, started)
            self.assertRegex(logs.records[-1].getMessage(),
                             r"status=interrupted radar_ms=- spamhaus_ms=- html_ms=- screenshot_ms=- google_ms=- virustotal_ms=- urlscan_ms=- dns_ms=- urlhaus_ms=- cloudflare_ms=\d+ cloudflare_wait_ms=- cloudflare_live_ms=- ai_message_ms=- ai_scan_ms=- total_ms=\d+$")

    async def test_timing_summary_separates_scanner_and_ai_review(self):
        import app
        now = 100
        gates = {stage: asyncio.Event() for stage in ("cloudflare", "scan")}
        scan = cf.Scan("linked page", "2026-11-23", ["Phishing"], True, page_text="Sign in", image="fixture")

        async def lookup(message, **kwargs):
            await gates["cloudflare"].wait()
            return scan, ""

        async def analyze(message, **settings):
            self.assertIs(settings["scan"], scan)
            await gates["scan"].wait()
            return None  # Unavailable AI calls still consume time.

        with (patch.object(app, "monotonic", lambda: now), patch.object(cf, "ENABLED", True),
              patch.object(cf, "lookup", lookup), patch.object(openrouter, "analyze", analyze),
              self.assertLogs("uvicorn.error", level="INFO") as logs):
            updates = app.assessment_updates("https://example.com/private", "fake-key", "model", "prompt", True)
            await anext(updates)
            await asyncio.sleep(0)
            for stage, now in [("cloudflare", 103), ("scan", 105)]:
                gates[stage].set()
                await anext(updates)
                await asyncio.sleep(0)
            now = 111  # Time spent delivering the final snapshot is outside the check.
            await updates.aclose()
            async for _ in app.assessment_updates("private text", "", "", "", False):
                pass
        self.assertEqual([r.getMessage() for r in logs.records], [
            "Assessment timing channel=web ip=unknown status=finished radar_ms=- spamhaus_ms=- html_ms=- screenshot_ms=- google_ms=- virustotal_ms=- urlscan_ms=- dns_ms=- urlhaus_ms=- cloudflare_ms=3000 cloudflare_wait_ms=- cloudflare_live_ms=- ai_message_ms=- ai_scan_ms=2000 total_ms=5000",
            "Assessment timing channel=web ip=unknown status=finished radar_ms=- spamhaus_ms=- html_ms=- screenshot_ms=- google_ms=- virustotal_ms=- urlscan_ms=- dns_ms=- urlhaus_ms=- cloudflare_ms=- cloudflare_wait_ms=- cloudflare_live_ms=- ai_message_ms=- ai_scan_ms=- total_ms=0",
        ])
