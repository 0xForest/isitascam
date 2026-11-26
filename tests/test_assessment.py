"""Synthetic checks for the model contract, verdicts, and fallback."""

import json
import unittest
from unittest.mock import patch

import httpx

import openrouter
import reputation
from assessment import assess


class AssessmentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.object(reputation, "SITE_AGE_ENABLED", False))

    def test_payment_report_changes_guidance_independently_of_verdict(self):
        from guidance import PAID_NEXT_STEP
        for verdict in ("Looks routine", "Unclear", "Suspicious", "Likely scam"):
            opinion = {"verdict": verdict, "evidence_status": "assessable", "signals": []}
            result = assess("I already paid the delivery fee. They now want a second payment.", opinion)
            self.assertTrue(result["already_paid"])
            self.assertEqual(result["next_step"], PAID_NEXT_STEP)
            self.assertEqual(result["verdict"], verdict)
        for message in ("Already paid.", "I’ve just paid them", "I've already sent them R500.",
                        "I made the payment. What can I do?", 'The text said “pay now”, so I wired the money.'):
            with self.subTest(message=message):
                self.assertTrue(assess(message, None)["already_paid"])
        for message in ("I haven't paid yet.", "I will pay tomorrow.", "They say I already paid.",
                        "If I paid, could I get a refund?", "Have I paid?", "I paid attention.",
                        'The sender wrote: “I already paid.”', "Payment successful", "Please pay now.",
                        "https://example.com/?note=already-paid", "My sister already paid."):
            with self.subTest(message=message):
                result = assess(message, None)
                self.assertFalse(result["already_paid"])
                self.assertNotEqual(result["next_step"], PAID_NEXT_STEP)

    async def test_web_assessments_exclude_developer_logs(self):
        import app
        origin = "http://localhost"
        headers = {"Origin": origin, "Content-Type": "text/plain", "X-Assessment-View": "web"}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url=origin) as browser:
            self.assertNotIn("Developer log for this check", (await browser.get("/")).text)
            with patch.object(openrouter, "API_KEY", ""):
                for accept in ("application/json", "application/x-ndjson"):
                    response = await browser.post("/assess", content="hello", headers={**headers, "Accept": accept})
                    self.assertEqual(response.status_code, 200)
                    for frame in response.text.splitlines():
                        self.assertNotIn("dev_logs", json.loads(frame))

    async def test_source_is_logged_once_per_check_from_the_transport(self):
        import app
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

        origin = "http://localhost"
        server = ProxyHeadersMiddleware(app.app, trusted_hosts=["192.0.2.10"])
        headers = {"Origin": origin, "Content-Type": "text/plain", "X-Forwarded-For": "2001:db8::9",
                   "X-WhatsApp-Number": "15550100123"}
        cases = [
            ("192.0.2.11", {}, "channel=web ip=192.0.2.11"),
            ("192.0.2.10", {}, "channel=web ip=2001:db8::9"),
            ("127.0.0.1", {"X-Bridge-Token": "wrong"}, "channel=web ip=127.0.0.1"),
            ("127.0.0.1", {"X-Bridge-Token": "test-token", "Accept": "application/x-ndjson"},
             "channel=whatsapp phone=+15550100123"),
            ("127.0.0.1", {"X-Bridge-Token": "test-token", "X-WhatsApp-Number": "123456789@lid"},
             "channel=whatsapp phone=unknown"),
        ]
        for peer, extra, expected in cases:
            transport = httpx.ASGITransport(app=server, client=(peer, 8080))
            with (self.subTest(expected=expected), patch.object(app, "BRIDGE_TOKEN", "test-token"),
                  patch.object(openrouter, "API_KEY", ""), self.assertLogs("uvicorn.error", level="INFO") as logs):
                async with httpx.AsyncClient(transport=transport, base_url=origin) as client:
                    result = await client.post("/assess", content="Private message", headers={**headers, **extra})
                self.assertEqual(result.status_code, 200)
                self.assertNotIn(expected, result.text)
                self.assertEqual(len(logs.records), 1)
                line = logs.records[0].getMessage()
                self.assertIn(expected + " status=finished", line)
                self.assertNotIn("test-token", line)
                self.assertNotIn("Private message", line)
                if "phone=+" not in expected:
                    self.assertNotIn("15550100123", line)

    async def test_contextual_assessments(self):
        cases = [
            ("Reply with your one-time code.", "assessable",
             [{"code": "verification_code_requested", "evidence": ["Reply with your one-time code."]}], "Suspicious"),
            ("Never reply with your one-time code.", "assessable", [], "Unclear"),
            ('A phishing example says "Reply with your one-time code."', "assessable", [], "Unclear"),
            ("Action needed today", "insufficient", [], "Unclear"),
            ("Enter your password. Keep this request secret.", "assessable", [
                {"code": "credentials_requested", "evidence": ["Enter your password."]},
                {"code": "secrecy_or_process_bypass", "evidence": ["Keep this request secret."]},
            ], "Likely scam"),
        ]
        for message, status, signals, verdict in cases:
            with self.subTest(message=message):
                observations = openrouter.validate(json.dumps({
                    "verdict": verdict, "signals": signals, "evidence_status": status,
                }), message)
                self.assertEqual(assess(message, observations)["verdict"], verdict)

    def test_all_message_signals_visible_with_channel_appropriate_evidence(self):
        message = "Pay an extra fee. Enter card details within two hours at https://tenant-12345.example/login"
        signals = [
            {"code": "unexpected_payment_requested", "evidence": ["Pay an extra fee"]},
            {"code": "payment_details_requested", "evidence": ["Enter card details"]},
            {"code": "pressure_or_threat", "evidence": ["within two hours"]},
            {"code": "misleading_link", "evidence": ["tenant-12345.example"]},
        ]
        checked = openrouter.validate(json.dumps({"verdict": "Likely scam", "signals": signals, "evidence_status": "assessable"}), message)
        web = assess(message, checked, web_view=True)
        self.assertEqual(web["verdict"], "Likely scam")
        self.assertEqual(len(web["reasons"]), 3)
        self.assertEqual(web["direct_findings"], [])
        review, = web["ai_reviews"]
        self.assertEqual(review["stage"], "message")
        self.assertEqual([(s["code"], s["evidence"]) for s in review["signals"]],
                         [(s["code"], s["evidence"]) for s in signals])
        chat = assess(message, checked)["ai_reviews"][0]
        self.assertEqual(chat["signals"][3]["code"], "misleading_link")
        self.assertEqual(chat["signals"][3]["evidence"], [])
        self.assertEqual(chat["signals"][0]["evidence"], ["Pay an extra fee"])

    def test_empty_review_is_distinct_from_unavailable(self):
        self.assertEqual(assess("Hello")["ai_reviews"], [])
        review, = assess("Hello", {"verdict": "Unclear", "signals": [], "evidence_status": "insufficient"})["ai_reviews"]
        self.assertEqual(review["signals"], [])
        self.assertIn("too little context", review["note"])
        self.assertIn("no supported warning signs", review["note"])

    def test_display_uses_verified_quotes_once_and_keeps_contact_details_out(self):
        message = "Pay a $1.99 fee. Act within 2 hours. Send it to example.org or call 555-123-4567."
        signals = [
            {"code": "unexpected_payment_requested", "evidence": ["Pay a $1.99 fee"]},
            {"code": "pressure_or_threat", "evidence": ["Pay a $1.99 fee", "within 2 hours"]},
            {"code": "unverified_contact_requested", "evidence": ["Send it to example.org"]},
        ]
        def check(items):
            data = openrouter.validate(json.dumps({"verdict": "Suspicious", "signals": items, "evidence_status": "assessable"}), message)
            return assess(message, data)["reasons"]

        reasons = check(signals)
        self.assertIn("“Pay a $1.99 fee”", reasons[0])
        self.assertIn("“within 2 hours”", reasons[1])
        self.assertNotIn("Pay a $1.99 fee", reasons[1])
        for span in ("Send it to example.org", "or call 555-123-4567"):
            [reason] = check([{"code": "unverified_contact_requested", "evidence": [span]}])
            self.assertEqual(reason, openrouter.SIGNALS["unverified_contact_requested"])
        self.assertNotIn("example.org", " ".join(reasons))
        self.assertFalse(any("“" in item for item in assess(message)["reasons"]))

    def test_remote_support_invitation_retains_warning_without_echoing_session_code(self):
        link = "https://secure.logmeinrescue.com/R?Code=000000"
        for bare in (False, True):
            message = link if bare else "Support contact\n18:16\n" + link
            access = {"code": "observation", "source": "input", "label": "Remote support invitation"} if bare else {
                "code": "software_or_access_requested"}
            reply = {"verdict": "Suspicious", "evidence_status": "assessable",
                     "signals": [{**access, "evidence": [link], "risk_action": "install_or_grant_access"}],
                     "request_details": {"method": link, "claimed_sender": "Support contact"}}
            opinion = openrouter.validate(json.dumps(reply), message)
            for web in (False, True):
                with self.subTest(bare=bare, web=web):
                    result = assess(message, opinion, web_view=web)
                    review, = result["ai_reviews"]
                    finding, = review["signals"]
                    self.assertEqual(result["verdict"], "Suspicious")
                    self.assertEqual(finding["code"], access["code"])
                    self.assertNotIn("000000", json.dumps(result))
                    if not bare:
                        self.assertEqual(review["request_details"]["claimed_sender"], "Support contact")
                    self.assertIn("decline requests for remote access", result["next_step"])
                    self.assertTrue(any("disconnect the device" in step for step in result["recovery_steps"]))

    async def test_command_recovery_available_before_review_and_for_a_clickfix_finding(self):
        import app
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="http://localhost") as client:
            page = (await client.get("/")).text
        self.assertIn('id="recovery-command"', page)
        self.assertIn("Disconnect that device from the internet now.", page)
        message = "Run this command to verify you are human."
        opinion = openrouter.validate(json.dumps({
            "verdict": "Suspicious", "evidence_status": "assessable",
            "signals": [{"code": "software_or_access_requested", "evidence": [message], "risk_action": "run_command"}],
        }), message)
        result = assess(message, opinion, web_view=True)
        self.assertEqual(result["verdict"], "Suspicious")
        self.assertIn("run a command", result["ai_reviews"][0]["signals"][0]["description"])
        self.assertIn("I ran a command from a message or website", result["next_step"])
        self.assertIn("sign out all other sessions", " ".join(result["recovery_steps"]))
        self.assertNotIn("COMMAND", [option["reply"] for option in result["recovery_options"]])

    async def test_verbatim_request_and_invalid_response_fallback(self):
        message = "Email alice@example.org or visit https://trusted.example@signin.example/private?code=246810#details.  "

        def reply(request):
            payload = json.loads(request.content)
            sent = json.loads(payload["messages"][1]["content"])["message"]
            self.assertEqual(sent, message)
            user_input = json.loads(payload["messages"][1]["content"])
            self.assertEqual(user_input["review_stage"], "message")
            self.assertEqual(user_input["visible_hostnames"], ["signin.example"])
            self.assertEqual(payload["provider"], {"data_collection": "deny", "zdr": True})
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({
                "signals": [{"code": "credentials_requested", "evidence": ["invented quote"]}],
                "verdict": "Suspicious", "evidence_status": "assessable",
            })}}]})

        client = httpx.AsyncClient(transport=httpx.MockTransport(reply))
        with patch.object(openrouter.httpx, "AsyncClient", return_value=client):
            observations = await openrouter.analyze(message, api_key="test", model="demo")
        self.assertIsNone(observations)
        result = assess(message, observations)
        self.assertEqual(result["verdict"], "Unclear")
        self.assertEqual(result["direct_findings"], [])
        self.assertIn("Limited check", result["limitations"])

    async def test_ai_outcomes_are_logged_without_submission_details(self):
        message = "Private submission 124680"
        content = json.dumps({"verdict": "Unclear", "signals": [], "evidence_status": "assessable"})
        cases = [
            (httpx.Response(200, json={"choices": [{"message": {"content": content}}]}), "ai_completed"),
            (httpx.Response(401, text=message), "provider_http_error status=401"),
            (httpx.Response(200, text=message), "invalid_model_response"),
            (httpx.Response(200, json={"choices": [{"finish_reason": "length", "message": {"content": "{"}}]}), "detail=output_truncated"),
            (httpx.Response(200, json={"choices": [{"message": {"content": None}}]}), "detail=missing_content"),
            (httpx.ReadTimeout(message), "provider_timeout"),
            (httpx.ConnectError(message), "provider_connection_error"),
        ]
        for response, expected in cases:
            with self.subTest(outcome=expected):
                def reply(request):
                    if isinstance(response, Exception):
                        raise response
                    return response

                client = httpx.AsyncClient(transport=httpx.MockTransport(reply))
                with patch.object(openrouter.httpx, "AsyncClient", return_value=client):
                    with self.assertLogs(openrouter.logger, level="INFO") as logs:
                        result = await openrouter.analyze(message, api_key="test", model="demo")
                self.assertEqual(result is not None, expected == "ai_completed")
                self.assertIn(expected, logs.output[-1])
                self.assertNotIn(message, " ".join(logs.output))

    async def test_404_routing_hints_preserve_privacy(self):
        for body, hint in [
            ({"error": {"message": "No endpoints found matching your data policy. private-value"}}, "privacy_policy"),
            ({"error": {"message": "No endpoints found for private-value"}}, "no_matching_endpoint"),
            ({"error": {"message": "Unknown model private-value"}}, "model_not_found"),
            ({"error": "private-value"}, "unspecified"),
            (None, "unspecified"),
        ]:
            with self.subTest(hint=hint):
                def reply(request):
                    payload = json.loads(request.content)
                    self.assertEqual(payload["provider"], {"data_collection": "deny", "zdr": True})
                    return httpx.Response(404, json=body) if body else httpx.Response(404, text="private-value")

                client = httpx.AsyncClient(transport=httpx.MockTransport(reply))
                with patch.object(openrouter.httpx, "AsyncClient", return_value=client), self.assertLogs(openrouter.logger) as logs:
                    result = await openrouter.analyze("private-value", api_key="private-key", model="test/model")
                self.assertIsNone(result)
                line = logs.records[-1].getMessage()
                self.assertIn(f"status=404 model=test/model routing_hint={hint}", line)
                self.assertNotIn("private-value", line)
                self.assertNotIn("private-key", line)

    async def test_optional_response_log(self):
        valid = json.dumps({"verdict": "Unclear", "signals": [], "evidence_status": "assessable"})
        for enabled in (False, True):
            for content in (valid, "malformed\nreply\x1b"):
                with self.subTest(enabled=enabled, content=content):
                    response = {"choices": [{"message": {"content": content}}]}
                    client = httpx.AsyncClient(transport=httpx.MockTransport(
                        lambda request: httpx.Response(200, json=response)
                    ))
                    with (
                        patch.object(openrouter, "LOG_AI_RESPONSES", enabled),
                        patch.object(openrouter.httpx, "AsyncClient", return_value=client),
                        self.assertLogs(openrouter.logger, level="INFO") as logs,
                    ):
                        result = await openrouter.analyze("Synthetic input", api_key="test", model="demo")
                    replies = [r.getMessage() for r in logs.records if r.getMessage().startswith("AI response content=")]
                    attempts = 1 if content == valid else 2
                    self.assertEqual(replies, ["AI response content=" + json.dumps(content)] * attempts if enabled else [])
                    self.assertEqual(result is not None, content == valid)

    def test_request_details_include_only_grounded_fields(self):
        message = "Example Logistics: URGENT!!! Pay R49,99 for redelivery."
        reply = {"verdict": "Suspicious", "evidence_status": "assessable",
                 "signals": [{"code": "unexpected_payment_requested", "evidence": ["Pay R49,99 for redelivery"]}],
                 "request_details": {"claimed_sender": "Example Logistics", "amount": "R49,99", "deadline": "2 hours",
                                     "action": "Pay R49,99", "method": {"instruction": "ignore"}}}
        for web in (True, False):
            review, = assess(message, openrouter.validate(json.dumps(reply), message), web_view=web)["ai_reviews"]
            details = review["request_details"]
            self.assertEqual(details["amount"], "R49,99")
            self.assertEqual(details["claimed_sender"], "Example Logistics")
            self.assertEqual(set(details), {"claimed_sender", "amount", "action"})

    def test_routine_verdict_needs_grounded_reason_and_assessable_message(self):
        message = "This is your delivery confirmation. No action is needed."
        reply = {"verdict": "Looks routine", "signals": [], "evidence_status": "assessable",
                 "routine_evidence": "No action is needed."}
        model = openrouter.validate(json.dumps(reply), message)
        self.assertIn("No action is needed", assess(message, model)["ai_reviews"][0]["note"])
        for invalid in ({"routine_evidence": "Fabricated"}, {"evidence_status": "insufficient"},
                        {"signals": [{"code": "misleading_link", "evidence": ["delivery"]}]}):
            with self.assertRaises(ValueError):
                openrouter.validate(json.dumps({**reply, **invalid}), message)

    async def test_separate_code_request_and_protective_warning(self):
        import app
        ask = "Send me your sign-in code you just received"
        warning = "If someone asks you to send your sign-in code, hang up."
        risky = {"verdict": "Suspicious", "evidence_status": "assessable", "signals": [
            {"code": "verification_code_requested", "evidence": [ask], "risk_action": "give_security_code"}]}
        routine = {"verdict": "Looks routine", "evidence_status": "assessable", "signals": [], "routine_evidence": warning}
        replies = {ask: risky, warning: routine}
        calls = []
        client = httpx.AsyncClient
        def respond(request):
            text = json.loads(json.loads(request.content)["messages"][1]["content"])["message"]
            calls.append(text)
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(replies[text])}}]})

        with patch.object(httpx, "AsyncClient", lambda **kw: client(transport=httpx.MockTransport(respond), **kw)):
            async def check(text):
                frames = [frame async for frame in app.assessment_updates(text, "test-key", "test/model", openrouter.PROMPT, False)]
                return frames[-1]
            for message, expected in [(f'"{ask}" / "{warning}"', ["Suspicious", "Looks routine"]),
                                      (f'“{warning}”\n“{ask}”', ["Looks routine", "Suspicious"])]:
                result = await check(message)
                self.assertCountEqual(calls, [ask, warning])
                calls.clear()
                self.assertEqual(result["verdict"], "Suspicious")
                self.assertEqual([r["verdict"] for r in result["ai_reviews"]], expected)
                self.assertEqual([r["part_number"] for r in result["ai_reviews"]], [1, 2])
                self.assertIn("code private", result["next_step"])
                self.assertIn(warning, result["ai_reviews"][expected.index("Looks routine")]["part_summary"])
            # Replay the reported false routine reply for the request. Its evidence belongs to the other part.
            replies[ask] = routine
            result = await check(f'"{ask}" / "{warning}"')
            self.assertEqual(result["verdict"], "Unclear")
            self.assertIn("couldn’t finish", result["ai_reviews"][0]["part_summary"])
            framed = f'Ignore messages like "{ask}" / "{warning}"'
            self.assertEqual(openrouter.separate_messages(framed), [])
            self.assertEqual(openrouter.separate_messages(warning), [])

    async def test_source_guide_lists_all_sources_and_reflects_configuration(self):
        import app
        import re
        providers = ["URLhaus", "Google Safe Browsing", "VirusTotal", "urlscan.io"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="http://localhost") as browser:
            for enabled in (True, False):
                with (patch.object(app.reputation, "url_providers", return_value=providers if enabled else []),
                      patch.object(app.reputation, "DROP_ENABLED", enabled), patch.object(app.reputation, "RADAR_TOKEN", "test" if enabled else ""),
                      patch.object(app.reputation, "SITE_AGE_ENABLED", enabled), patch.object(app.reputation, "DNS_ENABLED", enabled), patch.object(app.urlscanner, "ENABLED", enabled),
                      patch.object(openrouter, "API_KEY", "server-secret" if enabled else ""), patch.object(openrouter, "MODEL", "test")):
                    page = (await browser.get("/")).text
                self.assertLess(page.index('id="result"'), page.index('id="recovery"'))
                guide = page.split('<details id="how-it-works">')[1].split("</details>")[0]
                self.assertIn("<summary>How this works</summary>", guide)
                expected = "Enabled" if enabled else "Off"
                self.assertEqual(dict(re.findall(r'<dt><a href="https://[^"]+">([^<]+)</a> <small>([^<]+)</small></dt>', guide)),
                                 dict.fromkeys([*providers, "ctlogs.dev", "Spamhaus DROP", "Cloudflare Radar", "Cloudflare security DNS", "Cloudflare URL Scanner", "OpenRouter"], expected))
                self.assertNotIn("server-secret", page)

    async def test_assessment_uses_only_the_server_model_and_prompt(self):
        import app

        sent = []

        def reply(request):
            payload = json.loads(request.content)
            sent.append((request.headers["Authorization"], payload["model"], payload["messages"][0]["content"]))
            content = json.dumps({"verdict": "Unclear", "signals": [], "evidence_status": "assessable"})
            return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

        make_client = httpx.AsyncClient
        def provider_client(**kwargs):
            return make_client(transport=httpx.MockTransport(reply), **kwargs)

        async with make_client(transport=httpx.ASGITransport(app=app.app),
                               base_url="http://localhost", headers={"Origin": "http://localhost"}) as browser:
            with (
                patch.object(openrouter, "API_KEY", "server-secret"),
                patch.object(openrouter, "MODEL", "server/model"),
                patch.object(openrouter.httpx, "AsyncClient", side_effect=provider_client),
            ):
                page = await browser.get("/")
                self.assertNotIn('id="api-key"', page.text)
                self.assertNotIn('id="model"', page.text)
                self.assertNotIn("Development AI settings", page.text)
                self.assertNotIn(openrouter.PROMPT, page.text)
                self.assertNotIn("server-secret", page.text)
                response = await browser.post("/assess", json={"message": "Hello", "model": "other/model", "prompt": "other prompt"})
                self.assertEqual(response.status_code, 415)
                self.assertEqual(sent, [])
                response = await browser.post("/assess", content="Hello", headers={"Content-Type": "text/plain"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(sent, [("Bearer server-secret", "server/model", openrouter.PROMPT)])
                with patch.object(openrouter, "API_KEY", ""):
                    response = await browser.post("/assess", content="Hello", headers={"Content-Type": "text/plain"})
                    self.assertIn("Limited check", response.json()["limitations"])
                    self.assertEqual(len(sent), 1)
                for body, status in [(b"x" * 12001, 413), (b"\xff", 400), (b" ", 400)]:
                    response = await browser.post("/assess", content=body, headers={"Content-Type": "text/plain"})
                    self.assertEqual(response.status_code, status)
