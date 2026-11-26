import asyncio
import json
import logging
import os
import re
import secrets
from contextlib import aclosing, asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from time import gmtime, monotonic

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from assessment import QUICK_PHRASE_WEIGHTS, THREAT_CATEGORIES, URL, assess, is_url_only, quick_phrases, target_urls, visible_links
from guidance import RECOVERY_CHOICES
import background_scans
import openrouter
import reputation
import urlscanner

BASE = Path(__file__).resolve().parent
MAX_BYTES = 12_000
COMBINED = os.getenv("WHATSAPP_BRIDGE") == "1"
BRIDGE_TOKEN = secrets.token_hex(32) if COMBINED else None


@asynccontextmanager
async def services():
    openrouter.log_configuration()
    logging.getLogger("uvicorn.error").info("Reputation checks: hostname providers=%s URL providers=%s",
                                           ", ".join(reputation.host_providers()) or "none",
                                           ", ".join(reputation.url_providers()) or "none")
    if urlscanner.ENABLED:
        logging.getLogger("uvicorn.error").info(
            "Cloudflare URL Scanner enabled. Homepage submissions=%s screenshots=%s",
            urlscanner.SUBMIT, urlscanner.SCREENSHOTS,
        )
    elif urlscanner.ACCOUNT or urlscanner.TOKEN:
        logging.getLogger("uvicorn.error").warning("Cloudflare scanner needs a 32-digit hex account ID and API token.")
    if not COMBINED:
        yield
        return

    private_prefixes = ("OPENROUTER_", "CLOUDFLARE_", "URLHAUS_", "GOOGLE_SAFE_BROWSING_", "VIRUSTOTAL_", "URLSCAN_")
    bridge_env = {key: value for key, value in os.environ.items() if not key.startswith(private_prefixes)}
    bridge_env["REPUTATION_URL_PROVIDERS"] = ", ".join(reputation.url_providers())
    bridge_env["REPUTATION_SCAN_NOTICE"] = reputation.submission_notice()
    bridge_env["REPUTATION_HOST_PROVIDERS"] = ", ".join(reputation.host_providers())
    bridge_env["CHECK_BRIDGE_TOKEN"] = BRIDGE_TOKEN
    bridge = await asyncio.create_subprocess_exec("node", BASE / "whatsapp/bridge.js", env=bridge_env)
    logger = logging.getLogger("uvicorn.error")

    async def watch_bridge():
        code = await bridge.wait()
        logger.info("WhatsApp bridge exited (status %s). Restart the container to start it again.", code)

    watcher = asyncio.create_task(watch_bridge())
    try:
        yield
    finally:
        if bridge.returncode is None:
            bridge.terminate()
        try:
            await asyncio.wait_for(asyncio.shield(watcher), timeout=4)
        except TimeoutError:
            bridge.kill()
            await watcher


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        async with services():
            yield
    finally:
        await background_scans.shutdown()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
if COMBINED:
    hosts.append("127.0.0.1")  # The bridge calls the checker over container loopback.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src data: 'self'; "
        "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "recovery_choices": [choice for choice in RECOVERY_CHOICES if "action" not in choice],
        "url_providers": list(reputation.url_providers()),
        "host_providers": list(reputation.host_providers()),
        "submission_notice": reputation.submission_notice(),
        "scanner_enabled": urlscanner.ENABLED,
        "screenshots_enabled": urlscanner.ENABLED and urlscanner.SCREENSHOTS,
        "ai_enabled": bool(openrouter.API_KEY and openrouter.MODEL),
    })


def scan_caption(scan):
    if scan.image:
        return f"Cloudflare captured the {scan.scope} on {scan.capture_date}."
    if urlscanner.SCREENSHOTS:
        return "A screenshot was unavailable for this scan."
    return "Screenshot collection is disabled."


def submission_source(request: Request) -> str:
    token = request.headers.get("x-bridge-token", "")
    if BRIDGE_TOKEN and token.isascii() and secrets.compare_digest(token, BRIDGE_TOKEN):
        number = request.headers.get("x-whatsapp-number", "")
        phone = f"+{number}" if re.fullmatch(r"[1-9][0-9]{6,14}", number) else "unknown"
        return f"channel=whatsapp phone={phone}"

    # Uvicorn resolves forwarding headers only for its configured trusted proxies.
    try:
        address = ip_address(request.client.host.split("%", 1)[0]) if request.client else "unknown"
    except ValueError:
        address = "unknown"
    return f"channel=web ip={address}"


class UTCFormatter(logging.Formatter):
    converter = gmtime
    default_time_format = "%Y-%m-%dT%H:%M:%S"
    default_msec_format = "%s.%03dZ"

    def __init__(self):
        super().__init__("%(asctime)s %(levelname)s: %(message)s")


async def assessment_updates(message, api_key, model, prompt, preview, *, web_view=False, source="channel=web ip=unknown"):
    started = monotonic()
    finished = None
    durations = {}
    logger = logging.getLogger("uvicorn.error")

    def log_timing(status, end):
        logger.info(
            "Assessment timing %s status=%s radar_ms=%s spamhaus_ms=%s html_ms=%s screenshot_ms=%s google_ms=%s virustotal_ms=%s urlscan_ms=%s dns_ms=%s urlhaus_ms=%s cloudflare_ms=%s cloudflare_wait_ms=%s cloudflare_live_ms=%s ai_message_ms=%s ai_scan_ms=%s total_ms=%d",
            source, status, durations.get("Cloudflare Radar", "-"), durations.get("Spamhaus DROP", "-"),
            durations.get("cloudflare_html", "-"), durations.get("cloudflare_image", "-"), durations.get("Google Safe Browsing", "-"), durations.get("VirusTotal", "-"),
            durations.get("urlscan.io", "-"), durations.get("Cloudflare DNS", "-"), durations.get("URLhaus", "-"),
            durations.get("cloudflare", "-"), durations.get("cloudflare_wait", "-"), durations.get("cloudflare_live", "-"),
            durations.get("ai_message", "-"), durations.get("ai_scan", "-"),
            round((end - started) * 1000),
        )

    async def timed(stage, check, *args, fallback=None, **kwargs):
        stage_started = monotonic()
        try:
            return await check(*args, **kwargs)
        except Exception as error:
            # Keep an unexpected adapter failure inside its own task. Client cancellation still propagates.
            logger.warning("Assessment stage=%s unavailable error_type=%s", stage, type(error).__name__)
            return fallback
        finally:
            durations[stage] = round((monotonic() - stage_started) * 1000)

    ai_enabled = bool(api_key and model)
    failure_notes = []
    settings = dict(api_key=api_key, model=model, prompt=prompt, on_failure=failure_notes.append)
    tasks = {}
    opinion = scan = brand_finding = None
    notes = [] if ai_enabled else ["AI analysis is off."]
    url_only = is_url_only(message)
    phrases = quick_phrases(message)
    wording_score = sum(QUICK_PHRASE_WEIGHTS[phrase] for phrase in phrases)
    checks = {}
    reputation_results = {}
    ai_stage = None
    links = visible_links(message)
    has_link = bool(links)
    follow_capture = urlscanner.SCREENSHOTS and (web_view or ai_enabled)
    capture_was_queued = False
    capture_failure = None
    capture_note = "Cloudflare screenshot collection is off."
    if urlscanner.ENABLED and urlscanner.SCREENSHOTS:
        capture_note = "Looking for a Cloudflare capture of this link."
    url_providers = reputation.url_providers()
    host_providers = reputation.host_providers()
    target = target_urls(message)
    needs_capture = url_only or bool(target and urlscanner.ENABLED)
    missing_capture = ""
    shortened = bool(target and target[1] != target[2] and target[0] in {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "in.run"})
    checked_host = target[0] if target and (host_providers or url_providers or urlscanner.ENABLED) else None
    if host_providers or url_providers:
        if target:
            host, exact, _ = target
            for name, query in host_providers.items():
                checks[name] = (query, host)
            for name, query in url_providers.items():
                checks[name] = (query, exact)
        elif has_link:
            notes.append("Reputation checks skipped because none of the links met the public URL requirements.")
    try:
        for provider, (query, query_target) in checks.items():
            unavailable = ("unavailable", f"The {provider} reputation check was unavailable.")
            tasks[provider] = asyncio.create_task(timed(provider, reputation.lookup, provider, query, query_target,
                                                       fallback=unavailable))
        if urlscanner.ENABLED and has_link:
            tasks["Cloudflare lookup"] = asyncio.create_task(
                timed("cloudflare", urlscanner.lookup, message, follow_submission=follow_capture,
                      fallback=(None, "Cloudflare scan context was unavailable."))
            )

        preview_ready = False
        while True:
            if not tasks and ai_enabled and ai_stage is None and needs_capture and not (scan and scan.has_html and scan.image):
                missing = []
                if not scan or not scan.has_html:
                    missing.append("the page HTML")
                if not scan or not scan.image:
                    missing.append("a screenshot")
                if scan and scan.image:
                    missing_capture = "We received a screenshot, but the page itself was unavailable."
                else:
                    missing_capture = "Screenshot not available for this URL."
                logger.info("Website review skipped reason=incomplete_website_capture missing=%s", ", ".join(missing))
                if capture_failure and any(c.isalnum() for c in URL.sub("", message)):
                    ai_stage = "Message analysis"
                    tasks[ai_stage] = asyncio.create_task(timed("ai_message", openrouter.analyze, message, **settings))

            if not tasks and ai_enabled and ai_stage is None and not missing_capture:
                reports = [{"provider": name, "status": reputation_results[name][0], "detail": reputation_results[name][1]}
                           for name in checks if reputation_results[name][0] not in ("unavailable", "unknown")]
                if scan and scan.malicious:
                    reports.append({"provider": "Cloudflare URL Scanner", "status": "flagged",
                                    "detail": f"Cloudflare flagged the {scan.scope} as malicious at scan time."})
                if scan or reports:
                    ai_stage = "Context analysis"
                    tasks[ai_stage] = asyncio.create_task(
                        timed("ai_scan", openrouter.analyze, message, scan=scan, reports=reports, **settings))
                else:
                    ai_stage = "Message analysis"
                    tasks[ai_stage] = asyncio.create_task(timed("ai_message", openrouter.analyze, message, **settings))
            completed_checks = [reputation_results[name] for name in checks if name in reputation_results]
            result = assess(message, opinion, scan, with_context=ai_stage == "Context analysis",
                            web_view=web_view, reputation_checks=completed_checks)
            if preview_ready:
                capture_note = scan_caption(scan)
                if preview:
                    result["scan_preview"] = {"caption": capture_note, "image": scan.image or None}
            google = reputation_results.get("Google Safe Browsing")
            if google and google[0] == "flagged":
                result["google_warning"] = google[1]
            if not tasks:
                finished = monotonic()
                log_timing("finished", finished)
            flagged = [name for name, (status, _) in reputation_results.items() if status == "flagged"]
            if scan and (scan.malicious or any(label.casefold() in THREAT_CATEGORIES for label in scan.categories)):
                flagged.append("Cloudflare URL Scanner")
            result["ai_enabled"] = ai_enabled
            if scan and scan.report_id:
                result["cloudflare_report_id"] = scan.report_id
            if has_link:
                result["capture_note"] = capture_note
            if capture_failure:
                result["capture_failure"] = capture_failure.reason
            if missing_capture:
                result["ai_capture_note"] = missing_capture
                if missing_capture not in notes:
                    notes.append(missing_capture)
            if not tasks and ai_enabled:
                if not opinion:
                    result["review_note"] = missing_capture or (failure_notes[-1] if failure_notes else "We couldn’t finish the AI review. You can run the check again.")
                    if shortened and not url_only and not flagged:
                        result["review_note"] = ("The shortened link hides its destination. Verify the request through the organisation’s "
                                                 "official website before acting. The AI review was unavailable.")
                elif scan and scan.html_without_text and opinion["verdict"] == "Unclear" and not opinion.get("wording_only"):
                    result["review_note"] = f"The captured {scan.scope} had no readable body text. The screenshot and other available evidence were inconclusive."
            if web_view and follow_capture and not tasks and not capture_failure and (capture_was_queued or scan) and (missing_capture or not (scan and scan.image)):
                result["can_retry_capture"] = True
            if web_view and not tasks and ai_stage and not opinion and scan and scan.image:
                result["can_retry_review"] = True
            site_age = reputation_results.get(reputation.SITE_AGE_PROVIDER)
            result["quick_check"] = {"links": links if web_view else [], "checked_host": checked_host,
                                     "site_age_note": site_age[1] if site_age and site_age[0] == "recent" else "",
                                     "phrases": phrases, "wording_score": wording_score, "shortened": shortened,
                                     "domain_cautions": [label for label in scan.categories if label.casefold() in
                                                         {"new domains", "newly seen domains"}] if scan else [],
                                     "flagged_sources": flagged,
                                     "unavailable_sources": [name for name, (status, _) in reputation_results.items()
                                                             if status in ("unknown", "unavailable")],
                                     "pending_sources": [name for name in tasks if name in checks or name == "Cloudflare lookup"]}
            if tasks and ai_enabled:
                progress_note = "AI review in progress." if ai_stage else "Gathering available evidence for the AI review."
                unavailable = [detail for status, detail in reputation_results.values() if status == "unavailable"]
                result["limitations"] = " ".join([progress_note, *notes, *unavailable])
            else:
                result["limitations"] = " ".join([result["limitations"], *notes])
            if scan and scan.image and ai_enabled:
                if brand_finding:
                    visual = brand_finding
                elif "Context analysis" in tasks:
                    visual = {"status": "checking"}
                elif ai_stage is None and tasks:
                    visual = {"status": "waiting"}
                else:
                    visual = {"status": "unavailable"}
                result["brand_check"] = {**visual, "scope": scan.scope, "date": scan.capture_date}
            yield {**result, "pending": list(tasks)}
            if not tasks:
                return
            # Keep the response flowing through idle proxy timeouts during a provider wait.
            done, _ = await asyncio.wait(tasks.values(), timeout=12, return_when=asyncio.FIRST_COMPLETED)
            preview_ready = False
            for stage, task in list(tasks.items()):
                if task not in done:
                    continue
                del tasks[stage]
                if stage in checks:
                    reputation_results[stage] = task.result()
                elif stage in ("Cloudflare lookup", "Cloudflare scan", "Cloudflare live capture"):
                    if stage == "Cloudflare live capture":
                        scan, note = task.result(), ""
                    else:
                        scan, note = task.result()
                    if isinstance(scan, urlscanner.QueuedScan):
                        tasks["Cloudflare scan"] = asyncio.create_task(
                            timed("cloudflare_wait", urlscanner.wait_for_report, scan,
                                  fallback=(None, "Cloudflare could not provide a completed scan.")))
                        scan = None
                        capture_was_queued = True
                        capture_note = note
                        continue
                    if note:
                        notes.append(note)
                    if isinstance(scan, urlscanner.FailedScan):
                        capture_failure = scan
                        capture_note = scan.note
                        scan = None
                        continue
                    if scan:
                        # A fresh visit receives only the homepage. An exact deep-link
                        # report keeps its own artifacts so the assessed scope stays accurate.
                        if (stage != "Cloudflare live capture" and follow_capture and urlscanner.LIVE_SCREENSHOTS
                                and target and (scan.scope == "site homepage" or target[1] == target[2])):
                            capture_note = "Taking a fresh screenshot and reading the page…"
                            tasks["Cloudflare live capture"] = asyncio.create_task(
                                timed("cloudflare_live", urlscanner.live_capture, scan, target[2], fallback=scan))
                            continue
                        text_paths = [p for p in (scan.dom_path, scan.html_path) if p]
                        if text_paths:
                            tasks["Cloudflare page text"] = asyncio.create_task(
                                timed("cloudflare_html", urlscanner.read_artifact, "page text", *text_paths, wait_for_artifact=follow_capture))
                        if scan.image_path:
                            capture_note = "Cloudflare found a matching report. Retrieving its screenshot."
                            tasks["Cloudflare screenshot"] = asyncio.create_task(
                                timed("cloudflare_image", urlscanner.read_artifact, "screenshot", scan.image_path,
                                      *scan.image_alternates, wait_for_artifact=follow_capture, fallback=""))
                        else:
                            preview_ready = True
                    elif urlscanner.SCREENSHOTS:
                        capture_note = note
                elif stage == "Cloudflare screenshot":
                    scan.image = task.result() or ""
                    preview_ready = True
                elif stage == "Cloudflare page text":
                    extract = task.result()
                    scan.html_without_text = extract == ""
                    scan.page_text = extract or ""
                elif stage == ai_stage:
                    review = task.result()
                    brand_finding = review.get("brand_check") if review else None
                    opinion = review if review and "verdict" in review else None
                    if opinion and capture_failure:
                        opinion = {**opinion, "wording_only": True}
                    if opinion is None:
                        notes.append("AI analysis with source context did not complete." if stage == "Context analysis"
                                     else "AI analysis did not complete.")
    finally:
        for task in tasks.values():
            task.cancel()
        try:
            await asyncio.gather(*tasks.values(), return_exceptions=True)
        finally:
            if finished is None:
                log_timing("interrupted", monotonic())


@app.post("/assess")
async def check_message(request: Request):
    origin = request.headers.get("origin", "")
    expected_origin = f"{request.url.scheme}://{request.headers['host']}"
    if origin != expected_origin:
        raise HTTPException(403, "Submit the message from the checker page.")
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "text/plain":
        raise HTTPException(415, "Submit the message as plain text.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BYTES:
            raise HTTPException(413, "This message is too long. Paste a shorter excerpt.")
        body.extend(chunk)
    try:
        message = body.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "The message must be valid UTF-8.") from None
    if not message.strip():
        raise HTTPException(400, "Paste a message or link first.")
    web_view = request.headers.get("X-Assessment-View") == "web"
    preview = web_view or request.headers.get("X-Scan-Preview") == "1"
    updates = assessment_updates(message, openrouter.API_KEY, openrouter.MODEL, openrouter.PROMPT, preview,
                                 web_view=web_view, source=submission_source(request))
    if "application/x-ndjson" in request.headers.get("accept", ""):
        async def lines():
            async with aclosing(updates):
                async for update in updates:
                    yield json.dumps(update) + "\n"

        return StreamingResponse(lines(), media_type="application/x-ndjson", headers={"X-Accel-Buffering": "no"})

    # Existing clients get the final assessment with any preview attached.
    result = {}
    async with aclosing(updates):
        async for update in updates:
            result.update(update)
    del result["pending"]
    return result
