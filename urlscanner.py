"""Optional Cloudflare scan context. All HTTP requests go to the account API."""

import asyncio
import base64
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import json
import logging
import os
import re
from uuid import UUID
from urllib.parse import urlsplit

import httpx

import background_scans
import enrichment_http

from assessment import URL, comparison_url, target_urls

ACCOUNT = os.getenv("CLOUDFLARE_ACCOUNT_ID", "").strip()
TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
ENABLED = bool(re.fullmatch(r"[0-9a-fA-F]{32}", ACCOUNT) and TOKEN)
SUBMIT = os.getenv("CLOUDFLARE_SUBMIT_SCANS") == "1"
SCREENSHOTS = os.getenv("CLOUDFLARE_SCAN_SCREENSHOTS") == "1"
LIVE_SCREENSHOTS = os.getenv("CLOUDFLARE_LIVE_SCREENSHOTS") == "1"
SLOTS = asyncio.Semaphore(3)
ARTIFACT_SLOTS = asyncio.Semaphore(6)
REPORT_WAIT_SECONDS = 180
ARTIFACT_WAIT_SECONDS = 30
POLL_SECONDS = 5
logger = logging.getLogger("uvicorn.error")


@dataclass
class Scan:
    scope: str
    date: str
    categories: list[str]
    malicious: bool | None
    page_text: str = field(default="", repr=False)
    image: str = field(default="", repr=False)
    html_path: str = field(default="", repr=False)
    image_path: str = field(default="", repr=False)
    dom_path: str = field(default="", repr=False)
    image_alternates: list[str] = field(default_factory=list, repr=False)
    report_id: str = ""
    indicators: list[str] = field(default_factory=list)
    title: str = ""
    landing_host: str = ""
    html_without_text: bool = False
    live_date: str = ""
    live_landing_host: str = ""

    @property
    def capture_date(self):
        return self.live_date or self.date

    @property
    def has_html(self):
        return self.html_without_text or bool(self.page_text.strip())


@dataclass
class QueuedScan:
    target: str
    scope: str
    scan_id: str = ""
    receipt: asyncio.Task | None = None


@dataclass(frozen=True)
class FailedScan:
    scope: str
    reason: str

    @property
    def note(self):
        if self.reason == "connection_reset":
            return f"The connection closed while Cloudflare was loading the {self.scope}. There’s no screenshot from this scan."
        return f"Cloudflare couldn’t capture the {self.scope}. There’s no screenshot from this scan."


class ScanPending(ValueError):
    """Cloudflare has accepted the scan but has not published this resource yet."""


class PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.words = []
        self.has_body = False

    def handle_starttag(self, tag, attrs):
        if tag == "body":
            self.has_body = True
        if tag in {"head", "title", "script", "style", "template", "noscript"}:
            self.hidden += 1
        if not self.hidden and tag == "input":
            attributes = dict(attrs)
            kind = (attributes.get("type") or "text").lower()
            if kind == "hidden" or "hidden" in attributes:
                return
            # Sign-in forms often put the field label inside the empty input.
            placeholder = (attributes.get("placeholder") or "").strip()
            if placeholder:
                self.words.append(placeholder[:180])
            if kind == "password":
                self.words.append("[password field]")

    def handle_endtag(self, tag):
        if tag in {"head", "title", "script", "style", "template", "noscript"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.words.append(data.strip())


async def fetch(client, path, limit, *, params=None, body=None):
    async with client.stream("POST" if body else "GET", path, params=params, json=body) as response:
        response.raise_for_status()
        if response.status_code == 202 and not body:
            raise ScanPending()
        data = bytearray()
        async for chunk in response.aiter_bytes(65536):
            if len(data) + len(chunk) > limit:
                raise ValueError("Scan artifact exceeds limit")
            data.extend(chunk)
        return bytes(data)


def object_field(row, key):
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def list_field(row, key):
    value = row.get(key)
    return value if isinstance(value, list) else []


def clean_text(value, limit):
    return value.strip()[:limit] if isinstance(value, str) and value.strip().isprintable() else ""


def read_report(report, scan_id, scope):
    if report.get("errors") or report.get("error") or report.get("success") is False or report["task"].get("success") is not True:
        raise ValueError("Scan did not succeed")
    processors = object_field(object_field(report, "meta"), "processors")
    page = object_field(report, "page")
    page_url = page.get("url") if isinstance(page.get("url"), str) else ""
    try:
        landing_host = urlsplit(page_url).hostname or ""
    except ValueError:
        landing_host = ""
    overall = object_field(object_field(report, "verdicts"), "overall")
    domain_categories = list_field(object_field(processors, "domainCategories"), "data")
    categories = []
    url_categories = list_field(object_field(processors, "urlCategories"), "data")
    for row in domain_categories + url_categories:
        if not isinstance(row, dict):
            continue
        # Row names identify hosts/URLs. Category labels live inside risks and content.
        if row.get("isPrimary") is False:
            continue
        if row.get("isPrimary") is not True and (not row.get("name") or row["name"] not in (page_url, landing_host)):
            continue
        for group in ("risks", "content"):
            categories.extend(item.get("name") for item in list_field(row, group) if isinstance(item, dict))
    indicators = []
    for name in ("phishing", "phishing_v2"):
        for value in list_field(object_field(processors, name), "data"):
            if label := clean_text(value, 125):
                indicators.append(f"{name}: {label}")
    for name in ("categories", "tags"):
        for value in list_field(overall, name):
            if label := clean_text(value, 125):
                indicators.append(f"Verdict {name}: {label}")
    malicious = None if overall.get("hasVerdicts") is False else overall.get("malicious")
    scan = Scan(
        scope=scope, report_id=scan_id if str(report["task"].get("visibility")).lower() == "public" else "",
        date=datetime.fromisoformat(report["task"]["time"]).date().isoformat(),
        categories=list(dict.fromkeys(label for v in categories if (label := clean_text(v, 100))))[:24],
        indicators=list(dict.fromkeys(indicators))[:16],
        title=clean_text(page.get("title"), 180), landing_host=landing_host,
        malicious=malicious if isinstance(malicious, bool) else None,
    )
    for item in list_field(object_field(report, "data"), "requests"):
        if not isinstance(item, dict):
            continue
        entry = object_field(item, "response")
        resource = object_field(entry, "response")
        is_document = clean_text(entry.get("type"), 16).lower() == "document"
        if not is_document or not page_url or resource.get("url") != page_url or entry.get("contentAvailable") is False:
            continue
        digest = entry.get("hash", "")
        is_html = clean_text(resource.get("mimeType"), 100).split(";")[0].lower() == "text/html"
        if not is_html or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            continue
        scan.html_path = f"responses/{digest}"
        break
    if report["task"].get("domURL") or (SCREENSHOTS and not scan.html_path):
        scan.dom_path = f"dom/{scan_id}"
    if SCREENSHOTS:
        scan.image_path = f"screenshots/{scan_id}.png"
        resolutions = list_field(object_field(report["task"], "options"), "screenshotsResolutions")
        paths = [f"{scan.image_path}?resolution={device}" for device in ("desktop", "mobile", "tablet")
                 if device in resolutions]
        if paths:
            scan.image_path, *scan.image_alternates = paths
    return scan


async def read_artifact(kind, path, *alternates, logger=logger, wait_for_artifact=False):
    if ARTIFACT_SLOTS.locked() and not wait_for_artifact:
        logger.info("Cloudflare artifact=%s unavailable reason=busy", kind)
        return None
    try:
        async with asyncio.timeout(ARTIFACT_WAIT_SECONDS if wait_for_artifact else 6), account_client() as client:
            while True:
                try:
                    async with ARTIFACT_SLOTS, asyncio.timeout(6):
                        value = await download_artifact(client, kind, (path, *alternates))
                    if kind == "page text" and value == "":
                        logger.info("Cloudflare artifact=page text available=False html_body_available=True")
                    elif value is not None:
                        logger.info("Cloudflare artifact=%s available=True", kind)
                    return value
                except httpx.HTTPStatusError as error:
                    if not wait_for_artifact or error.response.status_code not in (404, 502, 503, 504):
                        raise
                except (ScanPending, httpx.TransportError, TimeoutError):
                    if not wait_for_artifact:
                        raise
                await asyncio.sleep(POLL_SECONDS)
    except httpx.HTTPStatusError as error:
        logger.info("Cloudflare artifact=%s unavailable http_status=%d", kind, error.response.status_code)
        return None
    except (TimeoutError, httpx.HTTPError, ValueError) as error:
        reason = str(error) if type(error) is ValueError and str(error) in ("Scan artifact exceeds limit", "Invalid screenshot") else type(error).__name__
        logger.info("Cloudflare artifact=%s unavailable reason=%s", kind, reason)
        return None


def page_extract(html):
    parser = PageText()
    parser.feed(html)
    parser.close()
    return " ".join(" ".join(parser.words).split())[:4000], parser.has_body


def valid_png(png):
    return png.startswith(b"\x89PNG\r\n\x1a\n") and png[12:16] == b"IHDR"


async def live_capture(scan, root, *, logger=logger):
    """Use a complete Browser Run snapshot or retain the original report and its artifact paths."""
    if ARTIFACT_SLOTS.locked():
        return scan
    try:
        async with asyncio.timeout(20), ARTIFACT_SLOTS, enrichment_http.client("Cloudflare Browser Run", timeout=20) as client:
            endpoint = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/browser-rendering/snapshot"
            client.headers["Authorization"] = f"Bearer {TOKEN}"
            body = {"url": root, "formats": ["content", "screenshot"],
                    "viewport": {"width": 1280, "height": 800, "deviceScaleFactor": 1.5},
                    "gotoOptions": {"waitUntil": "networkidle2", "timeout": 12000},
                    "screenshotOptions": {"type": "png"}}
            reply = json.loads(await fetch(client, endpoint, 6_000_000, body=body, params={"cacheTTL": 0}))
        if reply.get("success") is not True:
            raise ValueError("Snapshot failed")
        snapshot = reply["result"]
        html, image = snapshot["content"], snapshot["screenshot"]
        if not isinstance(html, str) or len(html.encode()) > 512_000 or not isinstance(image, str):
            raise ValueError("Invalid snapshot content")
        png = base64.b64decode(image, validate=True)
        if len(png) > 4_000_000 or not valid_png(png):
            raise ValueError("Invalid snapshot image")
        text, has_body = page_extract(html)
        if not has_body:
            raise ValueError("Missing snapshot body")
        final_url = object_field(reply, "meta").get("finalUrl") or ""
        landing_host = urlsplit(final_url).hostname or ""
        logger.info("Cloudflare live capture available=True")
        return replace(scan, page_text=text, html_without_text=not text, image="data:image/png;base64," + image,
                       live_date=datetime.now(timezone.utc).date().isoformat(), live_landing_host=landing_host,
                       dom_path="", html_path="", image_path="", image_alternates=[])
    except httpx.HTTPStatusError as error:
        logger.info("Cloudflare live capture unavailable http_status=%d", error.response.status_code)
    except (TimeoutError, httpx.HTTPError, KeyError, TypeError, ValueError, AttributeError):
        logger.info("Cloudflare live capture unavailable")
    return scan


async def download_artifact(client, kind, paths):
    # An empty extract from an HTML body is still evidence that the page was captured.
    found_body = False
    for candidate in paths:
        try:
            if kind == "screenshot":
                png = await fetch(client, candidate, 4_000_000)
                if not valid_png(png):
                    raise ValueError("Invalid screenshot")
                return "data:image/png;base64," + base64.b64encode(png).decode()
            html = await fetch(client, candidate, 512_000)
            value, has_body = page_extract(html.decode("utf-8", errors="replace"))
            if value:
                return value
            found_body |= has_body
        except httpx.HTTPStatusError as error:
            # The DOM endpoint can return 400 for an account that can still read the HTML response.
            unavailable = error.response.status_code == 404 or (candidate.startswith("dom/") and error.response.status_code == 400)
            if found_body and unavailable:
                continue
            if not unavailable or candidate == paths[-1]:
                raise
        except ValueError:
            if candidate == paths[-1] and not found_body:
                raise
    return "" if found_body else None


async def submit_homepage(client, root):
    endpoint = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/urlscanner/v2/scan"
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    options = {"url": root, "visibility": "Unlisted"}
    if SCREENSHOTS:
        options["screenshotsResolutions"] = ["desktop"]
    receipt = await fetch(client, endpoint, 8192, body=options)
    return str(UUID(json.loads(receipt)["uuid"]))


def account_client():
    return enrichment_http.client(
        "Cloudflare", base_url=f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/urlscanner/v2/",
        headers={"Authorization": f"Bearer {TOKEN}"}, timeout=6,
    )


async def matching_report(client, scan_id, url, scope, logger):
    report = json.loads(await fetch(client, f"result/{scan_id}", 10_000_000))
    task = object_field(report, "task")
    if str(task.get("status")).lower() in ("queued", "pending", "running", "processing") and task.get("success") is not True:
        raise ScanPending()
    if comparison_url(report["task"]["url"]) != url or report["task"].get("uuid", scan_id) != scan_id:
        raise ValueError("Scan target mismatch")
    if task.get("success") is False:
        # Provider details can include private URLs. Only pass on a recognized reason.
        reset = any(isinstance(error, dict) and isinstance(error.get("detail"), str)
                    and error["detail"].split(" ", 1)[0] == "net::ERR_CONNECTION_RESET"
                    for error in list_field(task, "errors"))
        failed = FailedScan(scope, "connection_reset" if reset else "scan_failed")
        logger.info("Cloudflare scan failed scope=%s reason=%s", scope, failed.reason)
        return failed, failed.note
    scan = read_report(report, scan_id, scope)
    logger.info("Cloudflare report ready scope=%s date=%s public_id=%s categories=%d indicators=%d",
                scope, scan.date, scan.report_id or "-", len(scan.categories), len(scan.indicators))
    return scan, f"Cloudflare context covers the {scope} of the first eligible link, as scanned on {scan.date}."


async def wait_for_report(queued, *, logger=logger):
    try:
        async with asyncio.timeout(REPORT_WAIT_SECONDS), account_client() as client:
            scan_id = queued.scan_id or await asyncio.shield(queued.receipt)
            if not scan_id:
                return None, "Cloudflare could not confirm the scan submission."
            while True:
                try:
                    async with SLOTS:
                        return await matching_report(client, scan_id, queued.target, queued.scope, logger)
                except httpx.HTTPStatusError as error:
                    if error.response.status_code not in (404, 502, 503, 504):
                        raise
                except (ScanPending, httpx.TransportError):
                    pass
                await asyncio.sleep(POLL_SECONDS)
    except TimeoutError:
        return None, "Cloudflare’s scan was still pending when this check finished."
    except enrichment_http.RateLimited:
        return None, "Cloudflare paused scan requests due to its rate limit."
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as error:
        logger.info("Cloudflare queued report unavailable reason=%s", type(error).__name__)
        return None, "Cloudflare could not provide a completed scan."


async def lookup(message, *, follow_submission=False, logger=logger):
    if not ENABLED:
        return None, ""
    targets = target_urls(message)
    if not targets:
        if URL.search(message):
            logger.info("Cloudflare lookup skipped reason=no_eligible_hostname")
            return None, "Cloudflare lookup skipped because none of the links met the public URL requirements."
        logger.info("Cloudflare lookup skipped reason=no_http_link")
        return None, ""
    host, exact, root = targets
    if SLOTS.locked():
        logger.info("Cloudflare lookup skipped reason=busy")
        return None, "Cloudflare lookup was busy."
    try:
        async with SLOTS, asyncio.timeout(8), account_client() as client:
            logger.info("Cloudflare report search started")
            since = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
            # A submitted homepage can redirect to a different page.domain. Keep private paths out of search.
            query_text = f'(task.url:"{root}" OR task.url:"{root[:-1]}")'
            if exact != root:
                query_text += f' OR (page.domain:"{host}" AND date:[{since} TO now])'
            query = {"q": query_text, "size": 50}
            search = json.loads(await fetch(client, "search", 256_000, params=query))
            if search.get("success") is False or search.get("errors") or search.get("error"):
                raise ValueError("Cloudflare search failed")
            hits = search["results"]
            if not isinstance(hits, list):
                raise ValueError("Invalid Cloudflare search response")
            candidates = {}
            failed_candidates = {}
            for row in hits:
                try:
                    task = row["task"]
                    url = comparison_url(task["url"])
                    if url in (exact, root):
                        group = failed_candidates if task.get("success") is False else candidates
                        group.setdefault(url, []).append(str(UUID(task["uuid"])))
                except (KeyError, TypeError, AttributeError, ValueError):
                    continue
            if not candidates and not SUBMIT:
                candidates = failed_candidates
            if not candidates:
                note = "No matching Cloudflare report was found in the search results."
                logger.info("Cloudflare lookup finished reason=no_matching_report submissions=%s screenshots=%s",
                            SUBMIT, SCREENSHOTS)
                if SUBMIT and SCREENSHOTS:
                    receipt, queue_note = background_scans.enqueue_with_receipt("Cloudflare", root, submit_homepage)
                    scope = "linked page" if exact == root else "site homepage"
                    if follow_submission and receipt is not None:
                        return QueuedScan(root, scope, receipt=receipt), "Waiting for Cloudflare to capture the homepage. The screenshot will appear here automatically."
                    # A later check can read our unlisted report by ID before search indexes it.
                    if receipt is not None and receipt.done() and not receipt.cancelled() and receipt.result():
                        try:
                            return await matching_report(client, receipt.result(), root, scope, logger)
                        except httpx.HTTPStatusError as error:
                            if error.response.status_code != 404:
                                raise
                        except ScanPending:
                            pass
                    note += " " + queue_note
                elif SUBMIT:
                    note += " " + background_scans.enqueue("Cloudflare", root, submit_homepage)
                else:
                    note += " New homepage scans are off."
                return None, note
            pending = None
            failed = None
            for url in dict.fromkeys((exact, root)):
                scope = "linked page" if url == exact else "site homepage"
                for scan_id in list(dict.fromkeys(candidates.get(url, ())))[:3]:
                    try:
                        result, note = await matching_report(client, scan_id, url, scope, logger)
                        if isinstance(result, FailedScan):
                            failed = failed or result
                            continue
                        return result, note
                    except httpx.HTTPStatusError as error:
                        if error.response.status_code != 404:
                            raise
                        pending = pending or QueuedScan(url, scope, scan_id=scan_id)
                    except ScanPending:
                        pending = pending or QueuedScan(url, scope, scan_id=scan_id)
                    except (KeyError, ValueError, TypeError, AttributeError):
                        continue
            if pending and follow_submission:
                return pending, "Cloudflare is processing the scan. The screenshot will appear here automatically."
            if failed:
                return failed, failed.note
            logger.info("Cloudflare lookup finished reason=no_usable_matching_report")
            return None, "Matching Cloudflare reports were found, but none of the checked reports was usable."
    except enrichment_http.RateLimited:
        logger.info("Cloudflare context unavailable reason=rate_limit")
        return None, "Cloudflare scan context was unavailable due to a rate limit."
    except httpx.HTTPStatusError as error:
        logger.warning("Cloudflare context unavailable status=%d", error.response.status_code)
    except (TimeoutError, httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, AssertionError) as error:
        logger.info("Cloudflare scan context unavailable reason=%s", type(error).__name__)
    return None, "Cloudflare scan context was unavailable."
