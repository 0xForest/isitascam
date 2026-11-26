"""Read existing reputation records. Requests go to fixed provider APIs."""

import asyncio
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import logging
import os
import re
from time import monotonic
from uuid import UUID
from ipaddress import IPv4Address, IPv4Network
from urllib.parse import urlsplit

import httpx
import proto
import tldextract
from google.protobuf.duration_pb2 import Duration
from google.protobuf.message import DecodeError

import background_scans
import enrichment_http
from assessment import THREAT_CATEGORIES

DNS_ENABLED = os.getenv("CLOUDFLARE_DNS_REPUTATION", "1") != "0"
SITE_AGE_ENABLED = os.getenv("SITE_AGE_CHECK", "1") != "0"
SITE_AGE_PROVIDER = "Site age"
CTLOGS_KEY = os.getenv("CTLOGS_API_KEY", "").strip()
ctlogs_lock = asyncio.Lock()  # The free tier allows one in-flight request per client.
RECENT_DOMAIN_AGE = timedelta(days=30)
# Use the packaged suffix list, including hosting platforms. No suffix downloads at runtime.
domain_parts = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)
rdap_registries = {}
rdap_refresh_after = 0
RADAR_TOKEN = os.getenv("CLOUDFLARE_RADAR_API_TOKEN", os.getenv("CLOUDFLARE_API_TOKEN", "")).strip()
DROP_ENABLED = os.getenv("SPAMHAUS_DROP_ENABLED") == "1"
URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
GOOGLE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
VT_SUBMIT = os.getenv("VIRUSTOTAL_SUBMIT_SCANS") == "1"
URLSCAN_SUBMIT = os.getenv("URLSCAN_SUBMIT_SCANS") == "1"
google_cache = {}  # URL digest -> (expiry on monotonic clock, templated finding)
TIMEOUT = 3
logger = logging.getLogger("uvicorn.error")


def host_providers():
    return {name: query for name, enabled, query in (
        ("Cloudflare DNS", DNS_ENABLED, cloudflare_dns),
        (SITE_AGE_PROVIDER, SITE_AGE_ENABLED, site_age),
        ("Cloudflare Radar", RADAR_TOKEN, radar_categories),
        ("Spamhaus DROP", DROP_ENABLED, spamhaus_drop),
    ) if enabled}


async def radar_categories(client, host):
    report = await read_record(client, "GET", f"https://api.cloudflare.com/client/v4/radar/ranking/domain/{host}",
                               headers={"Authorization": f"Bearer {RADAR_TOKEN}"})
    categories = report["result"]["details_0"]["categories"]
    if not isinstance(categories, list):
        raise ValueError("Invalid category list")
    labels = [item["name"][:100] for item in categories if isinstance(item.get("name"), str) and item["name"].strip()][:10]
    if not labels:
        return "unknown", "Cloudflare Radar returned no categories for the checked hostname."
    status = "flagged" if any(label.casefold() in THREAT_CATEGORIES for label in labels) else "known"
    return status, "Cloudflare Radar categories for the checked hostname: " + ", ".join(labels) + "."


# Only the public network list is cached. One refresh attempt per hour, including failures.
drop_networks = ()
drop_refresh_after = 0
drop_lock = asyncio.Lock()


async def ipv4_drop_list(client):
    global drop_networks, drop_refresh_after
    async with drop_lock:
        if monotonic() >= drop_refresh_after:
            drop_refresh_after = monotonic() + 3600
            drop_networks = ()
            async with client.stream("GET", "https://www.spamhaus.org/drop/drop_v4.json") as response:
                response.raise_for_status()
                data = bytearray()
                async for chunk in response.aiter_bytes(16384):
                    if len(data) + len(chunk) > 1_000_000:
                        raise ValueError("Oversized DROP list")
                    data.extend(chunk)
            records = [json.loads(line) for line in data.splitlines() if line.strip()]
            metadata = records.pop() if records else {}
            if not records or metadata.get("type") != "metadata" or metadata.get("records") != len(records):
                raise ValueError("Incomplete DROP list")
            drop_networks = tuple(IPv4Network(row["cidr"]) for row in records)
        if not drop_networks:
            raise ValueError("DROP list unavailable")
        return drop_networks


async def spamhaus_drop(client, host):
    # Resolve via a fixed DNS API. A lookup never connects to the resolved address.
    record = await read_record(client, "GET", "https://cloudflare-dns.com/dns-query",
                               params={"name": host, "type": "A"}, headers={"Accept": "application/dns-json"})
    question, = record["Question"]
    if record["Status"] != 0 or record.get("TC") is not False or question["type"] != 1 or question["name"].lower().rstrip(".") != host:
        return "unknown", "Spamhaus DROP had no usable IPv4 resolution for the checked hostname."
    answers = record.get("Answer", [])
    aliases = {row["name"].lower().rstrip("."): row["data"].lower().rstrip(".") for row in answers if row["type"] == 5}
    name = host
    for _ in range(8):
        if name not in aliases:
            break
        name = aliases[name]
    addresses = {IPv4Address(row["data"]) for row in answers if row["type"] == 1 and row["name"].lower().rstrip(".") == name}
    public = [ip for ip in addresses if ip.is_global]
    if not public:
        return "unknown", "Spamhaus DROP had no public IPv4 address to check."
    networks = await ipv4_drop_list(client)
    for ip in public:
        if any(ip in network for network in networks):
            return "flagged", f"Spamhaus DROP lists a network hosting the resolved IPv4 address {ip}. This may be shared infrastructure."
    return "no_match", "The resolved IPv4 addresses had no match in Spamhaus DROP."


async def read_record(client, method, endpoint, *, missing_code=None, limit=512_000, protobuf_type=None, **kwargs):
    async with client.stream(method, endpoint, **kwargs) as response:
        missing = response.status_code == 404 and missing_code is not None
        if not missing:
            response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes(16_384):
            if len(data) + len(chunk) > limit:
                raise ValueError("Oversized reputation record")
            data.extend(chunk)
    if protobuf_type and response.headers.get("content-type", "").split(";")[0] == "application/x-protobuf":
        try:
            message = protobuf_type.deserialize(bytes(data))
            record = protobuf_type.to_dict(message, preserving_proto_field_name=False, use_integers_for_enums=False)
        except DecodeError as error:
            raise ValueError("Invalid protobuf response") from error
    else:
        record = json.loads(data)
    if not isinstance(record, dict):
        raise ValueError("Expected a reputation record")
    if missing:
        if record.get("error", {}).get("code") == missing_code:
            return None
        response.raise_for_status()
    if record.get("error") or record.get("errors") or record.get("success") is False:
        raise ValueError("Provider returned an error record")
    return record


async def rdap_registry(client, tld):
    global rdap_registries, rdap_refresh_after
    if monotonic() >= rdap_refresh_after:
        bootstrap = await read_record(client, "GET", "https://data.iana.org/rdap/dns.json")
        # Follow only registry endpoints published by IANA, never links from a domain record.
        registries = {}
        for tlds, urls in bootstrap["services"]:
            base = next((url for url in urls if url.startswith("https://")), None)
            if base:
                registries.update(dict.fromkeys(tlds, base.rstrip("/")))
        rdap_registries = registries
        rdap_refresh_after = monotonic() + 86400
    return rdap_registries.get(tld)


def utc_timestamp(value):
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None:
        raise ValueError("Timestamp missing timezone")
    return instant.astimezone(timezone.utc)


async def site_age(client, host):
    unknown = ("unknown", "We couldn’t confirm how recently this site’s domain was registered.")
    parts = domain_parts(host)
    domain = parts.top_domain_under_public_suffix
    if not domain or parts.is_private:
        return unknown
    # ctlogs.dev matches literal names, including wildcards. Try a covering
    # wildcard only when there is no record for the specific hostname.
    names = [host]
    if host != domain:
        names.append("*." + host.partition(".")[2])
    headers = {"Authorization": f"Bearer {CTLOGS_KEY}"} if CTLOGS_KEY else {}
    for name in names:
        async with ctlogs_lock:
            record = await read_record(client, "GET", f"https://api.ctlogs.dev/v1/domain/{name}", headers=headers)
        rows = record["rows"]
        if not isinstance(rows, list):
            raise ValueError("Expected certificate rows")
        dates = [utc_timestamp(row["not_before"]) for row in rows if row["match"].lower().rstrip(".") == name]
        if dates:
            break
    now = datetime.now(timezone.utc)
    if not dates or any(date > now for date in dates):
        return unknown
    if min(dates) < now - RECENT_DOMAIN_AGE:
        return "known", "A public certificate record for this address is more than 30 days old."
    registry = await rdap_registry(client, domain.rsplit(".", 1)[1])
    if not registry:
        return unknown
    record = await read_record(client, "GET", f"{registry}/domain/{domain}")
    if record.get("objectClassName") != "domain" or record.get("ldhName", "").lower().rstrip(".") != domain:
        return unknown
    dates = [utc_timestamp(event["eventDate"]) for event in record["events"] if event.get("eventAction") == "registration"]
    if len(dates) != 1 or dates[0] > now:
        return unknown
    registered, = dates
    if now - registered <= RECENT_DOMAIN_AGE:
        return "recent", f"This site’s domain was registered on {registered:%d %b %Y}. It may be too new to have much of a track record."
    return "known", "The domain registration is more than 30 days old."


async def cloudflare_dns(client, host):
    record = await read_record(
        client, "GET", "https://security.cloudflare-dns.com/dns-query",
        params={"name": host, "type": "A"}, headers={"Accept": "application/dns-json"},
    )
    question, = record["Question"]
    if question["name"].rstrip(".").lower() != host or question["type"] != 1 or record.get("TC") is not False:
        raise ValueError("Unexpected DNS response")
    if record["Status"] == 3:
        return "unknown", "Cloudflare DNS could not resolve the first eligible hostname."
    if record["Status"] != 0:
        raise ValueError("DNS lookup failed")
    addresses = {IPv4Address(row["data"]) for row in record.get("Answer", []) if row["type"] == 1}
    sinkhole = IPv4Address("0.0.0.0")
    if sinkhole in addresses:
        blocked_host = any(row["type"] == 1 and row["name"].rstrip(".").lower() == host for row in record["Answer"])
        if blocked_host and addresses == {sinkhole} and "EDE(16): Censored" in record.get("Comment", []):
            return "flagged", "Cloudflare’s security DNS blocks the first eligible hostname as a threat."
        return "unknown", "Cloudflare DNS returned an inconclusive answer for the first eligible hostname."
    if not addresses:
        return "unknown", "Cloudflare DNS returned no IPv4 address for the first eligible hostname."
    return "no_match", "Cloudflare’s security DNS did not flag the first eligible hostname. Individual pages can still be harmful."


async def urlhaus(client, url):
    record = await read_record(
        client, "POST", "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url}, headers={"Auth-Key": URLHAUS_KEY},
    )
    if record["query_status"] == "no_results":
        return "no_match", "URLhaus has no malware-download record for the first eligible URL. It can still be harmful."
    if record["query_status"] != "ok" or record["url"] != url or record["threat"] != "malware_download":
        raise ValueError("Unexpected URLhaus record")
    status = record["url_status"]
    if status == "online":
        return "flagged", "URLhaus lists the first eligible URL as an online malware download."
    if status in ("offline", "unknown"):
        return "flagged", f"URLhaus previously recorded malware at the first eligible URL. Its listed status is {status}."
    raise ValueError("Unexpected URLhaus status")


async def lookup(provider, query, target, *, logger=logger):
    try:
        timeout = 6 if provider == SITE_AGE_PROVIDER else TIMEOUT
        async with asyncio.timeout(timeout), enrichment_http.client(provider, timeout=timeout) as client:
            status, detail = await query(client, target)
    except enrichment_http.RateLimited:
        logger.info("Reputation provider=%s status=unavailable reason=rate_limit", provider)
        return "unavailable", f"The {provider} reputation check was unavailable due to a rate limit."
    except httpx.HTTPStatusError as error:
        logger.info("Reputation provider=%s status=unavailable http_status=%d", provider, error.response.status_code)
    except (TimeoutError, httpx.TimeoutException):
        logger.info("Reputation provider=%s status=unavailable reason=timeout", provider)
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        logger.info("Reputation provider=%s status=unavailable reason=request_or_record_error", provider)
    else:
        logger.info("Reputation provider=%s status=%s", provider, status)
        return status, detail
    return "unavailable", f"The {provider} reputation check was unavailable."


def url_providers():
    """Only configured providers receive the eligible URL, including its query."""
    return {name: query for name, key, query in (
        ("URLhaus", URLHAUS_KEY, urlhaus),
        ("Google Safe Browsing", GOOGLE_KEY, google_safe_browsing),
        ("VirusTotal", VT_KEY, virustotal),
        ("urlscan.io", URLSCAN_KEY, urlscan),
    ) if key}


def submission_notice():
    notices = []
    if VT_KEY and VT_SUBMIT:
        notices.append("VirusTotal may scan and share previously unseen URLs with its security community.")
    if URLSCAN_KEY and URLSCAN_SUBMIT:
        notices.append("urlscan.io may visit previously unseen URLs in a private scan.")
    return " ".join(notices)


class GoogleThreatType(proto.Enum):
    THREAT_TYPE_UNSPECIFIED = 0
    MALWARE = 1
    SOCIAL_ENGINEERING = 2
    UNWANTED_SOFTWARE = 3
    POTENTIALLY_HARMFUL_APPLICATION = 4


class GoogleThreatUrl(proto.Message):
    url = proto.Field(proto.STRING, number=1)
    threat_types = proto.RepeatedField(proto.ENUM, number=2, enum=GoogleThreatType)


class GoogleSearchUrlsResponse(proto.Message):
    threats = proto.RepeatedField(proto.MESSAGE, number=1, message=GoogleThreatUrl)
    cache_duration = proto.Field(proto.MESSAGE, number=2, message=Duration)


async def google_safe_browsing(client, url):
    digest = sha256(url.encode()).digest()
    now = monotonic()
    cached = google_cache.get(digest)
    if cached and cached[0] > now:
        return cached[1]
    if len(google_cache) >= 4096:
        for expired in [key for key, (expiry, _) in google_cache.items() if expiry <= now]:
            del google_cache[expired]
        if len(google_cache) >= 4096:
            raise ValueError("Google cache at capacity")
    record = await read_record(client, "GET", "https://safebrowsing.googleapis.com/v5/urls:search",
                               params={"urls": url}, headers={"X-Goog-Api-Key": GOOGLE_KEY},
                               protobuf_type=GoogleSearchUrlsResponse)
    duration = record["cacheDuration"]
    if not re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,9})?s", duration):
        raise ValueError("Invalid Google cache duration")
    threats = record.get("threats", [])
    if not isinstance(threats, list):
        raise ValueError("Invalid Google threat list")
    descriptions = {"SOCIAL_ENGINEERING": "social engineering", "MALWARE": "malware",
                    "UNWANTED_SOFTWARE": "unwanted software", "POTENTIALLY_HARMFUL_APPLICATION": "a potentially harmful app"}
    found = set()
    for threat in threats:
        if not isinstance(threat["url"], str) or not threat["url"] or not isinstance(threat["threatTypes"], list):
            raise ValueError("Invalid Google threat entry")
        found.update(descriptions[kind] for kind in threat["threatTypes"] if kind in descriptions)
    if found:
        result = "flagged", "Google Safe Browsing warns that this link may expose you to " + ", ".join(sorted(found)) + "."
    elif threats:
        result = "unknown", "Google Safe Browsing returned an unrecognized threat category."
    else:
        result = "no_match", "Google Safe Browsing has no threat-list match for this link."
    google_cache[digest] = monotonic() + float(duration[:-1]), result
    return result


VT_ENDPOINT = "https://www.virustotal.com/api/v3/urls"


async def submit_virustotal(client, url):
    record = await read_record(client, "POST", VT_ENDPOINT, data={"url": url}, headers={"x-apikey": VT_KEY})
    if record["data"]["type"] != "analysis" or not record["data"]["id"]:
        raise ValueError("Invalid VirusTotal submission receipt")


async def virustotal(client, url):
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    report = await read_record(client, "GET", f"{VT_ENDPOINT}/{identifier}", headers={"x-apikey": VT_KEY},
                               missing_code="NotFoundError")
    if report is None:
        detail = "VirusTotal has no report for this URL."
        if VT_SUBMIT:
            detail += " " + background_scans.enqueue("VirusTotal", url, submit_virustotal)
        return "no_match", detail
    data = report["data"]
    if data["type"] != "url":
        raise ValueError("Unexpected VirusTotal report")
    attributes = data["attributes"]
    if not same_report_url(attributes["url"], url):
        return "unknown", "VirusTotal returned a record for a different URL spelling. Its verdict was omitted."
    stats = attributes.get("last_analysis_stats")
    if not stats:
        return "unknown", "VirusTotal has seen this URL but has no engine results available."
    counts = [stats[key] for key in ("malicious", "suspicious", "harmless", "undetected")]
    if any(type(n) is not int or n < 0 for n in counts):
        raise ValueError("Invalid VirusTotal engine counts")
    malicious, suspicious, _, _ = counts
    if not sum(counts):
        return "unknown", "VirusTotal has seen this URL but has no completed engine verdicts."
    reported = attributes.get("last_analysis_date")
    when = ""
    if type(reported) is int and 0 < reported < 253402300800:
        when = " on " + datetime.fromtimestamp(reported, timezone.utc).date().isoformat()
    return ("flagged" if malicious or suspicious else "known",
            f"In VirusTotal’s last report{when}, {malicious} engines marked this URL malicious and {suspicious} marked it suspicious.")


def same_report_url(reported, target):
    def parts(url):
        parsed = urlsplit(url)
        return parsed._replace(netloc=parsed.netloc.lower(), path=parsed.path or "/", fragment="")
    return parts(reported) == parts(target)


async def submit_urlscan(client, url):
    record = await read_record(client, "POST", "https://urlscan.io/api/v1/scan/",
                               json={"url": url, "visibility": "private"}, headers={"API-Key": URLSCAN_KEY})
    UUID(record["uuid"])


async def urlscan(client, url):
    # A quoted keyword is a literal Lucene phrase. Escape its delimiters.
    literal = url.replace("\\", "\\\\").replace('"', '\\"')
    headers = {"API-Key": URLSCAN_KEY}
    record = await read_record(client, "GET", "https://urlscan.io/api/v1/search/",
                               params={"q": f'task.url.keyword:"{literal}"', "size": 5}, headers=headers)
    rows = record["results"]
    if not isinstance(rows, list):
        raise ValueError("Invalid urlscan.io search response")
    # The index is case-insensitive, including paths. Check the actual submitted URL.
    for row in rows:
        task = row["task"]
        if not same_report_url(task["url"], url):
            continue
        date = datetime.fromisoformat(task["time"]).astimezone(timezone.utc).date()
        scan_id = UUID(task["uuid"])
        detail = f"urlscan.io previously scanned this URL on {date}."
        try:
            async with asyncio.timeout(1):
                report = await read_record(client, "GET", f"https://urlscan.io/api/v1/result/{scan_id}/",
                                           headers=headers, limit=2_000_000)
            if not same_report_url(report["task"]["url"], url) or UUID(report["task"]["uuid"]) != scan_id:
                raise ValueError("Different urlscan.io report")
            malicious = report["verdicts"]["overall"]["malicious"]
            if malicious is True:
                return "flagged", detail + " That scan flagged it as potentially malicious."
            if malicious is False:
                return "known", detail + " That scan did not flag it as malicious."
        except (TimeoutError, httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            pass
        return "known", detail + " Its verdict was unavailable."
    if type(record.get("total")) is int and record["total"] == len(rows) and not record.get("has_more"):
        detail = "urlscan.io found no previous scan of this URL in its searchable history."
        if URLSCAN_SUBMIT:
            detail += " " + background_scans.enqueue("urlscan.io", url, submit_urlscan)
        return "no_match", detail
    return "unknown", "urlscan.io search did not establish an exact URL match."
