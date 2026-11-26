"""Best-effort scan submissions for a single worker. Keep URLs only while sending."""

import asyncio
from hashlib import sha256
import logging
from time import monotonic

import httpx

import enrichment_http

logger = logging.getLogger("uvicorn.error")
active = set()
recent = {}
COOLDOWN = 600


def enqueue(provider, target, submit):
    _, note = enqueue_with_receipt(provider, target, submit)
    return note


def enqueue_with_receipt(provider, target, submit):
    """Share the background submission with callers that need its provider receipt."""
    key = (provider, sha256(target.encode()).digest())
    now = monotonic()
    for expired in [item for item, (until, _) in recent.items() if until <= now]:
        del recent[expired]
    if key in recent:
        return recent[key][1], "A scan was already queued recently. Check again later."
    if len(active) >= 8 or len(recent) >= 1024:
        return None, "The background scan queue was busy."
    task = asyncio.create_task(send(provider, target, submit))
    recent[key] = now + COOLDOWN, task
    active.add(task)
    task.add_done_callback(active.discard)
    return task, "A background scan was queued. Check again later for a report."


async def send(provider, target, submit):
    try:
        async with asyncio.timeout(6), enrichment_http.client(provider, timeout=5) as client:
            receipt = await submit(client, target)
        logger.info("Background scan provider=%s status=accepted", provider)
        return receipt
    except enrichment_http.RateLimited:
        logger.info("Background scan provider=%s status=unavailable reason=rate_limit", provider)
    except httpx.HTTPStatusError as error:
        logger.warning("Background scan provider=%s http_status=%d", provider, error.response.status_code)
    except Exception as error:
        logger.warning("Background scan provider=%s status=unconfirmed error_type=%s", provider, type(error).__name__)


async def shutdown():
    tasks = list(active)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    recent.clear()
