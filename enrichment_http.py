"""HTTP clients for optional sources. A quota response pauses new requests without waiting."""

from email.utils import parsedate_to_datetime
from time import monotonic, time

import httpx

# One deadline per provider, shared across checks in this worker. Never store submitted URLs.
retry_at = {}


class RateLimited(httpx.HTTPError):
    pass


def retry_delay(header):
    if header:
        try:
            if header.isascii() and header.isdecimal():
                return min(int(header), 86_400)
            date = parsedate_to_datetime(header)
            if date.tzinfo is not None:
                return max(0, min(date.timestamp() - time(), 86_400))
        except (ValueError, TypeError, OverflowError, OSError):
            pass
    return 60


def client(provider, **options):
    async def before_request(request):
        if monotonic() < retry_at.get(provider, 0):
            raise RateLimited("Provider rate limit")

    async def after_response(response):
        if response.status_code == 429:
            until = monotonic() + retry_delay(response.headers.get("Retry-After"))
            retry_at[provider] = max(until, retry_at.get(provider, 0))
            raise RateLimited("Provider rate limit")

    return httpx.AsyncClient(**options, follow_redirects=False,
                             event_hooks={"request": [before_request], "response": [after_response]})
