"""Google Safe Browsing Lookup API v4.

Batched URL lookup: send up to 500 URLs in one request, get back a list of
matches. Distinct from VirusTotal — Safe Browsing is Google's curated feed,
focused on phishing / social engineering / malware distribution.

Returns: a dict mapping URL → threat type (string like 'SOCIAL_ENGINEERING'
or 'MALWARE'). URLs NOT in the dict are considered clean by Safe Browsing.

No data when SAFE_BROWSING_API_KEY is not configured — returns empty dict.
"""

import logging

import httpx
from cachetools import TTLCache

from app.config import settings

logger = logging.getLogger(__name__)

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_CACHE_TTL_SECONDS = 24 * 60 * 60
_CACHE_SIZE = 10_000

_url_cache: TTLCache[str, "str | None"] = TTLCache(
    maxsize=_CACHE_SIZE, ttl=_CACHE_TTL_SECONDS
)


async def lookup_urls(urls: list[str]) -> dict[str, str]:
    """Look up multiple URLs in one request. Returns {url: threat_type} for
    matches only. Caches per-URL for 24h."""
    if not settings.safe_browsing_api_key or not urls:
        if not settings.safe_browsing_api_key:
            print("        Safe Browsing skipped (no API key)")
        return {}

    # Split between cached and uncached.
    flagged: dict[str, str] = {}
    to_query: list[str] = []
    for url in urls:
        if url in _url_cache:
            cached = _url_cache[url]
            if cached:
                flagged[url] = cached
                print(f"        SB cache hit for {url}: {cached}")
        else:
            to_query.append(url)

    if not to_query:
        return flagged

    payload = {
        "client": {"clientId": "email-scorer", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in to_query],
        },
    }

    print(f"        SB lookup_urls: {len(to_query)} URL(s)")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(
                _ENDPOINT,
                params={"key": settings.safe_browsing_api_key},
                json=payload,
            )
    except httpx.HTTPError as exc:
        logger.warning("Safe Browsing request failed: %s", exc)
        return flagged

    if response.status_code != 200:
        logger.warning(
            "Safe Browsing returned %s: %s", response.status_code, response.text[:200]
        )
        # Don't cache failures — try again next time.
        return flagged

    try:
        data = response.json()
    except ValueError:
        return flagged

    matches = data.get("matches") or []
    matched_urls: set[str] = set()
    for m in matches:
        url = (m.get("threat") or {}).get("url")
        threat = m.get("threatType") or "UNKNOWN"
        if url:
            flagged[url] = threat
            _url_cache[url] = threat
            matched_urls.add(url)

    # Mark non-matched URLs as clean (cache them too, so we don't re-query)
    for url in to_query:
        if url not in matched_urls:
            _url_cache[url] = None

    if matches:
        print(f"        SB result: {len(matches)} flagged out of {len(to_query)}")
    return flagged
