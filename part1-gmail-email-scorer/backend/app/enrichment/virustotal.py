"""VirusTotal v3 API client.

Looks up URLs and file hashes against VT's aggregated multi-engine database.
Returns None when the API key isn't configured (so callers can no-op gracefully)
or when VT has no data on the given URL/hash (also common).

Free-tier limits: 4 requests/min, 500/day. Responses are cached in-memory for
24 hours to amortize the limit across scans.
"""

import base64
import logging

import httpx
from cachetools import TTLCache
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h
_CACHE_SIZE = 10_000

_url_cache: TTLCache[str, "VTReport | None"] = TTLCache(maxsize=_CACHE_SIZE, ttl=_CACHE_TTL_SECONDS)
_hash_cache: TTLCache[str, "VTReport | None"] = TTLCache(maxsize=_CACHE_SIZE, ttl=_CACHE_TTL_SECONDS)


class VTReport(BaseModel):
    """A simplified view of VirusTotal's analysis stats for one URL/hash."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    reputation: int = 0

    @property
    def is_malicious(self) -> bool:
        return self.malicious >= 3 or self.malicious + self.suspicious >= 5

    @property
    def detection_ratio(self) -> str:
        return f"{self.malicious + self.suspicious}/{self.total_engines}"


async def lookup_url(url: str) -> VTReport | None:
    """Look up a URL against VirusTotal. Returns None if no data or not configured."""
    if not settings.virustotal_api_key:
        print(f"        VT skipped (no API key) for {url}")
        return None
    if url in _url_cache:
        print(f"        VT cache hit for {url}: {_url_cache[url]}")
        return _url_cache[url]

    print(f"        VT lookup_url: {url}")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    result = await _get(f"/urls/{url_id}")
    print(f"        VT result for {url}: {result}")
    _url_cache[url] = result
    return result


async def lookup_file_hash(sha256: str) -> VTReport | None:
    """Look up a file SHA-256 hash against VirusTotal."""
    if not settings.virustotal_api_key:
        print(f"        VT skipped (no API key) for hash {sha256}")
        return None
    sha256 = sha256.lower()
    if sha256 in _hash_cache:
        print(f"        VT cache hit for hash {sha256}: {_hash_cache[sha256]}")
        return _hash_cache[sha256]

    print(f"        VT lookup_file_hash: {sha256}")
    result = await _get(f"/files/{sha256}")
    print(f"        VT result for hash {sha256}: {result}")
    _hash_cache[sha256] = result
    return result


async def _get(path: str) -> VTReport | None:
    headers = {"x-apikey": settings.virustotal_api_key, "accept": "application/json"}
    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT) as client:
            response = await client.get(path, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("VirusTotal request failed: %s", exc)
        return None

    if response.status_code == 404:
        return None  # VT has no data on this URL/hash — common, not an error
    if response.status_code == 429:
        logger.warning("VirusTotal rate-limited (429)")
        return None
    if response.status_code != 200:
        logger.warning("VirusTotal returned %s: %s", response.status_code, response.text[:200])
        return None

    try:
        data = response.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
    except (KeyError, ValueError) as exc:
        logger.warning("VirusTotal response missing fields: %s", exc)
        return None

    return VTReport(
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total_engines=sum(stats.values()),
        reputation=data.get("reputation", 0),
    )
