"""Hybrid Analysis v2 API client.

Looks up file SHA-256 hashes against Hybrid Analysis's sandboxed-behavior reports.
Complements VirusTotal: VT runs static AV signature matching across many engines,
while Hybrid Analysis actually executes the file in a sandbox and reports observed
runtime behavior (network calls, file writes, registry edits, process spawns, etc.).

Returns None when:
  - HYBRID_ANALYSIS_API_KEY not configured
  - No submissions exist for the hash (HA hasn't seen the file)
  - The API call fails

Free tier: 100 lookups/day. Responses cached in memory for 24h.
"""

import logging

import httpx
from cachetools import TTLCache
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_CACHE_TTL_SECONDS = 24 * 60 * 60
_CACHE_SIZE = 10_000
_USER_AGENT = "Email-Scorer/0.1"

_hash_cache: TTLCache[str, "HybridReport | None"] = TTLCache(
    maxsize=_CACHE_SIZE, ttl=_CACHE_TTL_SECONDS
)


class HybridReport(BaseModel):
    """A simplified view of Hybrid Analysis findings for a file hash."""

    verdict: str | None = None
    threat_score: int = 0
    submission_count: int = 0

    @property
    def is_malicious(self) -> bool:
        return self.verdict == "malicious" or self.threat_score >= 75

    @property
    def is_suspicious(self) -> bool:
        return self.verdict == "suspicious" or self.threat_score >= 50


async def lookup_file_hash(sha256: str) -> HybridReport | None:
    if not settings.hybrid_analysis_api_key:
        return None
    sha256 = sha256.lower()
    if sha256 in _hash_cache:
        return _hash_cache[sha256]

    result = await _post_hash(sha256)
    _hash_cache[sha256] = result
    return result


async def _post_hash(sha256: str) -> HybridReport | None:
    headers = {
        "api-key": settings.hybrid_analysis_api_key,
        "user-agent": _USER_AGENT,
        "accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT) as client:
            response = await client.post(
                "/search/hash", headers=headers, data={"hash": sha256}
            )
    except httpx.HTTPError as exc:
        logger.warning("Hybrid Analysis request failed: %s", exc)
        return None

    if response.status_code == 429:
        logger.warning("Hybrid Analysis rate-limited (429)")
        return None
    if response.status_code != 200:
        logger.warning(
            "Hybrid Analysis returned %s: %s", response.status_code, response.text[:200]
        )
        return None

    try:
        submissions = response.json()
    except ValueError as exc:
        logger.warning("Hybrid Analysis response not JSON: %s", exc)
        return None

    if not submissions:
        return None

    verdicts = [s.get("verdict") for s in submissions if s.get("verdict")]
    if "malicious" in verdicts:
        verdict = "malicious"
    elif "suspicious" in verdicts:
        verdict = "suspicious"
    elif "no specific threat" in verdicts:
        verdict = "clean"
    else:
        verdict = None

    threat_score = max(
        (s.get("threat_score") or 0 for s in submissions), default=0
    )

    return HybridReport(
        verdict=verdict,
        threat_score=threat_score,
        submission_count=len(submissions),
    )
