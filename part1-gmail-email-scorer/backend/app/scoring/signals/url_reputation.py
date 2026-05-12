"""URL reputation signal — looks up email URLs against VirusTotal."""

import asyncio
import re

from app.enrichment.virustotal import VTReport, lookup_url
from app.scoring.schemas import Signal

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)\"'"
_MAX_URLS = 5  # stay under VT free tier 4/min and keep latency bounded
_MAX_POINTS = 20


def extract_urls(*texts: str | None) -> list[str]:
    """Pull unique URLs out of the given texts, preserving first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in _URL_REGEX.finditer(text):
            url = match.group(0).rstrip(_TRAILING_PUNCT)
            if url not in seen:
                seen.add(url)
                ordered.append(url)
            if len(ordered) >= _MAX_URLS:
                return ordered
    return ordered


async def compute(body_html: str | None, body_plain: str | None) -> Signal | None:
    urls = extract_urls(body_html, body_plain)
    print(f"    url_reputation: extracted {len(urls)} URL(s): {urls}")
    if not urls:
        return None

    reports = await asyncio.gather(*[lookup_url(u) for u in urls])

    flagged: list[tuple[str, VTReport]] = [
        (u, r) for u, r in zip(urls, reports, strict=False) if r is not None and r.is_malicious
    ]
    if not flagged:
        return None

    points = min(_MAX_POINTS, len(flagged) * 10)
    parts = [f"{u} ({r.detection_ratio} engines)" for u, r in flagged[:3]]
    if len(flagged) > 3:
        parts.append(f"(+{len(flagged) - 3} more)")

    return Signal(
        name="url_reputation",
        points=points,
        evidence="VirusTotal flagged: " + "; ".join(parts),
    )
