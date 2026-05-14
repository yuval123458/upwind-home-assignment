"""URL reputation signal — looks up email URLs against VirusTotal AND Google Safe Browsing.

Two independent sources:
  - VirusTotal aggregates ~90 AV engines (multi-engine signature scan)
  - Safe Browsing is Google's curated phishing/malware feed

A URL is flagged if EITHER source reports malicious. Sources complement each
other — Safe Browsing tends to catch fresh phishing campaigns Google has seen;
VirusTotal catches anything in the broader AV consensus.
"""

import asyncio
import re

from app.enrichment.safe_browsing import lookup_urls as sb_lookup_urls
from app.enrichment.virustotal import VTReport, lookup_url
from app.scoring.schemas import Signal

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)\"'"
_MAX_URLS = 5
_MAX_POINTS = 25


def extract_urls(*texts: str | None) -> list[str]:
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
    if not urls:
        return None

    # Run VirusTotal lookups + Safe Browsing batch in parallel.
    vt_task = asyncio.gather(*[lookup_url(u) for u in urls])
    sb_task = sb_lookup_urls(urls)
    vt_reports, sb_flagged = await asyncio.gather(vt_task, sb_task)

    flagged: list[tuple[str, VTReport | None, str | None]] = []
    for url, vt_report in zip(urls, vt_reports, strict=False):
        sb_threat = sb_flagged.get(url)
        vt_hit = vt_report is not None and vt_report.is_malicious
        if vt_hit or sb_threat:
            flagged.append((url, vt_report, sb_threat))

    if not flagged:
        return None

    points = min(_MAX_POINTS, len(flagged) * 15)
    parts: list[str] = []
    for url, vt_report, sb_threat in flagged[:3]:
        sources: list[str] = []
        if vt_report and vt_report.is_malicious:
            sources.append(f"VT {vt_report.detection_ratio}")
        if sb_threat:
            sources.append(f"Safe Browsing: {sb_threat}")
        parts.append(f"{url} ({', '.join(sources)})")
    if len(flagged) > 3:
        parts.append(f"(+{len(flagged) - 3} more)")

    return Signal(
        name="url_reputation",
        points=points,
        evidence="Flagged URL(s): " + "; ".join(parts),
    )
