"""Attachment reputation signal.

For each attachment hash on the scanned email, looks the hash up against:
  - VirusTotal (static multi-engine AV scan)
  - Hybrid Analysis (sandboxed behavior analysis)

If either source reports malicious findings, the attachment is flagged. Both
sources are queried in parallel and complement each other — static AV catches
known signatures, sandbox catches novel behavior.
"""

import asyncio

from app.enrichment.hybrid_analysis import HybridReport
from app.enrichment.hybrid_analysis import lookup_file_hash as ha_lookup
from app.enrichment.virustotal import VTReport
from app.enrichment.virustotal import lookup_file_hash as vt_lookup
from app.scoring.schemas import AttachmentMeta, Signal

_MAX_POINTS = 25
_POINTS_PER_FLAGGED = 15


async def compute(attachments: list[AttachmentMeta]) -> Signal | None:
    if not attachments:
        return None

    pairs = await asyncio.gather(
        *[
            asyncio.gather(vt_lookup(att.sha256), ha_lookup(att.sha256))
            for att in attachments
        ]
    )

    flagged: list[tuple[AttachmentMeta, VTReport | None, HybridReport | None]] = []
    for att, (vt_report, ha_report) in zip(attachments, pairs, strict=False):
        vt_hit = vt_report is not None and vt_report.is_malicious
        ha_hit = ha_report is not None and ha_report.is_malicious
        if vt_hit or ha_hit:
            flagged.append((att, vt_report, ha_report))

    if not flagged:
        return None

    points = min(_MAX_POINTS, len(flagged) * _POINTS_PER_FLAGGED)
    parts: list[str] = []
    for att, vt_report, ha_report in flagged[:3]:
        sources: list[str] = []
        if vt_report is not None and vt_report.is_malicious:
            sources.append(f"VT {vt_report.detection_ratio}")
        if ha_report is not None and ha_report.is_malicious:
            sources.append(f"HA verdict={ha_report.verdict!r} threat={ha_report.threat_score}")
        parts.append(f"{att.name} ({'; '.join(sources)})")
    if len(flagged) > 3:
        parts.append(f"(+{len(flagged) - 3} more)")

    return Signal(
        name="attachment_reputation",
        points=points,
        evidence="Malicious attachment(s): " + "; ".join(parts),
    )
