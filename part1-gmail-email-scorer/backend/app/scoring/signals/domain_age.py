"""Domain-age signal — fires for senders on very young domains.

Phishing campaigns frequently register fresh look-alike domains (paypa1.com,
microsoft-secure.ru) days or hours before a campaign launches. Reputation
databases like VirusTotal and Safe Browsing typically don't have data on
brand-new domains yet, leaving a gap. This signal fills that gap by querying
RDAP for the registration date and flagging anything very young.
"""

import re

from app.enrichment.whois_rdap import get_domain_age_days
from app.scoring.schemas import Signal

VERY_YOUNG_DAYS = 7
YOUNG_DAYS = 30
POINTS_VERY_YOUNG = 15
POINTS_YOUNG = 8

_EMAIL_PATTERN = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")


def _extract_domain(sender: str | None) -> str | None:
    if not sender:
        return None
    match = _EMAIL_PATTERN.search(sender)
    return match.group(1).lower() if match else None


async def compute(sender: str | None) -> Signal | None:
    domain = _extract_domain(sender)
    if not domain:
        return None

    age = await get_domain_age_days(domain)
    if age is None:
        return None  # RDAP didn't tell us — skip silently

    if age < VERY_YOUNG_DAYS:
        return Signal(
            name="domain_age",
            points=POINTS_VERY_YOUNG,
            evidence=f"Sender domain {domain!r} was registered {age} day(s) ago — extremely new.",
        )
    if age < YOUNG_DAYS:
        return Signal(
            name="domain_age",
            points=POINTS_YOUNG,
            evidence=f"Sender domain {domain!r} was registered {age} days ago — newly created.",
        )
    return None
