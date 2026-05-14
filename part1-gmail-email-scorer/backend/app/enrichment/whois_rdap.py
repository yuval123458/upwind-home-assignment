"""RDAP-based domain age lookup.

RDAP (Registration Data Access Protocol) is the IETF-standard replacement for
WHOIS. We hit `https://rdap.org/domain/{domain}` (a free public bootstrap
service that proxies to the authoritative registrar). No API key required.

Returns the age in days of the domain, or None if we can't determine it.
Cached for 24h since registration dates don't change minute-to-minute.
"""

import logging
from datetime import datetime, timezone

import httpx
from cachetools import TTLCache

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(8.0, connect=4.0)
_CACHE_TTL_SECONDS = 24 * 60 * 60
_CACHE_SIZE = 5_000

_age_cache: TTLCache[str, "int | None"] = TTLCache(
    maxsize=_CACHE_SIZE, ttl=_CACHE_TTL_SECONDS
)


def _registrable(domain: str) -> str:
    """Crude approximation — last two labels. Good for .com/.net/.org;
    over-matches for .co.uk style TLDs but RDAP usually handles either."""
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


async def get_domain_age_days(domain: str) -> int | None:
    if not domain:
        return None
    reg_domain = _registrable(domain)
    if reg_domain in _age_cache:
        print(f"        RDAP cache hit for {reg_domain}: {_age_cache[reg_domain]} days")
        return _age_cache[reg_domain]

    print(f"        RDAP lookup: {reg_domain}")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(f"https://rdap.org/domain/{reg_domain}")
    except httpx.HTTPError as exc:
        logger.warning("RDAP request failed for %s: %s", reg_domain, exc)
        _age_cache[reg_domain] = None
        return None

    if response.status_code != 200:
        print(f"        RDAP returned {response.status_code} for {reg_domain}")
        _age_cache[reg_domain] = None
        return None

    try:
        data = response.json()
    except ValueError:
        _age_cache[reg_domain] = None
        return None

    # RDAP events list — look for "registration" event
    events = data.get("events") or []
    for event in events:
        if event.get("eventAction") == "registration":
            event_date_str = event.get("eventDate")
            if not event_date_str:
                continue
            try:
                # Handle both "2024-01-15T00:00:00Z" and "2024-01-15T00:00:00+00:00"
                registered = datetime.fromisoformat(event_date_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue
            now = datetime.now(timezone.utc)
            if registered.tzinfo is None:
                registered = registered.replace(tzinfo=timezone.utc)
            age = (now - registered).days
            print(f"        RDAP result for {reg_domain}: registered {event_date_str}, age={age} days")
            _age_cache[reg_domain] = age
            return age

    _age_cache[reg_domain] = None
    return None
