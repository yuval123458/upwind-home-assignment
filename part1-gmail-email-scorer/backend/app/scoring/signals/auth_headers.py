"""Parses SPF / DKIM / DMARC results from the Authentication-Results header.

This signal fires when any auth check returns a non-pass result. Each failed
check contributes points; a DMARC fail under a strict policy (reject/quarantine)
bumps the contribution to the signal's maximum.
"""

import re

from app.scoring.schemas import Signal

MAX_POINTS = 25
PER_FAIL_POINTS = 9
FAIL_RESULTS = {"fail", "softfail", "permerror"}
STRICT_DMARC_POLICIES = {"reject", "quarantine"}


def compute(authentication_results: str | None) -> Signal | None:
    if not authentication_results:
        return None

    text = authentication_results.lower()
    spf = _parse_result(text, "spf")
    dkim = _parse_result(text, "dkim")
    dmarc = _parse_result(text, "dmarc")
    dmarc_policy = _parse_dmarc_policy(text)

    fails = [
        method
        for method, result in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc))
        if result in FAIL_RESULTS
    ]
    if not fails:
        return None

    points = min(MAX_POINTS, len(fails) * PER_FAIL_POINTS)
    if dmarc in FAIL_RESULTS and dmarc_policy in STRICT_DMARC_POLICIES:
        points = MAX_POINTS

    parts: list[str] = []
    if spf:
        parts.append(f"SPF={spf}")
    if dkim:
        parts.append(f"DKIM={dkim}")
    if dmarc:
        parts.append(f"DMARC={dmarc}")
    if dmarc_policy:
        parts.append(f"policy={dmarc_policy}")
    evidence = "Auth failures: " + ", ".join(fails) + " (" + "; ".join(parts) + ")"

    return Signal(name="auth_headers", points=points, evidence=evidence)


def _parse_result(text: str, method: str) -> str | None:
    match = re.search(rf"\b{method}\s*=\s*([a-z]+)", text)
    return match.group(1) if match else None


def _parse_dmarc_policy(text: str) -> str | None:
    match = re.search(r"\bp\s*=\s*([a-z]+)", text)
    return match.group(1) if match else None
