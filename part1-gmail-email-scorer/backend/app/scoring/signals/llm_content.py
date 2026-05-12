"""LLM-derived content signal.

Calls Claude to extract structured observations from the email body, then
maps those observations to point contributions deterministically. The LLM
never decides the score itself — it only reports what it sees.
"""

from app.llm.client import extract_content_signals
from app.scoring.schemas import Signal

MAX_POINTS = 30


async def compute(
    subject: str | None,
    sender: str | None,
    body_plain: str | None,
    body_html: str | None,
) -> Signal | None:
    body = body_plain or body_html
    obs = await extract_content_signals(subject, sender, body)
    if obs is None:
        return None

    points = 0
    reasons: list[str] = []

    if obs.credential_request:
        points += 8
        reasons.append("credential request")
    if obs.payment_request:
        points += 6
        reasons.append("payment/money request")
    if obs.urgency_score >= 0.7:
        points += 6
        reasons.append(f"high urgency ({obs.urgency_score:.2f})")
    elif obs.urgency_score >= 0.4:
        points += 3
        reasons.append(f"moderate urgency ({obs.urgency_score:.2f})")
    if obs.impersonation_target:
        points += 8
        reasons.append(f"impersonates {obs.impersonation_target!r}")
    if obs.authority_pressure:
        points += 4
        reasons.append("authority pressure")
    if obs.tone_mismatch:
        points += 4
        reasons.append("tone mismatch")

    points = min(points, MAX_POINTS)

    if points == 0 and not obs.tactics:
        return None

    evidence_parts: list[str] = []
    if reasons:
        evidence_parts.append(", ".join(reasons))
    if obs.tactics:
        evidence_parts.append("tactics: " + ", ".join(obs.tactics))
    evidence_parts.append(obs.summary)

    return Signal(
        name="llm_content",
        points=points,
        evidence=" — ".join(evidence_parts),
    )
