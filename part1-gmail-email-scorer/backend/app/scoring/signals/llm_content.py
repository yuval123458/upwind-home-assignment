"""LLM-derived content signal.

Calls Claude to extract structured observations from the email body, then
maps those observations to point contributions deterministically. The LLM
never decides the score itself — it only reports what it sees.
"""

import re
from html import unescape

from app.llm.client import extract_content_signals
from app.scoring.schemas import Signal

MAX_POINTS = 60

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_OUTLOOK_CONDITIONAL_RE = re.compile(r"<!--\[if[^>]*?>.*?<!\[endif\]-->", re.DOTALL | re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _html_to_text(html: str | None) -> str:
    """Strip HTML markup to visible text. Removes scripts/styles/Outlook conditional
    blocks first (their contents are noise), then all remaining tags, then decodes
    HTML entities and collapses whitespace. Phishing HTML often hides the actual
    phishing prose under 10–20KB of nested tables and inline CSS; stripping lets
    the LLM see the content."""
    if not html:
        return ""
    cleaned = _SCRIPT_STYLE_RE.sub(" ", html)
    cleaned = _OUTLOOK_CONDITIONAL_RE.sub(" ", cleaned)
    cleaned = _TAG_RE.sub(" ", cleaned)
    cleaned = unescape(cleaned)
    return _WHITESPACE_RE.sub(" ", cleaned).strip()


async def compute(
    subject: str | None,
    sender: str | None,
    body_plain: str | None,
    body_html: str | None,
) -> Signal | None:
    # Prefer whichever source yields more content. Many phishing emails ship
    # an HTML-only body (no plain part), and many multipart emails include a
    # minimal "this message is in HTML" plain part that hides the real content.
    text_plain = (body_plain or "").strip()
    text_from_html = _html_to_text(body_html)
    body = text_from_html if len(text_from_html) > len(text_plain) else text_plain

    obs = await extract_content_signals(subject, sender, body)
    if obs is None:
        return None

    points = 0
    reasons: list[str] = []

    if obs.credential_request:
        points += 16
        reasons.append("credential request")
    if obs.payment_request:
        points += 12
        reasons.append("payment/money request")
    if obs.urgency_score >= 0.7:
        points += 12
        reasons.append(f"high urgency ({obs.urgency_score:.2f})")
    elif obs.urgency_score >= 0.4:
        points += 6
        reasons.append(f"moderate urgency ({obs.urgency_score:.2f})")
    if obs.impersonation_target:
        points += 16
        reasons.append(f"impersonates {obs.impersonation_target!r}")
    if obs.authority_pressure:
        points += 8
        reasons.append("authority pressure")
    if obs.tone_mismatch:
        points += 8
        reasons.append("tone mismatch")
    if obs.advance_fee_pattern:
        points += 16
        reasons.append("advance-fee / 419 pattern")
    if obs.unsolicited_offer_or_reward:
        points += 10
        reasons.append("unsolicited offer or reward bait")
    if obs.out_of_band_reply_request:
        points += 10
        reasons.append("reply via out-of-band channel")
    if obs.suspicious_link_or_attachment_action:
        points += 8
        reasons.append("pressure to click link / open attachment")
    if obs.generic_recipient:
        points += 4
        reasons.append("generic recipient (mass-target)")

    points = min(points, MAX_POINTS)

    if points == 0 and not obs.tactics:
        return None

    evidence_parts: list[str] = []
    if reasons:
        evidence_parts.append(", ".join(reasons))
    if obs.tactics:
        evidence_parts.append("tactics: " + ", ".join(obs.tactics))

    return Signal(
        name="llm_content",
        points=points,
        evidence=" — ".join(evidence_parts) or "content observations only",
    )
