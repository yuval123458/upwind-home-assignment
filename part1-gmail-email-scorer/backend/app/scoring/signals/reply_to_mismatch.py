"""Detects when the Reply-To header routes replies to a different domain than From.

Classic Business Email Compromise pattern:
    From:     ceo@legitcompany.com    (compromised account, passes SPF/DKIM/DMARC)
    Reply-To: ceo.private@attacker.net (where the attacker actually gets replies)

Auth headers can't catch this because the sending infrastructure is legitimate;
the deception is in the routing of replies.
"""

import re

from app.scoring.schemas import Signal

MAX_POINTS = 10

_EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _extract_domain(header: str | None) -> str | None:
    if not header:
        return None
    match = _EMAIL_PATTERN.search(header)
    if not match:
        return None
    return match.group(0).split("@", 1)[1].lower()


def _registrable(domain: str) -> str:
    """Crude approximation of registrable domain — last two labels.

    Good enough for the common single-TLD cases (.com, .net, .org). For .co.uk
    and similar this would over-match (treats 'foo.co.uk' as 'co.uk'), but is
    fine for the signal's purpose because false-negatives just mean we don't
    fire — we wouldn't over-fire.
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def compute(sender: str | None, reply_to: str | None) -> Signal | None:
    if not sender or not reply_to:
        return None

    sender_domain = _extract_domain(sender)
    reply_to_domain = _extract_domain(reply_to)
    if not sender_domain or not reply_to_domain:
        return None
    if sender_domain == reply_to_domain:
        return None

    if _registrable(sender_domain) == _registrable(reply_to_domain):
        return None  # Same registrable domain — e.g., support@bigcorp.com vs replies@bigcorp.com

    return Signal(
        name="reply_to_mismatch",
        points=MAX_POINTS,
        evidence=(
            f"Reply-To routes to {reply_to_domain!r} but the email claims to come from "
            f"{sender_domain!r}. Replies would not go to the apparent sender."
        ),
    )
