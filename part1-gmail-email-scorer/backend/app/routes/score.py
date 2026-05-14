import asyncio
import json

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, desc, select

from app.auth.dependencies import get_current_user
from app.db.models import ScanHistory, User
from app.db.session import get_session
from app.rate_limit import limiter
from app.routes.blocklist import extract_sender_email
from app.routes.settings import get_sensitivity, thresholds_for
from app.scoring.schemas import ScoreRequest, ScoreResponse, SenderHistory, Signal
from app.scoring.signals import (
    attachment_reputation,
    auth_headers,
    domain_age,
    link_anchor_mismatch,
    llm_content,
    reply_to_mismatch,
    url_reputation,
)

router = APIRouter(tags=["scoring"])


@router.post("/score", response_model=ScoreResponse)
@limiter.limit("30/minute")
async def score(
    request: Request,
    req: ScoreRequest,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> ScoreResponse:
    print(f"\n=== /score request: msg={req.message_id} sender={req.sender!r}")
    signals: list[Signal] = []
    sender_email = extract_sender_email(req.sender or "")

    sender_history: SenderHistory | None = None
    if sender_email:
        prior_scans = session.exec(
            select(ScanHistory)
            .where(ScanHistory.user_id == user.id, ScanHistory.sender == sender_email)
            .order_by(desc(ScanHistory.scanned_at))
        ).all()
        if prior_scans:
            sender_history = SenderHistory(
                scan_count=len(prior_scans),
                last_band=prior_scans[0].band,  # type: ignore[arg-type]
            )
            print(f"    sender_history: {len(prior_scans)} prior, last_band={prior_scans[0].band}")
        else:
            print(f"    sender_history: no prior scans from {sender_email!r}")

    auth_signal = auth_headers.compute(req.authentication_results)
    print(f"    auth_headers:   {auth_signal.evidence if auth_signal else 'pass (no failures detected)'}")
    if auth_signal is not None:
        signals.append(auth_signal)

    reply_to_signal = reply_to_mismatch.compute(req.sender, req.reply_to)
    print(f"    reply_to:       {reply_to_signal.evidence if reply_to_signal else 'matches sender domain'}")
    if reply_to_signal is not None:
        signals.append(reply_to_signal)

    link_signal = link_anchor_mismatch.compute(req.body_html)
    print(f"    link_mismatch:  {link_signal.evidence if link_signal else 'no mismatches'}")
    if link_signal is not None:
        signals.append(link_signal)

    url_signal, llm_signal, attachment_signal, domain_age_signal = await asyncio.gather(
        url_reputation.compute(req.body_html, req.body_plain),
        llm_content.compute(req.subject, req.sender, req.body_plain, req.body_html),
        attachment_reputation.compute(req.attachments),
        domain_age.compute(req.sender),
    )
    print(f"    url_reputation: {url_signal.evidence if url_signal else 'no flagged URLs'}")
    if url_signal is not None:
        signals.append(url_signal)
    print(f"    llm_content:    {llm_signal.evidence if llm_signal else 'no LLM signal'}")
    if llm_signal is not None:
        signals.append(llm_signal)
    print(f"    attachment_rep: {attachment_signal.evidence if attachment_signal else 'no flagged attachments'}")
    if attachment_signal is not None:
        signals.append(attachment_signal)
    print(f"    domain_age:     {domain_age_signal.evidence if domain_age_signal else 'sender domain not flagged as young'}")
    if domain_age_signal is not None:
        signals.append(domain_age_signal)

    total = sum(s.points for s in signals)
    score_value = min(total, 100)

    sensitivity = get_sensitivity(user.id, session)  # type: ignore[arg-type]
    suspicious_min, malicious_min = thresholds_for(sensitivity)
    band = (
        "malicious"
        if score_value >= malicious_min
        else "suspicious"
        if score_value >= suspicious_min
        else "safe"
    )
    print(
        f"=== /score result: score={score_value} band={band} "
        f"sensitivity={sensitivity} thresholds=({suspicious_min},{malicious_min}) "
        f"fired={[s.name for s in signals]}\n"
    )

    history_row = ScanHistory(
        user_id=user.id,  # type: ignore[arg-type]
        message_id=req.message_id,
        subject=req.subject,
        sender=sender_email or None,
        score=score_value,
        band=band,
        signals_json=json.dumps([s.model_dump() for s in signals]),
    )
    session.add(history_row)
    session.commit()

    if not signals:
        signals.append(
            Signal(
                name="no_findings",
                points=0,
                evidence="No signals fired. Currently active: auth headers, URL reputation, content analysis, and attachment reputation.",
            )
        )

    explanation = (
        f"{len([s for s in signals if s.points > 0])} signal(s) contributed {score_value} points."
        if score_value > 0
        else "No malicious indicators detected by the currently-active signals."
    )
    recommendation = {
        "malicious": "Do not click links, open attachments, or reply. Report as phishing.",
        "suspicious": "Treat with caution. Verify sender via another channel before acting.",
        "safe": "No action needed.",
    }[band]

    return ScoreResponse(
        score=score_value,
        band=band,
        signals=signals,
        explanation=explanation,
        recommendation=recommendation,
        sender_history=sender_history,
    )
