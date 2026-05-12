import asyncio

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.auth.dependencies import get_current_user
from app.db.models import BlocklistEntry, User
from app.db.session import get_session
from app.routes.blocklist import extract_sender_email
from app.scoring.schemas import ScoreRequest, ScoreResponse, Signal
from app.scoring.signals import auth_headers, llm_content, url_reputation

router = APIRouter(tags=["scoring"])


@router.post("/score", response_model=ScoreResponse)
async def score(
    req: ScoreRequest,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> ScoreResponse:
    print(f"\n=== /score request: msg={req.message_id} sender={req.sender!r}")
    signals: list[Signal] = []

    sender_email = extract_sender_email(req.sender or "")
    if sender_email:
        hit = session.exec(
            select(BlocklistEntry).where(
                BlocklistEntry.user_id == user.id,
                BlocklistEntry.value == sender_email,
            )
        ).first()
        print(f"    blocklist:      {'HIT' if hit else 'miss'} (sender={sender_email!r})")
        if hit is not None:
            signals.append(
                Signal(
                    name="blocklist",
                    points=50,
                    evidence=f"Sender {sender_email!r} is on your blocklist.",
                )
            )

    auth_signal = auth_headers.compute(req.authentication_results)
    print(f"    auth_headers:   {auth_signal.evidence if auth_signal else 'pass (no failures detected)'}")
    if auth_signal is not None:
        signals.append(auth_signal)

    url_signal, llm_signal = await asyncio.gather(
        url_reputation.compute(req.body_html, req.body_plain),
        llm_content.compute(req.subject, req.sender, req.body_plain, req.body_html),
    )
    print(f"    url_reputation: {url_signal.evidence if url_signal else 'no flagged URLs'}")
    if url_signal is not None:
        signals.append(url_signal)
    print(f"    llm_content:    {llm_signal.evidence if llm_signal else 'no LLM signal'}")
    if llm_signal is not None:
        signals.append(llm_signal)

    total = sum(s.points for s in signals)
    score_value = min(total, 100)
    band = "malicious" if score_value >= 60 else "suspicious" if score_value >= 30 else "safe"
    print(f"=== /score result: score={score_value} band={band} fired={[s.name for s in signals]}\n")

    if not signals:
        signals.append(
            Signal(
                name="no_findings",
                points=0,
                evidence="No signals fired. More signals (LLM, more enrichments) are wired up next.",
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
    )
