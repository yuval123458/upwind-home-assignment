from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, desc, select

from app.auth.dependencies import get_current_user
from app.db.models import ScanHistory, User
from app.db.session import get_session
from app.scoring.schemas import HistoryEntry

router = APIRouter(tags=["history"])


@router.get("/history", response_model=list[HistoryEntry])
def list_history(
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[ScanHistory]:
    rows = session.exec(
        select(ScanHistory)
        .where(ScanHistory.user_id == user.id)
        .order_by(desc(ScanHistory.scanned_at))
        .limit(limit)
    ).all()
    return list(rows)
