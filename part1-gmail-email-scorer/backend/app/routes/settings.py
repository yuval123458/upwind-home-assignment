from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session

from app.auth.dependencies import get_current_user
from app.db.models import User, UserSettings
from app.db.session import get_session

router = APIRouter(prefix="/settings", tags=["settings"])

Sensitivity = Literal["low", "medium", "high"]

DEFAULT_SENSITIVITY: Sensitivity = "medium"


class SettingsOut(BaseModel):
    sensitivity: Sensitivity


class SettingsUpdate(BaseModel):
    sensitivity: Sensitivity


def get_sensitivity(user_id: int, session: Session) -> Sensitivity:
    """Read a user's sensitivity preference, defaulting to medium when no row exists."""
    row = session.get(UserSettings, user_id)
    if row is None:
        return DEFAULT_SENSITIVITY
    if row.sensitivity in ("low", "medium", "high"):
        return row.sensitivity  # type: ignore[return-value]
    return DEFAULT_SENSITIVITY


def thresholds_for(sensitivity: Sensitivity) -> tuple[int, int]:
    """Return (suspicious_min, malicious_min) thresholds for a sensitivity level.

    - low: 40 / 70 — fewer flags, only strong evidence pushes a band change
    - medium: 30 / 60 — default
    - high: 20 / 50 — more sensitive, smaller signals can shift band
    """
    if sensitivity == "low":
        return 40, 70
    if sensitivity == "high":
        return 20, 50
    return 30, 60


@router.get("", response_model=SettingsOut)
def read_settings(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> SettingsOut:
    return SettingsOut(sensitivity=get_sensitivity(user.id, session))  # type: ignore[arg-type]


@router.patch("", response_model=SettingsOut)
def update_settings(
    update: SettingsUpdate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> SettingsOut:
    row = session.get(UserSettings, user.id)
    if row is None:
        row = UserSettings(user_id=user.id, sensitivity=update.sensitivity)  # type: ignore[arg-type]
    else:
        row.sensitivity = update.sensitivity
        row.updated_at = datetime.utcnow()
    session.add(row)
    session.commit()
    session.refresh(row)
    return SettingsOut(sensitivity=row.sensitivity)  # type: ignore[arg-type]
