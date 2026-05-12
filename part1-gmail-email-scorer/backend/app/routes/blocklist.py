import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.auth.dependencies import get_current_user
from app.db.models import BlocklistEntry, User
from app.db.session import get_session

router = APIRouter(prefix="/blocklist", tags=["blocklist"])

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def extract_sender_email(raw: str) -> str:
    """Extract the email from a header value like 'Display Name <foo@bar.com>'."""
    if not raw:
        return ""
    match = _EMAIL_RE.search(raw)
    return match.group(0).lower() if match else raw.strip().lower()


class BlocklistEntryIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=320)
    gmail_filter_id: str | None = Field(None, max_length=128)


class BlocklistEntryOut(BaseModel):
    id: int
    value: str
    gmail_filter_id: str | None


@router.get("", response_model=list[BlocklistEntryOut])
def list_entries(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[BlocklistEntry]:
    rows = session.exec(
        select(BlocklistEntry).where(BlocklistEntry.user_id == user.id)
    ).all()
    return list(rows)


@router.post("", response_model=BlocklistEntryOut, status_code=status.HTTP_201_CREATED)
def add_entry(
    entry: BlocklistEntryIn,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> BlocklistEntry:
    normalized = extract_sender_email(entry.value)
    existing = session.exec(
        select(BlocklistEntry).where(
            BlocklistEntry.user_id == user.id, BlocklistEntry.value == normalized
        )
    ).first()
    if existing is not None:
        if entry.gmail_filter_id and existing.gmail_filter_id != entry.gmail_filter_id:
            existing.gmail_filter_id = entry.gmail_filter_id
            session.add(existing)
            session.commit()
            session.refresh(existing)
        return existing

    row = BlocklistEntry(
        user_id=user.id,  # type: ignore[arg-type]
        value=normalized,
        gmail_filter_id=entry.gmail_filter_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_entry(
    entry_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> None:
    row = session.get(BlocklistEntry, entry_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    session.delete(row)
    session.commit()
