from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Band = Literal["safe", "suspicious", "malicious"]


class SenderHistory(BaseModel):
    scan_count: int = Field(..., description="Number of prior scans for this sender (excludes current)")
    last_band: Band | None = Field(None, description="Band of the most recent prior scan for this sender")


class HistoryEntry(BaseModel):
    id: int
    message_id: str
    subject: str | None = None
    sender: str | None = None
    score: int
    band: Band
    scanned_at: datetime


class AttachmentMeta(BaseModel):
    name: str
    mime_type: str | None = None
    size: int | None = None
    sha256: str = Field(..., description="Lowercase hex SHA-256 of the attachment bytes")


class ScoreRequest(BaseModel):
    message_id: str = Field(..., description="Gmail message ID")
    subject: str | None = None
    sender: str | None = Field(None, description="Value of the From: header")
    reply_to: str | None = None
    body_plain: str | None = None
    body_html: str | None = None
    authentication_results: str | None = Field(
        None, description="Value of the Authentication-Results header"
    )
    attachments: list[AttachmentMeta] = Field(default_factory=list)


class Signal(BaseModel):
    name: str
    points: int
    evidence: str


class ScoreResponse(BaseModel):
    score: int = Field(..., ge=0, le=100)
    band: Band
    signals: list[Signal]
    explanation: str
    recommendation: str
    sender_history: SenderHistory | None = None
