from typing import Literal

from pydantic import BaseModel, Field

Band = Literal["safe", "suspicious", "malicious"]


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
