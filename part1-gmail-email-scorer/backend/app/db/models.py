from datetime import datetime

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    google_sub: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BlocklistEntry(SQLModel, table=True):
    __tablename__ = "blocklist_entries"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    value: str = Field(index=True)
    gmail_filter_id: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanHistory(SQLModel, table=True):
    __tablename__ = "scan_history"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    message_id: str = Field(index=True)
    subject: str | None = None
    sender: str | None = Field(default=None, index=True)
    score: int
    band: str
    signals_json: str
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
