from pydantic import BaseModel, Field


class ContentSignals(BaseModel):
    """Structured observations the LLM extracts from an email body.

    The LLM is asked to OBSERVE and REPORT, not to score or judge. The scoring
    engine maps these observations to point contributions deterministically.
    """

    urgency_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="How urgent the language sounds. 0 = no urgency cues, 1 = extreme manufactured urgency (countdowns, deadlines, threats of imminent loss).",
    )
    credential_request: bool = Field(
        ...,
        description="True if the email asks the recipient to verify, enter, or confirm login credentials, passwords, security codes, MFA codes, or similar.",
    )
    payment_request: bool = Field(
        ...,
        description="True if the email asks for a wire transfer, gift card purchase, cryptocurrency payment, invoice settlement, or other money movement.",
    )
    impersonation_target: str | None = Field(
        None,
        description="Brand, company, role, or person the email is pretending to be from (e.g., 'Microsoft', 'IRS', 'your CEO'). Null if no clear impersonation.",
    )
    authority_pressure: bool = Field(
        ...,
        description="True if the email leans on authority claims (CEO request, IT department, legal team, government agency) to pressure the recipient.",
    )
    tone_mismatch: bool = Field(
        ...,
        description="True if the writing style doesn't match what would be expected from the claimed sender (e.g., a 'CEO' email that's oddly informal, or a 'bank' email with grammar errors).",
    )
    tactics: list[str] = Field(
        default_factory=list,
        description="Recognized phishing/social-engineering tactics, e.g. 'account suspension threat', 'fake invoice', 'package delivery scam', 'romance scam'.",
    )
    summary: str = Field(
        ...,
        description="One-to-two-sentence prose summary of what the email asks the recipient to do.",
    )
