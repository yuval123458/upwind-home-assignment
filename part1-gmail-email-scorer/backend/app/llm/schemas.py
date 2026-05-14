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
    unsolicited_offer_or_reward: bool = Field(
        ...,
        description="True if the email offers an unsolicited prize, lottery win, gift card, refund, discount, or other reward as bait — anything the recipient didn't ask for that promises value.",
    )
    advance_fee_pattern: bool = Field(
        ...,
        description="True if the email matches the 419 / advance-fee fraud pattern: vague business proposal from a stranger, request to help move funds, inheritance / lottery / dying-relative narrative, or any 'I have a deal for you' email from an unknown sender.",
    )
    suspicious_link_or_attachment_action: bool = Field(
        ...,
        description="True if the email pushes the recipient to click a link or open an attachment to take a sensitive action ('click here to verify your account', 'open the attached invoice immediately', etc.).",
    )
    generic_recipient: bool = Field(
        ...,
        description="True if the email addresses the recipient with a non-personal greeting like 'Dear Customer', 'Dear User', 'Hello Friend', or has no greeting at all — a sign of mass-targeted phishing rather than a personal email.",
    )
    out_of_band_reply_request: bool = Field(
        ...,
        description="True if the email asks the recipient to reply through a channel other than the sender's domain — a personal email address, a WhatsApp number, a phone number, etc. Classic CEO-fraud / BEC pattern.",
    )
    tactics: list[str] = Field(
        default_factory=list,
        description="Recognized phishing/social-engineering tactics, e.g. 'account suspension threat', 'fake invoice', 'package delivery scam', 'romance scam', 'lottery scam', '419 advance-fee', 'BEC wire-fraud'.",
    )
    summary: str = Field(
        ...,
        description="One-to-two-sentence prose summary of what the email asks the recipient to do.",
    )
