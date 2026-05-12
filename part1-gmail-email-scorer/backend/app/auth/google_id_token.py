from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

from app.config import settings

_request_transport = google_requests.Request()


class InvalidTokenError(Exception):
    """Raised when a Google ID token fails verification."""


def verify(token: str) -> dict:
    """Verify a Google ID token and return its claims.

    Validates signature against Google's JWKS, expiration, and that the
    audience matches GOOGLE_CLIENT_ID. Raises InvalidTokenError on any failure.
    """
    if not settings.google_client_id:
        raise InvalidTokenError("GOOGLE_CLIENT_ID not configured")
    try:
        claims = google_id_token.verify_oauth2_token(
            token, _request_transport, settings.google_client_id
        )
    except ValueError as e:
        raise InvalidTokenError(str(e)) from e

    if not claims.get("email"):
        raise InvalidTokenError("Token missing email claim")
    if not claims.get("email_verified"):
        raise InvalidTokenError("Email not verified by Google")
    return claims
