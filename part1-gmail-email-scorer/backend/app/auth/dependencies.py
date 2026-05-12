from fastapi import Depends, Header, HTTPException, status
from sqlmodel import Session, select

from app.auth.google_id_token import InvalidTokenError, verify
from app.db.models import User
from app.db.session import get_session


def get_current_user(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:].strip()
    try:
        claims = verify(token)
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    sub: str = claims["sub"]
    email: str = claims["email"]

    user = session.exec(select(User).where(User.google_sub == sub)).first()
    if user is None:
        user = User(email=email, google_sub=sub)
        session.add(user)
        session.commit()
        session.refresh(user)
    elif user.email != email:
        user.email = email
        session.add(user)
        session.commit()
        session.refresh(user)
    return user
