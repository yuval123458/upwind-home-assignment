from fastapi import APIRouter, Depends

from app.auth.dependencies import get_current_user
from app.db.models import User

router = APIRouter(tags=["auth"])


@router.get("/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return {"id": user.id, "email": user.email, "google_sub": user.google_sub}
