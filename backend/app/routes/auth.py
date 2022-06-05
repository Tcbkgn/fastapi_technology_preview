from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestFormStrict
from sqlalchemy.orm import Session

from backend.app import models
from backend.app.tags import Tags
from backend.app.utils import get_db, get_pwd_context
from backend.db.schemas import User
from backend.app.modules import auth

router = APIRouter(prefix="/api/auth", tags=[Tags.auth])
pwd_context = get_pwd_context()

@router.post("/token", response_model=models.Token, responses={"400": {"description": "Incorrect username"}})
async def login(
    form_data: OAuth2PasswordRequestFormStrict = Depends(), db: Session = Depends(get_db)
):
    """
    Authorize with the API.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if user is None:
        raise HTTPException(400, detail="Incorrect username")

    if not pwd_context.verify(secret=form_data.password, hash=user.password):
        raise HTTPException(400, detail="Incorrect password")

    auth.verify_scopes(user, form_data.scopes)

    token = auth.create_access_token(user.id, minutes=120, scope_list=form_data.scopes)
    return {"access_token": token, "token_type": "bearer"}
