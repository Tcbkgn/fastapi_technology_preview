from fastapi import APIRouter, Body, Depends, HTTPException, Security
from sqlalchemy.orm import Session

from backend.app import models
from backend.app import scopes
from backend.app.modules.auth import current_user
from backend.app.utils import get_db, get_pwd_context
from backend.db.schemas import User

router = APIRouter(prefix="/api/users")

@router.get("/me", response_model=models.User)
async def me(user: models.User = Security(current_user, scopes=[scopes.LOGGED_IN])):
    return user

@router.post("/user")
async def add_user(
    username: str = Body(None),
    password: str = Body(None),
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.LOGGED_IN, scopes.ADMIN])
):
    pwd_context = get_pwd_context()
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already used.")
    user = User(username=username, password=pwd_context.hash(password), active=False, admin=False)
    db.add(user)
    db.commit()
