from fastapi import APIRouter, Body, Depends, HTTPException, Security
from sqlalchemy.orm import Session

from backend.app import models
from backend.app import scopes
from backend.app.modules.auth import current_user
from backend.app.tags import Tags
from backend.app.utils import get_db, get_pwd_context
from backend.db.schemas import User


user_router = APIRouter(prefix="/api/users", tags=[Tags.users])
admin_router = APIRouter(prefix="/api/users", tags=[Tags.users_admin])

@user_router.get("/me", response_model=models.User)
async def me(user: models.User = Security(current_user, scopes=[scopes.LOGGED_IN])):
    return user


@user_router.patch("/me", status_code=204)
async def me(
    username: str = Body(None),
    password: str = Body(None),
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.LOGGED_IN])
):
    db_user = db.query(User).filter(User.id == user.id).first()
    if username:
        db_user.username = username
    if password:
        pwd_context = get_pwd_context()
        db_user.password = pwd_context.hash(password)
    db.commit()


@admin_router.get("/user/{id}", response_model=models.User)
async def get_user(
    id: int,
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.ADMIN])
):
    user = db.query(User).filter(User.id == id).first()
    if user is None:
        raise HTTPException(404, "No user with id {_id}".format(_id=id))

    return user


@admin_router.post("/user", response_model=models.User, status_code=201)
async def add_user(
    username: str = Body(...),
    password: str = Body(...),
    active: bool = Body(False),
    admin: bool = Body(False),
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.ADMIN])
):
    pwd_context = get_pwd_context()
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already used.")
    user = User(username=username, password=pwd_context.hash(password), active=False, admin=False)
    db.add(user)
    db.commit()

    return user


@admin_router.patch("/user/{id}", status_code=204)
async def modify_user(
    id: int,
    username: str = Body(None),
    password: str = Body(None),
    active: bool = Body(None),
    admin: bool = Body(None),
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.ADMIN])
):
    user = db.query(User).filter(User.id == id).first()
    if username:
        user.username = username
    if password:
        pwd_context = get_pwd_context()
        user.password = pwd_context.hash(password)
    if active:
        user.active = active
    if admin:
        user.admin = admin
    db.commit()

router = APIRouter()
router.include_router(user_router)
router.include_router(admin_router)
