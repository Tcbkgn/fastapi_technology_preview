import traceback
import smtplib
import ssl

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Security
from jose import JWTError, jwt
from pydantic import EmailStr
from sqlalchemy.orm import Session

from backend.app import config
from backend.app import models
from backend.app import scopes
from backend.app.modules.auth import create_access_token, current_user
from backend.app.tags import Tags
from backend.app.utils import get_db, get_pwd_context
from backend.db.schemas import User

ACTIVATION_EMAIL_EXPIRATION = 15 # minutes
ACTIVATION_MESSAGE = """\
Subject: Activate your account for: {service}

Here is your activation link for your {service} account:
{url}

Have a good time using {service}!
"""

user_router = APIRouter(prefix="/api/users", tags=[Tags.users])
admin_router = APIRouter(prefix="/api/users", tags=[Tags.users_admin])


def send_activation_email(url, user):
    token = create_access_token(user.id, ACTIVATION_EMAIL_EXPIRATION, [scopes.ACTIVATE])
    host_address = "{scheme}://{netloc}".format(scheme=url.scheme, netloc=url.netloc)

    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls(context=context)
        server.login(config.EMAIL, config.EMAIL_PASSWORD)
        message = ACTIVATION_MESSAGE.format(
            service=config.SERVICE_NAME,
            url=host_address + user_router.url_path_for("activate_account", token=token)
        )
        server.sendmail(config.EMAIL, user.email, message)
    except smtplib.SMTPException as e:
        print("ERROR: Cannot send email - {err}".format(err=traceback.format_exception(e)))
    finally:
        server.quit()


@user_router.post("/create", response_model=models.User)
async def create_account(
    username: str,
    password: str,
    email: EmailStr,
    request: Request,
    db: Session = Depends(get_db),
):
    pwd_context = get_pwd_context()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "Email already used.")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already used.")
    user = User(username=username, password=pwd_context.hash(password), active=False, admin=False, email=email)
    db.add(user)
    db.commit()
    send_activation_email(request.url, user)
    return user

@user_router.get("/activate/{token}", status_code=200)
async def activate_account(
    token: str,
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(token, config.SECRET_KEY)
        _id = int(payload["sub"])
        token_scopes = payload.get("scopes", [])
    except (JWTError, KeyError) as err:
        raise HTTPException(401, "Unauthorized") from err

    if not scopes.ACTIVATE in token_scopes:
        raise HTTPException(401, "Unauthorized")

    user = db.query(User).filter(User.id == _id).first()
    if user is None:
        raise HTTPException(401, "Unauthorized")

    if user.active:
        raise HTTPException(400, "Account is already activated.")

    user.active = True
    db.commit()

    return {"message": "Activated account for user: {}".format(user.username)}


@user_router.get("/me", response_model=models.User)
async def get_my_user(user: models.User = Security(current_user, scopes=[scopes.LOGGED_IN])):
    return user


@user_router.post("/me/resend_activation", response_model=models.User)
async def resend_activation(request: Request, user: models.User = Security(current_user, scopes=[scopes.LOGGED_IN])):
    send_activation_email(request.url, user)


@user_router.patch("/me")
async def modify_my_user(
    username: str = Body(None),
    password: str = Body(None),
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.ACTIVE])
):
    db_user = db.query(User).filter(User.id == user.id).first()
    if username:
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(400, "Username already used.")
        db_user.username = username
    if password:
        pwd_context = get_pwd_context()
        db_user.password = pwd_context.hash(password)
    db.commit()


@admin_router.get("/u/{id}", response_model=models.User)
async def get_user(
    id: int,
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.ADMIN])
):
    user = db.query(User).filter(User.id == id).first()
    if user is None:
        raise HTTPException(404, "No user with id {_id}".format(_id=id))

    return user


@admin_router.post("/u", response_model=models.User, status_code=201)
async def add_user(
    username: str = Body(...),
    password: str = Body(...),
    email: str = Body(...),
    active: bool = Body(False),
    admin: bool = Body(False),
    db: Session = Depends(get_db),
    user: models.User = Security(current_user, scopes=[scopes.ADMIN])
):
    pwd_context = get_pwd_context()
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already used.")
    user = User(username=username, password=pwd_context.hash(password), email=email, active=active, admin=admin)
    db.add(user)
    db.commit()

    return user


@admin_router.patch("/u/{id}")
async def modify_user(
    id: int,
    username: str = Body(None),
    password: str = Body(None),
    email: str = Body(...),
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
    if email:
        user.email = email
    if active:
        user.active = active
    if admin:
        user.admin = admin
    db.commit()

router = APIRouter()
router.include_router(user_router)
router.include_router(admin_router)