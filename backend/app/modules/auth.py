from datetime import datetime, timedelta
import sqlite3

from jose import JWTError, jwt
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestFormStrict, SecurityScopes
from sqlalchemy.orm import Session

from backend.app import config
from backend.app import models
from backend.app import scopes
from backend.app.utils import get_db, get_pwd_context
from backend.db.schemas import User

router = APIRouter(prefix="/api/auth")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/auth/token",
    scopes = {
        scopes.LOGGED_IN: "Operations allowed for any logged in user.",
        scopes.ACTIVE: "Operations allowed only for activated accounts.",
        scopes.ADMIN: "Operations allowed only for administrators."
    }
)
pwd_context = get_pwd_context()

def create_access_token(user_id: int, minutes: int, scopes: list):
    data = {
        "sub": str(user_id),
        "scopes": scopes,
        "exp": datetime.utcnow() + timedelta(minutes=minutes)
    }
    return jwt.encode(data, config.SECRET_KEY)


def check_permissions(required_scopes: list, current_scopes: list):
    return all(r in current_scopes for r in required_scopes)


def verify_scopes(user: models.User, scope_list: list):
    valid = True
    for scope in scope_list:
        if scope == scopes.ACTIVE and not user.active:
            raise HTTPException(400, detail="Permission level too high for a unactivated account.")
        if scope == scopes.ADMIN and not user.admin:
            raise HTTPException(400, detail="Permission level too high for a non-administrator account.")
    return True


async def current_user(scopes: SecurityScopes, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    headers = {
        "WWW-Authenticate": "Bearer scope={scopes}".format(scopes=scopes.scope_str) if scopes.scopes else "Bearer"
    }
    try:
        payload = jwt.decode(token, config.SECRET_KEY)
        _id = int(payload["sub"])
        token_scopes = payload.get("scopes", [])
    except (JWTError, KeyError) as err:
        raise HTTPException(401, "Unauthorized", headers=headers) from err

    user = db.query(User).filter(User.id == _id).first()
    if user is None:
        raise HTTPException(401, "Unauthorized", headers=headers)

    if not check_permissions(required_scopes=scopes.scopes, current_scopes=token_scopes):
        raise HTTPException(401, "Not enough permissions", headers=headers)

    return user


@router.post("/token", response_model=models.Token)
async def login(form_data: OAuth2PasswordRequestFormStrict = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user is None:
        raise HTTPException(400, detail="Incorrect username")

    if not pwd_context.verify(secret=form_data.password, hash=user.password):
        raise HTTPException(400, detail="Incorrect password")

    verify_scopes(user, form_data.scopes)

    token = create_access_token(user.id, minutes=15, scopes=form_data.scopes)
    return {"access_token": token, "token_type": "bearer"}
