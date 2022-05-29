from datetime import datetime, timedelta

from jose import JWTError, jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from sqlalchemy.orm import Session

from backend.app import config
from backend.app import models
from backend.app import scopes
from backend.app.utils import get_db
from backend.db.schemas import User

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/auth/token",
    scopes = {
        scopes.LOGGED_IN: "Operations allowed for any logged in user.",
        scopes.ACTIVE: "Operations allowed only for activated accounts.",
        scopes.ADMIN: "Operations allowed only for administrators."
    }
)


def create_access_token(user_id: int, minutes: int, scope_list: list):
    data = {
        "sub": str(user_id),
        "scopes": scope_list,
        "exp": datetime.utcnow() + timedelta(minutes=minutes)
    }
    return jwt.encode(data, config.SECRET_KEY)


def check_permissions(required_scopes: list, current_scopes: list):
    return all(r in current_scopes for r in required_scopes)


def verify_scopes(user: models.User, scope_list: list):
    for scope in scope_list:
        if scope == scopes.ACTIVE and not user.active:
            raise HTTPException(400, detail="Permission level too high for a unactivated account.")
        if scope == scopes.ADMIN and not user.admin:
            raise HTTPException(
                400, detail="Permission level too high for a non-administrator account."
            )
    return True


async def current_user(
    required_scopes: SecurityScopes,
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    headers = {
        "WWW-Authenticate": "Bearer"
    }
    if required_scopes.scopes:
        headers["WWW-Authenticate"] = "Bearer scope={scopes}".format(
            scopes=required_scopes.scope_str
        )

    try:
        payload = jwt.decode(token, config.SECRET_KEY)
        _id = int(payload["sub"])
        token_scopes = payload.get("scopes", [])
    except (JWTError, KeyError) as err:
        raise HTTPException(401, "Unauthorized", headers=headers) from err

    user = db.query(User).filter(User.id == _id).first()
    if user is None:
        raise HTTPException(401, "Unauthorized", headers=headers)

    if not check_permissions(required_scopes=required_scopes.scopes, current_scopes=token_scopes):
        raise HTTPException(401, "Not enough permissions", headers=headers)

    return user
