from datetime import datetime, timedelta
import sqlite3

from jose import JWTError, jwt
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestFormStrict, SecurityScopes
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session

from backend.app import config
from backend.app import models
from backend.app.scopes import Scope
from backend.app.utils import get_engine, get_pwd_context
from backend.db.schemas import User


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes = {
        Scope.ME: "Read information about the current user."
    }
)
engine = get_engine()
SessionLocal = sessionmaker(bind=engine)
pwd_context = get_pwd_context()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(username, minutes, scopes):
    data = {
        "sub": username,
        "scopes": scopes,
        "exp": datetime.utcnow() + timedelta(minutes=minutes)
    }
    return jwt.encode(data, config.SECRET_KEY)

def check_scopes(required: list, current: list):
    return all(r in current for r in required)

async def current_user(scopes: SecurityScopes, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    headers = {
        "WWW-Authenticate": "Bearer scope={scopes}".format(scopes=scopes.scope_str) if scopes.scopes else "Bearer"
    }
    try:
        payload = jwt.decode(token, config.SECRET_KEY)
        username = payload["sub"]
        token_scopes = payload.get("scopes", [])
    except (JWTError, KeyError) as err:
        raise HTTPException(401, "Unauthorized", headers=headers) from err

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(401, "Unauthorized", headers=headers)

    if not check_scopes(required=scopes.scopes, current=token_scopes):
        raise HTTPException(401, "Not enough permissions", headers=headers)

    return user


@app.get("/")
async def hello():
    return "hello"


@app.get("/me", response_model=models.User)
async def me(user: models.User = Security(current_user, scopes=["me"])):
    return user


@app.post("/token", response_model=models.Token)
async def login(form_data: OAuth2PasswordRequestFormStrict = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user is None:
        raise HTTPException(400, detail="Incorrect username")

    if not pwd_context.verify(secret=form_data.password, hash=user.password):
        raise HTTPException(400, detail="Incorrect password")

    token = create_access_token(user.username, minutes=15, scopes=form_data.scopes)
    return {"access_token": token, "token_type": "bearer"}
