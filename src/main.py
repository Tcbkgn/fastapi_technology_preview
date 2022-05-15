from datetime import datetime, timedelta
import sqlite3

from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestFormStrict
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session

from src import config
from src.db.schemas import User
from src.utils import get_engine, get_pwd_context

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
engine = get_engine()
SessionLocal = sessionmaker(bind=engine)
pwd_context = get_pwd_context()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(username, minutes):
    data = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=minutes)
    }
    return jwt.encode(data, config.SECRET_KEY)


async def current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, config.SECRET_KEY)
        username = payload["sub"]
        expiration = payload["exp"]
    except (JWTError, KeyError) as err:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"}) from err

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})

    return user


@app.get("/hello")
async def hello(token: str = Depends(current_user)):
    return "Hello"


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestFormStrict = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user is None:
        raise HTTPException(400, detail="Incorrect username")

    if not pwd_context.verify(secret=form_data.password, hash=user.password):
        raise HTTPException(400, detail="Incorrect password")

    token = create_access_token(user.username, minutes=2)
    return {"access_token": token, "token_type": "bearer"}
