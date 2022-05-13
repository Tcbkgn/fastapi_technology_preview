from datetime import datetime, timedelta
import sqlite3

from jose import JWTError, jwt
#from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestFormStrict
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session

from src.db.schemas import User
from src.db.utils import get_engine

SECRET_KEY = "SuperSecret"

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
engine = get_engine()
SessionLocal = sessionmaker(bind=engine)
#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
    return jwt.encode(data, SECRET_KEY)


async def current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY)
        username = payload.get("sub")
        expiration = payload.get("exp")

        user = db.query(User).filter(User.username == username).first()
    except JWTError as err:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"}) from err

    if user is None:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})

    print(int(datetime.utcnow().timestamp()) - expiration)
    return user


@app.get("/hello")
async def hello(token: str = Depends(current_user)):
    return "Hello"


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestFormStrict = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if user is None:
        raise HTTPException(400, detail="Incorrect username")
    if user.password != form_data.password:
        raise HTTPException(400, detail="Incorrect password")

    token = create_access_token(user.username, minutes=5)
    return {"access_token": token, "token_type": "bearer"}
