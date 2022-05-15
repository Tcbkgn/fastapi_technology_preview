from passlib.context import CryptContext
from sqlalchemy import create_engine

db_engine = None
def get_engine():
    global db_engine
    if db_engine is None:
        db_engine = create_engine("sqlite:///database.db", echo=False, connect_args={"check_same_thread": False})
    return db_engine


pwd_context = None
def get_pwd_context():
    global pwd_context
    if pwd_context is None:
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context
