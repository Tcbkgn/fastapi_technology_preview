from passlib.context import CryptContext
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

db_engine = None
def get_engine():
    global db_engine
    if db_engine is None:
        db_engine = create_engine("sqlite:///database.db", echo=False, connect_args={"check_same_thread": False})
    return db_engine

SessionLocal = None
def get_session():
    global SessionLocal
    if SessionLocal is None:
        SessionLocal = sessionmaker(bind=get_engine())
    return SessionLocal

def get_db():
    Session = get_session()
    db = Session()
    try:
        yield db
    finally:
        db.close()

pwd_context = None
def get_pwd_context():
    global pwd_context
    if pwd_context is None:
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context
