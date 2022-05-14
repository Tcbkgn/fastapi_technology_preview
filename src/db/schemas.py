from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

if __name__ == "__main__":
    from utils import get_engine, get_pwd_context
    from passlib.context import CryptContext
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    pwd_context = get_pwd_context()
    user = User(username="admin", password=pwd_context.hash("admin"))
    db.add(user)
    db.commit()
