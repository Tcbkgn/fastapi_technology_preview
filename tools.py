import argparse

from passlib.context import CryptContext
from sqlalchemy.orm import sessionmaker

from backend.app import config
from backend.app.utils import get_engine, get_pwd_context
from backend.db.schemas import Base, User


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init_db"])
    args = parser.parse_args()

    if args.command == "init_db":
        engine = get_engine()
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        pwd_context = get_pwd_context()
        user = User(username="admin", password=pwd_context.hash(config.ADMIN_PASSWORD), active=True, admin=True)
        db.add(user)
        db.commit()
