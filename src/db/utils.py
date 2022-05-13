from sqlalchemy import create_engine

def get_engine():
    return create_engine("sqlite:///database.db", echo=False, connect_args={"check_same_thread": False})
