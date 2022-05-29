from fastapi import FastAPI

from backend.app.routes import auth
from backend.app.routes import users

app = FastAPI(redoc_url="/api")

app.include_router(auth.router)
app.include_router(users.router)
