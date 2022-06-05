from fastapi import FastAPI

from backend.app import config
from backend.app.routes import auth
from backend.app.routes import users

description = """
This API currently lets you create and modify users, activate their accounts and login into those accounts
using Oauth2.
"""

app = FastAPI(
    description=description,
    redoc_url="/api",
    title=config.SERVICE_NAME,
)

app.include_router(auth.router)
app.include_router(users.router)
