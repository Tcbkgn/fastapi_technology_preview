from pydantic import BaseModel

class User(BaseModel):
    id: int
    username: str
    active: bool
    admin: bool
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
