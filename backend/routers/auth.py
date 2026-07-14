"""Auth router — /api/auth/login, /api/auth/me, /api/"""
from fastapi import APIRouter, Depends, HTTPException

from schemas import LoginIn, TokenOut
from deps import db, get_current_user, verify_password, create_token

router = APIRouter()


@router.get("/")
async def root():
    return {"service": "NivXRay", "status": "ok"}


@router.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn):
    u = await db.users.find_one({"email": body.email})
    if not u or not verify_password(body.password, u["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenOut(access_token=create_token(body.email), email=body.email)


@router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user
