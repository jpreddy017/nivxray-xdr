"""Auth router — /api/auth/login, /api/auth/me, /api/auth/change-password"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from schemas import LoginIn, TokenOut
from deps import (
    db, get_current_user, get_current_user_raw,
    verify_password, hash_password, create_token,
)

router = APIRouter()


class ChangePasswordIn(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=12,
                              description="Minimum 12 characters. Enforce mix at UI level.")


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


@router.post("/auth/change-password", tags=["auth"])
async def change_password(body: ChangePasswordIn, user=Depends(get_current_user_raw)):
    """Rotate the current user's password. Clears the must_change_password
    flag on success. Uses ``get_current_user_raw`` to bypass the
    password-change gate — every other authenticated route stays gated
    until this endpoint completes successfully.
    """
    u = await db.users.find_one({"email": user["email"]})
    if not u or not verify_password(body.current_password, u["password"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from current")
    await db.users.update_one(
        {"email": user["email"]},
        {"$set": {
            "password": hash_password(body.new_password),
            "must_change_password": False,
        }},
    )
    # Issue a fresh token so the client immediately drops the gated session.
    return {"ok": True, "access_token": create_token(user["email"]), "email": user["email"]}
