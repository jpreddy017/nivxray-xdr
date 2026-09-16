"""NivXRay adapter — calls /api/decode/smart."""
import requests, os

def decode(payload: str, api: str, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(f"{api.rstrip('/')}/api/decode/smart",
                      json={"input": payload}, headers=headers, timeout=45)
    r.raise_for_status()
    return r.json()


def login(api: str, email: str, password: str) -> str:
    r = requests.post(f"{api.rstrip('/')}/api/auth/login",
                       json={"email": email, "password": password}, timeout=30)
    r.raise_for_status()
    return r.json().get("access_token") or r.json().get("token")
