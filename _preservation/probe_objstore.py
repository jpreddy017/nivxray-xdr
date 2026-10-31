"""Probe the Emergent managed object store: init, round-trip a small object, verify checksum.

Deliberately does NOT upload the secret-bearing preservation archive.
"""
import hashlib, os, sys, uuid

import requests

STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP = "nivxforge-edr"

print(f"proxy base : {STORAGE_BASE}")
print(f"key present: {bool(EMERGENT_KEY)}")

r = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
print(f"init       : {r.status_code}")
if r.status_code != 200:
    print(f"  body: {r.text[:300]}")
    sys.exit(1)
key = r.json()["storage_key"]
print(f"storage_key: acquired (len={len(key)})")

probe = os.urandom(5 * 1024 * 1024)          # 5 MB, non-sensitive random bytes
digest = hashlib.sha256(probe).hexdigest()
path = f"{APP}/_probe/{uuid.uuid4()}.bin"

r = requests.put(f"{STORAGE_URL}/objects/{path}",
                 headers={"X-Storage-Key": key, "Content-Type": "application/octet-stream"},
                 data=probe, timeout=300)
print(f"put 5MB    : {r.status_code} {str(r.json())[:160] if r.ok else r.text[:200]}")
if not r.ok:
    sys.exit(1)
returned = r.json().get("path", path)

r = requests.get(f"{STORAGE_URL}/objects/{returned}",
                 headers={"X-Storage-Key": key}, timeout=300)
print(f"get back   : {r.status_code} bytes={len(r.content)}")
back = hashlib.sha256(r.content).hexdigest()
print(f"sha256 match: {back == digest}  ({digest[:16]}...)")

r = requests.get(f"{STORAGE_URL}/objects?prefix={APP}/_probe/",
                 headers={"X-Storage-Key": key}, timeout=60)
print(f"list       : {r.status_code} {str(r.text)[:300]}")

r = requests.delete(f"{STORAGE_URL}/objects/{returned}",
                    headers={"X-Storage-Key": key}, timeout=60)
print(f"delete     : {r.status_code} (expected to be unsupported) {r.text[:160]}")
