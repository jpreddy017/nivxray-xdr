"""Compare every backend/ blob at the release head against the live /app/backend tree."""
import json, os, subprocess, urllib.request

REPO = "jpreddy017/nivxray-xdr"
REL = "73e2bfea8d09b269792db92360b902a6b75f7b76"
STAGED = "3bbc5c89b6c5de2f4339778868e082501c47d052"
TOK = subprocess.run(
    ["bash", "-lc", "grep '^GITHUB_TOKEN=' /app/backend/.env | cut -d= -f2- | tr -d '\"'"],
    capture_output=True, text=True).stdout.strip()


def tree(sha):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/git/trees/{sha}?recursive=1",
        headers={"Authorization": f"Bearer {TOK}", "Accept": "application/vnd.github+json"})
    d = json.load(urllib.request.urlopen(req, timeout=60))
    return ({e["path"]: e["sha"] for e in d["tree"] if e["type"] == "blob"},
            d.get("truncated", False))


rel, trel = tree(REL)
stg, tstg = tree(STAGED)
print(f"release tree truncated={trel}  staged tree truncated={tstg}")

relb = {p: s for p, s in rel.items() if p.startswith("backend/")}
stgb = {p: s for p, s in stg.items() if p.startswith("backend/")}
print(f"backend blobs: release={len(relb)} staged={len(stgb)}")

delta = {p for p in set(relb) | set(stgb) if relb.get(p) != stgb.get(p)}
print(f"\n[A] backend delta BETWEEN staged {STAGED[:8]} AND release {REL[:8]}: {len(delta)}")
for p in sorted(delta):
    print(f"    {p}  staged={(stgb.get(p) or 'ABSENT')[:8]} release={(relb.get(p) or 'ABSENT')[:8]}")

print(f"\n[B] live /app/backend vs release {REL[:8]}")
missing, differ, match = [], [], 0
for p, sha in sorted(relb.items()):
    local = "/app/" + p
    if not os.path.exists(local):
        missing.append(p)
        continue
    mine = subprocess.run(["git", "hash-object", local],
                          capture_output=True, text=True).stdout.strip()
    if mine == sha:
        match += 1
    else:
        differ.append((p, sha, mine))
print(f"    identical : {match}")
print(f"    differing : {len(differ)}")
print(f"    missing   : {len(missing)}")
for p, r, m in differ:
    print(f"      DIFF  {p}  release={r[:8]} local={m[:8]}")
for p in missing[:20]:
    print(f"      MISS  {p}")

extra = [p for p in stgb if p not in relb]
print(f"\n[C] in staged but not in release: {len(extra)}")
for p in extra[:20]:
    print(f"      {p}")
