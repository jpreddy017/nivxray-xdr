"""READ-ONLY MITRE ATT&CK v16.1 -> v19.2 compatibility delta.

Old catalogue is read from git (blob at 1800aeea), new from the working tree.
No file is written, no database is touched.
"""
import json
import subprocess
import sys


def git_blob(ref_path):
    return json.loads(subprocess.check_output(["git", "-C", "/app", "show", ref_path]))


old = git_blob("1800aeea:backend/mitre_catalogue/enterprise_v16_1.compact.json")
new = json.load(open("/app/backend/mitre_catalogue/enterprise_v19_2.compact.json"))


def rows(cat):
    for key in ("rows", "techniques", "entries", "data"):
        if isinstance(cat.get(key), list):
            return cat[key]
    for v in cat.values():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return v
    sys.exit(f"cannot locate rows; keys={list(cat)}")


def index(cat):
    out = {}
    for r in rows(cat):
        tid = r.get("id") or r.get("technique_id") or r.get("attack_id")
        if tid:
            out[tid] = r
    return out


o, n = index(old), index(new)
print(f"v16.1 rows={len(o)}   v19.2 rows={len(n)}")

gone = sorted(set(o) - set(n))
added = sorted(set(n) - set(o))
print(f"\nIDs PRESENT in v16.1 but ABSENT in v19.2: {len(gone)}")
for t in gone:
    print(f"   {t}  '{(o[t].get('name') or '')}'")
print(f"\nIDs NEW in v19.2: {len(added)}")
print("   " + ", ".join(added[:40]) + (" ..." if len(added) > 40 else ""))


def nm(r):
    return r.get("name") or r.get("title") or ""


renamed = [(t, nm(o[t]), nm(n[t])) for t in sorted(set(o) & set(n))
           if nm(o[t]) != nm(n[t])]
print(f"\nRENAMED (same ID, different name): {len(renamed)}")
for t, a, b in renamed:
    print(f"   {t}  '{a}'  ->  '{b}'")

dep_old = [t for t, r in o.items() if r.get("deprecated") or r.get("revoked")]
dep_new = [t for t, r in n.items() if r.get("deprecated") or r.get("revoked")]
print(f"\nflagged deprecated/revoked: v16.1={len(dep_old)}  v19.2={len(dep_new)}")
newly = sorted(set(dep_new) - set(dep_old))
print(f"NEWLY deprecated/revoked in v19.2: {len(newly)}")
for t in newly:
    print(f"   {t}  '{nm(n[t])}'")

subs_o = [t for t in o if "." in t]
subs_n = [t for t in n if "." in t]
print(f"\nsub-techniques: v16.1={len(subs_o)}  v19.2={len(subs_n)}")
print(f"tactic-bearing sample v19.2: "
      f"{ {k: n[k].get('tactics') or n[k].get('tactic') for k in list(n)[:2]} }")
