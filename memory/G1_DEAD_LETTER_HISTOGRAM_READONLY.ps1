# =====================================================================
# G1 . DEAD-LETTER HISTOGRAM . READ-ONLY MEASUREMENT
# ELEVATED PowerShell (Run as Administrator). Measures only.
#
# WHY THIS EXISTS: the 125,452-row G1 outbox lives ONLY on this endpoint
# (C:\ProgramData\NivXForge\state\outbox.db). The Preview container has no
# copy of it, so the histogram cannot be produced server-side.
#
# NON-MUTATION GUARANTEES:
#   * the live outbox.db / -wal / -shm are COPIED to a temp folder and every
#     query runs against the COPY, so the original files are only ever read;
#   * no acquisition, no replay, no status change, no recovery, no cleanup,
#     no collector start, no server call, no credential use;
#   * the collector must be STOPPED (it was terminated at the end of the
#     bounded run) - the script refuses to proceed if it is still running,
#     because copying under an active writer could yield a torn read.
#
# OUTPUT: C:\nivx\g1-proof\dead-letter-histogram.json  (+ console summary)
#         Bounded: counts, codes, sizes and identity only. No event payloads.
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1DeadLetterHistogram {

$StateDir = 'C:\ProgramData\NivXForge\state'
$Work     = 'C:\nivx'
$VenvPy   = "$Work\.venv\Scripts\python.exe"
$ProofDir = "$Work\g1-proof"
$OutFile  = "$ProofDir\dead-letter-histogram.json"

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db)) { throw "outbox database not found at $db" }

  # The collector must not be writing while we copy.
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*main:app*' }
  if ($live) {
    $live | ForEach-Object { Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw ('a collector process is still running. This measurement refuses to copy ' +
           'the outbox under an active writer. Stop it first (Stop-Process -Id <pid> -Force), ' +
           'then re-run. Nothing was read or changed.')
  }

  New-Item -ItemType Directory -Force -Path $ProofDir | Out-Null
  $tmp = Join-Path $env:TEMP ("nivx_dl_" + [guid]::NewGuid().ToString('N').Substring(0,8))
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  Write-Host "`n=== copying outbox for read-only analysis ===" -ForegroundColor Cyan
  foreach ($suf in @('', '-wal', '-shm')) {
    $src = "$db$suf"
    if (Test-Path $src) {
      Copy-Item $src (Join-Path $tmp ("outbox.db" + $suf)) -Force
      Write-Host ("  copied outbox.db" + $suf + "  " + (Get-Item $src).Length + " bytes")
    }
  }
  Write-Host "  originals untouched (read-only copy; every query runs on the copy)" -ForegroundColor DarkGray

  $py = @'
import json, os, sqlite3, sys

db = os.path.join(sys.argv[1], "outbox.db")
c = sqlite3.connect(db)
c.row_factory = sqlite3.Row
out = {"analyzed_copy": db, "note": "read-only copy of the endpoint outbox; originals unmodified"}

# ---- 1 . reconcile totals against the captured accounting -----------
out["totals_by_status"] = {r["status"]: r["n"] for r in c.execute(
    "SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status")}
out["total_rows"] = c.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]
dl = c.execute("SELECT COUNT(*) FROM envelopes WHERE status='dead_letter'").fetchone()[0]
out["dead_letter_count"] = dl
captured = {"total_durable_rows": 125452, "delivered": 2884,
            "dead_letter": 14868, "retrying": 125, "queued": 107525}
out["captured_accounting"] = captured
out["reconciliation"] = {
    "dead_letter_measured": dl,
    "dead_letter_captured": captured["dead_letter"],
    "delta": dl - captured["dead_letter"],
    "reconciles": dl == captured["dead_letter"],
    "total_delta": out["total_rows"] - captured["total_durable_rows"],
}

# ---- 2 . EXACT last_error histogram, unnormalised -------------------
rows = list(c.execute(
    "SELECT last_error, COUNT(*) AS n FROM envelopes WHERE status='dead_letter'"
    " GROUP BY last_error ORDER BY n DESC"))
out["histogram_exact"] = [
    {"last_error": r["last_error"], "count": r["n"],
     "percentage_of_dead_letters": (round(100.0 * r["n"] / dl, 4) if dl else None)}
    for r in rows]

# ---- 3 . classification, ONLY from stored values --------------------
buckets = ["HTTP 400", "HTTP 401", "HTTP 403", "HTTP 404", "HTTP 408",
           "HTTP 413", "HTTP 422", "HTTP 429", "HTTP 5xx", "DNS/connect",
           "timeout", "TLS", "other transport", "unknown/empty"]
cls = {b: 0 for b in buckets}
unclassified = {}
for r in rows:
    v = (r["last_error"] or "").strip()
    n = r["n"]
    low = v.lower()
    if v == "":
        cls["unknown/empty"] += n
    elif v.startswith("HTTP "):
        code = v[5:].strip()
        if code.isdigit() and code[0] == "5":
            cls["HTTP 5xx"] += n
        elif ("HTTP " + code) in cls:
            cls["HTTP " + code] += n
        else:
            unclassified[v] = unclassified.get(v, 0) + n
    elif "connecterror" in low or "nameresolution" in low or "dns" in low \
            or "getaddrinfo" in low:
        cls["DNS/connect"] += n
    elif "timeout" in low or "readtimeout" in low or "connecttimeout" in low:
        cls["timeout"] += n
    elif "ssl" in low or "tls" in low or "certificate" in low:
        cls["TLS"] += n
    elif "transport" in low or "protocolerror" in low or "remoteprotocol" in low:
        cls["other transport"] += n
    else:
        unclassified[v] = unclassified.get(v, 0) + n
out["classification"] = cls
out["classification_unmatched_exact_values"] = unclassified
out["classification_note"] = (
    "classified strictly from the stored last_error string. A stored 'HTTP 413' "
    "proves only that the endpoint received 413; it does not by itself prove why "
    "the server produced it. Likewise 403 != proven tenant violation and "
    "400 != proven malformed batch.")

# ---- 4 . attempt-count distribution (terminality evidence) ----------
out["dead_letter_attempts_distribution"] = {
    str(r["attempts"]): r["n"] for r in c.execute(
        "SELECT attempts, COUNT(*) AS n FROM envelopes WHERE status='dead_letter'"
        " GROUP BY attempts ORDER BY attempts")}

# ---- 5 . payload size distribution (no payload content) -------------
sz = c.execute(
    "SELECT MIN(length(raw_json)) mn, MAX(length(raw_json)) mx,"
    " AVG(length(raw_json)) av, SUM(CASE WHEN length(raw_json) > 524288 THEN 1 ELSE 0 END) over_512k,"
    " SUM(CASE WHEN length(raw_json) > 262144 THEN 1 ELSE 0 END) over_256k"
    " FROM envelopes WHERE status='dead_letter'").fetchone()
out["dead_letter_payload_bytes"] = {
    "min": sz["mn"], "max": sz["mx"],
    "avg": (round(sz["av"], 1) if sz["av"] is not None else None),
    "rows_over_512KB": sz["over_512k"], "rows_over_256KB": sz["over_256k"],
    "note": ("length(raw_json) only; the POST body also carries the canonical "
             "view and envelope fields, so the wire body is larger than this"),
}
szd = c.execute(
    "SELECT MAX(length(raw_json)) mx, SUM(CASE WHEN length(raw_json) > 524288 THEN 1 ELSE 0 END) over_512k"
    " FROM envelopes WHERE status='delivered'").fetchone()
out["delivered_payload_bytes_for_contrast"] = {
    "max": szd["mx"], "rows_over_512KB": szd["over_512k"]}

# ---- 6 . channel / source correlation -------------------------------
out["dead_letter_by_source_and_error"] = [dict(r) for r in c.execute(
    "SELECT source, declared_source, event_type, last_error, COUNT(*) AS n,"
    " MAX(length(raw_json)) AS max_raw_bytes"
    " FROM envelopes WHERE status='dead_letter'"
    " GROUP BY source, declared_source, event_type, last_error"
    " ORDER BY n DESC LIMIT 60")]
out["all_status_by_source"] = [dict(r) for r in c.execute(
    "SELECT source, status, COUNT(*) AS n FROM envelopes"
    " GROUP BY source, status ORDER BY source, status")]

# ---- 7 . the two named records --------------------------------------
targets = {"PowerShell_4104_510": "|510",
           "Security_4624_238776": "|238776"}
found = {}
for label, suffix in targets.items():
    r = c.execute(
        "SELECT id, source, declared_source, source_event_id, event_type, status,"
        " attempts, last_error, created_at, updated_at,"
        " length(raw_json) AS raw_bytes, length(canonical_json) AS canonical_bytes"
        " FROM envelopes WHERE source_event_id LIKE ?", ("%" + suffix,)).fetchone()
    if not r:
        found[label] = {"present": False,
                        "note": "no outbox row whose source_event_id ends with " + suffix}
        continue
    d = dict(r)
    # EventRecordID / EventID are read from the identity string and the
    # canonical view only - no payload body is emitted.
    parts = (d.get("source_event_id") or "").split("|")
    d["channel_from_identity"] = parts[2] if len(parts) >= 4 else None
    d["event_record_id_from_identity"] = parts[3] if len(parts) >= 4 else None
    try:
        can = json.loads(c.execute(
            "SELECT canonical_json FROM envelopes WHERE id=?",
            (d["id"],)).fetchone()[0] or "{}")
        d["event_id"] = can.get("event_id")
        d["event_record_id"] = can.get("event_record_id")
        d["provider"] = can.get("provider")
        d["origin_computer"] = can.get("origin_computer")
    except Exception as exc:
        d["canonical_read_error"] = "%s: %s" % (type(exc).__name__, exc)
    d["present"] = True
    found[label] = d
out["named_records"] = found

# ---- 8 . dead-letter time window ------------------------------------
w = c.execute(
    "SELECT MIN(created_at) c0, MAX(created_at) c1, MIN(updated_at) u0,"
    " MAX(updated_at) u1 FROM envelopes WHERE status='dead_letter'").fetchone()
out["dead_letter_window"] = {"first_created": w["c0"], "last_created": w["c1"],
                             "first_updated": w["u0"], "last_updated": w["u1"]}
print(json.dumps(out, indent=2, default=str))
'@
  $pyPath = Join-Path $tmp 'dl_hist.py'
  $py | Out-File -FilePath $pyPath -Encoding ASCII
  Write-Host "`n=== measuring ===" -ForegroundColor Cyan
  & $VenvPy $pyPath $tmp | Set-Content $OutFile -Encoding UTF8
  if ($LASTEXITCODE -ne 0) { throw "the measurement script failed; see console output above" }

  $j = Get-Content $OutFile -Raw | ConvertFrom-Json
  Write-Host ("  total rows        : " + $j.total_rows)
  Write-Host ("  dead_letter       : " + $j.dead_letter_count +
              "  (captured " + $j.captured_accounting.dead_letter +
              ", delta " + $j.reconciliation.delta + ")")
  Write-Host "`n  EXACT last_error histogram:" -ForegroundColor Cyan
  foreach ($h in $j.histogram_exact) {
    Write-Host ("    {0,-44} {1,8}  {2,7}%" -f $h.last_error, $h.count, $h.percentage_of_dead_letters)
  }
  Write-Host "`n  classification:" -ForegroundColor Cyan
  $j.classification.PSObject.Properties |
    Where-Object { $_.Value -gt 0 } |
    ForEach-Object { Write-Host ("    {0,-18} {1,8}" -f $_.Name, $_.Value) }
  Write-Host "`n  dead-letter payload bytes: min=$($j.dead_letter_payload_bytes.min) max=$($j.dead_letter_payload_bytes.max) over512KB=$($j.dead_letter_payload_bytes.rows_over_512KB)"
  Write-Host "  attempts distribution    : $($j.dead_letter_attempts_distribution | ConvertTo-Json -Compress)"
  Write-Host "`n  PowerShell 4104/510  present=$($j.named_records.PowerShell_4104_510.present) status=$($j.named_records.PowerShell_4104_510.status) last_error=$($j.named_records.PowerShell_4104_510.last_error)"
  Write-Host "  Security 4624/238776 present=$($j.named_records.Security_4624_238776.present) status=$($j.named_records.Security_4624_238776.status) last_error=$($j.named_records.Security_4624_238776.last_error)"
  Write-Host "`nArtifact: $OutFile" -ForegroundColor Cyan
  Write-Host "Send that file back. It contains counts, codes, sizes and identity only - no event payloads." -ForegroundColor Cyan
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "Temp copy deleted. The live outbox was only ever READ." -ForegroundColor DarkGray
}
catch {
  Write-Host ""
  Write-Host "=========== G1 HISTOGRAM MEASUREMENT FAILED ===========" -ForegroundColor Red
  Write-Host ("REASON: " + $_.Exception.Message) -ForegroundColor Red
  if ($_.InvocationInfo) {
    Write-Host ("WHERE : line " + $_.InvocationInfo.ScriptLineNumber) -ForegroundColor DarkGray
  }
  Write-Host "Nothing was written to the outbox. This console stays open." -ForegroundColor Yellow
  Write-Host "======================================================" -ForegroundColor Red
  return
}
}

# Run it. Nothing above executed on its own.
Invoke-G1DeadLetterHistogram
