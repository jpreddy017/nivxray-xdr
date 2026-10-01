# W1 · PHASE 1 — WINDOWS LAPTOP PREPARATION (owner actions)

Scope of this phase: **get genuine Sysmon events onto the laptop and verify
them locally.** Nothing is connected to NivXRay yet. No collector, no
credential, no forwarder, no `_COLLECTED_PRODUCTS` change.

Grounded in the current implementation, not on an assumed product:

* the only ingest boundary is `POST /api/xdr/ingest/telemetry` (HTTPS, JSON,
  header-authenticated). **There is no Windows agent or forwarder binary in
  this codebase today** — Phase 4 builds a small PowerShell forwarder that
  reads the Sysmon channel and POSTs the envelope shape the route already
  accepts. Nothing else is invented.
* `detection_content/telemetry/sysmon_dsm.py` declares
  `SUPPORTED_EVENT_IDS = {1, 3, 11, 12, 13, 14, 22}`. Any other Sysmon event
  id is **refused at the DSM boundary** and recorded as a routing block — it
  is not silently dropped, but it is also not evidence. The Phase 1 config
  therefore enables exactly those event ids and nothing else.
* the DSM reads `Hashes`, so **`HashAlgorithms` must include SHA256** or the
  endpoint hash IOC lane stays legitimately empty (the DSM will not invent a
  hash).

---

## 1.0 · Prerequisites (check, do not change anything yet)

| Requirement | Why |
| --- | --- |
| Windows 10 or 11, x64 (or ARM64), local **Administrator** | Sysmon installs a driver |
| PowerShell 5.1+ (built in) run **as Administrator** | all commands below |
| ~100 MB free disk | Sysmon + event log |
| The laptop may stay on its normal network for Phase 1 | no outbound connection to NivXRay is used until Phase 4 |

Decide now, and just tell me the value (it is not a secret):

* **the NivX tenant id** this laptop's evidence belongs to (e.g. `default`);
* whether this host should report to **preview** or **production** — that
  decision belongs to Phase 4, not here.

**Security:** nothing in Phase 1 produces a secret. Do not paste passwords,
private keys, API tokens or enrolment secrets into chat at any phase. When
Phase 4 mints the ingest key, you will paste it **only** into a local file on
the laptop (I will give you the exact path and an ACL command), never here.

---

## 1.1 · Record the machine facts (non-secret) — run first

```powershell
# Run PowerShell AS ADMINISTRATOR
$i = Get-ComputerInfo
[pscustomobject]@{
  Hostname   = $env:COMPUTERNAME
  OS         = $i.OsName
  Build      = $i.OsBuildNumber
  Arch       = $env:PROCESSOR_ARCHITECTURE
  PSVersion  = $PSVersionTable.PSVersion.ToString()
  Domain     = $i.CsDomain
  SysmonHere = [bool](Get-Service -Name Sysmon*, SysmonDrv -ErrorAction SilentlyContinue)
} | Format-List
```

**Expected:** a 7-line list. `SysmonHere` should be `False`. If it is `True`,
stop and send me the output of `sysmon64 -c` before installing anything — I
will not have you overwrite an existing Sysmon configuration blindly.

---

## 1.2 · Download Sysmon from Microsoft and verify the signature

```powershell
New-Item -ItemType Directory -Force C:\NivX\sysmon | Out-Null
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip `
  -OutFile C:\NivX\sysmon\Sysmon.zip
Expand-Archive C:\NivX\sysmon\Sysmon.zip -DestinationPath C:\NivX\sysmon -Force
Get-AuthenticodeSignature C:\NivX\sysmon\Sysmon64.exe |
  Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}
(Get-Item C:\NivX\sysmon\Sysmon64.exe).VersionInfo.FileVersion
```

**Expected:** `Status = Valid` and a signer containing
`O=Microsoft Corporation`. Send me the `Status`, the signer and the file
version. **Do not proceed if the status is anything but `Valid`.**
(On ARM64 use `Sysmon64a.exe` in every command below.)

---

## 1.3 · Write the configuration — exactly the event ids the DSM accepts

```powershell
@'
<Sysmon schemaversion="4.90">
  <!-- NivXRay XDR W1 · SHA256 is required by the canonical hash evidence path -->
  <HashAlgorithms>SHA256,MD5</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>
    <!-- LOG EVERYTHING for the event ids the Sysmon DSM supports.
         An empty onmatch="exclude" rule excludes nothing. -->
    <ProcessCreate onmatch="exclude"/>            <!-- EID 1  -->
    <NetworkConnect onmatch="exclude"/>           <!-- EID 3  -->
    <FileCreate onmatch="exclude"/>               <!-- EID 11 -->
    <RegistryEvent onmatch="exclude"/>            <!-- EID 12/13/14 -->
    <DnsQuery onmatch="exclude"/>                 <!-- EID 22 -->

    <!-- LOG NOTHING for every unsupported event id: an empty
         onmatch="include" rule matches nothing. These would be refused at
         the DSM boundary, so they are not generated in the first place. -->
    <ProcessTerminate onmatch="include"/>         <!-- 5  -->
    <DriverLoad onmatch="include"/>               <!-- 6  -->
    <ImageLoad onmatch="include"/>                <!-- 7  -->
    <CreateRemoteThread onmatch="include"/>       <!-- 8  -->
    <RawAccessRead onmatch="include"/>            <!-- 9  -->
    <ProcessAccess onmatch="include"/>            <!-- 10 -->
    <FileCreateTime onmatch="include"/>           <!-- 2  -->
    <FileCreateStreamHash onmatch="include"/>     <!-- 15 -->
    <PipeEvent onmatch="include"/>                <!-- 17/18 -->
    <WmiEvent onmatch="include"/>                 <!-- 19/20/21 -->
    <FileDelete onmatch="include"/>               <!-- 23 -->
    <ClipboardChange onmatch="include"/>          <!-- 24 -->
    <ProcessTampering onmatch="include"/>         <!-- 25 -->
    <FileDeleteDetected onmatch="include"/>       <!-- 26 -->
  </EventFiltering>
</Sysmon>
'@ | Set-Content -Encoding UTF8 C:\NivX\sysmon\nivx-w1-sysmon.xml

Get-FileHash C:\NivX\sysmon\nivx-w1-sysmon.xml -Algorithm SHA256 |
  Select-Object Hash
```

**Expected:** one SHA256 hash. Send it to me — it is how we prove later that
the evidence came from *this* configuration.

*Note on volume:* EID 22 (DNS) and EID 11 (FileCreate) are chatty on a daily
driver laptop. That is deliberate for W1 — we want genuine, unfiltered
evidence for the acceptance test. If the log grows uncomfortably we will add
**explicit, recorded** exclusions in a later phase rather than quietly
filtering evidence now.

---

## 1.4 · Install

```powershell
C:\NivX\sysmon\Sysmon64.exe -accepteula -i C:\NivX\sysmon\nivx-w1-sysmon.xml
Get-Service SysmonDrv, Sysmon64 | Select-Object Name, Status, StartType
C:\NivX\sysmon\Sysmon64.exe -c | Select-Object -First 25
```

**Expected:** `Sysmon64 installed.` / `Started SysmonDrv.` / `Started Sysmon64.`,
both services `Running` + `Automatic`, and `-c` printing
`HashAlgorithms: SHA256,MD5` with the rule set above.

---

## 1.5 · Verify genuine Sysmon events locally

```powershell
# a) the channel exists and is filling
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational |
  Select-Object LogName, RecordCount, IsEnabled

# b) which event ids are actually being produced (last 15 minutes)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    StartTime=(Get-Date).AddMinutes(-15)
  } | Group-Object Id | Sort-Object Name |
  Select-Object @{n='EventID';e={$_.Name}}, Count
```

**Expected:** `IsEnabled = True`, a non-zero `RecordCount`, and event ids
drawn **only** from `1, 3, 11, 12, 13, 14, 22`. If any other id appears, the
config did not apply — send me the `-c` output.

---

## 1.6 · Generate safe, benign activity and confirm it was recorded

Nothing malicious, nothing that touches a third party. These four are enough
to exercise every canonical field W1 fixed (process identity, parent, hashes,
DNS, file):

```powershell
# 1 · a process with a parent and a hashable image  (EID 1)
cmd.exe /c "whoami"

# 2 · an encoded PowerShell command that prints hello   (EID 1, -enc path)
powershell.exe -NoProfile -EncodedCommand `
  ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host hello')))

# 3 · a DNS query to a domain YOU control or a public one   (EID 22)
Resolve-DnsName example.com -Type A | Select-Object -First 1

# 4 · a file created in a user-writable path   (EID 11)
Set-Content C:\Users\Public\nivx-w1-benign.txt "w1 phase1"
```

Then confirm Sysmon saw them:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
    StartTime=(Get-Date).AddMinutes(-5)
  } -MaxEvents 3 | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      EventID          = $x.Event.System.EventID
      UtcTime          = $d['UtcTime']
      Computer         = $x.Event.System.Computer
      Image            = $d['Image']
      OriginalFileName = $d['OriginalFileName']
      HasProcessGuid   = [bool]$d['ProcessGuid']
      ParentImage      = $d['ParentImage']
      HasParentCmdLine = [bool]$d['ParentCommandLine']
      HashAlgos        = ($d['Hashes'] -split ',' | ForEach-Object { ($_ -split '=')[0] }) -join '+'
    }
  } | Format-List
```

**Expected — this is the Phase 1 acceptance:** for at least one record,
`HasProcessGuid = True`, `HasParentCmdLine = True`, a non-empty
`OriginalFileName`, and `HashAlgos` containing `SHA256`. Those are precisely
the fields the DSM used to discard and now preserves.

**Send me this `Format-List` output as-is.** It contains only local paths and
hashes — no credentials. If you would rather not share user names or file
paths, replace them with `REDACTED`; I only need the field *presence*.

---

## 1.7 · What to return for Phase 1 review

1. the 1.1 machine facts;
2. the 1.2 signature status, signer and Sysmon file version;
3. the 1.3 config SHA256;
4. the 1.4 service states and the first lines of `-c`;
5. the 1.5 event-id table;
6. the 1.6 `Format-List` output.

Do **not** install a forwarder, create a collector, or mint a key yet.

---

## Known gap to expect in a later phase (so it is not a surprise)

The platform has **no collector heartbeat today** — `xdr_collectors` carries a
`last_seen_at` field that the ingest route never writes, and every existing
collector reads `null`. Phase 5's connectivity verification will therefore be
proven by (a) the ingest receipt, (b) canonical rows whose
`provenance.collector_id` is this collector, and (c) the
`xdr_ingest_routing_blocks` diagnostic surface for anything refused. If you
want a genuine heartbeat surface, that is a small separate gate and I will not
fake one in the meantime.

**STOP — Phase 1 is owner action. W1 remains NOT CLOSED.**
