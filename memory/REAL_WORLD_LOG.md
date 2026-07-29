# NivXRay — Real-World Usage Log

_Started 2026-02-28. Purpose: let real SOC cases (not guesses) prioritize v1.6.0._

Format — one line per case:
```
YYYY-MM-DD · sample-class · verdict-correct? · what-missed · would-fix-priority
```

Sample classes to expect: `ps-encoded`, `cmd-lolbin`, `base64-macro`, `js-obfuscated`, `msi-installer`, `wmi-persist`, `scheduled-task`, `defender-tamper`, `powershell-download-cradle`, `dll-sideload`, etc.

---

## Entries

<!-- Paste one line per real case investigated. Example:
2026-03-01 · ps-encoded phishing lure       · YES · —                                     · —
2026-03-02 · base64 macro from Emotet doc   · NO  · stopped at L2 - variable rename issue · P0 semantic
2026-03-03 · js-eval-obfuscated loader      · YES · missed C2 IP in inline comment        · P1 evidence
-->
