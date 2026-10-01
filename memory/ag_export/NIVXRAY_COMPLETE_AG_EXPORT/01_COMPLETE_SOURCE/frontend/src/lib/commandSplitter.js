/**
 * commandSplitter — shared multi-command detector.
 *
 * Recognises the head token of a line as a known shell / LOLBAS /
 * scripting keyword so we can safely split single-newline pastes
 * into separate stages without needing the user to add blank lines.
 *
 * Exported so both ChainStageEditor and WorkspacePage use the same
 * heuristic (fixes the Feb-2026 bug where AUTO INVESTIGATE / DECODE
 * only analysed line 1 of a multi-command chain).
 */

const _CMD_HEADS = [
  "powershell", "pwsh", "cmd", "cmd.exe",
  "certutil", "mshta", "rundll32", "regsvr32", "regsvcs", "regasm",
  "msiexec", "installutil", "bitsadmin", "wmic", "wscript", "cscript",
  "schtasks", "at.exe", "sc.exe", "netsh", "net.exe", "net ",
  "curl", "wget", "iwr", "iex", "invoke-expression", "invoke-webrequest",
  "start-process", "start ", "cmdkey", "runas",
  "bash", "sh ", "python", "python3", "perl", "ruby", "node",
  "vssadmin", "wbadmin", "bcdedit", "reg add", "reg delete",
  "esentutl", "diskshadow", "dnx", "dotnet", "dxcap",
];

function _looksLikeCommand(line) {
  const t = (line || "").trim().toLowerCase();
  if (!t || t.length > 4000) return false;
  if (/^([#;>]|::|rem\s|\/\/)/.test(t)) return false;
  return _CMD_HEADS.some((h) => t.startsWith(h));
}

// A "continuation" line is a PowerShell script fragment that on its own is
// not a standalone attack — e.g. `$var = ...`, `$var = New-Object ...`, a
// lone closing brace `}`, or a trailing pipe. These should be glued to the
// preceding standalone command so the chain analysis treats the whole
// script block as one stage.
function _isContinuation(line) {
  const t = (line || "").trim();
  if (!t) return false;
  if (t.startsWith("$")) return true;            // $var = ...
  if (/^[)}\]]/.test(t)) return true;             // } ) ]
  if (/[|\\`]\s*$/.test(t)) return true;          // line ends with pipe / backslash / backtick
  // `IEX $var…` — IEX invoking a previously-declared PS variable is a
  // script continuation, not a fresh attack one-liner.
  if (/^iex\s+\$/i.test(t)) return true;
  return false;
}

/**
 * Split a multi-line blob into separate command lines. Returns null when
 * the blob is a single logical statement (< 2 lines OR only one line
 * looks command-like).
 *
 * Adjacent PowerShell script lines that BEGIN with `$` (variable
 * assignments) are glued to the preceding command line — they form ONE
 * logical script stage. Standalone attack one-liners (e.g. `(New-Object
 * Net.WebClient).DownloadString(...)`) remain their own stage.
 */
export function splitCommandLines(text) {
  if (!text || !text.includes("\n")) return null;

  // Fast path — blank-line delimited.
  const blankSplit = text.split(/\n\s*\n+/).map((p) => p.trim()).filter(Boolean);
  if (blankSplit.length > 1) return blankSplit;

  const raw = text.split(/\r?\n/).map((l) => l.replace(/[\t ]+$/g, ""))
                  .filter((l) => l.trim().length > 0);
  if (raw.length < 2) return null;

  // Walk the lines: standalone command lines start a new group, obvious
  // script continuations (`$var=…`, closing brace) glue to the previous.
  const groups = [];
  for (const line of raw) {
    if (groups.length === 0) {
      groups.push(line);
      continue;
    }
    if (_isContinuation(line)) {
      groups[groups.length - 1] += "\n" + line;
    } else {
      groups.push(line);
    }
  }

  if (groups.length < 2) return null;

  // Require ≥ 2 command-lookalike groups (each group starts with a command
  // head OR is a valid one-liner like `(New-Object ...)`).
  const cmdCount = groups.filter((g) => {
    const first = g.split("\n")[0].trim();
    return _looksLikeCommand(first) || /^\(\s*new-object/i.test(first);
  }).length;
  if (cmdCount >= 2) return groups;
  return null;
}

/** Convenience predicate for entry-point routing. */
export function isMultiCommandInput(text) {
  const parts = splitCommandLines(text);
  return Array.isArray(parts) && parts.length > 1;
}
