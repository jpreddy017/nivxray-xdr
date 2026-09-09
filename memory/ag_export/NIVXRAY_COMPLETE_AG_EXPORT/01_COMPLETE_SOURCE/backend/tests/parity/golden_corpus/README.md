# Golden Corpus · X-Lab canonical investigations

Long-term regression suite. Every fixture is a fully-populated CIO
(as returned by `/api/decode/smart` or synthesised by hand from a real
vendor alert) that the composer + critic must handle cleanly.

## Layout

    tests/parity/golden_corpus/
      cisco_xdr/          # Cisco Secure Endpoint / XDR
      crowdstrike/
      defender_xdr/
      sentinelone/
      qradar/
      splunk/
      sysmon/
      zeek/
      suricata/
      elastic/
      windows_event/
      powershell/
      lolbas/
      linux/
      macos/
      office/
      bits/
      wmi/
      scheduled_tasks/

Each vendor directory contains one JSON file per canonical case,
named `<case-slug>.json`. The JSON is a raw CIO with at minimum:

    {
      "case_id": "...",                    # optional
      "case_label": "PowerShell -enc IEX downloader",
      "expected_verdict": "Malicious",
      "expected_critic_score_min": 90,
      "cio": { … full CIO … }
    }

The runner (`test_golden_corpus.py`) walks every JSON, composes the
customer report, runs the critic, and asserts:

  1. Composer never raises.
  2. Verdict label matches `expected_verdict`.
  3. Critic score ≥ `expected_critic_score_min`.
  4. Critic reports zero `blocker`-severity issues.
  5. Zero forbidden-term leaks in the verdict surface.

Adding a new fixture:

  1. Drop a JSON at `<vendor>/<slug>.json`.
  2. Bump `expected_critic_score_min` to at least 90.
  3. Run `pytest tests/parity/test_golden_corpus.py -q`.

Target: **300–500 fixtures** across the 19 vendor categories. This
directory becomes the platform's long-term regression suite and the
factual basis for any future Incident Correlation Engine work.
