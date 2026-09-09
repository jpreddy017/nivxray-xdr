"""CyberChef headless adapter (docs · CyberChef-server).

Deploy CyberChef-server (https://github.com/gchq/CyberChef-server) and set
`--api http://localhost:3000`. You must translate NivXRay recipes into
CyberChef recipes — this is intentionally out-of-band because CyberChef
doesn't auto-solve.

For a fair fight we recommend running CyberChef in `magic` mode:
    POST /magic  { "input": <payload>, "args": { "depth": 3, "intensive": true } }
"""
import requests


def decode(payload: str, api: str, *_a, **_kw) -> dict:
    r = requests.post(f"{api.rstrip('/')}/magic",
                       json={"input": payload,
                             "args": {"depth": 3, "intensive": True}},
                       timeout=30)
    r.raise_for_status()
    return r.json()
