"""
=====================================================================
 DEMO / TEST TRAFFIC GENERATOR -- FOR LOCAL DETECTION DEMOS ONLY
=====================================================================
Generates controlled, safe traffic patterns aimed ONLY at your own
machine (127.0.0.1 by default) so you can trigger the NIDS detection
rules on demand without needing real attack traffic.

Requires the same Npcap + Administrator setup as the main app, because
it crafts raw packets with Scapy.

Usage (run in an Administrator PowerShell, with app.py already running
and monitoring started):

    python demo.py portscan
    python demo.py synflood
    python demo.py icmpflood
    python demo.py all

Optional: python demo.py portscan --target 127.0.0.1
=====================================================================
"""

import argparse
import sys
import time

from scapy.all import IP, TCP, ICMP, send, RandShort

BANNER = "[DEMO/TEST TRAFFIC]"


def run_portscan(target):
    # A realistic scan list: sequential low ports + a handful of the
    # "suspicious" service ports, so both Port Scan and Suspicious Port
    # Activity alerts fire together, just like a real scan would trigger.
    ports = list(range(2000, 2025)) + [21, 22, 23, 445, 3389]
    print(f"{BANNER} Port scan -> {target} across {len(ports)} ports")
    for i, port in enumerate(ports, 1):
        pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
        send(pkt, verbose=False)
        print(f"{BANNER}   SYN -> {target}:{port} ({i}/{len(ports)})")
        time.sleep(0.05)
    print(f"{BANNER} Port scan traffic complete.")


def run_synflood(target, port=80, count=100):
    print(f"{BANNER} SYN flood -> {target}:{port} ({count} packets)")
    pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
    send(pkt, count=count, inter=0.01, verbose=False)
    print(f"{BANNER} SYN flood traffic complete.")


def run_icmpflood(target, count=100):
    print(f"{BANNER} ICMP flood -> {target} ({count} packets)")
    pkt = IP(dst=target) / ICMP()
    send(pkt, count=count, inter=0.02, verbose=False)
    print(f"{BANNER} ICMP flood traffic complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate safe, local DEMO/TEST traffic to trigger NIDS alerts."
    )
    parser.add_argument(
        "mode",
        choices=["portscan", "synflood", "icmpflood", "all"],
        help="Which attack pattern to simulate.",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IP -- keep this at 127.0.0.1 or another IP of your own machine. Default: 127.0.0.1",
    )
    args = parser.parse_args()

    print(f"{BANNER} Target: {args.target}  (make sure this is YOUR OWN machine)")
    print(f"{BANNER} Make sure the NIDS dashboard is running and monitoring is started.\n")

    try:
        if args.mode in ("portscan", "all"):
            run_portscan(args.target)
            time.sleep(1)
        if args.mode in ("synflood", "all"):
            run_synflood(args.target)
            time.sleep(1)
        if args.mode in ("icmpflood", "all"):
            run_icmpflood(args.target)
    except PermissionError:
        print(
            "\nPermissionError: sending raw packets needs Administrator rights.\n"
            "Close this terminal and re-run it as Administrator."
        )
        sys.exit(1)

    print(f"\n{BANNER} Done. Check the dashboard for new alerts.")


if __name__ == "__main__":
    main()
