#!/usr/bin/env python3
# cyber-sniffer - simple packet sniffer (educational use only)
# Author: Ege Aksoy
# Usage: sudo python3 sniffer.py

from datetime import datetime
import json
import os
import signal
import sys

from scapy.all import sniff, IP, TCP, UDP, ICMP  # noqa: E402
from tabulate import tabulate  # noqa: E402


results = []
OUTPUT_DIR = "samples"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "capture.json")


def packet_to_row(pkt):
    """
    Convert a scapy packet into a structured dict with basic metadata.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src = pkt[IP].src if IP in pkt else "N/A"
    dst = pkt[IP].dst if IP in pkt else "N/A"

    proto = "OTHER"
    sport = ""
    dport = ""

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    return {
        "timestamp": ts,
        "src": src,
        "dst": dst,
        "proto": proto,
        "sport": sport,
        "dport": dport,
    }


def packet_handler(pkt):
    """
    Handle each captured packet:
    - Store row in memory
    - Print readable one-line summary
    """
    row = packet_to_row(pkt)
    results.append(row)

    sport = row["sport"] if row["sport"] != "" else "-"
    dport = row["dport"] if row["dport"] != "" else "-"

    # Break long f-string across lines to satisfy line length rules.
    print(
        "[{ts}] {src} -> {dst} | {proto} {sport}->{dport}".format(
            ts=row["timestamp"],
            src=row["src"],
            dst=row["dst"],
            proto=row["proto"],
            sport=sport,
            dport=dport,
        )
    )


def save_results():
    """
    Dump captured packets to samples/capture.json
    and print a small summary table (first 10 rows).
    """
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(
        "\nSaved {count} packets to {out}".format(
            count=len(results),
            out=OUTPUT_FILE,
        )
    )

    # Build a short preview table (first 10 captured rows)
    try:
        sample = results[:10]
        if sample:
            table = [
                [
                    r["timestamp"],
                    r["src"],
                    r["dst"],
                    r["proto"],
                    r["sport"],
                    r["dport"],
                ]
                for r in sample
            ]

            print("\nSample captured packets:")
            print(
                tabulate(
                    table,
                    headers=[
                        "time",
                        "src",
                        "dst",
                        "proto",
                        "sport",
                        "dport",
                    ],
                )
            )
    except Exception as err:
        # We don't want to kill shutdown flow just because of preview
        print("Summary table error:", err)


def signal_handler(sig, frame):
    """
    Trap CTRL+C:
    - stop sniffing cleanly
    - save captured results
    """
    print("\nStopping capture...")
    save_results()
    sys.exit(0)


def main():
    """
    Entry point. Start sniffing.
    Note: You may need sudo/root to capture traffic.
    On macOS you can specify the interface, e.g.:
    sniff(iface="en0", prn=packet_handler, store=False)
    """
    print("Cyber Sniffer Mini - starting capture (CTRL+C to stop).")
    print(
        "Note: You may need root privileges (sudo) "
        "to capture on interfaces."
    )

    signal.signal(signal.SIGINT, signal_handler)

    # default sniff on whatever interface scapy picks
    sniff(prn=packet_handler, store=False)


if __name__ == "__main__":
    main()
