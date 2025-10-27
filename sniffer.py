#!/usr/bin/env python3
# cyber-sniffer - simple packet sniffer (educational use only)
# Author: Ege Aksoy
# Usage: sudo python3 sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
from tabulate import tabulate
from datetime import datetime
import signal
import sys
import json
import os

# Save captured rows to memory and optionally to file on exit
results = []
OUTPUT_DIR = "logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "capture.json")

def packet_to_row(pkt):
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
    return {"timestamp": ts, "src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport}

def packet_handler(pkt):
    row = packet_to_row(pkt)
    results.append(row)
    # Print a compact, readable line for each packet
    sport = row["sport"] if row["sport"] != "" else "-"
    dport = row["dport"] if row["dport"] != "" else "-"
    print(f"[{row['timestamp']}] {row['src']} -> {row['dst']} | {row['proto']} {sport}->{dport}")

def save_results():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved {len(results)} packets to {OUTPUT_FILE}")

def signal_handler(sig, frame):
    print("\nStopping capture...")
    save_results()
    # Optionally print a small table summary (top 10 rows)
    try:
        sample = results[:10]
        if sample:
            table = [[r["timestamp"], r["src"], r["dst"], r["proto"], r["sport"], r["dport"]] for r in sample]
            print("\nSample captured packets:")
            print(tabulate(table, headers=["time","src","dst","proto","sport","dport"]))
    except Exception:
        pass
    sys.exit(0)

def main():
    print("Cyber Sniffer Mini - starting capture (CTRL+C to stop).")
    print("Note: You may need root privileges (sudo) to capture on interfaces.")
    signal.signal(signal.SIGINT, signal_handler)
    # Use sniff(iface=\"en0\", filter=\"tcp\", ...) to customize on mac
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    main()

