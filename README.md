# Cyber Sniffer Mini — by Ege Aksoy

Simple packet sniffer for educational purposes only.

## Overview
This tool listens to network traffic and prints basic info for each packet (source IP, destination IP, protocol, ports).  
When you stop the program with CTRL+C, it also saves a JSON log file under `logs/capture.json`.

## Features
- Live packet capture
- TCP / UDP / ICMP protocol identification
- Automatic JSON export
- Small traffic summary table on exit

## Requirements
- Python 3.8+
- macOS / Linux / WSL
- Root (sudo) may be required to sniff

## Install
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

