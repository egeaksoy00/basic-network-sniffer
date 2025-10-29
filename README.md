# 🕵️ Cyber Sniffer Mini — by Ege Aksoy

[![Python Lint](https://github.com/egeaksoy00/basic-network-sniffer/actions/workflows/python-lint.yml/badge.svg)](https://github.com/egeaksoy00/basic-network-sniffer/actions)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

> **Note:** This repository contains educational code.  
> I have **not** run the sniffer on networks without permission.  
> See [`samples/sample_capture.json`](samples/sample_capture.json) for example output.

---

## 📘 Overview
A simple Python-based packet sniffer that listens to network traffic and prints basic info for each packet (source IP, destination IP, protocol, ports).  
When you stop the program with CTRL+C, it saves captured packets as JSON in `samples/capture.json`.

This repository demonstrates:
- Basic packet capture using **Scapy**
- Simple packet parsing & logging
- Beginner-friendly repo structure for cybersecurity learners

---

## ⚙️ Features
- Live console output of captured packets  
- TCP / UDP / ICMP protocol identification  
- JSON export of captured traffic metadata  
- Automatic summary table on exit  

---

## 💻 Requirements
- Python **3.8+**
- macOS / Linux / WSL  
- Root (sudo) may be required for network sniffing  

---

## 🚀 Installation
```bash
git clone https://github.com/egeaksoy00/basic-network-sniffer.git
cd basic-network-sniffer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

