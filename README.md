<div align="center">

# TrinTech Guardian
### Autonomous Active Defense Grid & Intrusion Prevention System (IPS)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%2FUbuntu%2FLinux-orange.svg)](https://termux.dev/)
[![Security Status](https://img.shields.io/badge/status-Active%20Defense-success.svg)]()
[![Organization](https://img.shields.io/badge/TrinTech-Digital%20Defense-red.svg)](https://trintechdigitaldefense.github.io)

</div>

---

## 🛡️ Overview

**TrinTech Guardian** is a lightweight, autonomous Active Defense Grid and Intrusion Prevention System (IPS) engineered specifically for secure mobile network auditing and real-time threat neutralization. Built to operate seamlessly inside constrained environments (such as Android Termux and Ubuntu PRoot laboratories), Guardian provides enterprise-grade telemetry, behavioral analysis, and automated containment without requiring privileged raw kernel sockets.

---

## ⚡ Core Architecture & Modules

TrinTech Guardian operates on a modular defense pipeline designed to detect, verify, isolate, and log anomalous network activity instantly:

* **`__main__.py` (Orchestration Engine):** Initializes the runtime, boots security layers, and manages the primary event loop.
* **`stealth.py` (Ghost Node & Anti-Tamper Vault):** Masquerades the process execution state as a benign system daemon (`[systemd-resolved]`) and verifies core script integrity on boot.
* **`neural_core.py` (Behavioral Threat Engine):** Computes dynamic risk scores using rolling 60-second activity windows and multi-port scan penalties (`NORMAL`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **`failsafe.py` (Circuit Breaker):** Immunizes local gateways and loopback interfaces (`127.0.0.1`, `192.168.1.1`) to prevent accidental self-lockouts or misdirected isolation.
* **`containment.py` (Active Isolation):** Enforces real-time firewall rule dropping (`iptables`) with an integrated safety dry-run simulation mode.
* **`forensics.py` (Compliance Logger):** Automatically captures telemetry snapshots upon containment, writing structured JSON incident reports for risk assessments and client reporting.
* **`sniffer.py` (User-Space Sensors):** Binds unprivileged TCP sockets across high-risk ports to detect network scans and tarpit incoming connections instantly.

---

## 📂 Directory Structure

```text
trintech-guardian/
│
├── guardian/
│   ├── __init__.py
│   ├── __main__.py          # Main orchestration engine
│   ├── containment.py       # Firewall isolation & dry-run logic
│   ├── failsafe.py          # Circuit breaker & gateway immunity
│   ├── forensics.py         # JSON incident snapshot generator
│   ├── neural_core.py       # Behavioral scoring engine
│   ├── sniffer.py           # User-space port sensor
│   └── stealth.py           # Process masquerading & anti-tamper vault
│
├── incident_reports/        # Auto-generated JSON forensic logs
└── README.md

```
## 🚀 Installation & Quick Start
 1. **Clone the repository:**
   ```bash
   git clone [https://github.com/trintechdigitaldefense/trintech-guardian.git](https://github.com/trintechdigitaldefense/trintech-guardian.git)
   cd trintech-guardian
   
   ```
 2. **Run the defense grid:**
   ```bash
   python3 -m guardian
   
   ```
## 📋 Compliance & Reporting
When threats cross the alert threshold, Guardian generates instantaneous JSON incident reports inside the incident_reports/ directory. Each snapshot contains cryptographic timestamps, attacker IP telemetry, threat scores, and executed remediation actions—serving as immediate artifacts for professional security audits.
## 👤 Author & Organization
 * **Organization:** TrinTech Digital Defense
 * **Website:** trintechdigitaldefense.github.io
 * **GitHub:** github.com/trintechdigitaldefense
```

```
