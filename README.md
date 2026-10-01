<div align="center">

# TrinTech-Guardian
### Autonomous Active Defense Grid & Intrusion Prevention System (IPS)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%2FUbuntu%2FLinux-orange.svg)](https://termux.dev/)
[![Version](https://img.shields.io/badge/version-1.1.0-green.svg)]()
[![Organization](https://img.shields.io/badge/TrinTech-Digital%20Defense-red.svg)](https://trintechdigitaldefense.github.io)

</div>

---

## Overview

**TrinTech-Guardian** is a lightweight, autonomous Active Defense Grid and Intrusion Prevention System engineered for secure mobile network auditing and real-time threat neutralization.

It runs cleanly inside constrained environments (Android Termux, Ubuntu PRoot, modest VPS) and provides behavioral analysis, automated containment, process masquerading, and forensic logging — without requiring privileged raw kernel sockets.

**v1.1.0 upgrades:**
- Full CLI (`--live`, `--dry-run`, `--status`, `--release`, `--threshold`, `--ports`)
- Config-driven behaviour via `guardian/config.json`
- Smarter fail-safe (auto-detect local interfaces + private range protection)
- Persistent isolation state + cooldown
- Improved scoring and forensic reports
- Cleaner package structure

---

## Core Architecture

| Module | Role |
|--------|------|
| `__main__.py` | Orchestration + CLI |
| `stealth.py` | Process masquerading + anti-tamper vault |
| `neural_core.py` | Behavioral threat scoring (rolling window) |
| `failsafe.py` | Circuit breaker / local immunity |
| `containment.py` | iptables + nftables isolation + state |
| `forensics.py` | JSON incident snapshots |
| `sniffer.py` | User-space multi-port sensor |

---

## Installation & Quick Start

```bash
git clone https://github.com/trintechdigitaldefense/trintech-guardian.git
cd trintech-guardian

# Default = dry-run (safe)
python3 -m guardian

# Real containment (requires privileges for iptables/nft)
python3 -m guardian --live

# Custom threshold and ports
python3 -m guardian --threshold 40 --ports 22,80,443,8080,8443

# Check status / release an IP
python3 -m guardian --status
python3 -m guardian --release 203.0.113.50
```

No external dependencies required for core operation (stdlib only). Optional: `setproctitle` for better process renaming on some systems.

---

## Configuration

Edit `guardian/config.json`:

```json
{
  "version": "1.1.0",
  "dry_run": true,
  "alert_threshold": 50,
  "listen_ports": [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443],
  "whitelist": ["127.0.0.1", "::1", "localhost"],
  "auto_detect_local": true,
  "containment_cooldown_seconds": 300,
  "process_name": "[systemd-resolved]",
  "log_dir": "incident_reports",
  "state_file": "guardian_state.json",
  "webhook_url": null,
  "verbose": true
}
```

---

## Compliance & Reporting

When a threat crosses the alert threshold, Guardian writes a structured JSON incident report into `incident_reports/`. Each report contains:

- Cryptographic timestamp
- Attacker IP + threat score + severity
- Connection counts and unique ports
- Action taken (dry-run or live isolation)

These artifacts are ready for client reporting and audit trails.

---

## Authorized Use Only

TrinTech-Guardian is intended for **authorized defensive use and controlled testing only**.  
Unauthorized scanning or isolation of systems you do not own or have explicit permission to defend is illegal.

Reference: Trinidad & Tobago Cybercrime Act.

---

## Author & Organization

- **Organization:** TrinTech Digital Defense
- **Website:** [trintechdigitaldefense.github.io](https://trintechdigitaldefense.github.io)
- **GitHub:** [github.com/trintechdigitaldefense](https://github.com/trintechdigitaldefense)
- **Contact:** trintechdigitaldefense@gmail.com · WhatsApp +1-868-362-0679

---

*Defend. Detect. Dominate.*
