<div align="center">

# TrinTech-Guardian
### Autonomous Active Defense Grid & Intrusion Prevention System (IPS)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%2FUbuntu%2FLinux-orange.svg)](https://termux.dev/)
[![Version](https://img.shields.io/badge/version-1.2.0-green.svg)]()
[![Organization](https://img.shields.io/badge/TrinTech-Digital%20Defense-red.svg)](https://trintechdigitaldefense.github.io)

</div>

---

## Overview

**TrinTech-Guardian** is a lightweight, autonomous Active Defense Grid and Intrusion Prevention System engineered for secure mobile network auditing and real-time threat neutralization.

It runs cleanly inside constrained environments (Android Termux, Ubuntu PRoot, modest VPS) and provides behavioral analysis, automated containment, process masquerading, deception canaries, process scanning, and forensic logging — without requiring privileged raw kernel sockets.

### v1.2.0 Features
- Full CLI (`--live`, `--dry-run`, `--status`, `--release`, `--threshold`, `--ports`, `--scan-now`)
- Config-driven behaviour via `guardian/config.json`
- Smarter fail-safe (auto-detect local interfaces + private range protection)
- Persistent isolation state + cooldown
- **Webhook + Telegram alerting**
- **Process scanner** (reverse-shell & suspicious binary detection)
- **Deception canaries** (fake services that feed the scoring engine)
- Improved scoring and forensic reports

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
| `alerting.py` | Webhook + Telegram notifications |
| `process_scan.py` | Reverse-shell / suspicious process detection |
| `deception.py` | Fake service canaries |

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

# Check status / release an IP / one-shot process scan
python3 -m guardian --status
python3 -m guardian --release 203.0.113.50
python3 -m guardian --scan-now
```

No external dependencies required for core operation (stdlib only). Optional: `setproctitle` for better process renaming on some systems.

---

## Configuration

Edit `guardian/config.json`:

```json
{
  "version": "1.2.0",
  "dry_run": true,
  "alert_threshold": 50,
  "listen_ports": [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443],
  "whitelist": ["127.0.0.1", "::1", "localhost"],
  "auto_detect_local": true,
  "containment_cooldown_seconds": 300,
  "process_name": "[systemd-resolved]",
  "log_dir": "incident_reports",
  "state_file": "guardian_state.json",
  "verbose": true,

  "alerting": {
    "enabled": true,
    "webhook_url": null,
    "telegram_bot_token": null,
    "telegram_chat_id": null
  },

  "process_scan": {
    "enabled": true,
    "interval_seconds": 30
  },

  "deception": {
    "enabled": true,
    "ports": [21, 23, 3306, 6379, 27017]
  }
}
```

### Telegram Setup
1. Create a bot via @BotFather → copy token
2. Get your chat_id (message the bot, then hit `https://api.telegram.org/bot<TOKEN>/getUpdates`)
3. Put both values into `config.json` under `alerting`

### Webhook
Any HTTPS endpoint that accepts JSON POST works (Discord, Slack, custom, etc.).

---

## Compliance & Reporting

When a threat crosses the alert threshold (or a suspicious process is found), Guardian writes a structured JSON incident report into `incident_reports/`. Each report contains timestamp, attacker/process details, threat score, severity, and action taken.

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
