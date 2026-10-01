<div align="center">

# TrinTech-Guardian
### Autonomous Active Defense Grid & Intrusion Prevention System (IPS)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%2FUbuntu%2FLinux-orange.svg)](https://termux.dev/)
[![Version](https://img.shields.io/badge/version-1.3.0-green.svg)]()
[![Organization](https://img.shields.io/badge/TrinTech-Digital%20Defense-red.svg)](https://trintechdigitaldefense.github.io)

</div>

---

## Overview

**TrinTech-Guardian** is a lightweight, client-deployable Active Defense Grid and Intrusion Prevention System for secure mobile/network auditing and real-time threat neutralization.

Built for constrained environments (Android Termux, Ubuntu PRoot, modest VPS) and SMB clients in Trinidad & Tobago and the Caribbean.

### v1.3.0 — Client-Ready

- Install / uninstall scripts + optional systemd service
- Client HTML (and optional PDF) executive reports
- Timed containment blocks with auto-expiry + `--release` / `--release-all`
- Rate-limited Telegram + webhook alerting
- Process scanner (reverse shells / suspicious binaries)
- Deception canaries feeding the same scoring engine
- ROE template for signed engagements
- Unit tests for core modules
- Dry-run by default — live mode only after ROE

---

## Quick Start (operator)

```bash
git clone https://github.com/trintechdigitaldefense/trintech-guardian.git
cd trintech-guardian

python3 -m guardian
python3 -m guardian --report --client "Acme Ltd" --engagement ENG-2026-042
python3 -m guardian --scan-now
python3 -m guardian --status
python3 -m guardian --release 203.0.113.50
python3 -m guardian --release-all
```

## Install (server / client host)

```bash
sudo bash install.sh
guardian --status
sudo systemctl enable --now trintech-guardian   # optional
```

Uninstall: `sudo bash uninstall.sh` (add `--purge` to remove config).

---

## Configuration

After install: `/etc/trintech-guardian/config.json`  
Portable: `guardian/config.json`

| Key | Meaning |
|-----|---------|
| `dry_run` | `true` = log only (default). `false` = live timed blocks |
| `alert_threshold` | Score that triggers containment |
| `block_duration_seconds` | Live block duration (default 1800) |
| `alerting.*` | Webhook and/or Telegram credentials |
| `deception.ports` | Canary ports |
| `process_scan.enabled` | Local process detection |

---

## Client Engagement Flow

1. Sign **ROE** (`docs/ROE_TEMPLATE.md`)
2. Install with `install.sh` (stays dry-run until config updated)
3. Run monitoring window
4. Deliver report: `guardian --report --client "Name" --engagement ID`
5. Uninstall or leave as managed service

---

## Tests

```bash
python3 -m tests.test_core
```

---

## Authorized Use Only

Defensive use under signed Rules of Engagement only.  
Reference: Trinidad & Tobago Cybercrime Act.

---

**TrinTech Digital Defense** · Trinidad & Tobago  
https://trintechdigitaldefense.github.io  
trintechdigitaldefense@gmail.com · WhatsApp +1-868-362-0679  

*Defend. Detect. Dominate.*
