#!/usr/bin/env python3
"""
TrinTech-Guardian v1.1.0
Autonomous Active Defense Grid & Intrusion Prevention System
TrinTech Digital Defense · Trinidad & Tobago

Usage:
  python3 -m guardian                  # start with defaults (dry-run)
  python3 -m guardian --live           # enable real iptables/nft containment
  python3 -m guardian --status         # show current state
  python3 -m guardian --release IP     # release an isolated IP
  python3 -m guardian --threshold 40   # override alert threshold
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .stealth import AntiTamperVault, masquerade_process
from .neural_core import NeuralCore
from .failsafe import FailSafeGuard
from .containment import ContainmentEngine
from .forensics import ForensicInvestigator
from .sniffer import PortSensor


DEFAULT_CONFIG = {
    "version": "1.1.0",
    "dry_run": True,
    "alert_threshold": 50,
    "listen_ports": [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443],
    "whitelist": ["127.0.0.1", "::1", "localhost"],
    "auto_detect_local": True,
    "containment_cooldown_seconds": 300,
    "process_name": "[systemd-resolved]",
    "log_dir": "incident_reports",
    "state_file": "guardian_state.json",
    "webhook_url": None,
    "verbose": True,
}


def load_config(config_path: str = None) -> dict:
    """Load config.json if present, otherwise use defaults."""
    cfg = DEFAULT_CONFIG.copy()
    candidates = []
    if config_path:
        candidates.append(config_path)
    pkg_dir = Path(__file__).resolve().parent
    candidates.extend([
        pkg_dir / "config.json",
        Path.cwd() / "config.json",
        Path.cwd() / "guardian" / "config.json",
    ])
    for path in candidates:
        path = Path(path)
        if path.is_file() and path.stat().st_size > 0:
            try:
                with open(path, "r") as f:
                    user_cfg = json.load(f)
                cfg.update(user_cfg)
                return cfg
            except Exception:
                continue
    return cfg


def print_banner(version: str, dry_run: bool):
    mode = "DRY-RUN" if dry_run else "LIVE CONTAINMENT"
    print("\n" + "=" * 56)
    print("   TRINTECH GUARDIAN  v{}  —  Active Defense Grid".format(version))
    print("   Mode: {}".format(mode))
    print("   TrinTech Digital Defense · Trinidad & Tobago")
    print("=" * 56)


def threat_handler_factory(core, failsafe, containment, forensics, verbose=True):
    def handler(src_ip: str, dst_port: int):
        if failsafe.is_protected(src_ip):
            if verbose:
                print(f"[FAILSAFE] Protected address ignored: {src_ip}")
            return

        if containment.is_on_cooldown(src_ip):
            return

        analysis = core.record_event(src_ip, dst_port)

        if analysis["trigger_containment"]:
            print(
                f"\n[!] THREAT  {src_ip}  score={analysis['score']}  "
                f"severity={analysis['severity']}  ports={analysis['unique_ports']}"
            )

            if not failsafe.verify_action_safety(src_ip):
                print(f"[FAILSAFE] Containment blocked for protected IP: {src_ip}")
                return

            success = containment.isolate_ip(src_ip)
            if success:
                action = (
                    "DRY_RUN_LOGGED"
                    if containment.dry_run
                    else "ISOLATED_IPTABLES_OR_NFT"
                )
                forensics.generate_snapshot(analysis, action_taken=action)
                core.reset_score(src_ip)
            else:
                print(f"[!] Containment failed for {src_ip}")

    return handler


def cmd_status(cfg):
    containment = ContainmentEngine(
        dry_run=cfg["dry_run"],
        state_file=cfg["state_file"],
        cooldown_seconds=cfg["containment_cooldown_seconds"],
    )
    forensics = ForensicInvestigator(log_dir=cfg["log_dir"])
    print_banner(cfg.get("version", "1.1.0"), cfg["dry_run"])
    print("\n[STATUS]")
    print(json.dumps({
        "containment": containment.get_status(),
        "forensics": forensics.get_status(),
        "config_threshold": cfg["alert_threshold"],
        "listen_ports": cfg["listen_ports"],
    }, indent=2))


def cmd_release(cfg, ip: str):
    containment = ContainmentEngine(
        dry_run=cfg["dry_run"],
        state_file=cfg["state_file"],
        cooldown_seconds=cfg["containment_cooldown_seconds"],
    )
    ok = containment.release_ip(ip)
    print(f"Release {'succeeded' if ok else 'failed'} for {ip}")


def cmd_run(cfg, args):
    if args.live:
        cfg["dry_run"] = False
    if args.dry_run:
        cfg["dry_run"] = True
    if args.threshold is not None:
        cfg["alert_threshold"] = args.threshold
    if args.ports:
        cfg["listen_ports"] = [int(p) for p in args.ports.split(",")]

    print_banner(cfg.get("version", "1.1.0"), cfg["dry_run"])

    masquerade_process(cfg.get("process_name", "[systemd-resolved]"))

    pkg_dir = Path(__file__).resolve().parent
    vault_files = [
        str(pkg_dir / "config.json"),
        str(pkg_dir / "__main__.py"),
        str(pkg_dir / "neural_core.py"),
        str(pkg_dir / "containment.py"),
    ]
    vault = AntiTamperVault(vault_files)
    if not vault.verify_integrity():
        print("[!] CRITICAL: Core file integrity check failed. Aborting.")
        sys.exit(1)

    core = NeuralCore(alert_threshold=cfg["alert_threshold"])
    failsafe = FailSafeGuard(
        custom_whitelist=cfg.get("whitelist"),
        auto_detect_local=cfg.get("auto_detect_local", True),
    )
    containment = ContainmentEngine(
        dry_run=cfg["dry_run"],
        state_file=cfg["state_file"],
        cooldown_seconds=cfg["containment_cooldown_seconds"],
    )
    forensics = ForensicInvestigator(log_dir=cfg["log_dir"])

    print("[+] Ghost Node          : ENGAGED")
    print("[+] Neural Core         : ONLINE")
    print("[+] Fail-Safe Circuit   : ONLINE")
    print(f"[+] Containment Engine  : ONLINE ({'DRY-RUN' if cfg['dry_run'] else 'LIVE'})")
    print("[+] Forensic Engine     : ONLINE")
    print(f"[+] Alert Threshold     : {cfg['alert_threshold']}")

    handler = threat_handler_factory(
        core, failsafe, containment, forensics, verbose=cfg.get("verbose", True)
    )

    sensor = PortSensor(
        callback_function=handler,
        ports=cfg["listen_ports"],
    )

    print("\n[*] Guardian operational. Listening for threats... (Ctrl+C to stop)\n")
    try:
        sensor.start()
    except KeyboardInterrupt:
        print("\n[*] Guardian shutting down gracefully.")
        sensor.stop()
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="TrinTech-Guardian — Autonomous Active Defense Grid",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m guardian
  python3 -m guardian --live
  python3 -m guardian --threshold 40 --ports 22,80,443,8080
  python3 -m guardian --status
  python3 -m guardian --release 203.0.113.50
        """,
    )
    parser.add_argument("--live", action="store_true", help="Enable real containment (iptables/nft)")
    parser.add_argument("--dry-run", action="store_true", help="Force dry-run mode (default)")
    parser.add_argument("--threshold", type=int, help="Override alert threshold")
    parser.add_argument("--ports", type=str, help="Comma-separated ports to listen on")
    parser.add_argument("--config", type=str, help="Path to config.json")
    parser.add_argument("--status", action="store_true", help="Show current status and exit")
    parser.add_argument("--release", type=str, metavar="IP", help="Release an isolated IP and exit")

    args = parser.parse_args()
    cfg = load_config(args.config)

    if args.status:
        cmd_status(cfg)
        return
    if args.release:
        cmd_release(cfg, args.release)
        return

    cmd_run(cfg, args)


if __name__ == "__main__":
    main()
