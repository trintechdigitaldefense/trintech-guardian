"""
Active isolation engine for TrinTech-Guardian.
Supports dry-run, timed blocks, iptables + nftables, persistent state, safe release.
"""

import json
import os
import subprocess
import time
from typing import Dict


class ContainmentEngine:
    """Enforces isolation of hostile source IPs with optional auto-expiry."""

    def __init__(
        self,
        dry_run: bool = True,
        state_file: str = "guardian_state.json",
        cooldown_seconds: int = 300,
        block_duration_seconds: int = 1800,
    ):
        self.dry_run = dry_run
        self.state_file = state_file
        self.cooldown_seconds = cooldown_seconds
        self.block_duration_seconds = block_duration_seconds
        self.isolated_ips: Dict[str, dict] = {}
        self._load_state()
        self._expire_stale()

    def _load_state(self) -> None:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    raw = data.get("isolated_ips", {})
                    for ip, val in raw.items():
                        if isinstance(val, (int, float)):
                            self.isolated_ips[ip] = {
                                "ts": float(val),
                                "expires": float(val) + self.block_duration_seconds,
                            }
                        elif isinstance(val, dict):
                            self.isolated_ips[ip] = val
            except Exception:
                self.isolated_ips = {}

    def _save_state(self) -> None:
        try:
            with open(self.state_file, "w") as f:
                json.dump(
                    {
                        "isolated_ips": self.isolated_ips,
                        "dry_run": self.dry_run,
                        "block_duration_seconds": self.block_duration_seconds,
                        "updated": time.time(),
                    },
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def _expire_stale(self) -> None:
        now = time.time()
        expired = [ip for ip, meta in self.isolated_ips.items() if meta.get("expires", 0) <= now]
        for ip in expired:
            if not self.dry_run:
                self._iptables_delete(ip)
            self.isolated_ips.pop(ip, None)
        if expired:
            self._save_state()

    def is_on_cooldown(self, ip_address: str) -> bool:
        self._expire_stale()
        meta = self.isolated_ips.get(ip_address)
        if meta is None:
            return False
        return (time.time() - meta.get("ts", 0)) < self.cooldown_seconds

    def isolate_ip(self, ip_address: str) -> bool:
        self._expire_stale()
        if ip_address in self.isolated_ips and self.is_on_cooldown(ip_address):
            return True

        now = time.time()
        expires = now + self.block_duration_seconds

        if self.dry_run:
            print(f"[CONTAINMENT-DRY-RUN] Simulating DROP for {ip_address} (expires in {self.block_duration_seconds}s)")
            self.isolated_ips[ip_address] = {"ts": now, "expires": expires}
            self._save_state()
            return True

        success = self._iptables_drop(ip_address) or self._nftables_drop(ip_address)
        if success:
            print(f"[CONTAINMENT] Isolated {ip_address} for {self.block_duration_seconds}s")
            self.isolated_ips[ip_address] = {"ts": now, "expires": expires}
            self._save_state()
        else:
            print(f"[CONTAINMENT] Failed to isolate {ip_address}")
        return success

    def _iptables_drop(self, ip_address: str) -> bool:
        try:
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            if check.returncode == 0:
                return True
            res = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def _iptables_delete(self, ip_address: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            pass

    def _nftables_drop(self, ip_address: str) -> bool:
        try:
            res = subprocess.run(
                ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip_address, "drop"],
                capture_output=True, text=True, timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def release_ip(self, ip_address: str) -> bool:
        if ip_address not in self.isolated_ips:
            print(f"[CONTAINMENT] {ip_address} was not isolated")
            return True
        if self.dry_run:
            print(f"[CONTAINMENT-DRY-RUN] Releasing {ip_address}")
            self.isolated_ips.pop(ip_address, None)
            self._save_state()
            return True
        self._iptables_delete(ip_address)
        self.isolated_ips.pop(ip_address, None)
        self._save_state()
        print(f"[CONTAINMENT] Released {ip_address}")
        return True

    def release_all(self) -> int:
        ips = list(self.isolated_ips.keys())
        for ip in ips:
            self.release_ip(ip)
        return len(ips)

    def list_isolated(self) -> Dict[str, dict]:
        self._expire_stale()
        return dict(self.isolated_ips)

    def get_status(self) -> dict:
        self._expire_stale()
        return {
            "dry_run": self.dry_run,
            "isolated_count": len(self.isolated_ips),
            "isolated_ips": list(self.isolated_ips.keys()),
            "cooldown_seconds": self.cooldown_seconds,
            "block_duration_seconds": self.block_duration_seconds,
        }
