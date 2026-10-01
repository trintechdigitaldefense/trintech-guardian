"""
Active isolation / containment engine for TrinTech-Guardian.
Supports dry-run, iptables, and basic nftables fallback. Tracks state + cooldown.
"""

import json
import os
import subprocess
import time
from typing import Dict, Optional, Set


class ContainmentEngine:
    """Enforces real-time isolation of hostile source IPs."""

    def __init__(
        self,
        dry_run: bool = True,
        state_file: str = "guardian_state.json",
        cooldown_seconds: int = 300,
    ):
        self.dry_run = dry_run
        self.state_file = state_file
        self.cooldown_seconds = cooldown_seconds
        self.isolated_ips: Dict[str, float] = {}  # ip -> isolation timestamp
        self._load_state()

    def _load_state(self) -> None:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    self.isolated_ips = data.get("isolated_ips", {})
            except Exception:
                self.isolated_ips = {}

    def _save_state(self) -> None:
        try:
            with open(self.state_file, "w") as f:
                json.dump(
                    {
                        "isolated_ips": self.isolated_ips,
                        "dry_run": self.dry_run,
                        "updated": time.time(),
                    },
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def is_on_cooldown(self, ip_address: str) -> bool:
        ts = self.isolated_ips.get(ip_address)
        if ts is None:
            return False
        return (time.time() - ts) < self.cooldown_seconds

    def isolate_ip(self, ip_address: str) -> bool:
        """Attempt to isolate the given IP. Returns True on success or dry-run log."""
        if ip_address in self.isolated_ips and self.is_on_cooldown(ip_address):
            return True  # already handled recently

        if self.dry_run:
            print(f"[CONTAINMENT-DRY-RUN] Simulating DROP for {ip_address}")
            self.isolated_ips[ip_address] = time.time()
            self._save_state()
            return True

        # Live mode — try iptables first, then nftables
        success = self._iptables_drop(ip_address) or self._nftables_drop(ip_address)
        if success:
            print(f"[CONTAINMENT] Isolated {ip_address}")
            self.isolated_ips[ip_address] = time.time()
            self._save_state()
        else:
            print(f"[CONTAINMENT] Failed to isolate {ip_address}")
        return success

    def _iptables_drop(self, ip_address: str) -> bool:
        try:
            cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
            # Check if rule already exists
            check = subprocess.run(cmd, capture_output=True, text=True)
            if check.returncode == 0:
                return True  # already present

            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return res.returncode == 0
        except Exception:
            return False

    def _nftables_drop(self, ip_address: str) -> bool:
        """Minimal nftables fallback (adds to a simple set if available)."""
        try:
            # Best-effort: create a simple chain/set if it doesn't exist is complex;
            # for now we only attempt a direct add if the table exists.
            cmd = [
                "nft", "add", "rule", "inet", "filter", "input",
                "ip", "saddr", ip_address, "drop"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return res.returncode == 0
        except Exception:
            return False

    def release_ip(self, ip_address: str) -> bool:
        """Remove isolation for an IP."""
        if ip_address not in self.isolated_ips:
            return True

        if self.dry_run:
            print(f"[CONTAINMENT-DRY-RUN] Releasing {ip_address}")
            self.isolated_ips.pop(ip_address, None)
            self._save_state()
            return True

        try:
            # iptables delete
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception:
            pass

        self.isolated_ips.pop(ip_address, None)
        self._save_state()
        print(f"[CONTAINMENT] Released {ip_address}")
        return True

    def list_isolated(self) -> Dict[str, float]:
        return dict(self.isolated_ips)

    def get_status(self) -> dict:
        return {
            "dry_run": self.dry_run,
            "isolated_count": len(self.isolated_ips),
            "isolated_ips": list(self.isolated_ips.keys()),
            "cooldown_seconds": self.cooldown_seconds,
        }
