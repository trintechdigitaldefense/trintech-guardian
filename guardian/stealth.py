"""
Stealth & Anti-Tamper module for TrinTech-Guardian.
Process masquerading + integrity verification of core files.
"""

import ctypes
import hashlib
import os
from typing import List, Dict


PR_SET_NAME = 15


def masquerade_process(alias: str = "[systemd-resolved]") -> bool:
    """Rename the current process to appear as a benign system daemon."""
    try:
        libc = ctypes.CDLL("libc.so.6")
        safe_name = alias.encode("utf-8")[:15]
        libc.prctl(PR_SET_NAME, safe_name, 0, 0, 0)
        return True
    except Exception:
        try:
            import setproctitle
            setproctitle.setproctitle(alias)
            return True
        except ImportError:
            return False


def generate_file_hash(filepath: str) -> str:
    """SHA-256 of a file. Returns empty string on failure."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


class AntiTamperVault:
    """Verifies integrity of core Guardian files on startup."""

    def __init__(self, monitored_files: List[str]):
        self.monitored_files = [f for f in monitored_files if f and os.path.exists(f)]
        self.baseline_hashes: Dict[str, str] = {
            path: generate_file_hash(path) for path in self.monitored_files
        }

    def verify_integrity(self) -> bool:
        """Return True if all monitored files still match their baseline hashes."""
        for path in self.monitored_files:
            current = generate_file_hash(path)
            expected = self.baseline_hashes.get(path, "")
            if not current or current != expected:
                return False
        return True

    def get_status(self) -> dict:
        return {
            "monitored_files": len(self.monitored_files),
            "integrity_ok": self.verify_integrity(),
        }
