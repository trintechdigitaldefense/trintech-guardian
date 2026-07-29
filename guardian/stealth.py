import ctypes
import hashlib
import os

# Constants for Linux process naming
PR_SET_NAME = 15

def masquerade_process(alias: str = "[systemd-resolved]"):
    try:
        libc = ctypes.CDLL("libc.so.6")
        safe_name = alias.encode("utf-8")[:15]
        libc.prctl(PR_SET_NAME, safe_name, 0, 0, 0)
    except Exception:
        try:
            import setproctitle
            setproctitle.setproctitle(alias)
        except ImportError:
            pass

def generate_file_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return ""

class AntiTamperVault:
    def __init__(self, monitored_files: list):
        self.monitored_files = monitored_files
        self.baseline_hashes = {
            path: generate_file_hash(path) for path in monitored_files
        }

    def verify_integrity(self) -> bool:
        for path in self.monitored_files:
            current_hash = generate_file_hash(path)
            if current_hash != self.baseline_hashes.get(path):
                return False
        return True
