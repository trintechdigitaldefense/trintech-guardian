"""
Process scanner for TrinTech-Guardian.
Detects common reverse-shell patterns, suspicious interpreters, and known attack tooling.
Lightweight — uses /proc on Linux (works in most Termux / PRoot environments).
"""

import os
import re
import time
from typing import List, Dict, Optional


# High-signal command-line patterns (case-insensitive)
REVERSE_SHELL_PATTERNS = [
    r"bash\s+-i",
    r"/dev/tcp/",
    r"nc\s+-[elp]",
    r"ncat\s+",
    r"socat\s+",
    r"python[23]?\s+-c\s+.*socket",
    r"perl\s+-e\s+.*socket",
    r"php\s+-r\s+.*fsockopen",
    r"ruby\s+-rsocket",
    r"powershell\s+.*-nop",
    r"msfvenom",
    r"meterpreter",
    r"reverse.?shell",
    r"bind.?shell",
]

SUSPICIOUS_BINARIES = {
    "nc", "ncat", "netcat", "socat", "nmap", "masscan",
    "hydra", "medusa", "john", "hashcat", "mimikatz",
    "linpeas", "winpeas", "pspy", "chisel", "ligolo",
}


class ProcessScanner:
    """Scans running processes for reverse-shell and post-exploitation indicators."""

    def __init__(self, interval_seconds: int = 30, enabled: bool = True):
        self.interval = interval_seconds
        self.enabled = enabled
        self.last_scan = 0.0
        self.findings: List[dict] = []
        self._compiled = [re.compile(p, re.IGNORECASE) for p in REVERSE_SHELL_PATTERNS]

    def should_scan(self) -> bool:
        if not self.enabled:
            return False
        return (time.time() - self.last_scan) >= self.interval

    def scan(self) -> List[dict]:
        """Perform a full process scan. Returns list of suspicious findings."""
        if not self.enabled:
            return []

        self.last_scan = time.time()
        findings = []

        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    cmdline_path = f"/proc/{pid}/cmdline"
                    with open(cmdline_path, "rb") as f:
                        raw = f.read()
                    if not raw:
                        continue
                    cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                    if not cmdline:
                        continue

                    # Check reverse-shell patterns
                    for pat in self._compiled:
                        if pat.search(cmdline):
                            findings.append({
                                "pid": int(pid),
                                "cmdline": cmdline[:300],
                                "reason": f"matched pattern: {pat.pattern}",
                                "severity": "CRITICAL",
                            })
                            break
                    else:
                        # Check binary name
                        binary = cmdline.split()[0].split("/")[-1].lower()
                        if binary in SUSPICIOUS_BINARIES:
                            findings.append({
                                "pid": int(pid),
                                "cmdline": cmdline[:300],
                                "reason": f"suspicious binary: {binary}",
                                "severity": "HIGH",
                            })
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue
        except Exception as e:
            print(f"[PROCESS-SCAN] Error: {e}")

        self.findings = findings
        return findings

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "interval_seconds": self.interval,
            "last_scan": self.last_scan,
            "recent_findings": len(self.findings),
        }
