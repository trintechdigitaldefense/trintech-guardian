"""
Forensic snapshot and incident logging for TrinTech-Guardian.
Produces structured JSON reports suitable for client delivery.
"""

import json
import os
import time
from typing import Dict, Optional


class ForensicInvestigator:
    """Generates timestamped incident reports on containment events."""

    def __init__(self, log_dir: str = "incident_reports"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

    def generate_snapshot(self, attack_data: dict, action_taken: str) -> str:
        """Write a JSON incident report and return the filepath."""
        timestamp = int(time.time())
        safe_ip = attack_data.get("source_ip", "unknown").replace(".", "_").replace(":", "_")
        report_id = f"TRINTECH_INCIDENT_{safe_ip}_{timestamp}"
        filepath = os.path.join(self.log_dir, f"{report_id}.json")

        report = {
            "incident_id": report_id,
            "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp)),
            "timestamp_unix": timestamp,
            "attacker_ip": attack_data.get("source_ip"),
            "threat_score": attack_data.get("score"),
            "severity_level": attack_data.get("severity"),
            "connections_in_window": attack_data.get("hits_last_min"),
            "unique_ports_scanned": attack_data.get("unique_ports"),
            "action_taken": action_taken,
            "engine": "TrinTech-Guardian",
            "organization": "TrinTech Digital Defense",
            "version": "1.1.0",
        }

        try:
            with open(filepath, "w") as f:
                json.dump(report, f, indent=4)
            print(f"[FORENSICS] Snapshot saved → {filepath}")
            return filepath
        except Exception as e:
            print(f"[FORENSICS] Failed to write report: {e}")
            return ""

    def list_recent(self, limit: int = 10) -> list:
        """Return paths of the most recent incident reports."""
        try:
            files = [
                os.path.join(self.log_dir, f)
                for f in os.listdir(self.log_dir)
                if f.endswith(".json")
            ]
            files.sort(key=os.path.getmtime, reverse=True)
            return files[:limit]
        except Exception:
            return []

    def get_status(self) -> dict:
        recent = self.list_recent(5)
        return {
            "log_dir": self.log_dir,
            "recent_reports": [os.path.basename(r) for r in recent],
            "total_reports": len(self.list_recent(1000)),
        }
