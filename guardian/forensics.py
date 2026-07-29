import json
import time
import os

class ForensicInvestigator:
    """Generates instant incident snapshots and telemetry logs upon threat containment."""

    def __init__(self, log_dir="incident_reports"):
        self.log_dir = log_dir
        # Ensure the reporting directory exists
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def generate_snapshot(self, attack_data: dict, action_taken: str) -> str:
        timestamp = int(time.time())
        report_id = f"TRINTECH_INCIDENT_{attack_data['source_ip'].replace('.', '_')}_{timestamp}"
        filepath = os.path.join(self.log_dir, f"{report_id}.json")

        report = {
            "incident_id": report_id,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp)),
            "attacker_ip": attack_data['source_ip'],
            "threat_score": attack_data['score'],
            "severity_level": attack_data['severity'],
            "connections_last_min": attack_data['hits_last_min'],
            "unique_ports_scanned": attack_data['unique_ports'],
            "action_taken": action_taken,
            "handled_by": "TrinTech Digital Defense - Guardian Engine"
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"[FORENSICS] [+] Forensic snapshot locked and saved to: {filepath}")
            return filepath
        except Exception as e:
            print(f"[FORENSICS] [!] Failed to write forensic report: {e}")
            return ""
