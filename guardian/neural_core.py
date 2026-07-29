import time
from collections import defaultdict

class NeuralCore:
    """Lightweight behavioral threat engine for scoring anomalous network activity."""
    
    def __init__(self, alert_threshold: int = 50):
        self.alert_threshold = alert_threshold
        self.ip_hits = defaultdict(list)
        self.ip_ports = defaultdict(set)
        self.threat_scores = defaultdict(int)

    def record_event(self, source_ip: str, target_port: int) -> dict:
        now = time.time()
        # Maintain a rolling 60-second activity window
        self.ip_hits[source_ip] = [t for t in self.ip_hits[source_ip] if now - t < 60]
        self.ip_hits[source_ip].append(now)
        self.ip_ports[source_ip].add(target_port)

        hit_count = len(self.ip_hits[source_ip])
        port_count = len(self.ip_ports[source_ip])

        # Dynamic Threat Scoring Formula:
        # - Frequency weight: 5 pts per connection in 60s
        # - Multi-port scan penalty: 15 pts per unique targeted port
        score = (hit_count * 5) + (port_count * 15)
        self.threat_scores[source_ip] = score

        severity = "NORMAL"
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"

        return {
            "source_ip": source_ip,
            "score": score,
            "severity": severity,
            "hits_last_min": hit_count,
            "unique_ports": port_count,
            "trigger_containment": score >= self.alert_threshold
        }

    def get_top_threats(self) -> list:
        return sorted(self.threat_scores.items(), key=lambda x: x[1], reverse=True)
