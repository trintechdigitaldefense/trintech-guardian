"""
Behavioral threat scoring engine for TrinTech-Guardian.
Tracks activity windows, unique ports, and produces severity levels.
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple


class NeuralCore:
    """Lightweight behavioral threat engine."""

    def __init__(self, alert_threshold: int = 50, window_seconds: int = 60):
        self.alert_threshold = alert_threshold
        self.window_seconds = window_seconds
        self.ip_hits: Dict[str, List[float]] = defaultdict(list)
        self.ip_ports: Dict[str, set] = defaultdict(set)
        self.threat_scores: Dict[str, int] = defaultdict(int)
        self.last_containment: Dict[str, float] = {}

    def record_event(self, source_ip: str, target_port: int) -> dict:
        """Record a connection attempt and return threat analysis."""
        now = time.time()

        # Rolling activity window
        self.ip_hits[source_ip] = [
            t for t in self.ip_hits[source_ip] if now - t < self.window_seconds
        ]
        self.ip_hits[source_ip].append(now)
        self.ip_ports[source_ip].add(target_port)

        hit_count = len(self.ip_hits[source_ip])
        port_count = len(self.ip_ports[source_ip])

        # Scoring formula
        # Frequency: 5 pts per hit in window
        # Multi-port scan penalty: 15 pts per unique port
        # Rapid burst bonus: extra 10 if > 8 hits in window
        score = (hit_count * 5) + (port_count * 15)
        if hit_count >= 8:
            score += 10

        self.threat_scores[source_ip] = score

        if score >= 80:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "NORMAL"

        return {
            "source_ip": source_ip,
            "score": score,
            "severity": severity,
            "hits_last_min": hit_count,
            "unique_ports": port_count,
            "trigger_containment": score >= self.alert_threshold,
            "timestamp": now,
        }

    def reset_score(self, source_ip: str) -> None:
        """Reset score after successful containment (prevents spam)."""
        self.threat_scores[source_ip] = 0
        self.ip_hits[source_ip] = []
        self.ip_ports[source_ip] = set()

    def get_top_threats(self, limit: int = 10) -> List[Tuple[str, int]]:
        return sorted(
            self.threat_scores.items(), key=lambda x: x[1], reverse=True
        )[:limit]

    def get_status(self) -> dict:
        return {
            "tracked_ips": len(self.threat_scores),
            "alert_threshold": self.alert_threshold,
            "top_threats": self.get_top_threats(5),
        }
