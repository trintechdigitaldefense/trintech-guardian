#!/usr/bin/env python3
"""Basic unit tests for TrinTech-Guardian core modules."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from guardian.neural_core import NeuralCore
from guardian.failsafe import FailSafeGuard
from guardian.containment import ContainmentEngine
from guardian.forensics import ForensicInvestigator
from guardian.alerting import AlertDispatcher


class TestNeuralCore(unittest.TestCase):
    def test_scoring_increases(self):
        core = NeuralCore(alert_threshold=50)
        r1 = core.record_event("203.0.113.10", 22)
        self.assertEqual(r1["hits_last_min"], 1)
        self.assertFalse(r1["trigger_containment"])
        for port in (22, 80, 443, 8080, 3306):
            core.record_event("203.0.113.10", port)
        r = core.record_event("203.0.113.10", 21)
        self.assertTrue(r["score"] >= 50)

    def test_reset(self):
        core = NeuralCore(alert_threshold=10)
        core.record_event("1.2.3.4", 22)
        core.record_event("1.2.3.4", 80)
        core.reset_score("1.2.3.4")
        self.assertEqual(core.threat_scores["1.2.3.4"], 0)


class TestFailsafe(unittest.TestCase):
    def test_loopback_protected(self):
        fs = FailSafeGuard(auto_detect_local=False, protect_private_ranges=True)
        self.assertTrue(fs.is_protected("127.0.0.1"))
        self.assertFalse(fs.verify_action_safety("127.0.0.1"))

    def test_private_range(self):
        fs = FailSafeGuard(auto_detect_local=False, protect_private_ranges=True)
        self.assertTrue(fs.is_protected("192.168.1.50"))
        self.assertTrue(fs.is_protected("10.0.0.5"))

    def test_public_not_protected(self):
        fs = FailSafeGuard(auto_detect_local=False, protect_private_ranges=True)
        self.assertFalse(fs.is_protected("203.0.113.99"))
        self.assertTrue(fs.verify_action_safety("203.0.113.99"))


class TestContainment(unittest.TestCase):
    def test_dry_run_isolate_and_release(self):
        with tempfile.TemporaryDirectory() as td:
            state = os.path.join(td, "state.json")
            eng = ContainmentEngine(dry_run=True, state_file=state, block_duration_seconds=60)
            self.assertTrue(eng.isolate_ip("198.51.100.20"))
            self.assertIn("198.51.100.20", eng.list_isolated())
            self.assertTrue(eng.release_ip("198.51.100.20"))
            self.assertNotIn("198.51.100.20", eng.list_isolated())

    def test_cooldown(self):
        with tempfile.TemporaryDirectory() as td:
            state = os.path.join(td, "state.json")
            eng = ContainmentEngine(
                dry_run=True, state_file=state, cooldown_seconds=60, block_duration_seconds=300
            )
            eng.isolate_ip("198.51.100.30")
            self.assertTrue(eng.is_on_cooldown("198.51.100.30"))


class TestForensics(unittest.TestCase):
    def test_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            fi = ForensicInvestigator(log_dir=td)
            path = fi.generate_snapshot(
                {
                    "source_ip": "203.0.113.55",
                    "score": 75,
                    "severity": "HIGH",
                    "hits_last_min": 8,
                    "unique_ports": 4,
                },
                action_taken="DRY_RUN_LOGGED",
            )
            self.assertTrue(os.path.isfile(path))
            self.assertGreaterEqual(fi.get_status()["total_reports"], 1)


class TestAlertRateLimit(unittest.TestCase):
    def test_rate_limit(self):
        ad = AlertDispatcher(enabled=True, min_interval_seconds=60, max_per_hour=5)
        r1 = ad.send("t", "b", "HIGH", {"attacker_ip": "1.1.1.1"})
        self.assertFalse(r1)


if __name__ == "__main__":
    unittest.main()
