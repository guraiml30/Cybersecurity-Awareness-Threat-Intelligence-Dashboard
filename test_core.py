import unittest
from src.generate_data import generate
from src.scoring import enrich, severity_from_score, classify_lifecycle
from src.analysis import analyze_indicator
from src.taxonomy import LIFECYCLE, SEVERITIES, CATEGORIES, ATTACK_MAP


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.rows = enrich(generate(200, seed=1))

    def test_deterministic(self):
        self.assertEqual(generate(20, 5), generate(20, 5))

    def test_vocab(self):
        for r in self.rows:
            self.assertIn(r["lifecycle"], LIFECYCLE)
            self.assertIn(r["severity"], SEVERITIES)
            self.assertIn(r["category"], CATEGORIES)
            self.assertTrue(0 <= r["score"] <= 100)

    def test_incident_needs_confirmation(self):
        for r in self.rows:
            self.assertEqual(r["lifecycle"] == "INCIDENT", r["impact_confirmed"])

    def test_not_everything_is_a_threat(self):
        incidents = sum(r["lifecycle"] == "INCIDENT" for r in self.rows)
        self.assertLess(incidents, len(self.rows) * 0.1)

    def test_synthetic_safety(self):
        for r in self.rows:
            v = r["indicator"]
            if r["indicator_type"] == "URL":
                self.assertTrue(v.startswith("hxxps://"))
            if r["indicator_type"] in ("DOMAIN", "EMAIL/SENDER DOMAIN"):
                self.assertTrue(v.endswith(("[.]example", "[.]invalid", "[.]test")))
            if r["indicator_type"] == "CVE ID":
                self.assertTrue(v.startswith("CVE-2099-"))

    def test_severity_bounds(self):
        self.assertEqual(severity_from_score(0), "INFORMATIONAL")
        self.assertEqual(severity_from_score(100), "CRITICAL")

    def test_low_confidence_is_observation(self):
        r = {"impact_confirmed": False, "corroborating_sources": 1, "confidence": 20, "seen_internally": False}
        self.assertEqual(classify_lifecycle(r, 10)[0], "OBSERVATION")

    def test_analysis(self):
        self.assertIn("Private", analyze_indicator("IP ADDRESS", "10[.]0[.]0[.]5")[0][0])
        self.assertIn("SHA-256", analyze_indicator("FILE HASH", "a" * 64)[0][0])
        self.assertTrue(any(p > 0 for _, p in analyze_indicator("URL", "hxxp://login-secure-123.evil-site.test/x")))

    def test_attack_map_complete(self):
        self.assertEqual(set(ATTACK_MAP), set(CATEGORIES))


if __name__ == "__main__":
    unittest.main()
