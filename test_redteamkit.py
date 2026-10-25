"""Minimal regression tests for RedTeamKit."""

import json
import tempfile
import unittest
from pathlib import Path

from redteamkit.profiles import load_profile, list_profiles
from redteamkit.campaign import CampaignPlanner
from redteamkit.attack import AttackLibrary, Tactic
from redteamkit.detection import DetectionMatrix
from redteamkit.opsec import OpsecChecklist
from redteamkit.cli import main


class TestProfiles(unittest.TestCase):
    def test_known_profiles(self):
        for name in ["APT29", "APT28", "FIN7", "Lazarus", "Turla", "APT41"]:
            p = load_profile(name)
            self.assertIsNotNone(p, f"Missing profile: {name}")
            self.assertTrue(len(p.ttps) > 0)

    def test_list(self):
        names = list_profiles()
        self.assertIn("APT29", names)
        self.assertIn("FIN7", names)


class TestCampaign(unittest.TestCase):
    def test_destructive_excluded_by_default(self):
        camp = CampaignPlanner().create(adversary="Lazarus")
        self.assertIn("T1486", camp.excluded_techniques)
        self.assertNotIn("T1486", camp.all_techniques())

    def test_from_profile_tactic_mapping(self):
        camp = CampaignPlanner().from_profile("APT29")
        # Build phase -> tactics present
        lib = AttackLibrary()
        for phase in camp.phases:
            for tid in phase.techniques:
                tech = lib.get(tid)
                if not tech:
                    continue
                # Cleanup phase should only have T1070-style cleanup, not phishing or credential dumping
                if phase.name == "Cleanup & Measure":
                    self.assertNotIn(tech.tactic, {
                        Tactic.INITIAL_ACCESS, Tactic.CREDENTIAL_ACCESS, Tactic.LATERAL_MOVEMENT
                    }, f"{tid} ({tech.tactic.name}) wrongly in Cleanup")

    def test_allow_destructive(self):
        camp = CampaignPlanner().create(adversary="Lazarus", allow_destructive=True, exclude=[])
        # When allow_destructive and empty exclude, T1486 can appear if in template/profile
        # Just ensure the flag is respected (no forced exclusion)
        self.assertNotIn("T1486", camp.excluded_techniques)


class TestDetection(unittest.TestCase):
    def test_unknown_technique_raises(self):
        with self.assertRaises(ValueError):
            DetectionMatrix().build(["T9999"])

    def test_mark_zero_mttd(self):
        m = DetectionMatrix().build(["T1566"])
        m.mark("T1566", detected=True, actual_mttd=0.0)
        e = m.entries[0]
        self.assertEqual(e.actual_mttd, 0.0)
        self.assertEqual(e.gap_priority, "None")  # 0 <= max, so no gap

    def test_low_priority_miss(self):
        m = DetectionMatrix().build(["T1082"])  # low priority
        m.mark("T1082", detected=False)
        self.assertEqual(m.entries[0].gap_priority, "Low")


class TestOpsec(unittest.TestCase):
    def test_starts_blank(self):
        cl = OpsecChecklist()
        score = cl.score()
        self.assertEqual(score["passed"], 0)
        self.assertFalse(score["ready"])


class TestReportCLI(unittest.TestCase):
    def test_report_refuses_without_results(self):
        # argparse raises SystemExit(2) for missing required --results
        with self.assertRaises(SystemExit) as cm:
            main(["report", "--adversary", "APT29"])
        self.assertNotEqual(cm.exception.code, 0)

    def test_report_with_real_results(self):
        results = {
            "T1566": {"detected": True, "mttd": 10.0, "notes": "gateway"},
            "T1003": {"detected": False, "mttd": None, "notes": "missed"},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(results, f)
            path = f.name
        try:
            rc = main(["report", "--adversary", "APT29", "--results", path, "--days", "7"])
            self.assertEqual(rc, 0)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
