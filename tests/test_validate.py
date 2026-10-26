import unittest

from redteamkit.campaign import CampaignError, CampaignPlanner, Phase
from redteamkit.profiles import load_generated_profiles, load_profile


class TestV32ProfileAndCampaignSafety(unittest.TestCase):
    def test_curated_profile_wins_over_generated_name(self):
        profile = load_profile("APT29")
        self.assertIsNotNone(profile)
        self.assertFalse(profile.generated)
        self.assertTrue(profile.origin)
        self.assertTrue(profile.tools)

    def test_generated_only_group_resolves(self):
        load_generated_profiles([{
            "attack_id": "G9999",
            "name": "Synthetic Test Group",
            "aliases": ["STG"],
            "description": "Test-only generated profile",
            "ttps": ["T1566"],
        }])
        try:
            profile = load_profile("Synthetic Test Group")
            self.assertIsNotNone(profile)
            self.assertTrue(profile.generated)
            self.assertEqual(profile.ttps, ["T1566"])
        finally:
            load_generated_profiles([])

    def test_empty_generated_load_preserves_curated_lookup(self):
        load_generated_profiles([])
        profile = load_profile("APT29")
        self.assertIsNotNone(profile)
        self.assertFalse(profile.generated)

    def test_custom_phase_destructive_filter_is_real(self):
        phase = Phase(name="Impact test", order=1, techniques=["T1486"])
        safe = CampaignPlanner().create(adversary="Lazarus", custom_phases=[phase])
        self.assertNotIn("T1486", safe.phases[0].techniques)
        authorized = CampaignPlanner().create(
            adversary="Lazarus", custom_phases=[phase], allow_destructive=True, exclude=[]
        )
        self.assertIn("T1486", authorized.phases[0].techniques)

    def test_seed_mismatch_has_actionable_error(self):
        with self.assertRaises(CampaignError):
            CampaignPlanner().from_profile("Synthetic Test Group", custom_phases=[Phase("No match", 1, techniques=[])])


if __name__ == "__main__":
    unittest.main()
