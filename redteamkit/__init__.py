"""
RedTeamKit — High-fidelity authorized red team planning & simulation engine.
Version: 3.0.0

Modules:
  - profiles      Adversary / APT profiles
  - attack        MITRE ATT&CK technique library & mapping
  - campaign      Multi-phase campaign planner
  - detection     Detection validation & gap analysis
  - reporting     Professional report generation
  - opsec         OPSEC checklist & risk scoring
  - eng           Social engineering campaign designer
"""

__version__ = "3.0.0"
__author__ = "RedTeamKit"

from .profiles import AdversaryProfile, load_profile, list_profiles
from .attack import Technique, Tactic, AttackLibrary, get_technique
from .campaign import Campaign, CampaignPlanner, Phase
from .detection import DetectionMatrix, GapAnalyzer
from .reporting import ReportBuilder
from .opsec import OpsecChecklist, score_opsec

__all__ = [
    "AdversaryProfile", "load_profile", "list_profiles",
    "Technique", "Tactic", "AttackLibrary", "get_technique",
    "Campaign", "CampaignPlanner", "Phase",
    "DetectionMatrix", "GapAnalyzer",
    "ReportBuilder",
    "OpsecChecklist", "score_opsec",
]
