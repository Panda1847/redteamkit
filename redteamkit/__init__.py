"""
RedTeamKit — High-fidelity authorized red team planning & simulation engine.
Version: 3.2.0

Modules:
  - profiles      Adversary / APT profiles
  - attack        MITRE ATT&CK technique library & mapping
  - campaign      Multi-phase campaign planner
  - detection     Detection validation & gap analysis
  - reporting     Professional report generation
  - opsec         OPSEC checklist & risk scoring
  - eng           Social engineering campaign designer
"""

__version__ = "3.2.0"
__author__ = "RedTeamKit"

from .attack import AttackLibrary, Tactic, Technique, get_technique
from .attackdata import AttackDataError, load_index, sync
from .campaign import Campaign, CampaignPlanner, Phase
from .detection import DetectionMatrix, GapAnalyzer
from .opsec import OpsecChecklist, score_opsec
from .profiles import AdversaryProfile, list_profiles, load_profile
from .reporting import ReportBuilder

__all__ = [
    "AdversaryProfile", "load_profile", "list_profiles",
    "Technique", "Tactic", "AttackLibrary", "get_technique",
    "Campaign", "CampaignPlanner", "Phase",
    "DetectionMatrix", "GapAnalyzer",
    "ReportBuilder",
    "OpsecChecklist", "score_opsec",
    "AttackDataError", "load_index", "sync",
]
