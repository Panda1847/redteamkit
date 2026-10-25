"""
Multi-phase campaign planner and timeline engine.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta, timezone
import uuid


@dataclass
class Phase:
    name: str
    order: int
    objectives: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)   # ATT&CK IDs
    duration_days: int = 1
    opsec_notes: str = ""
    success_criteria: str = ""
    abort_conditions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "order": self.order,
            "objectives": self.objectives,
            "techniques": self.techniques,
            "duration_days": self.duration_days,
            "opsec_notes": self.opsec_notes,
            "success_criteria": self.success_criteria,
            "abort_conditions": self.abort_conditions,
        }


@dataclass
class Campaign:
    campaign_id: str
    name: str
    adversary: str
    objectives: List[str]
    phases: List[Phase] = field(default_factory=list)
    start_date: Optional[str] = None
    duration_days: int = 14
    team_size: int = 3
    fidelity: str = "high"          # low | medium | high
    rules_of_engagement: Dict[str, Any] = field(default_factory=dict)
    excluded_techniques: List[str] = field(default_factory=list)
    status: str = "planned"
    notes: str = ""

    def all_techniques(self) -> List[str]:
        seen = set()
        out = []
        for p in self.phases:
            for t in p.techniques:
                if t not in seen and t not in self.excluded_techniques:
                    seen.add(t)
                    out.append(t)
        return out

    def technique_count(self) -> int:
        return len(self.all_techniques())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "adversary": self.adversary,
            "objectives": self.objectives,
            "phases": [p.to_dict() for p in self.phases],
            "duration_days": self.duration_days,
            "team_size": self.team_size,
            "fidelity": self.fidelity,
            "excluded_techniques": self.excluded_techniques,
            "status": self.status,
            "technique_count": self.technique_count(),
        }

    def summary(self) -> str:
        lines = [
            f"CAMPAIGN: {self.name} [{self.campaign_id}]",
            f"Adversary : {self.adversary}",
            f"Objectives: {', '.join(self.objectives)}",
            f"Duration  : {self.duration_days} days | Team: {self.team_size} | Fidelity: {self.fidelity}",
            f"Techniques: {self.technique_count()} unique",
            f"Status    : {self.status}",
            "",
            "PHASES:",
        ]
        for p in sorted(self.phases, key=lambda x: x.order):
            lines.append(f"  {p.order}. {p.name} ({p.duration_days}d) — {', '.join(p.techniques[:5])}{'...' if len(p.techniques)>5 else ''}")
            if p.objectives:
                lines.append(f"     Objectives: {', '.join(p.objectives)}")
        if self.excluded_techniques:
            lines.append(f"\nExcluded: {', '.join(self.excluded_techniques)}")
        return "\n".join(lines)


class CampaignPlanner:
    """Build realistic multi-phase campaigns from adversary profiles + objectives."""

    # Default phase templates keyed by high-level objective
    PHASE_TEMPLATES = {
        "default": [
            ("Reconnaissance", ["OSINT", "attack surface mapping"], ["T1082", "T1018", "T1087"], 2),
            ("Initial Access", ["foothold"], ["T1566", "T1190", "T1078", "T1133"], 3),
            ("Establish & Persist", ["persistence", "C2"], ["T1059", "T1053", "T1547", "T1071"], 2),
            ("Escalate & Move", ["privilege escalation", "lateral movement"], ["T1003", "T1021", "T1550", "T1548"], 4),
            ("Collection & Objectives", ["data access", "objective completion"], ["T1005", "T1560", "T1041", "T1567"], 2),
            ("Cleanup & Measure", ["artifact removal", "detection validation"], ["T1070"], 1),
        ]
    }

    # Techniques that require explicit scope + rollback before inclusion
    DESTRUCTIVE_DEFAULT_EXCLUDE = ["T1486", "T1490", "T1485"]

    def create(
        self,
        adversary: str = "Custom",
        name: Optional[str] = None,
        objectives: Optional[List[str]] = None,
        duration_days: int = 14,
        team_size: int = 3,
        fidelity: str = "high",
        exclude: Optional[List[str]] = None,
        custom_phases: Optional[List[Phase]] = None,
        allow_destructive: bool = False,
    ) -> Campaign:
        objectives = objectives or ["credential_access", "lateral_movement", "data_access"]
        exclude = list(exclude) if exclude else []
        if not allow_destructive:
            for t in self.DESTRUCTIVE_DEFAULT_EXCLUDE:
                if t not in exclude:
                    exclude.append(t)
        campaign_id = uuid.uuid4().hex[:10]

        if name is None:
            name = f"{adversary} Emulation — {datetime.now(timezone.utc).strftime('%Y%m%d')}"

        if custom_phases:
            phases = custom_phases
        else:
            phases = []
            for i, (pname, pobjs, techs, days) in enumerate(self.PHASE_TEMPLATES["default"], 1):
                # Filter excluded
                techs = [t for t in techs if t not in exclude]
                phases.append(Phase(
                    name=pname,
                    order=i,
                    objectives=pobjs,
                    techniques=techs,
                    duration_days=days,
                    success_criteria=f"Complete {pobjs[0]} objectives under OPSEC constraints",
                    abort_conditions=["Production impact outside RoE", "Detection of red team infrastructure", "Client abort request"],
                ))

        # Scale durations roughly to total duration_days
        total_template = sum(p.duration_days for p in phases) or 1
        scale = duration_days / total_template
        for p in phases:
            p.duration_days = max(1, round(p.duration_days * scale))

        return Campaign(
            campaign_id=campaign_id,
            name=name,
            adversary=adversary,
            objectives=objectives,
            phases=phases,
            duration_days=duration_days,
            team_size=team_size,
            fidelity=fidelity,
            excluded_techniques=exclude,
            status="planned",
        )

    def from_profile(self, profile_name: str, **kwargs) -> Campaign:
        from .profiles import load_profile
        from .attack import AttackLibrary, Tactic

        profile = load_profile(profile_name)
        if not profile:
            raise ValueError(f"Unknown profile: {profile_name}")

        # Prefer the profile's own TTP list for higher fidelity
        camp = self.create(adversary=profile.name, **kwargs)

        # Map profile TTPs into phases by tactic match (not round-robin)
        PHASE_TACTICS = {
            "Reconnaissance": {Tactic.RECONNAISSANCE, Tactic.DISCOVERY},
            "Initial Access": {Tactic.INITIAL_ACCESS},
            "Establish & Persist": {Tactic.EXECUTION, Tactic.PERSISTENCE, Tactic.COMMAND_AND_CONTROL},
            "Escalate & Move": {
                Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION,
                Tactic.CREDENTIAL_ACCESS, Tactic.LATERAL_MOVEMENT,
            },
            "Collection & Objectives": {Tactic.COLLECTION, Tactic.EXFILTRATION},
            # Cleanup intentionally gets no injected TTPs
        }

        lib = AttackLibrary()
        profile_ttps = [t for t in profile.ttps if t not in camp.excluded_techniques]
        for phase in camp.phases:
            allowed = PHASE_TACTICS.get(phase.name, set())
            if not allowed:
                continue
            extra = [
                t for t in profile_ttps
                if (tech := lib.get(t)) and tech.tactic in allowed
            ]
            phase.techniques = list(dict.fromkeys(phase.techniques + extra))

        camp.notes = profile.fidelity_notes or profile.operational_notes
        return camp
