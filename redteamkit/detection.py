"""
Detection validation matrix and gap analysis engine.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .attack import AttackLibrary


@dataclass
class DetectionEntry:
    technique_id: str
    technique_name: str
    tactic: str
    expected_data_sources: List[str]
    expected_alerts: List[str]
    max_mttd_minutes: int = 60
    priority: str = "medium"
    detected: Optional[bool] = None
    actual_mttd: Optional[float] = None
    notes: str = ""
    gap_priority: str = ""          # Critical / High / Medium / Low / None
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "expected_data_sources": self.expected_data_sources,
            "expected_alerts": self.expected_alerts,
            "max_mttd_minutes": self.max_mttd_minutes,
            "priority": self.priority,
            "detected": self.detected,
            "actual_mttd": self.actual_mttd,
            "gap_priority": self.gap_priority,
            "recommendation": self.recommendation,
            "notes": self.notes,
        }


class DetectionMatrix:
    """Build and score a detection validation matrix from a list of techniques."""

    def __init__(self):
        self.lib = AttackLibrary()
        self.entries: List[DetectionEntry] = []

    def build(self, technique_ids: List[str], default_mttd: int = 60) -> "DetectionMatrix":
        self.entries = []
        for tid in technique_ids:
            t = self.lib.get(tid)
            if not t:
                raise ValueError(
                    f"Unknown technique ID: {tid}. "
                    f"Known IDs: {', '.join(sorted(self.lib.techniques.keys())[:20])}..."
                )

            # Reasonable MTTD defaults by priority
            mttd_map = {"critical": 15, "high": 30, "medium": 60, "low": 240}
            mttd = mttd_map.get(t.detection_priority, default_mttd)

            self.entries.append(DetectionEntry(
                technique_id=t.technique_id,
                technique_name=t.name,
                tactic=t.tactic.name,
                expected_data_sources=t.data_sources or [],
                expected_alerts=t.detections or [],
                max_mttd_minutes=mttd,
                priority=t.detection_priority,
            ))
        return self

    def mark(self, technique_id: str, detected: bool, actual_mttd: Optional[float] = None, notes: str = ""):
        for e in self.entries:
            if e.technique_id == technique_id:
                e.detected = detected
                e.actual_mttd = actual_mttd
                e.notes = notes
                if not detected:
                    pri_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
                    e.gap_priority = pri_map.get(e.priority, "Medium")
                    e.recommendation = (
                        f"Add or tune detection for {e.technique_id} using sources: "
                        f"{', '.join(e.expected_data_sources) or 'TBD'}"
                    )
                elif actual_mttd is not None and actual_mttd > e.max_mttd_minutes:
                    e.gap_priority = "Medium"
                    e.recommendation = f"Improve MTTD for {e.technique_id} (target ≤ {e.max_mttd_minutes}m)"
                else:
                    e.gap_priority = "None"
                break

    def detection_rate(self) -> float:
        scored = [e for e in self.entries if e.detected is not None]
        if not scored:
            return 0.0
        return sum(1 for e in scored if e.detected) / len(scored) * 100

    def gaps(self) -> List[DetectionEntry]:
        return [e for e in self.entries if e.gap_priority and e.gap_priority != "None"]

    def summary(self) -> str:
        lines = [
            f"DETECTION MATRIX — {len(self.entries)} techniques",
            f"Detection rate: {self.detection_rate():.1f}%",
            "",
            f"{'ID':<10} {'Name':<35} {'Pri':<8} {'Detect':<8} {'MTTD':<8} {'Gap'}",
            "-" * 90,
        ]
        for e in self.entries:
            det = "Y" if e.detected is True else "N" if e.detected is False else "—"
            mttd = f"{e.actual_mttd:.0f}m" if e.actual_mttd is not None else "—"
            lines.append(f"{e.technique_id:<10} {e.technique_name[:34]:<35} {e.priority:<8} {det:<8} {mttd:<8} {e.gap_priority or '—'}")
        gaps = self.gaps()
        if gaps:
            lines.append(f"\nGAPS ({len(gaps)}):")
            for g in gaps:
                lines.append(f"  [{g.gap_priority}] {g.technique_id} — {g.recommendation}")
        return "\n".join(lines)


class GapAnalyzer:
    """Higher-level gap analysis and prioritization."""

    def __init__(self, matrix: DetectionMatrix):
        self.matrix = matrix

    def prioritized_gaps(self) -> List[Dict[str, Any]]:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        gaps = sorted(self.matrix.gaps(), key=lambda e: order.get(e.gap_priority, 9))
        return [g.to_dict() for g in gaps]

    def report(self) -> str:
        gaps = self.prioritized_gaps()
        lines = [
            "DETECTION GAP ANALYSIS",
            f"Total techniques evaluated: {len(self.matrix.entries)}",
            f"Detection rate: {self.matrix.detection_rate():.1f}%",
            f"Gaps identified: {len(gaps)}",
            "",
        ]
        if not gaps:
            lines.append("No significant detection gaps recorded.")
            return "\n".join(lines)

        for g in gaps:
            lines.append(f"[{g['gap_priority']}] {g['technique_id']} — {g['technique_name']}")
            lines.append(f"  Sources : {', '.join(g['expected_data_sources']) or 'TBD'}")
            lines.append(f"  Action  : {g['recommendation']}")
            lines.append("")
        return "\n".join(lines)
