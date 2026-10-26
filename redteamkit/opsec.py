"""
OPSEC checklist and risk scoring for red team campaigns.
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class OpsecItem:
    category: str
    item: str
    required: bool = True
    status: str = "unchecked"   # unchecked | pass | fail | n/a
    notes: str = ""


class OpsecChecklist:
    """Standard OPSEC checklist for authorized red team engagements."""

    DEFAULT_ITEMS = [
        ("Authorization", "Written RoE / authorization letter on file", True),
        ("Authorization", "Emergency / abort contacts confirmed", True),
        ("Authorization", "Out-of-scope systems explicitly listed", True),
        ("Infrastructure", "Attack infrastructure segregated from personal/work accounts", True),
        ("Infrastructure", "Domains / IPs non-attributable within RoE constraints", True),
        ("Infrastructure", "Redirectors / proxies in place where required", False),
        ("Infrastructure", "Kill-switch / sinkhole capability tested", True),
        ("Operational", "Beacon jitter and sleep ranges defined", True),
        ("Operational", "Time-of-day / volume constraints documented", True),
        ("Operational", "Noisy techniques gated behind explicit approval", True),
        ("Operational", "Credential handling procedure defined", True),
        ("Logging", "All red team actions logged for debrief", True),
        ("Logging", "Client-side evidence collection plan ready", True),
        ("Cleanup", "Cleanup / artifact removal plan written before first implant", True),
        ("Cleanup", "Persistence removal verification steps defined", True),
        ("Safety", "Production impact abort conditions clear", True),
        ("Safety", "Destructive techniques explicitly excluded or fully scoped", True),
        ("Communication", "Daily / phase status cadence agreed", True),
        ("Communication", "Secure channel for red↔client communication established", True),
    ]

    def __init__(self):
        self.items: List[OpsecItem] = [
            OpsecItem(category=c, item=i, required=r) for c, i, r in self.DEFAULT_ITEMS
        ]

    def mark(self, item_substring: str, status: str, notes: str = ""):
        for it in self.items:
            if item_substring.lower() in it.item.lower():
                it.status = status
                it.notes = notes
                return True
        return False

    def score(self) -> Dict[str, Any]:
        required = [i for i in self.items if i.required]
        checked = [i for i in required if i.status in ("pass", "n/a")]
        failed = [i for i in required if i.status == "fail"]
        unchecked = [i for i in required if i.status == "unchecked"]
        score = (len(checked) / len(required) * 100) if required else 0
        return {
            "score": round(score, 1),
            "required_total": len(required),
            "passed": len(checked),
            "failed": len(failed),
            "unchecked": len(unchecked),
            "ready": score >= 85 and len(failed) == 0,
        }

    def summary(self) -> str:
        s = self.score()
        lines = [
            f"OPSEC CHECKLIST — Score: {s['score']}%  |  Ready: {'YES' if s['ready'] else 'NO'}",
            f"Passed: {s['passed']}  Failed: {s['failed']}  Unchecked: {s['unchecked']}",
            "",
        ]
        current_cat = None
        for it in self.items:
            if it.category != current_cat:
                current_cat = it.category
                lines.append(f"[{current_cat}]")
            flag = {"pass": "✓", "fail": "✗", "n/a": "–", "unchecked": "·"}.get(it.status, "?")
            req = " *" if it.required else ""
            lines.append(f"  {flag} {it.item}{req}")
            if it.notes:
                lines.append(f"      → {it.notes}")
        lines.append("\n* = required")
        return "\n".join(lines)


def score_opsec(checklist: OpsecChecklist) -> Dict[str, Any]:
    return checklist.score()
