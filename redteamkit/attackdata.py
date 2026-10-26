"""ATT&CK STIX data synchronization and local index helpers.

The parser intentionally accepts only the official Enterprise collection shape and
fails loudly when the bundle is structurally incompatible. Runtime consumers use
the checked-in compact index so normal planning remains offline and deterministic.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.0/enterprise-attack/enterprise-attack.json"
DATA_VERSION = "20.0"


class AttackDataError(RuntimeError):
    """Raised when the source bundle cannot be interpreted safely."""


def data_path() -> Path:
    return Path(__file__).with_name("data") / "attack_techniques.json"


def load_index(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the compact local index, or raise a useful error if it is absent."""
    target = Path(path) if path else data_path()
    try:
        with target.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise AttackDataError(f"ATT&CK index not found: {target}") from exc
    except json.JSONDecodeError as exc:
        raise AttackDataError(f"ATT&CK index is not valid JSON: {target}") from exc
    required = {"attack_version", "techniques", "groups", "digest", "source"}
    missing = required.difference(data)
    if missing:
        raise AttackDataError(f"ATT&CK index is missing required fields: {', '.join(sorted(missing))}")
    return data


def _external_id(obj: Dict[str, Any], prefix: str) -> Optional[str]:
    for ref in obj.get("external_references", []):
        value = ref.get("external_id", "")
        if ref.get("source_name") == "mitre-attack" and value.startswith(prefix):
            return value
    return None


def _tactic_id(phase_name: str) -> Optional[str]:
    return {
        "reconnaissance": "TA0043",
        "resource-development": "TA0042",
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "stealth": "TA0005",
        "defense-impairment": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "command-and-control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }.get(phase_name)


def _technique_record(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    attack_id = _external_id(obj, "T")
    if not attack_id or obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    phases = obj.get("kill_chain_phases") or []
    tactic = next((_tactic_id(p.get("phase_name", "").replace("attack-", "")) for p in phases), None)
    if not tactic:
        return None
    priority = "medium"
    if tactic == "TA0040":
        priority = "critical"
    elif tactic in {"TA0004", "TA0006", "TA0008"}:
        priority = "high"
    return {
        "id": attack_id,
        "name": obj.get("name", attack_id),
        "tactic_id": tactic,
        "description": obj.get("description", ""),
        "platforms": obj.get("x_mitre_platforms") or [],
        "data_sources": obj.get("x_mitre_data_sources") or [],
        "detection": obj.get("x_mitre_detection", ""),
        "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        "priority": priority,
    }


def parse_bundle(bundle: Dict[str, Any], source: str = DATA_URL) -> Dict[str, Any]:
    """Convert an Enterprise STIX bundle into a deterministic compact index."""
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise AttackDataError("ATT&CK bundle has no objects list")
    techniques: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, Dict[str, Any]] = {}
    uses: List[Dict[str, str]] = []
    strategy_count = 0
    strategy_ids: Dict[str, str] = {}
    detects: List[Dict[str, str]] = []
    for obj in objects:
        kind = obj.get("type")
        if kind == "attack-pattern":
            record = _technique_record(obj)
            if record:
                techniques[record["id"]] = record
        elif kind == "intrusion-set":
            gid = _external_id(obj, "G")
            if gid and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                groups[gid] = {
                    "attack_id": gid,
                    "name": obj.get("name", gid),
                    "aliases": obj.get("aliases") or [],
                    "description": obj.get("description", ""),
                    "ttps": [],
                    "deprecated": False,
                    "revoked": False,
                }
        elif kind == "x-mitre-detection-strategy":
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                strategy_count += 1
                external_id = _external_id(obj, "DET")
                if external_id:
                    strategy_ids[obj.get("id", "")] = external_id
        elif kind == "relationship" and obj.get("relationship_type") == "uses":
            uses.append({"source_ref": obj.get("source_ref", ""), "target_ref": obj.get("target_ref", "")})
        elif kind == "relationship" and obj.get("relationship_type") == "detects":
            if not obj.get("x_mitre_deprecated") and not obj.get("revoked"):
                detects.append({"source_ref": obj.get("source_ref", ""), "target_ref": obj.get("target_ref", "")})
    if strategy_count == 0:
        raise AttackDataError("ATT&CK bundle contains no active detection strategies; detection model shape changed")
    if not detects:
        raise AttackDataError("ATT&CK bundle contains detection strategies but no detects relationships")
    stix_to_attack: Dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            aid = _external_id(obj, "T")
            if aid:
                stix_to_attack[obj.get("id", "")] = aid
        elif obj.get("type") == "intrusion-set":
            gid = _external_id(obj, "G")
            if gid:
                stix_to_attack[obj.get("id", "")] = gid
    for relation in uses:
        gid = stix_to_attack.get(relation["source_ref"])
        tid = stix_to_attack.get(relation["target_ref"])
        if gid in groups and tid in techniques and tid not in groups[gid]["ttps"]:
            groups[gid]["ttps"].append(tid)
    technique_strategy_ids: Dict[str, List[str]] = {}
    for relation in detects:
        tid = stix_to_attack.get(relation["target_ref"])
        strategy_id = strategy_ids.get(relation["source_ref"])
        if tid in techniques and strategy_id:
            technique_strategy_ids.setdefault(tid, []).append(strategy_id)
    for tid, strategy_list in technique_strategy_ids.items():
        techniques[tid]["detection_strategies"] = sorted(set(strategy_list))
    for record in groups.values():
        record["ttps"].sort()
    canonical = {
        "attack_version": DATA_VERSION,
        "source": source,
        "techniques": dict(sorted(techniques.items())),
        "groups": dict(sorted(groups.items())),
        "detection_strategy_count": strategy_count,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    canonical["digest"] = hashlib.sha256(encoded).hexdigest()
    canonical["technique_count"] = len(techniques)
    canonical["group_count"] = len(groups)
    return canonical


def _fetch(url: str = DATA_URL) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "RedTeamKit/3.2"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)
    except Exception as exc:  # pragma: no cover - network-specific error paths
        raise AttackDataError(f"unable to fetch ATT&CK data from {url}: {exc}") from exc


def sync(dry_run: bool = False, offline: bool = False, output: Optional[Path] = None) -> Dict[str, Any]:
    """Fetch v20.0 and optionally write the compact local index."""
    if offline:
        raise AttackDataError("offline mode refuses network synchronization")
    parsed = parse_bundle(_fetch())
    if not dry_run:
        target = Path(output) if output else data_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            json.dump(parsed, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return parsed


def print_header(index: Dict[str, Any]) -> None:
    fields = ("attack_version", "technique_count", "group_count", "digest", "source")
    print(json.dumps({field: index.get(field) for field in fields}, indent=2))
