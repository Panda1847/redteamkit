#!/usr/bin/env python3
"""Build the checked-in compact ATT&CK seed from an official STIX bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Set

from redteamkit.attackdata import DATA_URL, parse_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path, help="Downloaded enterprise-attack.json")
    parser.add_argument("--output", type=Path, default=Path("redteamkit/data/attack_techniques.json"))
    args = parser.parse_args()
    with args.bundle.open(encoding="utf-8") as handle:
        full = parse_bundle(json.load(handle), source=DATA_URL)

    curated: Set[str] = {
        "T1566", "T1190", "T1078", "T1133", "T1059", "T1053", "T1547",
        "T1071", "T1003", "T1021", "T1550", "T1548", "T1005", "T1560",
        "T1041", "T1567", "T1082", "T1018", "T1087", "T1486", "T1490", "T1485",
    }
    high_tactics = {"TA0004", "TA0006", "TA0008", "TA0040"}
    techniques: Dict[str, Dict[str, Any]] = {}
    for tid, record in full["techniques"].items():
        if tid in curated or record.get("tactic_id") in high_tactics or record.get("priority") in {"critical", "high"}:
            techniques[tid] = {
                "id": record["id"],
                "name": record["name"],
                "tactic_id": record["tactic_id"],
                "platforms": record.get("platforms") or [],
                "data_sources": record.get("data_sources") or [],
                "detection": record.get("detection", "")[:500],
                "priority": record.get("priority", "medium"),
            }
    groups = {
        gid: {
            "attack_id": group["attack_id"],
            "name": group["name"],
            "aliases": group.get("aliases") or [],
            "description": group.get("description", "")[:600],
            "ttps": group.get("ttps") or [],
            "deprecated": False,
            "revoked": False,
        }
        for gid, group in full["groups"].items()
        if group.get("ttps")
    }
    seed = {
        "attack_version": full["attack_version"],
        "source": "seed",
        "techniques": dict(sorted(techniques.items())),
        "groups": dict(sorted(groups.items())),
        "detection_strategy_count": full.get("detection_strategy_count", 0),
    }
    digest_payload = json.dumps(seed, sort_keys=True, separators=(",", ":")).encode()
    seed["digest"] = hashlib.sha256(digest_payload).hexdigest()
    seed["technique_count"] = len(techniques)
    seed["group_count"] = len(groups)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(seed, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({k: seed[k] for k in ("attack_version", "source", "technique_count", "group_count", "digest")}, indent=2))
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
