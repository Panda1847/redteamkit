#!/usr/bin/env python3
"""
RedTeamKit CLI — High-fidelity authorized red team planning engine.

Usage examples:
  python -m redteamkit profiles
  python -m redteamkit profiles APT29
  python -m redteamkit.cli campaign --adversary APT29 --days 14 --objectives credential_access,lateral_movement
  python -m redteamkit.cli matrix T1566,T1003,T1021,T1059
  python -m redteamkit.cli report --adversary FIN7 --days 10
  python -m redteamkit.cli opsec
  python -m redteamkit.cli techniques --tactic CREDENTIAL_ACCESS
"""

import argparse
import json
import sys
from typing import List

from .profiles import list_profiles, load_profile, search_profiles
from .attack import AttackLibrary, Tactic
from .campaign import CampaignPlanner
from .detection import DetectionMatrix, GapAnalyzer
from .reporting import ReportBuilder
from .opsec import OpsecChecklist


def cmd_profiles(args):
    if args.name:
        p = load_profile(args.name)
        if not p:
            print(f"Profile not found: {args.name}")
            print("Available:", ", ".join(list_profiles()))
            return 1
        print(p.summary())
        if args.json:
            print("\n" + json.dumps(p.to_dict(), indent=2))
    else:
        print("Available adversary profiles:")
        for name in list_profiles():
            p = load_profile(name)
            print(f"  {name:12} — {p.origin} | {p.motivation[:50]}")
    return 0


def cmd_campaign(args):
    planner = CampaignPlanner()
    objectives = [o.strip() for o in args.objectives.split(",")] if args.objectives else None
    exclude = [e.strip() for e in args.exclude.split(",")] if args.exclude else []

    if args.adversary and load_profile(args.adversary):
        camp = planner.from_profile(
            args.adversary,
            duration_days=args.days,
            team_size=args.team,
            fidelity=args.fidelity,
            exclude=exclude,
            objectives=objectives,
        )
    else:
        camp = planner.create(
            adversary=args.adversary or "Custom",
            duration_days=args.days,
            team_size=args.team,
            fidelity=args.fidelity,
            exclude=exclude,
            objectives=objectives,
        )

    print(camp.summary())
    if args.json:
        print("\n" + json.dumps(camp.to_dict(), indent=2))
    return 0


def cmd_matrix(args):
    ids = [t.strip().upper() for t in args.techniques.split(",")]
    matrix = DetectionMatrix().build(ids)
    print(matrix.summary())
    if args.json:
        print("\n" + json.dumps([e.to_dict() for e in matrix.entries], indent=2))
    return 0


def cmd_report(args):
    """Generate a report. Requires --results JSON with real detection data.

    Expected JSON format:
    {
      "T1566": {"detected": true, "mttd": 12.5, "notes": "..."},
      "T1003": {"detected": false, "mttd": null, "notes": "No alert fired"}
    }
    """
    import json
    from pathlib import Path

    if not args.results:
        print(
            "ERROR: report requires real detection results.\n"
            "  Provide --results <file.json> with technique outcomes.\n"
            "  Format: {\"T1566\": {\"detected\": true, \"mttd\": 12.5, \"notes\": \"...\"}, ...}\n"
            "  Refusing to invent findings."
        )
        return 1

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"ERROR: results file not found: {results_path}")
        return 1

    with open(results_path) as f:
        results = json.load(f)

    if not isinstance(results, dict) or not results:
        print("ERROR: results file must be a non-empty JSON object keyed by technique ID")
        return 1

    planner = CampaignPlanner()
    objectives = [o.strip() for o in args.objectives.split(",")] if args.objectives else None
    exclude = [e.strip() for e in args.exclude.split(",")] if args.exclude else None

    if args.adversary and load_profile(args.adversary):
        camp = planner.from_profile(
            args.adversary,
            duration_days=args.days,
            fidelity=args.fidelity,
            exclude=exclude,
            objectives=objectives,
        )
    else:
        camp = planner.create(
            adversary=args.adversary or "Custom",
            duration_days=args.days,
            fidelity=args.fidelity,
            exclude=exclude,
            objectives=objectives,
        )

    # Build matrix only from techniques that have real results
    tech_ids = list(results.keys())
    matrix = DetectionMatrix().build(tech_ids)

    for tid, data in results.items():
        if not isinstance(data, dict) or "detected" not in data:
            print(f"ERROR: result for {tid} must contain at least 'detected' (bool)")
            return 1
        matrix.mark(
            tid,
            detected=bool(data["detected"]),
            actual_mttd=data.get("mttd"),
            notes=data.get("notes", ""),
        )

    report = ReportBuilder().full_report(camp, matrix)
    print(report)
    return 0


def cmd_opsec(args):
    cl = OpsecChecklist()
    # Checklist starts blank — operator must mark items explicitly
    print(cl.summary())
    return 0


def cmd_techniques(args):
    lib = AttackLibrary()
    if args.tactic:
        try:
            tac = Tactic[args.tactic.upper()]
        except KeyError:
            print("Unknown tactic. Valid:", ", ".join(t.name for t in Tactic))
            return 1
        techs = lib.by_tactic(tac)
    elif args.priority:
        techs = lib.by_priority(args.priority)
    elif args.search:
        techs = lib.search(args.search)
    else:
        techs = list(lib.techniques.values())

    print(f"{'ID':<10} {'Name':<40} {'Tactic':<22} {'Priority'}")
    print("-" * 85)
    for t in techs:
        print(f"{t.technique_id:<10} {t.name[:39]:<40} {t.tactic.name:<22} {t.detection_priority}")
    print(f"\n{len(techs)} techniques")
    return 0


def main(argv: List[str] = None):
    parser = argparse.ArgumentParser(
        prog="redteamkit",
        description="RedTeamKit — Authorized red team planning & simulation engine v3",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # profiles (also accepts "profile" as alias)
    p = sub.add_parser("profiles", aliases=["profile"], help="List or show adversary profiles")
    p.add_argument("name", nargs="?", help="Profile name (APT29, FIN7, ...)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_profiles)

    # campaign
    p = sub.add_parser("campaign", help="Build a multi-phase campaign plan")
    p.add_argument("--adversary", "-a", default="Custom")
    p.add_argument("--days", "-d", type=int, default=14)
    p.add_argument("--team", "-t", type=int, default=3)
    p.add_argument("--fidelity", "-f", default="high", choices=["low", "medium", "high"])
    p.add_argument("--objectives", "-o", help="Comma-separated objectives")
    p.add_argument("--exclude", "-x", help="Comma-separated technique IDs to exclude")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_campaign)

    # matrix
    p = sub.add_parser("matrix", help="Build detection validation matrix")
    p.add_argument("techniques", help="Comma-separated ATT&CK technique IDs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_matrix)

    # report
    p = sub.add_parser("report", help="Generate full engagement report (requires real results)")
    p.add_argument("--adversary", "-a", default="APT29")
    p.add_argument("--days", "-d", type=int, default=14)
    p.add_argument("--fidelity", "-f", default="high")
    p.add_argument("--objectives", "-o")
    p.add_argument("--exclude", "-x", help="Comma-separated technique IDs to exclude")
    p.add_argument("--results", "-r", required=True,
                   help="JSON file of real detection results: {tech_id: {detected, mttd, notes}}")
    p.set_defaults(func=cmd_report)

    # opsec
    p = sub.add_parser("opsec", help="Show OPSEC checklist")
    p.set_defaults(func=cmd_opsec)

    # techniques
    p = sub.add_parser("techniques", help="Query ATT&CK technique library")
    p.add_argument("--tactic", help="Filter by tactic name (e.g. CREDENTIAL_ACCESS)")
    p.add_argument("--priority", choices=["critical", "high", "medium", "low"])
    p.add_argument("--search", "-s")
    p.set_defaults(func=cmd_techniques)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
