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
from pathlib import Path
from typing import List, Optional

from .attack import AttackLibrary, Tactic
from .attackdata import AttackDataError, load_index, print_header
from .attackdata import sync as sync_attack_data
from .campaign import CampaignPlanner
from .detection import DetectionMatrix
from .opsec import OpsecChecklist
from .pentest import (
    TOOL_ADAPTERS,
    PentestError,
    build_evidence_manifest,
    build_plan,
    load_scope,
    render_markdown,
    render_plan,
)
from .profiles import list_profiles, load_profile
from .reporting import ReportBuilder


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
            source = "generated" if p.generated else "hand-maintained"
            print(f"  {name:24} [{source:15}] — {p.origin or p.motivation[:50]}")
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


def cmd_sync(args):
    try:
        index = sync_attack_data(dry_run=args.dry_run, offline=args.offline)
    except AttackDataError as exc:
        print(f"ATT&CK sync failed: {exc}", file=sys.stderr)
        return 1
    print_header(index)
    return 0


def cmd_validate(args):
    try:
        index = load_index()
    except AttackDataError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}))
        return 1
    profiles = []
    for name in list_profiles():
        profile = load_profile(name)
        profiles.append({
            "profile": name,
            "generated": bool(profile.generated) if profile else False,
            "technique_count": len(profile.ttps) if profile else 0,
        })
    result = {
        "valid": True,
        "attack_version": index.get("attack_version"),
        "technique_count": index.get("technique_count", len(index.get("techniques", {}))),
        "group_count": index.get("group_count", len(index.get("groups", {}))),
        "profiles": profiles,
    }
    print(json.dumps(result, indent=2))
    return 0


def cmd_pentest_tools(args):
    for adapter in TOOL_ADAPTERS.values():
        print(f"{adapter.name:14} {adapter.category:24} {adapter.repository}")
        print(f"{'':14} {adapter.purpose}")
    return 0


def cmd_pentest_scope(args):
    try:
        scope = load_scope(args.scope)
    except PentestError as exc:
        print(f"Scope rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(scope.to_dict(), indent=2) if args.json else "SCOPE VALID\n" + json.dumps(scope.to_dict(), indent=2))
    return 0


def cmd_pentest_plan(args):
    try:
        scope = load_scope(args.scope)
        tools = [item.strip() for item in args.tools.split(",")] if args.tools else None
        plan = build_plan(scope, tools=tools, output_dir=args.output_dir)
    except PentestError as exc:
        print(f"Pentest plan rejected: {exc}", file=sys.stderr)
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = render_markdown(plan) if args.format == "markdown" else json.dumps(plan, indent=2) + "\n"
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote reviewable plan: {args.output}")
    else:
        if args.format == "markdown":
            print(render_markdown(plan))
        else:
            print(json.dumps(plan, indent=2) if args.json else render_plan(plan))
    return 0


def cmd_pentest_evidence(args):
    try:
        manifest = build_evidence_manifest(args.plan, args.evidence_dir)
    except PentestError as exc:
        print(f"Evidence manifest rejected: {exc}", file=sys.stderr)
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote evidence manifest: {args.output}")
    else:
        print(json.dumps(manifest, indent=2))
    return 0


def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        prog="redteamkit",
        description="RedTeamKit — Authorized red team planning & simulation engine v3.3",
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

    # ATT&CK data lifecycle
    p = sub.add_parser("sync", help="Fetch and index the official ATT&CK Enterprise bundle")
    p.add_argument("--dry-run", action="store_true", help="Validate and summarize without writing the index")
    p.add_argument("--offline", action="store_true", help="Refuse network synchronization")
    p.add_argument("--json", action="store_true", help="Emit the index header as JSON")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("validate", help="Validate the local ATT&CK index and profile registry")
    p.add_argument("--json", action="store_true", help="Emit JSON")
    p.set_defaults(func=cmd_validate)

    # Authorized pentest planning and tool adapters
    p = sub.add_parser("pentest", help="Plan an authorized pentest without executing tools")
    pentest_sub = p.add_subparsers(dest="pentest_command", required=True)
    tools = pentest_sub.add_parser("tools", help="List vetted tool adapters and official repositories")
    tools.set_defaults(func=cmd_pentest_tools)
    scope = pentest_sub.add_parser("scope", help="Validate an explicit JSON or simple YAML scope file")
    scope.add_argument("--scope", required=True, type=Path)
    scope.add_argument("--json", action="store_true")
    scope.set_defaults(func=cmd_pentest_scope)
    plan = pentest_sub.add_parser("plan", help="Generate a reviewable, plan-only assessment runbook")
    plan.add_argument("--scope", required=True, type=Path)
    plan.add_argument("--tools", help="Comma-separated subset of tools allowed by the scope")
    plan.add_argument("--output-dir", type=Path, default=Path("evidence"))
    plan.add_argument("--output", type=Path, help="Write JSON plan to this path")
    plan.add_argument("--format", choices=["json", "markdown"], default="json")
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(func=cmd_pentest_plan)
    evidence = pentest_sub.add_parser("evidence", help="Hash collected evidence and report missing artifacts")
    evidence.add_argument("--plan", required=True, type=Path)
    evidence.add_argument("--evidence-dir", type=Path, default=Path("evidence"))
    evidence.add_argument("--output", type=Path, help="Write the manifest to this path")
    evidence.set_defaults(func=cmd_pentest_evidence)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
