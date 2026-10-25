# RedTeamKit v3.1

Authorized red team planning & simulation engine.  
Stdlib only. No network calls. No fabricated findings.

## Install / Run

```bash
# From the directory that contains the redteamkit/ package:
python3 -m redteamkit profiles
python3 -m redteamkit profile APT29
python3 -m redteamkit campaign --adversary FIN7 --days 10
python3 -m redteamkit techniques --priority critical
python3 -m redteamkit matrix T1566,T1003,T1021,T1059
python3 -m redteamkit opsec
python3 -m redteamkit report --adversary APT29 --results results.json
```

## Report requires real results

`report` will **refuse** to run without a `--results` JSON file:

```json
{
  "T1566": {"detected": true, "mttd": 12.5, "notes": "Email gateway alert"},
  "T1003": {"detected": false, "mttd": null, "notes": "No LSASS access alert"},
  "T1021": {"detected": true, "mttd": 45.0, "notes": "RDP from unusual source"}
}
```

This is intentional. Invented detection rates have no place in client deliverables.

## Destructive techniques

`T1486`, `T1490`, `T1485` are excluded by default from every campaign.  
Pass `--exclude` to add more, or use the planner with `allow_destructive=True` only when you have explicit scope and rollback.

## Modules

| Module | Role |
|--------|------|
| profiles | APT28/29/41, FIN7, Lazarus, Turla, Custom |
| attack | ATT&CK library (data sources, detections, mitigations, priority) |
| campaign | Multi-phase planner with tactic-aware TTP injection |
| detection | Validation matrix + gap analysis |
| opsec | Checklist (starts blank) + readiness score |
| reporting | Executive + technical + detection appendix |
| cli | Command-line interface |

## License

For authorized security testing only. Obtain written permission before any engagement.
