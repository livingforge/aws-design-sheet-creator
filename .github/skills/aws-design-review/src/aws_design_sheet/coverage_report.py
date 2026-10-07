"""Report research coverage for the pinned CloudFormation resource types."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from .ledger import STATES, validate_ledger


def build_report(ledger_path: Path, schema_dir: Path,
                 tiers_path: Path | None = None) -> dict:
    ruleset_path = ledger_path.parent / "ruleset.json"
    ledger = validate_ledger(ledger_path, schema_dir,
                             ruleset_path if ruleset_path.exists() else None)
    state_counts = Counter(entry["state"] for entry in ledger["types"].values())
    by_namespace: dict[str, Counter] = defaultdict(Counter)
    work_by_namespace: dict[str, Counter] = defaultdict(Counter)
    for type_name, entry in ledger["types"].items():
        namespace = type_name.split("::")[1]
        by_namespace[namespace][entry["state"]] += 1
        work_by_namespace[namespace]["rules"] += len(entry["rule_ids"])
        work_by_namespace[namespace]["open_questions"] += len(entry["open_questions"])
    default_tiers = Path(__file__).resolve().parents[2] / "rules/service-tiers.json"
    tier_data = json.loads((tiers_path or default_tiers).read_text(encoding="utf-8"))
    known_namespaces = set(by_namespace)
    assigned: dict[str, str] = {}
    for tier, namespaces in tier_data["tiers"].items():
        for namespace in namespaces:
            if namespace not in known_namespaces:
                raise ValueError(f"unknown tier namespace: {namespace}")
            if namespace in assigned:
                raise ValueError(f"duplicate tier namespace: {namespace}")
            assigned[namespace] = tier
    by_tier: dict[str, Counter] = defaultdict(Counter)
    work_by_tier: dict[str, Counter] = defaultdict(Counter)
    tier_namespaces: dict[str, list[str]] = defaultdict(list)
    for namespace, counts in by_namespace.items():
        tier = assigned.get(namespace, tier_data["default_tier"])
        by_tier[tier].update(counts)
        work_by_tier[tier].update(work_by_namespace[namespace])
        tier_namespaces[tier].append(namespace)
    return {
        "status": "COMPLETE",
        "schema_region": ledger["schema_region"],
        "schema_zip_sha256": ledger["schema_zip_sha256"],
        "ledger_version": ledger["ledger_version"],
        "ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        "total_types": len(ledger["types"]),
        "rule_count": sum(counts["rules"] for counts in work_by_namespace.values()),
        "open_question_count": sum(counts["open_questions"] for counts in work_by_namespace.values()),
        "state_counts": {state: state_counts[state] for state in sorted(STATES)},
        "tier_version": tier_data["tier_version"],
        "tier_counts": {
            tier: {"namespaces": sorted(tier_namespaces[tier]),
                   "total": sum(by_tier[tier].values()),
                   "rule_count": work_by_tier[tier]["rules"],
                   "open_question_count": work_by_tier[tier]["open_questions"],
                   "state_counts": {state: by_tier[tier][state] for state in sorted(STATES)}}
            for tier in sorted(set(by_tier) | set(tier_data["tiers"]))},
        "namespace_counts": {
            namespace: {"total": sum(counts.values()),
                        "rule_count": work_by_namespace[namespace]["rules"],
                        "open_question_count": work_by_namespace[namespace]["open_questions"],
                        "state_counts": {state: counts[state] for state in sorted(STATES)}}
            for namespace, counts in sorted(by_namespace.items())},
        "unresearched_types": sorted(type_name for type_name, entry in ledger["types"].items()
                                     if entry["state"] == "UNRESEARCHED"),
    }


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Report design-rule research coverage")
    parser.add_argument("--ledger", type=Path, default=root / "rules/ledger.json")
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--tiers", type=Path, default=root / "rules/service-tiers.json")
    parser.add_argument("--output", type=Path, help="JSON file; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.ledger, args.schemas, args.tiers)
    except Exception as exc:
        report = {"status": "FAILED", "diagnostic": str(exc)}
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0 if report["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
