"""Report research coverage for the pinned CloudFormation resource types."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from .ledger import STATES, validate_ledger


def build_report(ledger_path: Path, schema_dir: Path) -> dict:
    ruleset_path = ledger_path.parent / "ruleset.json"
    ledger = validate_ledger(ledger_path, schema_dir,
                             ruleset_path if ruleset_path.exists() else None)
    state_counts = Counter(entry["state"] for entry in ledger["types"].values())
    by_namespace: dict[str, Counter] = defaultdict(Counter)
    for type_name, entry in ledger["types"].items():
        by_namespace[type_name.split("::")[1]][entry["state"]] += 1
    return {
        "status": "COMPLETE",
        "schema_region": ledger["schema_region"],
        "schema_zip_sha256": ledger["schema_zip_sha256"],
        "ledger_version": ledger["ledger_version"],
        "ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        "total_types": len(ledger["types"]),
        "state_counts": {state: state_counts[state] for state in sorted(STATES)},
        "namespace_counts": {
            namespace: {"total": sum(counts.values()),
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
    parser.add_argument("--output", type=Path, help="JSON file; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.ledger, args.schemas)
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
