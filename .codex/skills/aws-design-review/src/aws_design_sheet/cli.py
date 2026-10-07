"""Local command entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import Checker
from .models import Design


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate saved AWS design JSON")
    parser.add_argument("input", type=Path, help="intermediate design JSON")
    parser.add_argument("--output", type=Path, help="result JSON; defaults to stdout")
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--profile", type=Path, default=root / "profiles/vpc-subnet.json")
    parser.add_argument("--ledger", type=Path, default=root / "rules/ledger.json")
    parser.add_argument("--ruleset", type=Path, default=root / "rules/ruleset.json")
    parser.add_argument("--references", type=Path, default=None)
    parser.add_argument("--no-cfn-lint", action="store_true",
                        help="skip CloudFormation validation of the exported design with cfn-lint")
    args = parser.parse_args(argv)
    try:
        design = Design.model_validate_json(args.input.read_text(encoding="utf-8"))
        result = Checker(args.schemas, args.profile, args.ledger, args.ruleset, args.references,
                         cfn_lint=not args.no_cfn_lint).check(design)
    except Exception as exc:
        result = {"status": "FAILED", "diagnostic": str(exc), "results": [], "coverage": []}
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0 if result["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
