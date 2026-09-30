"""Apply a reviewed correction to saved intermediate data and rerun checks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .checker import Checker
from .models import Design, FieldValue, ValueState


def correct(design: Design, previous_result: dict, *, resource_id: str, path: str,
            value, evidence_id: str | None, author: str, reason: str) -> Design:
    if previous_result.get("status") != "COMPLETE":
        raise ValueError("source run did not complete")
    current_hash = hashlib.sha256(design.model_dump_json(exclude_none=False).encode()).hexdigest()
    if previous_result.get("input_sha256") != current_hash:
        raise ValueError("source run does not match intermediate data")
    if evidence_id is not None and evidence_id not in {e.id for e in design.evidence}:
        raise ValueError("unknown evidence ID")
    if not author.strip() or not reason.strip():
        raise ValueError("author and reason are required")
    data = design.model_dump(mode="json")
    resource = next((r for r in data["resources"] if r["id"] == resource_id), None)
    if resource is None:
        raise ValueError("resource ID not found")
    fields = resource["fields"]
    existing = next((f for f in fields if f["path"] == path), None)
    before = existing.copy() if existing else None
    edit_id = uuid4().hex
    candidate_id = "edit-" + edit_id
    document_id = "correction-" + edit_id
    correction_evidence_id = "correction-evidence-" + edit_id
    statement = json.dumps({"resource": resource_id, "path": path, "value": value,
                            "author": author, "reason": reason}, ensure_ascii=False)
    data["documents"].append({"id": document_id, "name": "review correction", "version": "1",
                              "sha256": hashlib.sha256(statement.encode("utf-8")).hexdigest(),
                              "text": statement, "extracted_ranges": [[1, 1]]})
    data["evidence"].append({"id": correction_evidence_id, "document_id": document_id,
                             "start_line": 1, "end_line": 1, "excerpt": statement})
    after = {"path": path, "state": ValueState.KNOWN.value,
             "selected_candidate_id": candidate_id,
             "candidates": [{"id": candidate_id, "raw": json.dumps(value, ensure_ascii=False),
                             "value": value,
                             "evidence_ids": [correction_evidence_id] + ([evidence_id] if evidence_id else []),
                             "origin": "corrected"}]}
    FieldValue.model_validate(after)
    if existing:
        fields[fields.index(existing)] = after
    else:
        fields.append(after)
    data["corrections"].append({"target": f"{resource_id}{path}", "before": before,
                                "after": after, "reason": reason, "author": author,
                                "source_run_id": previous_result["run_id"]})
    return Design.model_validate(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Correct intermediate JSON and rerun checks")
    parser.add_argument("input", type=Path)
    parser.add_argument("source_result", type=Path)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--value", required=True, help="JSON literal, e.g. false or '\"10.0.1.0/24\"'")
    parser.add_argument("--evidence-id", help="optional supporting source evidence ID")
    parser.add_argument("--author", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--intermediate", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--schemas", type=Path, default=root / "schemas")
    parser.add_argument("--profile", type=Path, default=root / "profiles/vpc-subnet.json")
    parser.add_argument("--ledger", type=Path, default=root / "rules/ledger.json")
    parser.add_argument("--ruleset", type=Path, default=root / "rules/ruleset.json")
    parser.add_argument("--references", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        if args.intermediate.resolve() == args.input.resolve():
            raise ValueError("output intermediate must differ from source")
        design = Design.model_validate_json(args.input.read_text(encoding="utf-8"))
        previous = json.loads(args.source_result.read_text(encoding="utf-8"))
        new_design = correct(design, previous, resource_id=args.resource, path=args.path,
                             value=json.loads(args.value), evidence_id=args.evidence_id,
                             author=args.author, reason=args.reason)
        result = Checker(args.schemas, args.profile, args.ledger, args.ruleset, args.references).check(new_design)
        args.intermediate.parent.mkdir(parents=True, exist_ok=True)
        args.intermediate.write_text(new_design.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        result = {"status": "FAILED", "diagnostic": str(exc), "results": [], "coverage": []}
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if result["status"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
