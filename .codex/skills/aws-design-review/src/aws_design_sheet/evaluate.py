"""Compare extraction and findings with a hand-reviewed gold dataset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import Design, ValueState


def _key(type_name: str, name: str, path: str, value) -> tuple[str, str, str, str]:
    return type_name, name, path, json.dumps(value, ensure_ascii=False, sort_keys=True)


def evaluate(design: Design, result: dict, gold: dict) -> dict:
    document_names = {d.id: d.name for d in design.documents}
    resource_by_id = {r.id: r for r in design.resources}
    evidence_by_id = {e.id: e for e in design.evidence}
    predicted = {}
    for resource in design.resources:
        for field in resource.fields:
            if field.state == ValueState.KNOWN:
                candidate = field.selected()
                predicted[_key(resource.type, resource.name, field.path, candidate.value)] = candidate.evidence_ids
    for relation in design.relations:
        source = resource_by_id.get(relation.source_resource_id)
        target = resource_by_id.get(relation.target_resource_id)
        if source and (target or relation.unresolved_name):
            name = target.name if target else relation.unresolved_name
            predicted[_key(source.type, source.name, relation.source_path, name)] = relation.evidence_ids
    expected = {_key(f["type"], f["resource"], f["path"], f["value"]): f
                for f in gold.get("facts", [])}
    common = predicted.keys() & expected.keys()
    provenance_correct = 0
    for key in common:
        target = expected[key]
        if any((document_names.get(evidence_by_id[e].document_id) == target["document"]
                and evidence_by_id[e].start_line <= target["line"] <= evidence_by_id[e].end_line)
               for e in predicted[key] if e in evidence_by_id):
            provenance_correct += 1
    expected_findings = {(f["rule_id"], f["resource"], f.get("path"), f["verdict"])
                         for f in gold.get("findings", [])}
    observed_findings = set()
    for finding in result.get("results", []):
        if finding["verdict"] in ("FAIL", "NEEDS_REVIEW", "ERROR"):
            resource = resource_by_id.get(finding["resource_id"])
            observed_findings.add((finding["rule_id"], resource.name if resource else None,
                                   finding["path"], finding["verdict"]))
    correct_findings = observed_findings & expected_findings
    return {"extraction": {"expected": len(expected), "predicted": len(predicted),
                           "correct": len(common),
                           "precision": len(common) / len(predicted) if predicted else (1.0 if not expected else 0.0),
                           "recall": len(common) / len(expected) if expected else 1.0,
                           "provenance_accuracy": provenance_correct / len(common) if common else (1.0 if not expected else 0.0)},
            "findings": {"expected": len(expected_findings), "predicted": len(observed_findings),
                         "correct": len(correct_findings),
                         "precision": len(correct_findings) / len(observed_findings)
                         if observed_findings else (1.0 if not expected_findings else 0.0),
                         "recall": len(correct_findings) / len(expected_findings)
                         if expected_findings else 1.0}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate extraction and checks against gold JSON")
    parser.add_argument("intermediate", type=Path)
    parser.add_argument("result", type=Path)
    parser.add_argument("gold", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    design = Design.model_validate_json(args.intermediate.read_text(encoding="utf-8"))
    result = json.loads(args.result.read_text(encoding="utf-8"))
    gold = json.loads(args.gold.read_text(encoding="utf-8"))
    report = evaluate(design, result, gold)
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
