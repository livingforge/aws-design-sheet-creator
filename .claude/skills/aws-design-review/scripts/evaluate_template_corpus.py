"""Measure findings on a corpus of deployable CloudFormation templates.

Templates in the corpus are assumed to deploy, so every FAIL is a candidate
false positive until triaged. Each FAIL gets an automatic category and the
cfn-lint diagnostics on the same logical resource, when cfn-lint is supplied.
The categories are hints for manual triage, not verdicts.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

from aws_design_sheet.cfn_template import _contains_unresolved, import_template
from aws_design_sheet.checker import Checker


ROOT = Path(__file__).resolve().parents[1]
SUFFIXES = {".yaml", ".yml", ".json", ".template"}
SCALAR_TYPES = {"integer", "number", "boolean"}
FORMAT_PREFERENCE = {".yaml": 0, ".yml": 1, ".template": 2, ".json": 3}


def rule_paths(node) -> set[str]:
    if isinstance(node, str):
        return {node} if node.startswith("/properties/") else set()
    if isinstance(node, dict):
        return set().union(*(rule_paths(value) for value in node.values()), set())
    if isinstance(node, list):
        return set().union(*(rule_paths(value) for value in node), set())
    return set()


def overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def categorize(item: dict, relation_paths: list[str], declared_paths: set[str]) -> str:
    paths = declared_paths | ({item["path"]} if item.get("path") else set())
    if any(overlaps(rel, path) for rel in relation_paths for path in paths):
        return "reference_invisible_to_rule"
    if item["rule_id"] == "SCHEMA_CONSTRAINT" and "is not of type" in (item.get("reason") or ""):
        expected = item.get("expected")
        expected = set(expected) if isinstance(expected, list) else {expected}
        actual = item.get("actual")
        if isinstance(actual, str) and expected & SCALAR_TYPES:
            return "string_to_scalar_coercion"
        if isinstance(actual, (bool, int, float)) and "string" in expected:
            return "scalar_to_string_coercion"
    return "unclassified"


def unique_templates(files: list[Path]) -> tuple[list[Path], list[Path]]:
    """Keep one format of each template published as both JSON and YAML."""
    chosen: dict[Path, Path] = {}
    for path in files:
        key = path.with_suffix("")
        current = chosen.get(key)
        if current is None or FORMAT_PREFERENCE[path.suffix.lower()] < FORMAT_PREFERENCE[current.suffix.lower()]:
            chosen[key] = path
    kept = sorted(chosen.values())
    return kept, [path for path in files if path not in set(kept)]


def run_cfn_lint(executable: Path, corpus: Path, files: list[Path], region: str) -> dict:
    """Return cfn-lint matches keyed by (relative file, logical ID)."""
    found: dict[tuple[str, str | None], list[dict]] = defaultdict(list)
    relative = [path.relative_to(corpus).as_posix() for path in files]
    for start in range(0, len(relative), 40):
        completed = subprocess.run(
            [str(executable), "--format", "json", "--regions", region, "--", *relative[start:start + 40]],
            cwd=corpus, capture_output=True, text=True, encoding="utf-8")
        for match in json.loads(completed.stdout or "[]"):
            location = match.get("Location", {}).get("Path") or []
            logical = location[1] if len(location) > 1 and location[0] == "Resources" else None
            found[(Path(match["Filename"]).as_posix(), logical)].append({
                "rule": match["Rule"]["Id"], "level": match["Level"],
                "path": location, "message": match["Message"]})
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cfn-lint", type=Path, default=None)
    parser.add_argument("--region", default="ap-northeast-1")
    parser.add_argument("--account", default="111111111111")
    parser.add_argument("--environment", default="prod")
    args = parser.parse_args()

    checker = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json", ROOT / "rules/ledger.json",
                      ROOT / "rules/ruleset.json", None)
    declared = {rule["id"]: rule_paths({"when": rule.get("when"), "assert": rule.get("assert"),
                                        "scope": rule.get("scope")})
                for rule in json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8"))["rules"]}
    files = sorted(path for path in args.corpus.rglob("*")
                   if path.suffix.lower() in SUFFIXES and ".git" not in path.parts)
    files, duplicates = unique_templates(files)
    templates, skipped, failures = [], {}, []
    verdicts, fail_rules, review_rules, review_unresolved = Counter(), Counter(), Counter(), Counter()
    fail_severity, review_reasons, review_groups = Counter(), Counter(), 0
    started = time.perf_counter()
    for path in files:
        name = path.relative_to(args.corpus).as_posix()
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
        if "Rain::" in text:
            skipped[name] = "Rain directives require rain pkg preprocessing"
            continue
        try:
            design, report = import_template(
                text, name, project="corpus", environment=args.environment, account=args.account,
                region=args.region, reference_catalog=checker.reference_types)
        except Exception as exc:  # parse failures and unexpanded transforms are reported, not fatal
            skipped[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
            continue
        result = checker.check(design)
        by_id = {resource.id: resource for resource in design.resources}
        relations = defaultdict(list)
        for relation in design.relations:
            relations[relation.source_resource_id].append(relation.source_path)
        unresolved = {(resource.id, field.path) for resource in design.resources
                      for field in resource.fields if field.state.value == "UNRESOLVED" or
                      field.state.value == "KNOWN" and _contains_unresolved(field.selected().value)}
        verdicts.update(result["summary"])
        groups = set()
        for item in result["results"]:
            if item["verdict"] == "NEEDS_REVIEW":
                review_rules[item["rule_id"]] += 1
                paths = set(item.get("dependencies") or []) | {item.get("path")}
                if any((item["resource_id"], "/".join(p.split("/")[:3])) in unresolved
                       for p in paths if p and p.startswith("/properties/")):
                    review_unresolved[item["rule_id"]] += 1
                else:
                    review_reasons[(item["rule_id"], item.get("reason") or "")] += 1
                    groups.add((item["rule_id"], item.get("reason") or ""))
            if item["verdict"] != "FAIL":
                continue
            fail_rules[item["rule_id"]] += 1
            fail_severity[item.get("severity", "ERROR")] += 1
            resource = by_id.get(item["resource_id"])
            failures.append({
                "template": name, "logical_id": resource.name if resource else None,
                "type": resource.type if resource else None, "rule_id": item["rule_id"],
                "path": item.get("path"), "severity": item.get("severity", "ERROR"),
                "reason": item.get("reason"),
                "expected": item.get("expected"), "actual": item.get("actual"),
                "category": categorize(item, relations[item["resource_id"]],
                                       declared.get(item["rule_id"], set()))})
        review_groups += len(groups)
        templates.append({"template": name, **report.as_dict(),
                          "checked_resources": len(design.resources),
                          "summary": result["summary"],
                          "uncovered": dict(Counter(c["kind"] for c in result["coverage"]))})
    elapsed = time.perf_counter() - started

    lint_summary = None
    if args.cfn_lint:
        lint = run_cfn_lint(args.cfn_lint, args.corpus,
                            [args.corpus / t["template"] for t in templates], args.region)
        for failure in failures:
            failure["cfn_lint_same_resource"] = [
                m for m in lint.get((failure["template"], failure["logical_id"]), [])
                if m["level"] == "Error"]
        failed_resources = {(f["template"], f["logical_id"]) for f in failures}
        lint_errors = [{"template": key[0], "logical_id": key[1], **m}
                       for key, matches in lint.items() for m in matches if m["level"] == "Error"]
        lint_summary = {
            "errors": len(lint_errors), "warnings": sum(m["level"] == "Warning" for v in lint.values() for m in v),
            "error_rules": dict(Counter(e["rule"] for e in lint_errors).most_common()),
            "fails_with_lint_error_on_same_resource": sum(bool(f["cfn_lint_same_resource"]) for f in failures),
            "lint_errors_on_resources_without_fail": [
                e for e in lint_errors if (e["template"], e["logical_id"]) not in failed_resources]}

    resources = sum(t["converted"] for t in templates)
    properties = sum(t["resolved_properties"] + t["unresolved_properties"] for t in templates)
    report = {
        "corpus": str(args.corpus), "region": args.region, "elapsed_seconds": round(elapsed, 2),
        "files": len(files) + len(duplicates), "duplicate_formats_excluded": len(duplicates),
        "templates": len(templates), "skipped": skipped,
        "resources": resources,
        "resources_skipped": sum(len(t["skipped"]) for t in templates),
        "properties": properties,
        "unresolved_properties": sum(t["unresolved_properties"] for t in templates),
        "verdicts": dict(verdicts),
        "per_100_resources": {k: round(100 * v / resources, 2) for k, v in verdicts.items()
                              if k in ("FAIL", "NEEDS_REVIEW")} if resources else {},
        "templates_with_fail": sum(bool(t["summary"].get("FAIL")) for t in templates),
        "fail_by_severity": dict(fail_severity),
        "templates_with_error_fail": len({f["template"] for f in failures if f["severity"] == "ERROR"}),
        "needs_review_known_inputs": sum(review_reasons.values()),
        "needs_review_known_inputs_per_100_resources": round(100 * sum(review_reasons.values()) / resources, 2) if resources else 0,
        "needs_review_groups_per_template": round(review_groups / len(templates), 2) if templates else 0,
        "needs_review_known_input_reasons": [
            {"rule_id": rule, "reason": reason, "count": count}
            for (rule, reason), count in review_reasons.most_common()],
        "fail_categories": dict(Counter(f["category"] for f in failures).most_common()),
        "fail_rules": dict(fail_rules.most_common()),
        "needs_review_rules": dict(review_rules.most_common()),
        "needs_review_from_unresolved_fields": dict(review_unresolved.most_common()),
        "cfn_lint": lint_summary, "failures": failures, "per_template": templates}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("templates", "resources", "verdicts", "per_100_resources",
                                             "templates_with_fail", "fail_by_severity",
                                             "templates_with_error_fail", "needs_review_known_inputs",
                                             "needs_review_known_inputs_per_100_resources",
                                             "needs_review_groups_per_template")},
                     ensure_ascii=False))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
