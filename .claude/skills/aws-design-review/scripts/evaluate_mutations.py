"""Measure detection of seeded design defects in known-good templates.

Every operator of `mutation_operators` is applied once per template, at its
first eligible place. The original and each mutant are written as JSON and
checked by this tool, and by cfn-lint and checkov when supplied. A defect
counts as found by a tool only through findings that are new compared with
the original template and lie on one of the mutation's target resources, so
findings the original already had are never credited.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

from aws_design_sheet.cfn_template import import_template, load_template
from aws_design_sheet.checker import Checker
from scripts.evaluate_template_corpus import SUFFIXES, run_cfn_lint, unique_templates
from scripts.mutation_operators import OPERATORS, Context


ROOT = Path(__file__).resolve().parents[1]
OURS_ORDER = {"FAIL": 0, "NEEDS_REVIEW": 1}
LINT_ORDER = {"Error": 0, "Warning": 1}


def corpus_templates(corpus: Path) -> list[tuple[str, dict]]:
    """Templates the corpus evaluation converts: no Rain directives or transforms."""
    files = sorted(path for path in corpus.rglob("*")
                   if path.suffix.lower() in SUFFIXES and ".git" not in path.parts)
    templates = []
    for path in unique_templates(files)[0]:
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
        if "Rain::" in text:
            continue
        try:
            template = load_template(text)
        except Exception:  # not a template or unparsable; the corpus evaluation reports these
            continue
        if not template.get("Transform"):
            templates.append((path.relative_to(corpus).as_posix(), template))
    return templates


def ours_findings(checker: Checker, text: str, name: str, args) -> set[tuple] | None:
    """(logical ID, rule, path, verdict) of FAIL and NEEDS_REVIEW, or None if import fails."""
    try:
        design, _ = import_template(text, name, project="mutation", environment=args.environment,
                                    account=args.account, region=args.region,
                                    reference_catalog=checker.reference_types)
    except Exception:  # a mutant the importer cannot read is reported, not fatal
        return None
    names = {resource.id: resource.name for resource in design.resources}
    return {(names.get(item["resource_id"]), item["rule_id"], item.get("path"), item["verdict"])
            for item in checker.check(design)["results"] if item["verdict"] in OURS_ORDER}


def run_checkov(python: Path, work: Path) -> dict[tuple[str, str], set[str]]:
    """checkov failed check IDs keyed by (relative file, logical ID)."""
    completed = subprocess.run(
        [str(python), "-m", "checkov.main", "-d", str(work), "--framework", "cloudformation",
         "-o", "json", "--quiet", "--compact", "--skip-download"],
        capture_output=True, text=True, encoding="utf-8")
    (work / "checkov.json").write_text(completed.stdout, encoding="utf-8")
    return parse_checkov(completed.stdout)


def parse_checkov(stdout: str) -> dict[tuple[str, str], set[str]]:
    data = json.loads(stdout[min(i for i in (stdout.find("{"), stdout.find("["), len(stdout)) if i >= 0):])
    found: dict[tuple[str, str], set[str]] = defaultdict(set)
    for report in data if isinstance(data, list) else [data]:
        for check in (report.get("results") or {}).get("failed_checks", []):
            logical = check["resource"].split(".", 1)[-1]
            found[(check["file_path"].replace("\\", "/").lstrip("/"), logical)].add(check["check_id"])
    return found


def strongest(keys: set[tuple], order: dict[str, int]) -> str:
    levels = sorted({key[-1] for key in keys}, key=lambda level: order.get(level, 99))
    return levels[0] if levels else "MISSED"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--work", type=Path, default=ROOT / "output/mutations/work",
                        help="folder for the written original and mutant templates")
    parser.add_argument("--cfn-lint", type=Path, default=None)
    parser.add_argument("--checkov-python", type=Path, default=None,
                        help="Python executable with checkov installed")
    parser.add_argument("--region", default="ap-northeast-1")
    parser.add_argument("--account", default="111111111111")
    parser.add_argument("--environment", default="prod")
    parser.add_argument("--with-cfn-lint", action="store_true",
                        help="check with the built-in cfn-lint step, as the CLI does")
    args = parser.parse_args()

    checker = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json", ROOT / "rules/ledger.json",
                      ROOT / "rules/ruleset.json", None, cfn_lint=args.with_cfn_lint)
    started = time.perf_counter()
    args.work.mkdir(parents=True, exist_ok=True)
    cases, files, baselines = [], [], {}
    templates = corpus_templates(args.corpus)
    for index, (name, template) in enumerate(templates):
        folder = f"{index:03d}"
        (args.work / folder).mkdir(exist_ok=True)
        base_file = f"{folder}/base.json"
        text = json.dumps(template, ensure_ascii=False, indent=1, default=str)
        (args.work / base_file).write_text(text, encoding="utf-8")
        baselines[folder] = ours_findings(checker, text, name, args)
        files.append(base_file)
        context = Context(template, account=args.account, region=args.region)
        for op in OPERATORS:
            mutation = op.apply(context)
            if mutation is None:
                continue
            mutant_file = f"{folder}/{op.id}.json"
            mutant_text = json.dumps(mutation.template, ensure_ascii=False, indent=1, default=str)
            (args.work / mutant_file).write_text(mutant_text, encoding="utf-8")
            files.append(mutant_file)
            cases.append({"template": name, "folder": folder, "file": mutant_file, "operator": op.id,
                          "kind": op.kind, "category": op.category, "targets": mutation.targets,
                          "note": mutation.note,
                          "ours": ours_findings(checker, mutant_text, name, args)})
    ours_seconds = time.perf_counter() - started

    lint = run_cfn_lint(args.cfn_lint, args.work, [args.work / f for f in files], args.region) \
        if args.cfn_lint else None
    checkov = run_checkov(args.checkov_python, args.work) if args.checkov_python else None

    def lint_keys(file: str) -> set[tuple]:
        return {(logical, m["rule"], tuple(map(str, m["path"])), m["level"])
                for (name, logical), matches in lint.items() if name == file for m in matches}

    def checkov_keys(file: str) -> set[tuple]:
        return {(logical, check, "FAILED") for (name, logical), checks in checkov.items()
                if name == file for check in checks}

    for case in cases:
        base_file = f"{case['folder']}/base.json"
        targets = set(case["targets"])
        base = baselines[case["folder"]]
        if case["ours"] is None or base is None:
            case["ours"] = {"outcome": "IMPORT_ERROR", "rules": []}
        else:
            new = case["ours"] - base
            hits = {key for key in new if key[0] in targets}
            case["ours"] = {"outcome": strongest(hits, OURS_ORDER),
                            "rules": sorted({f"{key[1]}:{key[3]}" for key in hits}),
                            # A FAIL the original already had on a target can mask the defect.
                            "base_fail_on_target": sorted({key[1] for key in base
                                                           if key[0] in targets and key[3] == "FAIL"}),
                            "new_fail_elsewhere": sorted({f"{key[0]}:{key[1]}" for key in new - hits
                                                          if key[3] == "FAIL"})}
        if lint is not None:
            hits = {key for key in lint_keys(case["file"]) - lint_keys(base_file) if key[0] in targets}
            case["cfn_lint"] = {"outcome": strongest(hits, LINT_ORDER),
                                "rules": sorted({f"{key[1]}:{key[3]}" for key in hits})}
        if checkov is not None:
            hits = {key for key in checkov_keys(case["file"]) - checkov_keys(base_file)
                    if key[0] in targets}
            case["checkov"] = {"outcome": strongest(hits, {"FAILED": 0}),
                               "rules": sorted({key[1] for key in hits})}

    def found(case: dict, tool: str, strict: bool) -> bool:
        outcome = case.get(tool, {}).get("outcome")
        return outcome in ({"FAIL", "Error", "FAILED"} if strict else
                           {"FAIL", "NEEDS_REVIEW", "Error", "Warning", "FAILED"})

    tools = ["ours"] + (["cfn_lint"] if lint is not None else []) + (["checkov"] if checkov is not None else [])

    def summarize(group: list[dict]) -> dict:
        summary = {"cases": len(group)}
        for strict in (True, False):
            label = "strict" if strict else "any"
            summary[label] = {tool: sum(found(c, tool, strict) for c in group) for tool in tools}
            summary[label]["union"] = sum(any(found(c, t, strict) for t in tools) for c in group)
            summary[label]["only_ours"] = sum(found(c, "ours", strict) and
                                              not any(found(c, t, False) for t in tools if t != "ours")
                                              for c in group)
            summary[label]["only_others"] = sum(not found(c, "ours", False) and
                                                any(found(c, t, strict) for t in tools if t != "ours")
                                                for c in group)
        summary["ours_outcomes"] = dict(Counter(c["ours"]["outcome"] for c in group))
        return summary

    by_operator = {}
    for op in OPERATORS:
        group = [c for c in cases if c["operator"] == op.id]
        entry = {"kind": op.kind, "category": op.category, "summary": op.summary, "basis": op.basis,
                 **summarize(group)}
        for tool in tools:
            entry[f"{tool}_rules"] = dict(Counter(r for c in group for r in c[tool]["rules"]).most_common(5))
        by_operator[op.id] = entry
    report = {
        "corpus": str(args.corpus), "region": args.region, "environment": args.environment,
        "templates": len(templates), "operators": len(OPERATORS), "mutants": len(cases),
        "ours_seconds": round(ours_seconds, 2), "tools": tools,
        "overall": summarize(cases),
        "by_kind": {kind: summarize([c for c in cases if c["kind"] == kind])
                    for kind in sorted({op.kind for op in OPERATORS})},
        "by_operator": by_operator,
        "not_applied": [op.id for op in OPERATORS if not by_operator[op.id]["cases"]],
        "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("templates", "mutants", "overall", "by_kind", "not_applied")},
                     ensure_ascii=False, indent=1))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
