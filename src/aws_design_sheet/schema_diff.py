"""Carry the review ledger across a schema archive update.

Added types start UNRESEARCHED. Removed types lose their ledger entry, rules and
references. A changed schema invalidates a "no additional rules" claim, so such
types return to UNRESEARCHED; types with registered rules or open questions keep
their rules but become REVIEW_REQUIRED with an explicit re-review question.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

from .rule_review import basis_errors, dump_json


def _schemas(manifest: dict, archive: bytes) -> dict[str, dict]:
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        return {name: json.loads(zipped.read(member)) for name, member in manifest["types"].items()}


def _digest(schema: dict) -> str:
    return hashlib.sha256(json.dumps(schema, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def diff_types(old_manifest: dict, old_archive: bytes, new_manifest: dict,
               new_archive: bytes) -> dict:
    old, new = _schemas(old_manifest, old_archive), _schemas(new_manifest, new_archive)
    return {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)),
            "changed": sorted(name for name in set(old) & set(new)
                              if _digest(old[name]) != _digest(new[name])),
            "schemas": new}


def reconcile(rules_dir: Path, old_manifest: dict, old_archive: bytes, new_manifest: dict,
              new_archive: bytes, checked_at: str) -> dict:
    """Update ledger.json, ruleset.json and references.json in rules_dir for a new archive."""
    changes = diff_types(old_manifest, old_archive, new_manifest, new_archive)
    schemas = changes.pop("schemas")
    ledger_path, ruleset_path = rules_dir / "ledger.json", rules_dir / "ruleset.json"
    references_path = rules_dir / "references.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ruleset = (json.loads(ruleset_path.read_text(encoding="utf-8")) if ruleset_path.exists()
               else {"ruleset_version": "1.0.0", "rules": []})
    references = (json.loads(references_path.read_text(encoding="utf-8")) if references_path.exists()
                  else None)
    removed, changed = set(changes["removed"]), set(changes["changed"])
    report = {**changes, "reset": [], "review_required": [], "broken_basis": [],
              "removed_rules": [], "removed_references": []}

    for name in changes["removed"]:
        ledger["types"].pop(name, None)
    for name in changes["added"]:
        ledger["types"][name] = {"service": name.split("::")[1], "state": "UNRESEARCHED",
                                 "source_urls": [], "rule_ids": [], "open_questions": []}
    kept_rules = []
    for rule in ruleset["rules"]:
        if rule["source_type"] in removed:
            report["removed_rules"].append(rule["id"])
            continue
        if rule["source_type"] in changed:
            problems = basis_errors(rule.get("basis", []), schemas[rule["source_type"]], rule["id"])
            report["broken_basis"].extend(problems)
        kept_rules.append(rule)
    ruleset["rules"] = kept_rules
    if references is not None:
        kept = []
        for item in references["references"]:
            if item["source_type"] in removed or item["target_type"] in removed:
                report["removed_references"].append([item["source_type"], item["path"]])
                continue
            if item["source_type"] in changed:
                report["broken_basis"].extend(basis_errors(item["basis"], schemas[item["source_type"]],
                                                           f"{item['source_type']} {item['path']}"))
            kept.append(item)
        references["references"] = kept

    question = (f"Pinned schema changed on {checked_at}; re-review registered rules, open questions "
                "and references against the new schema")
    for name in changes["changed"]:
        entry = ledger["types"][name]
        if entry["state"] == "UNRESEARCHED":
            continue
        if entry["state"] == "REVIEWED_NO_ADDITIONAL_RULES":
            ledger["types"][name] = {"service": entry["service"], "state": "UNRESEARCHED",
                                     "source_urls": [], "rule_ids": [], "open_questions": []}
            report["reset"].append(name)
            continue
        entry["state"] = "REVIEW_REQUIRED"
        if question not in entry["open_questions"]:
            entry["open_questions"].append(question)
        entry["reviewed_at"] = entry.get("reviewed_at", checked_at)
        report["review_required"].append(name)

    ledger["types"] = dict(sorted(ledger["types"].items()))
    ledger["schema_region"] = new_manifest["region"]
    ledger["schema_zip_sha256"] = new_manifest["zip_sha256"]
    ledger_path.write_text(dump_json(ledger), encoding="utf-8")
    if report["removed_rules"]:
        major, minor, *_ = ruleset["ruleset_version"].split(".") + ["0", "0"]
        ruleset["ruleset_version"] = f"{major}.{int(minor) + 1}.0"
    if ruleset_path.exists():
        ruleset_path.write_text(dump_json(ruleset), encoding="utf-8")
    if references is not None:
        if report["removed_references"]:
            major, minor, *_ = references["catalog_version"].split(".") + ["0", "0"]
            references["catalog_version"] = f"{major}.{int(minor) + 1}.0"
        references_path.write_text(dump_json(references), encoding="utf-8")
    return report
