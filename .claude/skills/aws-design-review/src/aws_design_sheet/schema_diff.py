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
from .schema_reviews import SCHEMA_QUESTION


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
    return _apply(rules_dir, changes, schemas, new_manifest, checked_at)


def reconcile_from_hashes(rules_dir: Path, previous: dict[str, str], schemas: dict,
                          manifest: dict, checked_at: str, accepted: dict[str, str] | None = None) -> dict:
    """Rebuild the local ledger without distributing the previous AWS schemas.

    accepted maps a changed type to the fingerprint a recorded re-review covered;
    only an exact match with intact rule bases keeps the type's reviewed state.
    """
    changes = {"added": sorted(set(schemas) - set(previous)),
               "removed": sorted(set(previous) - set(schemas)),
               "changed": sorted(t for t in set(previous) & set(schemas)
                                 if previous[t] != _digest(schemas[t]))}
    return _apply(rules_dir, changes, schemas, manifest, checked_at, quarantine=True, accepted=accepted)


def _apply(rules_dir, changes, schemas, new_manifest, checked_at, *, quarantine=False, accepted=None):
    ledger_path, ruleset_path = rules_dir / "ledger.json", rules_dir / "ruleset.json"
    references_path = rules_dir / "references.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ruleset = (json.loads(ruleset_path.read_text(encoding="utf-8")) if ruleset_path.exists()
               else {"ruleset_version": "1.0.0", "rules": []})
    references = (json.loads(references_path.read_text(encoding="utf-8")) if references_path.exists()
                  else None)
    removed, changed = set(changes["removed"]), set(changes["changed"])
    broken_types = set()
    report = {**changes, "reset": [], "review_required": [], "broken_basis": [],
              "removed_rules": [], "removed_references": []}
    if quarantine:
        report.update(quarantined_rules=[], quarantined_references=[])

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
            if problems:
                broken_types.add(rule["source_type"])
            if quarantine and problems:
                report["quarantined_rules"].append(rule["id"])
                ledger["types"][rule["source_type"]]["rule_ids"].remove(rule["id"])
                continue
        kept_rules.append(rule)
    ruleset["rules"] = kept_rules
    if references is not None:
        kept = []
        for item in references["references"]:
            if item["source_type"] in removed or item["target_type"] in removed:
                report["removed_references"].append([item["source_type"], item["path"]])
                continue
            if item["source_type"] in changed:
                problems = basis_errors(item["basis"], schemas[item["source_type"]],
                                        f"{item['source_type']} {item['path']}")
                report["broken_basis"].extend(problems)
                if problems:
                    broken_types.add(item["source_type"])
                if quarantine and problems:
                    report["quarantined_references"].append([item["source_type"], item["path"]])
                    continue
            kept.append(item)
        references["references"] = kept

    question = SCHEMA_QUESTION.format(date=checked_at)
    review_accepted = []
    for name in changes["changed"]:
        entry = ledger["types"][name]
        if entry["state"] == "UNRESEARCHED":
            continue
        if (accepted or {}).get(name) == _digest(schemas[name]) and name not in broken_types:
            review_accepted.append(name)
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

    if review_accepted:
        report["schema_review_accepted"] = review_accepted
    ledger["types"] = dict(sorted(ledger["types"].items()))
    ledger["schema_region"] = new_manifest["region"]
    ledger["schema_zip_sha256"] = new_manifest["zip_sha256"]
    ledger_path.write_bytes(dump_json(ledger).encode("utf-8"))
    if report["removed_rules"] or report.get("quarantined_rules"):
        major, minor, *_ = ruleset["ruleset_version"].split(".") + ["0", "0"]
        ruleset["ruleset_version"] = f"{major}.{int(minor) + 1}.0"
    if ruleset_path.exists():
        ruleset_path.write_bytes(dump_json(ruleset).encode("utf-8"))
    if references is not None:
        if report["removed_references"] or report.get("quarantined_references"):
            major, minor, *_ = references["catalog_version"].split(".") + ["0", "0"]
            references["catalog_version"] = f"{major}.{int(minor) + 1}.0"
        references_path.write_bytes(dump_json(references).encode("utf-8"))
    return report
