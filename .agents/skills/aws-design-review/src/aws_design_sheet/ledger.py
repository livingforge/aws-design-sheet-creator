"""Validate the review ledger against a pinned CloudFormation schema archive."""
from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from urllib.parse import urlparse


STATES = {
    "UNRESEARCHED",
    "REVIEWED_NO_ADDITIONAL_RULES",
    "RULES_REGISTERED",
    "REVIEW_REQUIRED",
}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def _strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{label} must be a list of nonempty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicates")
    return value


def validate_ledger(ledger_path: Path, schema_dir: Path,
                    ruleset_path: Path | None = None) -> dict:
    """Return a ledger only if its type set, provenance, and rule IDs are valid.

    A ledger with registered rules requires a ruleset. The ruleset is checked for
    unique IDs and all ledger IDs must resolve to rules for the same source type.
    """
    manifest = _read_json(schema_dir / "manifest.json")
    archive = schema_dir / manifest["archive"]
    actual_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual_hash != manifest["zip_sha256"]:
        raise ValueError("schema archive hash mismatch")
    ledger = _read_json(ledger_path)
    if ledger.get("ledger_version") != "1.0.0":
        raise ValueError("unsupported ledger version")
    if ledger.get("schema_region") != manifest["region"]:
        raise ValueError("ledger schema region mismatch")
    if ledger.get("schema_zip_sha256") != actual_hash:
        raise ValueError("ledger schema ZIP hash mismatch")
    entries = ledger.get("types")
    if not isinstance(entries, dict) or set(entries) != set(manifest["types"]):
        missing = set(manifest["types"]) - set(entries or {}) if isinstance(entries, dict) else set()
        extra = set(entries or {}) - set(manifest["types"]) if isinstance(entries, dict) else set()
        raise ValueError(f"ledger type set mismatch: {len(missing)} missing, {len(extra)} extra")

    if ruleset_path is None:
        adjacent_ruleset = ledger_path.parent / "ruleset.json"
        default_ruleset = schema_dir.parent / "rules/ruleset.json"
        ruleset_path = (adjacent_ruleset if adjacent_ruleset.exists() else
                        default_ruleset if default_ruleset.exists() else None)
    rules = {}
    if ruleset_path is not None:
        ruleset = _read_json(ruleset_path)
        if not isinstance(ruleset.get("rules"), list):
            raise ValueError("ruleset.rules must be a list")
        for rule in ruleset["rules"]:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"]:
                raise ValueError("invalid ruleset rule")
            if rule["id"] in rules:
                raise ValueError(f"duplicate ruleset rule ID: {rule['id']}")
            rules[rule["id"]] = rule

    claimed_ids = set()
    for type_name, entry in entries.items():
        if not isinstance(entry, dict):
            raise ValueError(f"invalid ledger entry: {type_name}")
        service = type_name.split("::")[1]
        if entry.get("service") != service:
            raise ValueError(f"service mismatch: {type_name}")
        state = entry.get("state")
        if state not in STATES:
            raise ValueError(f"invalid ledger state: {type_name}")
        source_urls = _strings(entry.get("source_urls"), f"{type_name}.source_urls")
        rule_ids = _strings(entry.get("rule_ids"), f"{type_name}.rule_ids")
        questions = _strings(entry.get("open_questions"), f"{type_name}.open_questions")
        if state == "UNRESEARCHED":
            if source_urls or rule_ids or questions or entry.get("reviewed_at") or entry.get("rationale"):
                raise ValueError(f"unresearched type has review claims: {type_name}")
            continue
        try:
            date.fromisoformat(entry["reviewed_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid reviewed_at: {type_name}") from exc
        if not source_urls or any(urlparse(url).scheme != "https" or
                                  not urlparse(url).hostname or
                                  not (urlparse(url).hostname == "aws.amazon.com" or
                                       urlparse(url).hostname.endswith(".amazonaws.com") or
                                       urlparse(url).hostname.endswith(".aws.amazon.com"))
                                  for url in source_urls):
            raise ValueError(f"reviewed type needs AWS HTTPS sources: {type_name}")
        if state == "REVIEWED_NO_ADDITIONAL_RULES":
            if rule_ids or questions or not isinstance(entry.get("rationale"), str) or not entry["rationale"].strip():
                raise ValueError(f"no-additional-rules claim lacks rationale: {type_name}")
        elif state == "RULES_REGISTERED":
            if not rule_ids or questions:
                raise ValueError(f"registered type needs rule IDs and no open questions: {type_name}")
        elif state == "REVIEW_REQUIRED" and not questions:
            raise ValueError(f"review-required type needs open questions: {type_name}")
        for rule_id in rule_ids:
            if rule_id in claimed_ids:
                raise ValueError(f"rule ID claimed by multiple types: {rule_id}")
            claimed_ids.add(rule_id)
            if rule_id not in rules or rules[rule_id].get("source_type") != type_name:
                raise ValueError(f"rule ID missing or source type differs: {rule_id}")
    return ledger
