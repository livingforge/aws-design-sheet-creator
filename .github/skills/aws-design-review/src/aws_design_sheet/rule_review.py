"""Per-namespace review of pinned resource types: material, validation and merge.

A review fragment records the outcome of reading one namespace's pinned schema
and official pages. Validation re-checks every claim that can be checked
offline: quoted basis text must appear in the pinned schema description at the
cited pointer, and every rule's examples must produce the expected verdicts.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .doc_pages import BASE as PAGE_BASE, quote_in_page, type_pages
from .ledger import STATES, validate_ledger
from .rule_engine import TYPE_NAME, evaluate_rule_all, example_resource, load_ruleset


SCHEMA_ZIP_URL = "https://schema.cloudformation.{region}.amazonaws.com/CloudformationSchema.zip"
CONDITION = re.compile(
    r"\b(?:if|when|whenever|must|cannot|can't|requires?|required|only|either|unless|depends?|"
    r"dependent|exclusive|mutually|conflicts?|both|neither|not supported|at least|at most|"
    r"ignored|otherwise|in addition|same|one|single|up to|no more than|between|valid values?|"
    r"supported|allowed|unique|combination|together|instead)\b", re.IGNORECASE)
COMBINATORS = ("oneOf", "anyOf", "allOf", "not", "dependencies", "if", "dependentRequired",
               "dependentSchemas")
REFERENCE_PATH = re.compile(r"^/properties(?:/(?:(?:[^~/*]|~[01])+|\*))*/(?:[^~/*]|~[01])+(?:/\*)?$")
FRAGMENT_KEYS = {"fragment_version", "namespace", "reviewed_at", "types", "rules", "references",
                 "partial"}
ENTRY_KEYS = {"state", "source_urls", "rule_ids", "open_questions", "rationale"}


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _resolve(document: Any, pointer: str) -> Any:
    node = document
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            raise KeyError(pointer)
    return node


def _aws_url(url: Any) -> bool:
    if not isinstance(url, str):
        return False
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return parsed.scheme == "https" and (host == "aws.amazon.com" or host.endswith(".aws.amazon.com")
                                         or host.endswith(".amazonaws.com"))


class PinnedSchemas:
    def __init__(self, schema_dir: Path):
        self.manifest = json.loads((schema_dir / "manifest.json").read_text(encoding="utf-8"))
        self.archive = zipfile.ZipFile(schema_dir / self.manifest["archive"])
        self.cache: dict[str, dict] = {}

    def types(self, namespace: str | None = None) -> list[str]:
        return sorted(name for name in self.manifest["types"]
                      if namespace is None or name.split("::")[1] == namespace)

    def schema(self, type_name: str) -> dict:
        if type_name not in self.cache:
            self.cache[type_name] = json.loads(self.archive.read(self.manifest["types"][type_name]))
        return self.cache[type_name]


def basis_errors(basis: list[dict] | tuple[dict, ...], schema: dict, label: str) -> list[str]:
    errors = []
    for item in basis:
        if "pointer" not in item:
            continue
        try:
            node = _resolve(schema, item["pointer"])
        except KeyError:
            errors.append(f"{label}: basis pointer not in pinned schema: {item['pointer']}")
            continue
        description = node.get("description") if isinstance(node, dict) else None
        if not isinstance(description, str):
            errors.append(f"{label}: basis pointer has no description: {item['pointer']}")
        elif _normalize(item["quote"]) not in _normalize(description):
            errors.append(f"{label}: basis quote not found at {item['pointer']}")
    return errors


def example_errors(rule) -> list[str]:
    errors = []
    for index, example in enumerate(rule.examples):
        try:
            results = evaluate_rule_all(rule, example_resource(rule, example))
        except Exception as exc:  # malformed example values surface as review errors
            errors.append(f"{rule.id}: example {index} failed: {exc}")
            continue
        verdicts = sorted({result["verdict"] for result in results})
        if verdicts != [example["verdict"]]:
            errors.append(f"{rule.id}: example {index} expected {example['verdict']}, got {verdicts}")
    return errors


def required_example_verdicts(rule) -> set[str]:
    verdicts = {"PASS", "FAIL", "NEEDS_REVIEW"}
    if rule.when["op"] != "always" or rule.scope is not None or rule.assertion["op"] in (
            "value_in", "matches", "compare", "unique", "items_in", "multiple_of"):
        verdicts.add("NOT_APPLICABLE")
    return verdicts


def load_reference_catalog(raw: Any, known_types: dict | set) -> dict[tuple[str, str], str]:
    if not isinstance(raw, dict) or set(raw) != {"catalog_version", "references"}:
        raise ValueError("invalid reference catalog keys")
    if not isinstance(raw["catalog_version"], str) or not raw["catalog_version"]:
        raise ValueError("catalog_version must be a nonempty string")
    if not isinstance(raw["references"], list):
        raise ValueError("references must be an array")
    catalog: dict[tuple[str, str], str] = {}
    for item in raw["references"]:
        reference_entry_errors(item, known_types, "reference catalog", raise_first=True)
        key = (item["source_type"], item["path"])
        if key in catalog:
            raise ValueError(f"duplicate reference path: {key}")
        catalog[key] = item["target_type"]
    return catalog


def reference_entry_errors(item: Any, known_types: dict | set, label: str, *,
                           raise_first: bool = False) -> list[str]:
    errors = []
    if not isinstance(item, dict) or set(item) != {"source_type", "path", "target_type", "basis"}:
        errors.append(f"{label}: invalid reference keys")
    else:
        for key in ("source_type", "target_type"):
            if not isinstance(item[key], str) or item[key] not in known_types:
                errors.append(f"{label}: {key} absent from pinned schema: {item[key]}")
        if not isinstance(item["path"], str) or not REFERENCE_PATH.fullmatch(item["path"]):
            errors.append(f"{label}: invalid reference path: {item['path']}")
        if not isinstance(item["basis"], list) or not item["basis"] or any(
                not isinstance(entry, dict) or len(set(entry) & {"pointer", "url"}) != 1 or
                set(entry) - {"pointer", "url", "quote"} or
                not isinstance(entry.get("pointer", entry.get("url")), str) or
                not isinstance(entry.get("quote"), str) or not entry["quote"].strip()
                for entry in item["basis"]):
            errors.append(f"{label}: reference basis needs one pointer or url and a quote")
    if errors and raise_first:
        raise ValueError(errors[0])
    return errors


def page_basis_errors(basis: list[dict] | tuple[dict, ...], cache_dir: Path | None,
                      label: str) -> list[str]:
    errors = []
    for item in basis:
        if "url" not in item:
            continue
        if not item["url"].startswith(PAGE_BASE) or "#" not in item["url"]:
            errors.append(f"{label}: basis url must be a Template Reference page with a section anchor")
        elif cache_dir is not None and not quote_in_page(item["url"], item["quote"], cache_dir):
            errors.append(f"{label}: basis quote not found at {item['url']}")
    return errors


def validate_fragment(fragment: Any, schemas: PinnedSchemas, ledger: dict,
                      ruleset: dict, references: dict, cache_dir: Path | None = None) -> list[str]:
    """Return every problem found in one namespace review fragment."""
    if not isinstance(fragment, dict) or set(fragment) - FRAGMENT_KEYS or not {
            "fragment_version", "namespace", "reviewed_at", "types"} <= set(fragment):
        return ["fragment keys are invalid"]
    errors: list[str] = []
    namespace = fragment["namespace"]
    names = schemas.types(namespace) if isinstance(namespace, str) else []
    if not names:
        return [f"unknown namespace: {namespace}"]
    if fragment["fragment_version"] != "1.0.0":
        errors.append("unsupported fragment_version")
    try:
        date.fromisoformat(fragment["reviewed_at"])
    except (TypeError, ValueError):
        errors.append("reviewed_at must be an ISO date")
    entries = fragment["types"]
    if not isinstance(entries, dict):
        return errors + ["types must be an object"]
    pending = {name for name in names if ledger["types"][name]["state"] == "UNRESEARCHED"}
    revisable = {name for name in names if ledger["types"][name]["state"] == "REVIEW_REQUIRED"}
    if fragment.get("partial") not in (None, True):
        errors.append("partial must be true when present")
    for name in pending - set(entries) if fragment.get("partial") is not True else ():
        errors.append(f"{name}: unresearched type missing from fragment")
    for name in set(entries) - set(names):
        errors.append(f"{name}: type is outside namespace {namespace}")
    for name in set(entries) & set(names) - pending - revisable:
        errors.append(f"{name}: type was already reviewed; edit the ledger entry directly")

    raw_rules = fragment.get("rules", [])
    try:
        rules = load_ruleset({"ruleset_version": "fragment", "rules": raw_rules})
    except (ValueError, re.error) as exc:
        return errors + [f"rules: {exc}"]
    existing_ids = {rule["id"] for rule in ruleset["rules"]}
    by_type: dict[str, set[str]] = {}
    for raw, rule in zip(raw_rules, rules):
        label = rule.id
        by_type.setdefault(rule.source_type, set()).add(rule.id)
        prefix = ".".join(part.upper() for part in rule.source_type.split("::")[1:]) + "."
        if not rule.id.startswith(prefix) or not re.fullmatch(r"[A-Z0-9_.]+", rule.id):
            errors.append(f"{label}: rule id must start with {prefix} and use A-Z, 0-9, _")
        if rule.id in existing_ids:
            errors.append(f"{label}: rule id already registered")
        if rule.source_type not in entries:
            errors.append(f"{label}: source type is not part of this fragment")
            continue
        if rule.authority != "AWS_SPEC":
            errors.append(f"{label}: review fragments register AWS_SPEC rules only")
        if not rule.source_urls or not all(_aws_url(url) for url in rule.source_urls):
            errors.append(f"{label}: source_urls must be AWS HTTPS URLs")
        if rule.source_checked_at != fragment["reviewed_at"]:
            errors.append(f"{label}: source_checked_at must equal reviewed_at")
        if not raw.get("description"):
            errors.append(f"{label}: description is required")
        if not rule.basis:
            errors.append(f"{label}: basis is required")
        errors.extend(basis_errors(rule.basis, schemas.schema(rule.source_type), label))
        errors.extend(page_basis_errors(rule.basis, cache_dir, label))
        missing = required_example_verdicts(rule) - {example["verdict"] for example in rule.examples}
        if missing:
            errors.append(f"{label}: examples lack verdicts {sorted(missing)}")
        errors.extend(example_errors(rule))

    for name, entry in entries.items():
        if name not in names:
            continue
        if not isinstance(entry, dict) or set(entry) - ENTRY_KEYS or not {
                "state", "source_urls", "rule_ids", "open_questions"} <= set(entry):
            errors.append(f"{name}: invalid entry keys")
            continue
        state = entry["state"]
        if state not in STATES - {"UNRESEARCHED"}:
            errors.append(f"{name}: invalid state {state}")
        lists_ok = True
        for key in ("source_urls", "rule_ids", "open_questions"):
            value = entry[key]
            if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip()
                                                  for item in value) or len(value) != len(set(value)):
                errors.append(f"{name}: {key} must be unique nonempty strings")
                lists_ok = False
        if not lists_ok:
            continue
        if not entry["source_urls"] or not all(_aws_url(url) for url in entry["source_urls"]):
            errors.append(f"{name}: source_urls must be AWS HTTPS URLs")
        prior_ids = set(ledger["types"][name]["rule_ids"]) if name in revisable else set()
        if set(entry["rule_ids"]) != prior_ids | by_type.get(name, set()):
            errors.append(f"{name}: rule_ids must list exactly the existing and fragment rules for this type")
        rationale = entry.get("rationale")
        if rationale is not None and (not isinstance(rationale, str) or not rationale.strip()):
            errors.append(f"{name}: rationale must be a nonempty string")
        if state == "REVIEWED_NO_ADDITIONAL_RULES" and (entry["rule_ids"] or entry["open_questions"]
                                                       or not rationale):
            errors.append(f"{name}: no-additional-rules needs a rationale and no rules or questions")
        if state == "RULES_REGISTERED" and (not entry["rule_ids"] or entry["open_questions"]):
            errors.append(f"{name}: registered state needs rules and no open questions")
        if state == "REVIEW_REQUIRED" and not entry["open_questions"]:
            errors.append(f"{name}: review-required state needs open questions")

    from .checker import REFERENCE_TYPES  # built-in references are checked by the checker itself

    known = {(item["source_type"], item["path"]) for item in references["references"]} | set(REFERENCE_TYPES)
    for index, item in enumerate(fragment.get("references", [])):
        label = f"reference {index}"
        found = reference_entry_errors(item, schemas.manifest["types"], label)
        errors.extend(found)
        if found:
            continue
        if item["source_type"] not in entries:
            errors.append(f"{label}: source type is not part of this fragment")
            continue
        key = (item["source_type"], item["path"])
        if key in known:
            errors.append(f"{label}: reference path already registered")
        known.add(key)
        errors.extend(basis_errors(item["basis"], schemas.schema(item["source_type"]), label))
        errors.extend(page_basis_errors(item["basis"], cache_dir, label))
    return errors


def _bump(version: str) -> str:
    major, minor, *_ = (version.split(".") + ["0", "0"])[:3]
    return f"{major}.{int(minor) + 1}.0"


def dump_json(data: Any) -> str:
    """Stable JSON with short arrays and objects kept on one line."""
    def render(value: Any, indent: int) -> str:
        flat = json.dumps(value, ensure_ascii=False)
        if not isinstance(value, (dict, list)) or len(flat) + indent <= 100 or not value:
            return flat
        pad, inner = " " * indent, " " * (indent + 2)
        if isinstance(value, list):
            return "[\n" + ",\n".join(inner + render(item, indent + 2) for item in value) + "\n" + pad + "]"
        return "{\n" + ",\n".join(f"{inner}{json.dumps(key, ensure_ascii=False)}: "
                                  f"{render(item, indent + 2)}" for key, item in value.items()) + "\n" + pad + "}"
    return render(data, 0) + "\n"


def merge_fragments(paths: list[Path], root: Path) -> dict:
    schemas = PinnedSchemas(root / "schemas")
    ledger_path, ruleset_path = root / "rules/ledger.json", root / "rules/ruleset.json"
    references_path = root / "rules/references.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ruleset = json.loads(ruleset_path.read_text(encoding="utf-8"))
    references = (json.loads(references_path.read_text(encoding="utf-8")) if references_path.exists()
                  else {"catalog_version": "1.0.0", "references": []})
    merged, counts = [], {"types": 0, "rules": 0, "references": 0}
    for path in paths:
        fragment = json.loads(path.read_text(encoding="utf-8"))
        errors = validate_fragment(fragment, schemas, ledger, ruleset, references,
                                   root / "output/doc-cache")
        if errors:
            raise ValueError(f"{path}: " + "; ".join(errors[:20]))
        for name, entry in fragment["types"].items():
            record = {"service": name.split("::")[1], "state": entry["state"],
                      "source_urls": entry["source_urls"], "rule_ids": entry["rule_ids"],
                      "open_questions": entry["open_questions"],
                      "reviewed_at": fragment["reviewed_at"]}
            if entry.get("rationale"):
                record["rationale"] = entry["rationale"]
            ledger["types"][name] = record
        ruleset["rules"].extend(fragment.get("rules", []))
        references["references"].extend(fragment.get("references", []))
        counts["types"] += len(fragment["types"])
        counts["rules"] += len(fragment.get("rules", []))
        counts["references"] += len(fragment.get("references", []))
        merged.append(fragment["namespace"])
    if not merged:
        return {"merged": [], **counts}
    if counts["rules"]:
        ruleset["ruleset_version"] = _bump(ruleset["ruleset_version"])
    if counts["references"]:
        references["references"].sort(key=lambda item: (item["source_type"], item["path"]))
        references["catalog_version"] = (_bump(references["catalog_version"])
                                         if references_path.exists() else "1.0.0")
    ledger_path.write_text(dump_json(ledger), encoding="utf-8")
    ruleset_path.write_text(dump_json(ruleset), encoding="utf-8")
    if counts["references"] or references_path.exists():
        references_path.write_text(dump_json(references), encoding="utf-8")
    validate_ledger(ledger_path, root / "schemas", ruleset_path)
    return {"merged": merged, **counts}


def _walk(node: Any, pointer: str, descriptions: list, combinators: list):
    if isinstance(node, dict):
        if isinstance(node.get("description"), str):
            descriptions.append((pointer, node["description"]))
        for key, value in node.items():
            if key in COMBINATORS:
                combinators.append((pointer + "/" + key, json.dumps(value, ensure_ascii=False)[:300]))
            if key != "description":
                _walk(value, pointer + "/" + key.replace("~", "~0").replace("/", "~1"),
                      descriptions, combinators)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, f"{pointer}/{index}", descriptions, combinators)


def review_material(namespace: str, root: Path, *, include_all: bool = False,
                    cache_dir: Path | None = None) -> str:
    """Plain-text review material for every type in one namespace."""
    schemas = PinnedSchemas(root / "schemas")
    ledger = json.loads((root / "rules/ledger.json").read_text(encoding="utf-8"))
    audit_path = root / "rules/source-audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))["types"] if audit_path.exists() else {}
    names = schemas.types(namespace)
    if not names:
        raise ValueError(f"unknown namespace: {namespace}")
    lines = [f"# {namespace}: {len(names)} types (schema {schemas.manifest['region']}, "
             f"zip sha256 {schemas.manifest['zip_sha256'][:12]})",
             "Lines starting with '*' are Template Reference sections; cite them as url#anchor.",
             "Lines starting with '-' are pinned schema descriptions; cite them by JSON Pointer.", ""]
    for name in names:
        schema = schemas.schema(name)
        page = audit.get(name, {})
        lines.append(f"## {name}  [ledger: {ledger['types'][name]['state']}]")
        lines.append(f"page: {page.get('url', '-')} (title verified: {page.get('title_matches_type', False)})")
        lines.append(f"required: {', '.join(schema.get('required', [])) or '-'}")
        for key in ("readOnlyProperties", "writeOnlyProperties", "createOnlyProperties"):
            if schema.get(key):
                lines.append(f"{key}: {', '.join(schema[key])}")
        props = []
        for key, definition in schema.get("properties", {}).items():
            kind = definition.get("type") or (definition.get("$ref", "").split("/")[-1]) or "?"
            if kind == "array":
                item = definition.get("items", {})
                kind = "array<" + (item.get("type") or item.get("$ref", "").split("/")[-1] or "?") + ">"
            props.append(f"{key}:{kind}")
        lines.append("properties: " + ", ".join(props))
        descriptions, combinators = [], []
        _walk({"properties": schema.get("properties", {}), "definitions": schema.get("definitions", {})},
              "", descriptions, combinators)
        _walk({key: schema[key] for key in COMBINATORS if key in schema}, "", [], combinators)
        for pointer, text in combinators:
            lines.append(f"schema combinator {pointer}: {text}")
        corpus = []
        for page in type_pages(name, cache_dir) if cache_dir is not None else []:
            if page.get("error") or not page.get("sections"):
                lines.append(f"page unavailable: {page['url']} ({page.get('error', 'no property sections')})")
                continue
            if page.get("intro") and (include_all or CONDITION.search(page["intro"])):
                lines.append(f"* {page['url']}#intro: {page['intro']}")
            for section in page["sections"]:
                body = section["text"]
                corpus.append(_normalize(body))
                if include_all or CONDITION.search(body.split(" Required:")[0]) or \
                        "Required: Conditional" in body:
                    body = body.split(" Update requires:")[0]
                    lines.append(f"* {page['url']}#{section['id']} [{section['name']}]: {body}")
        shown = [(p, d) for p, d in descriptions if include_all or CONDITION.search(d)]
        repeated = {p for p, d in shown if any(_normalize(d) in item for item in corpus)}
        lines.append(f"schema descriptions: {len(descriptions)} total, {len(shown)} with condition words, "
                     f"{len(repeated)} of those repeat page text above")
        for pointer, text in shown:
            if pointer not in repeated:
                lines.append(f"- {pointer}: {_normalize(text)}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Review pinned resource types by namespace")
    commands = parser.add_subparsers(dest="command", required=True)
    material = commands.add_parser("material", help="print review material for a namespace")
    material.add_argument("namespace")
    material.add_argument("--all", action="store_true", help="show every description")
    schema = commands.add_parser("schema", help="print one pinned resource schema")
    schema.add_argument("type_name")
    check = commands.add_parser("validate", help="validate review fragments without merging")
    check.add_argument("fragments", nargs="+", type=Path)
    merge = commands.add_parser("merge", help="validate and merge fragments into the rules")
    merge.add_argument("fragments", nargs="+", type=Path)
    pending = commands.add_parser("pending", help="list namespaces with unresearched types")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    if args.command == "material":
        sys.stdout.write(review_material(args.namespace, root, include_all=args.all,
                                         cache_dir=root / "output/doc-cache") + "\n")
        return 0
    if args.command == "schema":
        if not TYPE_NAME.fullmatch(args.type_name):
            parser.error("invalid type name")
        sys.stdout.write(json.dumps(PinnedSchemas(root / "schemas").schema(args.type_name),
                                    ensure_ascii=False, indent=1) + "\n")
        return 0
    if args.command == "pending":
        ledger = json.loads((root / "rules/ledger.json").read_text(encoding="utf-8"))
        counts: dict[str, int] = {}
        for name, entry in sorted(ledger["types"].items()):
            if entry["state"] == "UNRESEARCHED":
                counts[name.split("::")[1]] = counts.get(name.split("::")[1], 0) + 1
        sys.stdout.write(json.dumps(counts, ensure_ascii=False) + "\n")
        return 0
    if args.command == "validate":
        schemas = PinnedSchemas(root / "schemas")
        ledger = json.loads((root / "rules/ledger.json").read_text(encoding="utf-8"))
        ruleset = json.loads((root / "rules/ruleset.json").read_text(encoding="utf-8"))
        references_path = root / "rules/references.json"
        references = (json.loads(references_path.read_text(encoding="utf-8")) if references_path.exists()
                      else {"catalog_version": "1.0.0", "references": []})
        failed = False
        for path in args.fragments:
            try:
                fragment = json.loads(path.read_text(encoding="utf-8"))
                errors = validate_fragment(fragment, schemas, ledger, ruleset, references,
                                           root / "output/doc-cache")
            except (OSError, ValueError) as exc:
                errors = [str(exc)]
            failed = failed or bool(errors)
            sys.stdout.write(json.dumps({"fragment": str(path), "valid": not errors,
                                         "errors": errors}, ensure_ascii=False) + "\n")
        return 2 if failed else 0
    try:
        result = merge_fragments(args.fragments, root)
    except ValueError as exc:
        sys.stdout.write(json.dumps({"status": "FAILED", "diagnostic": str(exc)}, ensure_ascii=False) + "\n")
        return 2
    sys.stdout.write(json.dumps({"status": "COMPLETE", **result}, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
