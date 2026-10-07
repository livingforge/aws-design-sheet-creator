"""Check the exported design with cfn-lint and map matches back to the design.

cfn-lint covers single-template CloudFormation validity: property types,
ranges, formats, combinations and service limits. Its matches become results
with rule IDs `CFN_LINT.<id>`: errors FAIL with severity ERROR and warnings
FAIL with severity WARNING. Matches the export itself causes are not results:
those on placeholders for unknown values, on the placeholder parameters, and
reference format matches (E1040, E1041) on relations, because the design does
not record which attribute a relation uses. They are listed as coverage.
Template-authoring advice that does not apply to a design is not reported.
"""
from __future__ import annotations

import json

from cfnlint.api import ManualArgs, lint
from cfnlint.version import __version__ as CFN_LINT_VERSION

from .cfn_export import ExportedTemplate, export_templates
from .models import Design


REFERENCE_FORMAT_RULES = {"E1040", "E1041"}
# Template-authoring advice that does not apply to a design document.
DESIGN_IGNORED_RULES = {
    "W3005": "a redundant DependsOn is harmless, and the importer lists implied dependencies on purpose",
    "W3010": "a design states its Availability Zones explicitly",
}
SEVERITIES = {"error": "ERROR", "warning": "WARNING"}


def _pointer(parts: list) -> str:
    return "/properties" + "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def _within(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _design_path(design: Design, resource_id: str | None, tokens: list) -> str:
    """Pointer for a match; cross-resource matches such as E3060 point through the
    referenced resource, so fall back to the matched property of this resource."""
    path = _pointer(tokens)
    resource = next((r for r in design.resources if r.id == resource_id), None)
    if resource is None or not tokens:
        return path
    known = [f.path for f in resource.fields] + [r.source_path for r in design.relations
                                                 if r.source_resource_id == resource_id]
    if any(_within(path, k) or _within(k, path) for k in known):
        return path
    last = _pointer(tokens[-1:])
    return last if last in known else path


def _evidence(design: Design, resource_id: str | None, path: str | None) -> list[str]:
    resource = next((r for r in design.resources if r.id == resource_id), None)
    if resource is None:
        return []
    ids: list[str] = []
    for item in resource.fields:
        if path and (_within(path, item.path) or _within(item.path, path)):
            ids += [*item.intent_evidence_ids, *(e for c in item.candidates for e in c.evidence_ids)]
    for relation in design.relations:
        if relation.source_resource_id == resource_id and path and _within(path, relation.source_path):
            ids += relation.evidence_ids
    if not ids and resource.template:
        ids = list(resource.template.evidence_ids)
    return list(dict.fromkeys(ids))


def _map(match, exported: ExportedTemplate, design: Design) -> tuple[str, dict]:
    """('result' | 'coverage', entry) for one cfn-lint match."""
    rule_id, location = match.rule.id, list(match.path)
    if location[:1] == ["Parameters"]:
        return "skip", {}
    resource_id = path = None
    if location[:1] == ["Resources"] and len(location) > 1:
        resource_id = exported.resource_ids.get(location[1])
        if location[2:3] == ["Properties"]:
            path = _design_path(design, resource_id, location[3:])
        elif location[2:3] == ["DependsOn"]:
            path = "/template/depends_on"
    # Only a match on the unknown value itself, or one quoting it, is the export's doing; a
    # match on a parent (an item count, a required property) still holds for the known parts.
    for name, (owner, unknown_path) in exported.placeholders.items():
        if owner == resource_id and path and _within(path, unknown_path) or f"'{name}'" in match.message:
            return "coverage", {"kind": "CFN_LINT_UNKNOWN_VALUE", "resource_id": resource_id, "path": path,
                                "reason": f"cfn-lint {rule_id} not evaluated: value unknown in design"}
    if rule_id in REFERENCE_FORMAT_RULES and path and any(
            _within(path, ref) for ref in exported.relation_paths.get(resource_id, ())):
        return "coverage", {"kind": "CFN_LINT_REFERENCE_FORMAT", "resource_id": resource_id, "path": path,
                            "reason": f"cfn-lint {rule_id} not evaluated: design does not record the referenced attribute"}
    return "result", {
        "rule_id": f"CFN_LINT.{rule_id}", "rule_version": CFN_LINT_VERSION,
        "resource_id": resource_id, "path": path, "verdict": "FAIL",
        "severity": SEVERITIES.get(match.rule.severity, "WARNING"),
        "expected": None, "actual": None, "reason": match.message,
        "evidence_ids": _evidence(design, resource_id, path), "dependencies": [],
        "authority": "CFN_LINT", "source_urls": [match.rule.source_url] if match.rule.source_url else []}


def lint_design(design: Design) -> tuple[list[dict], list[dict]]:
    """cfn-lint results and coverage entries for every exported template."""
    results: list[dict] = []
    coverage: list[dict] = []
    for exported in export_templates(design):
        config = ManualArgs(regions=[exported.region])
        for match in lint(json.dumps(exported.template, ensure_ascii=False),
                          regions=[exported.region], config=config):
            if match.rule.severity not in SEVERITIES or match.rule.id in DESIGN_IGNORED_RULES:
                continue
            kind, entry = _map(match, exported, design)
            if kind == "result":
                results.append(entry)
            elif kind == "coverage":
                coverage.append(entry)
        for relation in exported.outside_relations:
            coverage.append({"kind": "CFN_LINT_CROSS_TEMPLATE", "resource_id": relation["resource_id"],
                             "path": relation["path"],
                             "reason": "cfn-lint checks one template; the referenced resource is in another"})
    unique = {json.dumps(r, sort_keys=True): r for r in results}
    return list(unique.values()), coverage
