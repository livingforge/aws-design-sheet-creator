"""Check the exported design with cfn-lint and map matches back to the design.

cfn-lint covers single-template CloudFormation validity: property types,
ranges, formats, combinations and service limits. Its matches become results
with rule IDs `CFN_LINT.<id>`: errors FAIL with severity ERROR and warnings
FAIL with severity WARNING. Matches the export itself causes are not results:
those on placeholders for unknown values, on the placeholder parameters, and
reference format matches (E1040, E1041) on legacy relations whose exact Ref or
GetAtt expression is unknown. Exact imported references keep these findings.
Uncertain cases are listed as coverage.
Template-authoring advice that does not apply to a design is not reported.
"""
from __future__ import annotations

import json
import re

from cfnlint.api import ManualArgs
from cfnlint.version import __version__ as CFN_LINT_VERSION

from .cfn_export import ExportedTemplate, export_templates
from .models import Design
from .cfn_compat import lint_template, reference_format_gap


REFERENCE_FORMAT_RULES = {"E1040", "E1041"}
QUOTED = re.compile(r"(?='([^']*)')")
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


class _DesignIndex:
    """Resources and their outgoing relations by ID, built once per lint run."""

    def __init__(self, design: Design):
        self.resources: dict = {}
        for resource in design.resources:
            self.resources.setdefault(resource.id, resource)
        self.relations: dict[str, list] = {}
        for relation in design.relations:
            self.relations.setdefault(relation.source_resource_id, []).append(relation)


def _design_path(index: _DesignIndex, resource_id: str | None, tokens: list) -> str:
    """Pointer for a match; cross-resource matches such as E3060 point through the
    referenced resource, so fall back to the matched property of this resource."""
    path = _pointer(tokens)
    resource = index.resources.get(resource_id)
    if resource is None or not tokens:
        return path
    known = [f.path for f in resource.fields] + [r.source_path for r in index.relations.get(resource_id, ())]
    if any(_within(path, k) or _within(k, path) for k in known):
        return path
    last = _pointer(tokens[-1:])
    return last if last in known else path


def _evidence(index: _DesignIndex, resource_id: str | None, path: str | None) -> list[str]:
    resource = index.resources.get(resource_id)
    if resource is None:
        return []
    ids: list[str] = []
    for item in resource.fields:
        if path and (_within(path, item.path) or _within(item.path, path)):
            ids += [*item.intent_evidence_ids, *(e for c in item.candidates for e in c.evidence_ids)]
    for relation in index.relations.get(resource_id, ()):
        if path and _within(path, relation.source_path):
            ids += relation.evidence_ids
    if not ids and resource.template:
        ids = list(resource.template.evidence_ids)
    return list(dict.fromkeys(ids))


def _quoted(message: str) -> set[str]:
    """Every text between a quote and the next one, so `'{name}' in message` is a set lookup."""
    return set(QUOTED.findall(message))


def _map(match, exported: ExportedTemplate, design: Design | _DesignIndex) -> tuple[str, dict]:
    """('result' | 'coverage', entry) for one cfn-lint match."""
    index = design if isinstance(design, _DesignIndex) else _DesignIndex(design)
    rule_id, location = match.rule.id, list(match.path)
    if location[:1] == ["Parameters"]:
        return "skip", {}
    resource_id = path = None
    if location[:1] == ["Resources"] and len(location) > 1:
        resource_id = exported.resource_ids.get(location[1])
        if location[2:3] == ["Properties"]:
            path = _design_path(index, resource_id, location[3:])
        elif location[2:3] == ["DependsOn"]:
            path = "/template/depends_on"
    # Only a match on the unknown value itself, or one quoting it, is the export's doing; a
    # match on a parent (an item count, a required property) still holds for the known parts.
    if (path and any(_within(path, unknown) for unknown in exported.placeholder_paths(resource_id))
            or any(name in exported.placeholders for name in _quoted(match.message))):
        return "coverage", {"kind": "CFN_LINT_UNKNOWN_VALUE", "resource_id": resource_id, "path": path,
                            "reason": f"cfn-lint {rule_id} not evaluated: value unknown in design"}
    if rule_id in REFERENCE_FORMAT_RULES and path and any(
            _within(path, ref) and ref not in exported.exact_relation_paths.get(resource_id, ())
            for ref in exported.relation_paths.get(resource_id, ())):
        return "coverage", {"kind": "CFN_LINT_REFERENCE_FORMAT", "resource_id": resource_id, "path": path,
                            "reason": f"cfn-lint {rule_id} not evaluated: design does not record the referenced attribute"}
    if rule_id in REFERENCE_FORMAT_RULES and path and resource_id:
        source = reference_format_gap(rule_id, exported.template, location[1], path)
        if source:
            return "coverage", {"kind": "CFN_LINT_FORMAT_COMPATIBILITY_GAP", "resource_id": resource_id,
                                "path": path, "rule_id": f"CFN_LINT.{rule_id}",
                                "reason": f"cfn-lint format metadata disagrees with the documented reference; not a confirmed defect: {match.message}",
                                "source_urls": [source], "evidence_ids": _evidence(index, resource_id, path)}
    return "result", {
        "rule_id": f"CFN_LINT.{rule_id}", "rule_version": CFN_LINT_VERSION,
        "resource_id": resource_id, "path": path, "verdict": "FAIL",
        "severity": SEVERITIES.get(match.rule.severity, "WARNING"),
        "expected": None, "actual": None, "reason": match.message,
        "evidence_ids": _evidence(index, resource_id, path), "dependencies": [],
        "authority": "CFN_LINT", "source_urls": [match.rule.source_url] if match.rule.source_url else []}


def lint_design(design: Design, exported_templates: list[ExportedTemplate] | None = None
                ) -> tuple[list[dict], list[dict]]:
    """cfn-lint results and coverage entries for every exported template.

    Pass `exported_templates` when the caller already exported this design.
    """
    results: list[dict] = []
    coverage: list[dict] = []
    index = _DesignIndex(design)
    for exported in export_templates(design) if exported_templates is None else exported_templates:
        config = ManualArgs(regions=[exported.region])
        for match in lint_template(json.dumps(exported.template, ensure_ascii=False),
                          regions=[exported.region], config=config):
            if match.rule.severity not in SEVERITIES or match.rule.id in DESIGN_IGNORED_RULES:
                continue
            kind, entry = _map(match, exported, index)
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
