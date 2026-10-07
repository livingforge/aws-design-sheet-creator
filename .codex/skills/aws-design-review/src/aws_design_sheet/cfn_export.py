"""Export the intermediate design as CloudFormation templates.

Resources are grouped into one template per declared template ID and scope;
resources without template membership form one template per scope. Known
values are written as literals and relations as Ref. A value the design does
not determine (unresolved, conflicting, nested unknown parts, or a relation to
a resource outside the template) becomes a parameter without a default, so a
linter treats it as unknown. The intermediate design records that a property
refers to a resource, not which attribute, so every relation is a plain Ref.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Design, Resource, ValueState


UNRESOLVED = {"$state": "UNRESOLVED"}
REFERENCE = re.compile(r"^@([A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+)/(.+)$")
OMITTED_STATES = {ValueState.MISSING, ValueState.NOT_APPLICABLE}


@dataclass
class ExportedTemplate:
    """A template plus the maps needed to read linter findings back."""
    template_id: str | None
    environment: str
    account: str
    region: str
    template: dict = field(default_factory=lambda: {"AWSTemplateFormatVersion": "2010-09-09",
                                                    "Resources": {}})
    resource_ids: dict[str, str] = field(default_factory=dict)  # logical ID -> resource ID
    placeholders: dict[str, tuple[str, str]] = field(default_factory=dict)  # parameter -> (resource ID, path)
    relation_paths: dict[str, set[str]] = field(default_factory=dict)  # resource ID -> paths written as Ref
    outside_relations: list[dict] = field(default_factory=list)

    def unknown(self, resource_id: str, path: str) -> dict:
        name = f"Unknown{len(self.placeholders) + 1}"
        self.template.setdefault("Parameters", {})[name] = {"Type": "String"}
        self.placeholders[name] = (resource_id, path)
        return {"Ref": name}


def _tokens(path: str) -> list[str]:
    return [part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[2:]]


def _put(properties: dict, path: str, value) -> None:
    parts = _tokens(path)
    node = properties
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        child = None if last else ([] if parts[index + 1].isdigit() else {})
        if isinstance(node, list):
            position = int(part)
            node.extend([None] * (position + 1 - len(node)))
            if last:
                node[position] = value
            elif not isinstance(node[position], (dict, list)):
                node[position] = child
            node = node[position]
        else:
            if last:
                node[part] = value
            elif not isinstance(node.get(part), (dict, list)):
                node[part] = child
            node = node[part]


def _logical_id(name: str, used: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9]", "", name) or "Resource"
    candidate, number = base, 2
    while candidate in used:
        candidate, number = f"{base}{number}", number + 1
    used.add(candidate)
    return candidate


def _group_key(resource: Resource) -> tuple:
    template_id = resource.template.id if resource.template and resource.template.state == ValueState.KNOWN \
        else None
    return (template_id, resource.scope.environment, resource.scope.account, resource.scope.region)


def export_templates(design: Design) -> list[ExportedTemplate]:
    groups: dict[tuple, ExportedTemplate] = {}
    group_of: dict[str, ExportedTemplate] = {}
    logical: dict[str, str] = {}
    names: dict[tuple, dict[tuple[str, str], str]] = {}
    for resource in design.resources:
        key = _group_key(resource)
        exported = groups.get(key) or groups.setdefault(key, ExportedTemplate(*key))
        group_of[resource.id] = exported
        logical[resource.id] = _logical_id(resource.name, set(exported.resource_ids))
        exported.resource_ids[logical[resource.id]] = resource.id
        names.setdefault(key, {})[(resource.type, resource.name)] = logical[resource.id]

    for resource in design.resources:
        exported = group_of[resource.id]
        local = names[_group_key(resource)]

        def convert(value, path: str):
            if value == UNRESOLVED:
                return exported.unknown(resource.id, path)
            if isinstance(value, dict):
                return {key: convert(item, f"{path}/{key.replace('~', '~0').replace('/', '~1')}")
                        for key, item in value.items()}
            if isinstance(value, list):
                return [convert(item, f"{path}/{index}") for index, item in enumerate(value)]
            if isinstance(value, str) and (match := REFERENCE.match(value)):
                target = local.get((match.group(1), match.group(2)))
                exported.relation_paths.setdefault(resource.id, set()).add(path)
                return {"Ref": target} if target else exported.unknown(resource.id, path)
            return value

        properties: dict = {}
        for item in resource.fields:
            if not item.path.startswith("/properties/") or item.state in OMITTED_STATES:
                continue
            selected = item.selected()
            if item.state == ValueState.KNOWN and selected is not None:
                _put(properties, item.path, convert(selected.value, item.path))
            else:
                _put(properties, item.path, exported.unknown(resource.id, item.path))
        for relation in design.relations:
            if relation.source_resource_id != resource.id:
                continue
            exported.relation_paths.setdefault(resource.id, set()).add(relation.source_path)
            target = relation.target_resource_id
            if target in group_of and group_of[target] is exported:
                _put(properties, relation.source_path, {"Ref": logical[target]})
            else:
                if target in group_of:
                    exported.outside_relations.append({"resource_id": resource.id,
                                                       "path": relation.source_path, "target": target})
                _put(properties, relation.source_path, exported.unknown(resource.id, relation.source_path))
        body: dict = {"Type": resource.type}
        if properties:
            body["Properties"] = properties
        if resource.template and resource.template.depends_on:
            depends = [local[(t, n)] for (t, n) in local if n in resource.template.depends_on
                       and local[(t, n)] != logical[resource.id]]
            if depends:
                body["DependsOn"] = sorted(set(depends))
        exported.template["Resources"][logical[resource.id]] = body
    return list(groups.values())
