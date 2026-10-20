"""Lookup tables over one design, shared by the checks of one checker run.

Checks look up relations of a resource property and resources by ID or type
many times per resource; scanning the whole design for each lookup makes a run
quadratic or worse in the design size. ``Checker.check`` activates an index for
the design it checks. Helpers ask for it with ``active(design)``, which answers
only for that same design object, so a direct call with any other design (tests,
scripts) keeps the plain scans. Checks never modify the design while it runs.
Every list keeps design order, and callers receive copies.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from ...models import ValueState

_ACTIVE: ContextVar[DesignIndex | None] = ContextVar('design_index', default=None)


def _scope(resource) -> tuple[str, str, str]:
    return resource.scope.environment, resource.scope.account, resource.scope.region


def template_key(resource) -> tuple | None:
    """Template ID and scope shared by the members of one declared template."""
    template = resource.template
    if not template or template.state != ValueState.KNOWN:
        return None
    return (template.id, *_scope(resource))


class DesignIndex:
    def __init__(self, design):
        self.design = design
        self.by_id = {resource.id: resource for resource in design.resources}
        self.position = {resource.id: i for i, resource in enumerate(design.resources)}
        self.memo: dict = {}
        self.by_type: dict[str, list] = {}
        self.templates: dict[tuple, list] = {}
        self.template_names: dict[tuple, dict[str, list]] = {}
        self.template_ids: dict[tuple, set[str]] = {}
        for resource in design.resources:
            self.by_type.setdefault(resource.type, []).append(resource)
            if (key := template_key(resource)) is not None:
                self.templates.setdefault(key, []).append(resource)
                self.template_names.setdefault(key, {}).setdefault(resource.name, []).append(resource)
                self.template_ids.setdefault(key, set()).add(resource.id)
        self.from_source: dict[str, list] = {}
        self.at_path: dict[tuple[str, str], list] = {}
        for relation in design.relations:
            self.from_source.setdefault(relation.source_resource_id, []).append(relation)
            self.at_path.setdefault((relation.source_resource_id, relation.source_path), []).append(relation)


def active(design) -> DesignIndex | None:
    index = _ACTIVE.get()
    return index if index is not None and index.design is design else None


@contextmanager
def indexed(design):
    """Make an index of the design available to helpers until the block ends."""
    token = _ACTIVE.set(DesignIndex(design))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def resources_by_id(design) -> dict:
    """ID -> resource. Shared while indexed: read it, never modify it."""
    index = active(design)
    return index.by_id if index is not None else {item.id: item for item in design.resources}


def resources_of_type(design, type_name: str) -> list:
    index = active(design)
    if index is not None:
        return list(index.by_type.get(type_name, ()))
    return [resource for resource in design.resources if resource.type == type_name]


def resources_of_types(design, types) -> list:
    """Resources of any of the types, in design order."""
    index = active(design)
    if index is not None:
        found = [resource for type_name in set(types) for resource in index.by_type.get(type_name, ())]
        return sorted(found, key=lambda resource: index.position[resource.id])
    return [resource for resource in design.resources if resource.type in types]


def memo(design, key, compute):
    """compute() once per indexed run; without an index, on every call.

    Only for results that depend on the design alone, never on the caller's state.
    """
    index = active(design)
    if index is None:
        return compute()
    if key not in index.memo:
        index.memo[key] = compute()
    return index.memo[key]


def relations_from(design, source_id: str) -> list:
    index = active(design)
    if index is not None:
        return list(index.from_source.get(source_id, ()))
    return [relation for relation in design.relations if relation.source_resource_id == source_id]


def relations_at(design, source_id: str, path: str) -> list:
    index = active(design)
    if index is not None:
        return list(index.at_path.get((source_id, path), ()))
    return [relation for relation in design.relations
            if relation.source_resource_id == source_id and relation.source_path == path]
