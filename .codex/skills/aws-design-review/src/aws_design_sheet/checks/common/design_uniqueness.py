"""Uniqueness of identifiers among resources declared in one design."""
from __future__ import annotations

from ...models import ValueState
from .context import Context
from .field_reads import UNKNOWN, read


class _Context(Context):
    def finding(self, rule_id, path, verdict, reason):
        if verdict == 'NEEDS_REVIEW' and not self.dependencies:
            self.dependencies.append(self.resource.id + path)
        return {**super().finding(rule_id, path, verdict, reason), 'source_checked_at': '2026-10-02'}


def _identity(ctx, resource, path):
    value = read(ctx, resource, path)
    field = resource.field(path)
    if field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING):
        return UNKNOWN
    refs = [r for r in ctx.design.relations if r.source_resource_id == resource.id and r.source_path == path]
    if refs:
        ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
        target = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
        if target is not None and target.scope == resource.scope:
            return ('resource', target.id)
        return UNKNOWN
    return ('literal', value) if isinstance(value, str) else UNKNOWN


def unique_in_design(design, resource, path, rule, owner_path=None):
    ctx = _Context(design, resource)
    identity = _identity(ctx, resource, path)
    owner = _identity(ctx, resource, owner_path) if owner_path else None
    pending = identity is UNKNOWN or owner is UNKNOWN
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_owner = _identity(ctx, other, owner_path) if owner_path else None
        other_id = _identity(ctx, other, path)
        if owner is not UNKNOWN and other_owner is not UNKNOWN and owner != other_owner:
            if owner_path and owner[0] != other_owner[0]:
                pending = True  # A literal physical ID may describe a linked owner.
            continue
        if identity is not UNKNOWN and owner is not UNKNOWN and identity == other_id and owner == other_owner:
            return ctx.finding(rule, path, 'FAIL', 'duplicate identity in the same design scope')
        if other_owner is UNKNOWN or other_id is UNKNOWN or (
                identity is not UNKNOWN and identity[0] != other_id[0]):
            pending = True
    return ctx.finding(rule, path, 'NEEDS_REVIEW' if pending else 'PASS',
                       'design identities are unresolved' if pending else 'no duplicate identity in the design')
