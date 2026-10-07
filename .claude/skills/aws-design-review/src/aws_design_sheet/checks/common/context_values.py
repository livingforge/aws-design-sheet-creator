"""Check context with value lookup and explicit resource links."""
from __future__ import annotations

from ...models import ValueState
from .context import Context
from .field_reads import UNKNOWN, linked as _linked, read

CFN = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'


class _Context(Context):
    def finding(self, rule_id, path, verdict, reason):
        if verdict == 'NEEDS_REVIEW' and not self.dependencies:
            self.dependencies.append(self.resource.id + path)
        return {**super().finding(rule_id, path, verdict, reason), 'source_checked_at': '2026-10-03'}


def value(ctx, resource, path):
    """A property relation establishes presence, but does not resolve a scalar."""
    refs = [r for r in ctx.design.relations if r.source_resource_id == resource.id and r.source_path == path]
    if refs:
        ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
        ctx.dependencies.append(resource.id + path)
        return UNKNOWN
    return read(ctx, resource, path)


def linked(ctx, resource, path, expected):
    refs = [r for r in ctx.design.relations if r.source_resource_id == resource.id and r.source_path == path]
    if any(r.condition for r in refs):
        return None
    for field in resource.fields:
        if path != field.path and not path.startswith(field.path + '/'):
            continue
        if field.state not in (ValueState.KNOWN, ValueState.MISSING):
            return None
        if field.state == ValueState.MISSING:
            continue
        node = field.selected().value
        for key in path[len(field.path):].strip('/').split('/') if path != field.path else ():
            if isinstance(node, dict) and '$state' in node:
                return None
            node = (node.get(key) if isinstance(node, dict) else
                    node[int(key)] if isinstance(node, list) and key.isdigit() and int(key) < len(node) else None)
        if isinstance(node, dict) and '$state' in node:
            return None
    return _linked(ctx, resource, path, expected)
