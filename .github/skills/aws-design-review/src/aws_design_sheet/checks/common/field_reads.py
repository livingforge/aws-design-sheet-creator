"""Raw field reads: ABSENT and UNKNOWN markers, resolved values and links."""
from __future__ import annotations

from ...models import ValueState

ABSENT = object()
UNKNOWN = object()


def _unresolved_expression(value):
    return isinstance(value, dict) and any(
        key in ('$state', '$ref', 'Ref') or isinstance(key, str) and key.startswith('Fn::')
        for key in value)


def read(ctx: _Context, resource: Resource, path: str):
    """Read explicit child fields or a known ancestor; never substitute defaults."""
    current = path
    while current.startswith('/properties/'):
        field = resource.field(current)
        if field is not None:
            if field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
                return ABSENT
            value = ctx.value(resource, current)
            if field.state != ValueState.KNOWN:
                return UNKNOWN
            for key in path[len(current):].strip('/').split('/') if current != path else ():
                if _unresolved_expression(value):
                    value = UNKNOWN
                    break
                if isinstance(value, dict):
                    value = value.get(key, ABSENT)
                elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
                    value = value[int(key)]
                else:
                    value = UNKNOWN
                    break
                if value is ABSENT:
                    break
            if _unresolved_expression(value):
                value = UNKNOWN
            if value is UNKNOWN:
                ctx.dependencies.append(resource.id + path)
            return value
        current = current.rsplit('/', 1)[0]
    # A parent may be represented entirely by explicit child fields.
    children = [f for f in resource.fields if f.path.startswith(path + '/')]
    if children:
        value = {}
        for field in children:
            keys = field.path[len(path) + 1:].split('/')
            target = value
            for key in keys[:-1]:
                target = target.setdefault(key, {})
            target[keys[-1]] = read(ctx, resource, field.path)
        return value
    return ABSENT


def linked(ctx: _Context, resource: Resource, path: str, expected: str):
    current = path
    while current.startswith('/properties/'):
        field = resource.field(current)
        if field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING):
            ctx.dependencies.append(resource.id + current)
            return None
        current = current.rsplit('/', 1)[0]
    refs = [r for r in ctx.design.relations
            if r.source_resource_id == resource.id and r.source_path == path]
    if not refs:
        return None
    return ctx.target(resource, path, expected)
