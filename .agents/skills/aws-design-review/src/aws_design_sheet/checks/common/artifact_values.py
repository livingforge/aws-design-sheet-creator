"""Value access for checks that inspect artifact contents included in the design."""
from .context_values import value as _value
from .field_reads import UNKNOWN


def value(ctx, resource, path):
    content = _value(ctx, resource, path)
    if isinstance(content, str) and '{{resolve:' in content:
        ctx.dependencies.append(resource.id + path)
        return UNKNOWN
    return content
