"""Required-value verdicts and unresolved-value detection."""
from .context_values import value
from .field_reads import ABSENT, UNKNOWN


def uncertain(v):
    return v is UNKNOWN or (isinstance(v, str) and '{{resolve:' in v)


def required_value(ctx, resource, path):
    v = value(ctx, resource, path)
    if v is ABSENT:
        return 'FAIL'
    if uncertain(v) or v is None:
        return 'NEEDS_REVIEW'
    return 'PASS'
