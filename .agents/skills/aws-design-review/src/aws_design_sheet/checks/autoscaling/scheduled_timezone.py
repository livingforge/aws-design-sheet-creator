"""Checks for AWS::AutoScaling::ScheduledAction."""
from functools import lru_cache
from importlib.resources import files
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.timezones import timezone_names

SOURCES = {
    'AUTOSCALING_SCHEDULE_TIMEZONE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-scheduledaction.html',
        'https://pypi.org/project/tzdata/2026.4/',
    ],
}


@lru_cache(maxsize=1)
def canonical_timezone_names():
    if timezone_names() is None:
        return None
    try:
        data = files('tzdata').joinpath('zoneinfo/tzdata.zi').read_text(encoding='utf-8')
        names = frozenset(line.split()[1] for line in data.splitlines() if line.startswith('Z '))
        return names or None
    except (OSError, IndexError):
        return None


@resource_check('AWS::AutoScaling::ScheduledAction')
def scheduled_timezone(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/TimeZone'
    name = value(ctx, resource, path)
    if name is ABSENT:
        return []
    names, canonical = timezone_names(), canonical_timezone_names()
    verdict = 'NEEDS_REVIEW'
    if names is not None and canonical is not None and isinstance(name, str) and '{{' not in name:
        verdict = 'PASS' if name in canonical else 'NEEDS_REVIEW' if name in names else 'FAIL'
    return [ctx.finding('AUTOSCALING_SCHEDULE_TIMEZONE', path, verdict,
        'checks canonical zones in pinned tzdata 2026.4; legacy links, unresolved names and unavailable data need review, without assuming AWS alias acceptance')]
