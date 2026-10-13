"""Checks for AWS::RDS::EventSubscription."""
import json
from functools import lru_cache
from pathlib import Path
from ..registry import resource_check
from ..common.artifact_values import value
from ..common.context_values import CFN, _Context
from ..common.field_reads import ABSENT

SOURCES = {
    'RDS_EVENT_CATEGORY_SNAPSHOT': [CFN + 'aws-resource-rds-eventsubscription.html',
        'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Events.Messages.html',
        'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Events.Messages.html'],
}


@lru_cache(maxsize=1)
def event_category_snapshot():
    return json.loads((Path(__file__).resolve().parents[4] / 'rules/rds-event-categories.json').read_text(encoding='utf-8'))


@resource_check('AWS::RDS::EventSubscription')
def event_categories(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/EventCategories'
    categories = value(ctx, resource, path)
    if categories is ABSENT or categories == []:
        return []
    source = value(ctx, resource, '/properties/SourceType')
    snapshot = event_category_snapshot()
    allowed = snapshot['categories'].get(source) if isinstance(source, str) else None
    verdict = 'NEEDS_REVIEW'
    if allowed is not None and isinstance(categories, list) and all(isinstance(c, str) and c in allowed for c in categories):
        verdict = 'PASS'
    return [{**ctx.finding('RDS_EVENT_CATEGORY_SNAPSHOT', path, verdict,
        'checks membership in the reviewed RDS/Aurora documentation snapshot; unlisted categories require DescribeEventCategories review, not rejection'),
        'severity': 'WARNING', 'source_checked_at': snapshot['checked_at'],
        'rule_version': snapshot['version']}]
