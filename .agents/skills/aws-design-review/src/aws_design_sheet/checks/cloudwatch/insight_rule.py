"""Contributor Insights structure; field-path evaluation remains separate."""
import json
import math
from ..registry import resource_check
from .insight_paths import insight_paths
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_constants import reject_constant

SOURCES = {
    'CLOUDWATCH_INSIGHT_STRUCTURE': ['https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html'],
    'CLOUDWATCH_INSIGHT_TAG_COUNT': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-insightrule.html'],
}


def string_array(item, maximum=None):
    return isinstance(item, list) and (maximum is None or len(item) <= maximum) and all(isinstance(v, str) for v in item)


def structure(body):
    if not isinstance(body, dict):
        return 'FAIL'
    schema = body.get('Schema')
    if schema != {'Name': 'CloudWatchLogRule', 'Version': 1} or type(schema.get('Version')) is not int:
        return 'NEEDS_REVIEW'  # No assumptions about other rule schemas or versions.
    bad = ('LogGroupNames' in body) == ('LogGroupARNs' in body)
    for field in ('LogGroupNames', 'LogGroupARNs'):
        if field in body:
            bad |= not string_array(body[field])
    bad |= body.get('LogFormat') not in ('JSON', 'CLF')
    bad |= body.get('AggregateOn') not in ('Count', 'Sum')
    contribution = body.get('Contribution')
    if not isinstance(contribution, dict):
        return 'FAIL'
    bad |= not string_array(contribution.get('Keys'), 4)
    if 'ValueOf' in contribution:
        bad |= body.get('AggregateOn') != 'Sum' or not isinstance(contribution['ValueOf'], str)
    filters = contribution.get('Filters', [])
    if not isinstance(filters, list) or len(filters) > 4:
        return 'FAIL'
    arrays = {'In', 'NotIn', 'StartsWith'}
    numbers = {'GreaterThan', 'LessThan', 'EqualTo', 'NotEqualTo'}
    operators = arrays | numbers | {'IsPresent'}
    for item in filters:
        if not isinstance(item, dict):
            return 'FAIL'
        selected = set(item) & operators
        if len(selected) != 1 or not isinstance(item.get('Match'), str):
            return 'FAIL'
        operator = next(iter(selected))
        operand = item[operator]
        if operator in arrays:
            bad |= not string_array(operand, 10)
        elif operator in numbers:
            bad |= type(operand) not in (int, float) or (type(operand) is float and not math.isfinite(operand))
        else:
            bad |= type(operand) is not bool
    return 'FAIL' if bad else 'PASS'


@resource_check('AWS::CloudWatch::InsightRule')
def insight_rule(design, resource):
    ctx = _Context(design, resource)
    results = []
    raw = value(ctx, resource, '/properties/RuleBody')
    if raw is not ABSENT:
        verdict = 'NEEDS_REVIEW'
        if isinstance(raw, str) and '{{resolve:' not in raw:
            try:
                verdict = structure(json.loads(raw, parse_constant=reject_constant))
            except (ValueError, RecursionError):
                verdict = 'FAIL'
        results.append(ctx.finding('CLOUDWATCH_INSIGHT_STRUCTURE', '/properties/RuleBody', verdict,
            'checks JSON, log-source exclusivity, fixed values, contribution counts and filter operand types; field paths and CLF aliases remain separate'))
    tags = value(ctx, resource, '/properties/Tags')
    if tags is not ABSENT:
        verdict = 'PASS' if isinstance(tags, list) and len(tags) <= 50 else 'FAIL' if isinstance(tags, list) else 'NEEDS_REVIEW'
        results.append(ctx.finding('CLOUDWATCH_INSIGHT_TAG_COUNT', '/properties/Tags', verdict,
            'at most 50 tags; tagging permission is not evaluated'))
    return results + insight_paths(design, resource)
