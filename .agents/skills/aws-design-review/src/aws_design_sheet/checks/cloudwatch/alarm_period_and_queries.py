"""Checks for AWS::CloudWatch::Alarm, AWS::CloudWatch::AnomalyDetector."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, UNKNOWN, read


SOURCES = {
    "CLOUDWATCH_ALARM_PERIOD": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html#cfn-cloudwatch-alarm-period"],
    "CLOUDWATCH_QUERY_IDS_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-alarm-metricdataquery.html"],
    "CLOUDWATCH_QUERY_RETURN_DATA": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-alarm-metricdataquery.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-anomalydetector-metricmathanomalydetector.html"],
}


@resource_check('AWS::CloudWatch::Alarm', 'AWS::CloudWatch::AnomalyDetector')
def cloudwatch_queries(design, resource):
    ctx = _Context(design, resource)
    path = ('/properties/Metrics' if resource.type == 'AWS::CloudWatch::Alarm' else
            '/properties/MetricMathAnomalyDetector/MetricDataQueries')
    queries = read(ctx, resource, path)
    if queries is ABSENT:
        return []
    if not isinstance(queries, list) or not queries:
        return [ctx.finding('CLOUDWATCH_QUERY_IDS_UNIQUE', path, 'NEEDS_REVIEW', 'queries are unresolved'),
                ctx.finding('CLOUDWATCH_QUERY_RETURN_DATA', path, 'NEEDS_REVIEW', 'queries are unresolved')]
    ids = [read(ctx, resource, path + f'/{i}/Id') for i in range(len(queries))]
    known_ids = [v for v in ids if isinstance(v, str)]
    verdict = ('FAIL' if len(known_ids) != len(set(known_ids)) else
               'NEEDS_REVIEW' if len(known_ids) != len(ids) else 'PASS')
    results = [ctx.finding('CLOUDWATCH_QUERY_IDS_UNIQUE', path, verdict, 'metric query IDs must be unique')]
    flags = [read(ctx, resource, path + f'/{i}/ReturnData') for i in range(len(queries))]
    count = sum(v is True for v in flags)
    expressions = [read(ctx, resource, path + f'/{i}/Expression') for i in range(len(queries))]
    math = any(isinstance(v, str) for v in expressions)
    wrong_result = resource.type == 'AWS::CloudWatch::Alarm' and math and any(
        flag is True and expression is ABSENT for flag, expression in zip(flags, expressions))
    verdict = ('FAIL' if count > 1 or wrong_result else
               'NEEDS_REVIEW' if any(type(v) is not bool for v in flags) or
               (math and any(v is UNKNOWN for v in expressions)) else
               'PASS' if count == 1 else 'FAIL')
    results.append(ctx.finding('CLOUDWATCH_QUERY_RETURN_DATA', path, verdict,
                              'exactly one query must return data; a math alarm must return its expression'))
    return results


@resource_check('AWS::CloudWatch::Alarm')
def alarm_period(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    period = read(ctx, resource, '/properties/Period')
    if period is ABSENT:
        return []
    verdict = ('NEEDS_REVIEW' if type(period) is not int else
               'PASS' if period in (10, 20, 30) or period > 0 and period % 60 == 0 else 'FAIL')
    return [ctx.finding('CLOUDWATCH_ALARM_PERIOD', '/properties/Period', verdict,
                        'period must be 10, 20, 30 seconds or a positive multiple of 60')]
