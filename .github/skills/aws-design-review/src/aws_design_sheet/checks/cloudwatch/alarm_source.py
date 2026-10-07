"""Checks for AWS::CloudWatch::Alarm."""
from ..registry import resource_check
from .dashboard_and_metric_stream import extended_statistic
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

SOURCES = {
    'CLOUDWATCH_ALARM_SOURCE': ['https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html'],
    'CLOUDWATCH_PROMQL_PROPERTIES': ['https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html'],
}


@resource_check('AWS::CloudWatch::Alarm')
def alarm_source(design, resource):
    ctx = _Context(design, resource)
    fields = [value(ctx, resource, '/properties/' + k) for k in ('MetricName', 'Metrics', 'EvaluationCriteria')]
    known = sum(v is not ABSENT and v is not UNKNOWN for v in fields)
    pending = any(v is UNKNOWN for v in fields)
    verdict = 'FAIL' if known > 1 or known == 0 and not pending else 'NEEDS_REVIEW' if pending else 'PASS'
    results = [ctx.finding('CLOUDWATCH_ALARM_SOURCE', '/properties', verdict,
        'specify one alarm source: MetricName, Metrics or EvaluationCriteria')]
    if fields[2] is not ABSENT:
        excluded = ('Namespace', 'MetricName', 'Dimensions', 'Period', 'Unit', 'Statistic', 'ExtendedStatistic',
                    'Metrics', 'Threshold', 'ComparisonOperator', 'ThresholdMetricId', 'EvaluationPeriods',
                    'DatapointsToAlarm', 'EvaluationWindow')
        values = [value(ctx, resource, '/properties/' + k) for k in excluded]
        interval = value(ctx, resource, '/properties/EvaluationInterval')
        bad = any(v is not ABSENT and v is not UNKNOWN for v in values) or interval is ABSENT or (
            type(interval) is int and not (10 <= interval <= 3600 and (interval in (10, 20, 30) or interval % 60 == 0)))
        pending = fields[2] is UNKNOWN or any(v is UNKNOWN for v in values) or type(interval) is not int
        verdict = 'NEEDS_REVIEW' if fields[2] is UNKNOWN else 'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS'
        results.append(ctx.finding('CLOUDWATCH_PROMQL_PROPERTIES', '/properties/EvaluationCriteria', verdict,
            'PromQL requires an evaluation interval and excludes ordinary metric alarm evaluation fields'))
    return results + extended_statistic(design, resource)
