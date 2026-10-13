"""Checks for AWS::CloudWatch::AnomalyDetector."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.timezones import timezone_names

SOURCES = {
    'CLOUDWATCH_ANOMALY_TIMEZONE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-anomalydetector-configuration.html',
        'https://pypi.org/project/tzdata/2026.4/',
    ],
}


@resource_check('AWS::CloudWatch::AnomalyDetector')
def anomaly_timezone(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/Configuration/MetricTimeZone'
    name = value(ctx, resource, path)
    if name is ABSENT:
        return []
    names = timezone_names()
    verdict = ('NEEDS_REVIEW' if names is None or not isinstance(name, str) or '{{' in name else
               'PASS' if name in names else 'FAIL')
    return [ctx.finding('CLOUDWATCH_ANOMALY_TIMEZONE', path, verdict,
        'timezone name must appear in pinned tzdata 2026.4 (IANA 2026d), including aliases; missing or different dataset requires review')]
