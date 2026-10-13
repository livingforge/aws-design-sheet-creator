"""Checks for AWS::CloudWatch::MetricStream, AWS::CloudWatch::CompositeAlarm."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scope import scope_findings

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLOUDWATCH_SUPPRESSOR_DECLARATION': [CF + 'aws-resource-cloudwatch-compositealarm.html'],
    'CLOUDWATCH_STREAM_ARN_ACCOUNT': [CF + 'aws-resource-cloudwatch-metricstream.html'],
}
SCOPE_SPECS = {
    'AWS::Route53::HostedZone': [('/properties/QueryLoggingConfig/CloudWatchLogsLogGroupArn', 'logs', 'AWS::Logs::LogGroup', 'account', 'ROUTE53_QUERY_LOG_ACCOUNT')],
    'AWS::ECR::PullThroughCacheRule': [('/properties/CustomRoleArn', 'iam', 'AWS::IAM::Role', 'account', 'ECR_CACHE_ROLE_ACCOUNT')],
    'AWS::CloudWatch::MetricStream': [('/properties/RoleArn', 'iam', 'AWS::IAM::Role', 'account', 'CLOUDWATCH_STREAM_ARN_ACCOUNT'),
        ('/properties/FirehoseArn', 'firehose', 'AWS::KinesisFirehose::DeliveryStream', 'account', 'CLOUDWATCH_STREAM_ARN_ACCOUNT')],
    'AWS::KMS::Alias': [('/properties/TargetKeyId', 'kms', 'AWS::KMS::Key', 'both', 'KMS_ALIAS_TARGET_SCOPE')],
}


@resource_check('AWS::CloudWatch::MetricStream')
def metric_stream_scope(design, resource):
    return scope_findings(_Context(design, resource), resource, SCOPE_SPECS[resource.type])


@resource_check('AWS::CloudWatch::CompositeAlarm')
def composite_alarm_suppressor(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/ActionsSuppressor'
    if value(ctx, resource, path) is ABSENT:
        return []
    alarm = linked(ctx, resource, path, 'AWS::CloudWatch::Alarm')
    if alarm is None:
        alarm = linked(ctx, resource, path, 'AWS::CloudWatch::CompositeAlarm')
    known_scope = (re.fullmatch(r'[0-9]{12}', resource.scope.account)
                   and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+', resource.scope.region))
    return [ctx.finding('CLOUDWATCH_SUPPRESSOR_DECLARATION', path,
        'PASS' if known_scope and alarm is not None and alarm.id != resource.id else 'NEEDS_REVIEW',
        'checks an explicit same-scope suppressor alarm declaration only; deployment order, alarm state, AlarmRule references and external existence remain separate')]
