"""Checks for AWS::ECR::PullThroughCacheRule."""
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.scope import scope_findings

SOURCES = {
    'ECR_CACHE_ROLE_ACCOUNT': ['https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreatePullThroughCacheRule.html'],
}
SCOPE_SPECS = {
    'AWS::Route53::HostedZone': [('/properties/QueryLoggingConfig/CloudWatchLogsLogGroupArn', 'logs', 'AWS::Logs::LogGroup', 'account', 'ROUTE53_QUERY_LOG_ACCOUNT')],
    'AWS::ECR::PullThroughCacheRule': [('/properties/CustomRoleArn', 'iam', 'AWS::IAM::Role', 'account', 'ECR_CACHE_ROLE_ACCOUNT')],
    'AWS::CloudWatch::MetricStream': [('/properties/RoleArn', 'iam', 'AWS::IAM::Role', 'account', 'CLOUDWATCH_STREAM_ARN_ACCOUNT'),
        ('/properties/FirehoseArn', 'firehose', 'AWS::KinesisFirehose::DeliveryStream', 'account', 'CLOUDWATCH_STREAM_ARN_ACCOUNT')],
    'AWS::KMS::Alias': [('/properties/TargetKeyId', 'kms', 'AWS::KMS::Key', 'both', 'KMS_ALIAS_TARGET_SCOPE')],
}


@resource_check('AWS::ECR::PullThroughCacheRule')
def ecr_cache_role_scope(design, resource):
    return scope_findings(_Context(design, resource), resource, SCOPE_SPECS[resource.type])
