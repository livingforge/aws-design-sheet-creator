"""Checks for AWS::Cognito::LogDeliveryConfiguration."""
import re
from ..registry import resource_check
from .logs import log_verdict
from ..common.context_values import _Context, value
from ..common.literals import expand

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_LOG_GROUP_ACCOUNT_ENCRYPTION': [CF+'aws-properties-cognito-logdeliveryconfiguration-cloudwatchlogsconfiguration.html',CF+'aws-resource-logs-loggroup.html'],
}


@resource_check('AWS::Cognito::LogDeliveryConfiguration')
def evaluate_cognito_log_group_account_encryption(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::Cognito::LogDeliveryConfiguration':
        pattern='/properties/LogConfigurations/*/CloudWatchLogsConfiguration/LogGroupArn'
        for p in expand(ctx, resource, pattern):
            exact=re.fullmatch(r'/properties/LogConfigurations/\d+/CloudWatchLogsConfiguration/LogGroupArn',p)
            verdict=log_verdict(ctx,resource,p) if exact else 'NEEDS_REVIEW'
            emit('COGNITO_LOG_GROUP_ACCOUNT_ENCRYPTION',p,verdict,'Declared log group must share the uniquely linked user-pool account and omit KMS encryption. Explicit KMS references establish encryption; omitted KmsKeyId uses documented non-KMS encryption. Raw/reference conflicts, unknown/conditional/external identity and encryption stay reviewable. Live state, policies and delivery are separate.')
    return results
