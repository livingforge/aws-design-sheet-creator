"""Checks for AWS::Config::DeliveryChannel."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .key_region import config_key_region

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONFIG_BUCKET_KMS_REGION': [CF+'aws-resource-config-deliverychannel.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html'],
}


@resource_check('AWS::Config::DeliveryChannel')
def evaluate_config_bucket_kms_region(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::Config::DeliveryChannel':
        path = '/properties/S3KmsKeyArn'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            emit('CONFIG_BUCKET_KMS_REGION',path,config_key_region(ctx,resource),'KMS key ARN or explicit linked key Region must match destination S3 bucket Region. Named cross-account/Region bucket references are supported. Unknown scope/templates and conditional or external references remain reviewable; access policies are separate.')
    return results
